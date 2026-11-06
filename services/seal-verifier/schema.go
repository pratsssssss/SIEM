package main

import (
	"encoding/json"
	"regexp"
	"strconv"
	"time"
)

var (
	uidPattern = regexp.MustCompile(`^(?:[0-9a-f]{64}|[0-9a-f-]{36})\z`)
	idPattern  = regexp.MustCompile(`^[0-9]{1,5}\z`)
	ridPattern = regexp.MustCompile(`^[0-9]{1,20}\z`)
)

var channels = map[string]bool{
	"Security": true, "System": true,
	"Microsoft-Windows-Sysmon/Operational":                               true,
	"Microsoft-Windows-PowerShell/Operational":                           true,
	"Microsoft-Windows-Windows Defender/Operational":                     true,
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": true,
	"Microsoft-Windows-TaskScheduler/Operational":                        true,
	linuxJournal: true, linuxPackage: true,
}

var topFields = map[string]bool{
	"activity_id": true, "channel": true, "computer": true, "event_data": true, "event_id": true, "event_uid": true,
	"host": true, "keyword_names": true, "keywords": true, "labels": true, "level": true, "level_value": true,
	"opcode": true, "opcode_name": true, "process_id": true, "provider_guid": true, "provider_name": true,
	"qualifiers": true, "record_id": true, "related_activity_id": true, "sealed": true, "source_type": true,
	"string_inserts": true, "task": true, "task_name": true, "thread_id": true, "timestamp": true, "user_data": true,
	"user_id": true, "user_name": true, "version": true, "xml": true,
}

const (
	sysmonChannel     = "Microsoft-Windows-Sysmon/Operational"
	powershellChannel = "Microsoft-Windows-PowerShell/Operational"
	linuxJournal      = "linux-journal"
	linuxPackage      = "linux-package"
)

func isLinux(channel string) bool { return channel == linuxJournal || channel == linuxPackage }

// restricted lists the fields D22 seals. These are never allowed through in plaintext.
func restricted(channel, id string) []string {
	if isLinux(channel) {
		// Any Linux program can write anything to the journal, so all message text is sealed.
		return []string{"Message", "CommandLine"}
	}
	switch channel + "|" + id {
	case sysmonChannel + "|1":
		return []string{"CommandLine", "ParentCommandLine"}
	case sysmonChannel + "|13":
		return []string{"Details"}
	case sysmonChannel + "|19":
		return []string{"Query"}
	case sysmonChannel + "|20":
		return []string{"Destination"}
	case powershellChannel + "|4104":
		return []string{"ScriptBlockText"}
	case powershellChannel + "|4100":
		return []string{"ContextInfo", "Payload", "UserData"}
	case "Security|4688":
		return []string{"CommandLine"}
	case "Security|4697":
		return []string{"ServiceFileName"}
	case "System|7045":
		return []string{"ImagePath"}
	}
	return nil
}

func sealRequired(channel, id string) bool {
	return (channel == sysmonChannel && id == "1") || (channel == powershellChannel && (id == "4104" || id == "4100"))
}

// idText gives the same text the agent's to_string gave, for a JSON number or string.
func idText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		if _, err := strconv.ParseUint(number.String(), 10, 64); err == nil {
			return number.String()
		}
	}
	return ""
}

func emptyValue(raw json.RawMessage) bool {
	var text string
	return raw == nil || string(raw) == "null" || (json.Unmarshal(raw, &text) == nil && text == "")
}

type checkedEvent struct {
	ref    eventRef
	data   map[string]json.RawMessage
	sealed map[string]json.RawMessage
}

// checkEvent validates an authenticated event. A valid MAC proves who wrote it, and these checks
// prove it is the shape the pipeline expects, so a broken agent cannot leak or stall anything.
func checkEvent(event map[string]json.RawMessage, envelopeUID string, now time.Time) (checkedEvent, string) {
	out := checkedEvent{data: map[string]json.RawMessage{}, sealed: map[string]json.RawMessage{}}
	json.Unmarshal(event["channel"], &out.ref.Channel)
	json.Unmarshal(event["event_uid"], &out.ref.EventUID)
	out.ref.EventID = idText(event["event_id"])
	out.ref.RecordID = idText(event["record_id"])

	if !uidPattern.MatchString(out.ref.EventUID) || out.ref.EventUID != envelopeUID {
		return out, "schema_identity"
	}
	if !channels[out.ref.Channel] {
		return out, "schema_channel"
	}
	if !idPattern.MatchString(out.ref.EventID) || !ridPattern.MatchString(out.ref.RecordID) {
		return out, "schema_ids"
	}
	for name := range event {
		if !topFields[name] {
			return out, "schema_unknown_field"
		}
	}
	var computer, stamp string
	if json.Unmarshal(event["computer"], &computer) != nil || computer == "" || json.Unmarshal(event["timestamp"], &stamp) != nil {
		return out, "schema_fields"
	}
	when, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return out, "schema_timestamp"
	}
	if now.Sub(when) > maxEventAge {
		return out, "stale_event"
	}
	if raw, ok := event["event_data"]; ok && json.Unmarshal(raw, &out.data) != nil {
		return out, "schema_event_data"
	}
	if out.data == nil {
		out.data = map[string]json.RawMessage{}
	}
	if raw, ok := event["sealed"]; ok && json.Unmarshal(raw, &out.sealed) != nil {
		return out, "schema_sealed"
	}
	if out.sealed == nil {
		out.sealed = map[string]json.RawMessage{}
	}

	allowed := restricted(out.ref.Channel, out.ref.EventID)
	for _, name := range allowed {
		if !emptyValue(out.data[name]) {
			return out, "unsealed_restricted"
		}
	}
	sysmonOrPowershell := out.ref.Channel == sysmonChannel || out.ref.Channel == powershellChannel
	if _, inserts := event["string_inserts"]; inserts && sysmonOrPowershell {
		return out, "unsealed_restricted"
	}
	if _, inserts := out.data["_string_inserts"]; inserts {
		return out, "unsealed_restricted"
	}
	if len(out.sealed) > maxSealed {
		return out, "sealed_too_many"
	}
	var labels struct {
		SealFailed bool `json:"seal_failed"`
		Oversized  bool `json:"oversized"`
	}
	json.Unmarshal(event["labels"], &labels)
	if len(out.sealed) == 0 && !labels.SealFailed && !labels.Oversized && sealRequired(out.ref.Channel, out.ref.EventID) {
		return out, "seal_missing"
	}
	for name, item := range out.sealed {
		permitted := name == "_string_inserts"
		for _, field := range allowed {
			permitted = permitted || field == name
		}
		if !permitted {
			return out, "sealed_field_not_allowed"
		}
		var shape map[string]json.RawMessage
		if json.Unmarshal(item, &shape) != nil || shape == nil {
			return out, "sealed_shape"
		}
	}
	return out, ""
}
