#!/bin/bash
# Changes the OpenSearch admin password to one the operator types. Run as root, in a real
# terminal, with OpenSearch up. Input is hidden. The password never appears in arguments,
# output or logs, and is stored only in the root-only credential file.
# admin is a reserved account, so the change uses the admin client certificate.
# The credential file is replaced only after the new password has been proven to work.
set -euo pipefail

U=https://127.0.0.1:9200
CA=/etc/opensearch/root-ca.pem
SECRETS=/root/.siem
CRED=$SECRETS/opensearch-admin.curl
PKI=$SECRETS/pki
USERS=/etc/opensearch/opensearch-security/internal_users.yml
HOME_OS=/usr/share/opensearch
MIN_LENGTH=12

[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }
{ [ -t 0 ] && : </dev/tty; } 2>/dev/null || { echo "Run this in an interactive terminal" >&2; exit 1; }
umask 077
ulimit -c 0

BODY=$(mktemp "$SECRETS/.rotate-body.XXXXXX")
NEW_CFG=$(mktemp "$SECRETS/.rotate-new.XXXXXX")
OLD_CFG=$(mktemp "$SECRETS/.rotate-old.XXXXXX")
SEED_TMP=""
trap 'rm -f "$BODY" "$NEW_CFG" "$OLD_CFG" ${SEED_TMP:+"$SEED_TMP"}' EXIT
trap 'exit 130' INT TERM

status_with() { # curl-config
  curl -s --max-time 10 --cacert "$CA" -K "$1" -o /dev/null -w '%{http_code}' "$U/" || true
}

wait_for_status() { # curl-config expected-status
  local _
  for _ in {1..15}; do
    [ "$(status_with "$1")" = "$2" ] && return 0
    sleep 1
  done
  return 1
}

put_admin_hash() { # bcrypt-hash
  printf '{"hash":"%s","backend_roles":["admin"],"description":"SIEM administrator"}' "$1" >"$BODY"
  curl -s --max-time 30 --cacert "$CA" --cert "$PKI/admin.pem" --key "$PKI/admin-key.pem" -o /dev/null \
    -w '%{http_code}' -XPUT "$U/_plugins/_security/api/internalusers/admin" \
    -H 'Content-Type: application/json' -d @"$BODY" || true
}

cp -p "$CRED" "$OLD_CFG"
[ "$(status_with "$OLD_CFG")" = 200 ] ||
  { echo "The stored credential does not work, or OpenSearch is down. Nothing was changed." >&2; exit 1; }
OLD_HASH=$(awk '/^  hash: /{gsub(/^  hash: "|"$/, ""); print; exit}' "$USERS")
[[ "$OLD_HASH" =~ ^\$2[aby]\$ ]] || { echo "Could not read the current hash. Nothing was changed." >&2; exit 1; }

IFS= read -rs -p 'New OpenSearch admin password: ' PW </dev/tty || { echo; echo "No input. Nothing was changed." >&2; exit 1; }
echo
IFS= read -rs -p 'Confirm new password: ' PW2 </dev/tty || { echo; echo "No input. Nothing was changed." >&2; exit 1; }
echo

[ -n "$PW" ] || { echo "Empty password rejected. Nothing was changed." >&2; exit 1; }
[ "$PW" = "$PW2" ] || { echo "Passwords did not match. Nothing was changed." >&2; exit 1; }
unset PW2
[ "${#PW}" -ge "$MIN_LENGTH" ] || { echo "Use at least $MIN_LENGTH characters. Nothing was changed." >&2; exit 1; }
if [[ "$PW" =~ [[:cntrl:]] ]]; then
  echo "Control characters are not allowed. Nothing was changed." >&2
  exit 1
fi

# curl configuration files treat backslash and double quote as special inside quotes.
ESCAPED=${PW//\\/\\\\}
ESCAPED=${ESCAPED//\"/\\\"}
printf 'user = "admin:%s"\n' "$ESCAPED" >"$NEW_CFG"
unset ESCAPED

[ "$(status_with "$NEW_CFG")" != 200 ] || { echo "That is already the current password. Nothing was changed." >&2; exit 1; }

# The password reaches the hashing tool through its environment, not its arguments.
HASH=$(SIEM_OS_PW=$PW OPENSEARCH_JAVA_HOME=$HOME_OS/jdk \
  bash "$HOME_OS/plugins/opensearch-security/tools/hash.sh" -env SIEM_OS_PW 2>/dev/null | grep -E '^\$2[aby]\$' || true)
unset PW
[ -n "$HASH" ] || { echo "Password hashing failed. Nothing was changed." >&2; exit 1; }

CODE=$(put_admin_hash "$HASH")
[ "$CODE" = 200 ] || { echo "Password change refused: HTTP $CODE. Nothing was changed." >&2; exit 1; }

if ! wait_for_status "$NEW_CFG" 200; then
  CODE=$(put_admin_hash "$OLD_HASH")
  if [ "$CODE" = 200 ] && wait_for_status "$OLD_CFG" 200; then
    echo "The new password did not verify. The old password was restored." >&2
  else
    echo "The new password did not verify, and restoring the old one failed: HTTP $CODE." >&2
    echo "The credential file is unchanged. Rotate again with the admin certificate." >&2
  fi
  exit 1
fi

mv "$NEW_CFG" "$CRED"
chmod 600 "$CRED"

# Keeps the seed file in step, so a rebuilt security index gets the same password.
SEED_TMP=$(mktemp "$USERS.XXXXXX")
cp -p "$USERS" "$SEED_TMP"
if SIEM_HASH=$HASH awk 'BEGIN{h=ENVIRON["SIEM_HASH"]}
    !done && /^  hash: /{print "  hash: \"" h "\""; done=1; next} {print}' "$USERS" >"$SEED_TMP"; then
  mv "$SEED_TMP" "$USERS"
  SEED_TMP=""
else
  echo "The password changed, but the seed file was not updated." >&2
  exit 1
fi

echo "new password: verified"
if wait_for_status "$OLD_CFG" 401; then
  echo "old password: rejected"
else
  echo "old password: STILL ACCEPTED. Investigate before relying on this rotation." >&2
  exit 1
fi
