# Decides what the operator must be told. Kept free of side effects so that it can be tested.

$script:AlertRepeatMinutes = @{ WARN = 360; CRITICAL = 60; LOST = 60; CHECK_FAILED = 60 }

# A report that is missing, unreadable or old is not a healthy report. With WSL stopped on purpose
# Kafka deletes nothing, so a stale report matters only if WSL is meant to be up or the agent runs.
function Get-AlertStatus($Report, [datetime] $Now, [int] $MaxAgeMinutes, [bool] $WslRunning, [bool] $AgentRunning) {
  if (-not $WslRunning -and -not $AgentRunning) {
    return @{ Status = 'STOPPED'; Message = 'WSL is stopped and the agent is not running' }
  }
  if (-not $WslRunning) {
    return @{ Status = 'CHECK_FAILED'; Message = 'WSL is stopped while the agent is running, so Kafka is not being checked' }
  }
  if ($null -eq $Report) {
    return @{ Status = 'CHECK_FAILED'; Message = 'No expiry report could be read' }
  }
  if ($null -eq $Report.checked_ms -or $null -eq $Report.status) {
    return @{ Status = 'CHECK_FAILED'; Message = 'The expiry report is malformed' }
  }
  $Checked = [DateTimeOffset]::FromUnixTimeMilliseconds([int64] $Report.checked_ms).UtcDateTime
  $Age = ($Now.ToUniversalTime() - $Checked).TotalMinutes
  if ($Age -gt $MaxAgeMinutes) {
    return @{ Status = 'CHECK_FAILED'; Message = "The expiry report is $([int] $Age) minutes old" }
  }
  @{ Status = [string] $Report.status; Message = [string] $Report.message }
}

# Notifies on any change, and repeats while an alert stands. Silent while OK or stopped.
function Get-AlertAction($Current, $Previous, [datetime] $Now) {
  $Quiet = @('OK', 'STOPPED')
  $Was = if ($Previous) { [string] $Previous.status } else { 'OK' }
  if ($Quiet -contains $Current.Status) {
    if ($Quiet -contains $Was) { return 'none' }
    return 'resolved'
  }
  if ($Current.Status -ne $Was) { return 'notify' }
  if (-not $script:AlertRepeatMinutes.ContainsKey($Current.Status)) { return 'notify' }
  $Sent = if ($Previous.sent) { [datetime]::Parse($Previous.sent, [Globalization.CultureInfo]::InvariantCulture, 'RoundtripKind') } else { [datetime]::MinValue }
  if (($Now.ToUniversalTime() - $Sent.ToUniversalTime()).TotalMinutes -ge $script:AlertRepeatMinutes[$Current.Status]) { return 'notify' }
  'none'
}

function Get-AlertText($Current, [string] $Source = 'kafka-expiry') {
  $Titles = @{
    'kafka-expiry' = @{
      WARN         = 'SIEM warning: Kafka events are waiting'
      CRITICAL     = 'SIEM CRITICAL: Kafka events near expiry'
      LOST         = 'SIEM LOST: Kafka events expired unread'
      CHECK_FAILED = 'SIEM: expiry check is not working'
    }
    'disk-guard'   = @{
      WARN         = 'SIEM warning: storage is getting low'
      CRITICAL     = 'SIEM CRITICAL: ingestion stopped for storage'
      CHECK_FAILED = 'SIEM: disk guard is not working'
    }
    'detector'     = @{
      WARN         = 'SIEM warning: detection rules are failing or behind'
      CRITICAL     = 'SIEM CRITICAL: alerts are not being published'
      CHECK_FAILED = 'SIEM: detection engine is not reporting'
    }
    'enricher'     = @{
      WARN         = 'SIEM warning: threat feeds are stale or a provider is paused'
      CHECK_FAILED = 'SIEM: enrichment is not reporting'
    }
    'correlator'   = @{
      WARN         = 'SIEM warning: correlation is behind or cannot reach a service'
      CHECK_FAILED = 'SIEM: correlation is not reporting'
    }
  }
  $Set = if ($Titles.ContainsKey($Source)) { $Titles[$Source] } else { @{} }
  $Title = if ($Set.ContainsKey($Current.Status)) { $Set[$Current.Status] } else { "SIEM ${Source}: $($Current.Status)" }
  @{ Title = $Title; Body = $Current.Message }
}
