# Tests the Vector firewall rules with real connections. A healthcheck runs only without
# --no-environment, so every probe here is a real network attempt. Sends no event data.
#
# -Rule applies one rule, and removes it automatically if it breaks Kafka or does not restrict the
# protected binary. Kafka is checked again after every change. Run A, then B, then C, one at a time.
# It needs elevation. Without -Rule it changes nothing and needs no elevation.
# Exit status: 0 expected result, 1 not as expected.
param(
  [string] $Protected = 'C:\Program Files\Vector\bin\vector.exe',
  [Parameter(Mandatory)] [string] $Control,
  [ValidateSet('', 'A', 'B', 'C')] [string] $Rule = '',
  [string] $ExternalUrl = 'https://example.com/',
  [string] $WorkFolder = (Join-Path $env:TEMP "vector-fw-$PID")
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'vector-agent-lib.ps1')
New-Item -ItemType Directory -Force $WorkFolder | Out-Null
$Failures = 0
function Result([string] $Name, [bool] $Ok, [string] $Detail) {
  Write-Output "$(('FAIL','PASS')[[int]$Ok]) $Name ($Detail)"
  if (-not $Ok) { $script:Failures++ }
}
function Write-Config([string] $Name, [string] $Sink) {
  $Path = Join-Path $WorkFolder "$Name.yaml"
  $Data = ($WorkFolder -replace '\\', '/')
  "data_dir: `"$Data`"`nsources: {d: {type: demo_logs, format: json, count: 3, interval: 0.2}}`nsinks:`n  s: $Sink`n" | Set-Content -LiteralPath $Path -Encoding ASCII
  $Path
}
# True when the healthcheck connected. A probe with no network path fails with exit 78.
function Test-Probe([string] $Exe, [string] $Config) {
  $ErrorActionPreference = 'Continue'
  & $Exe validate $Config *> $null
  $LASTEXITCODE -eq 0
}
$Kafka = Write-Config 'kafka' '{type: kafka, inputs: [d], bootstrap_servers: "127.0.0.1:9092", topic: siem-raw-logs, encoding: {codec: json}, socket_timeout_ms: 8000, healthcheck: {enabled: true}}'
$Closed = Write-Config 'closed' '{type: kafka, inputs: [d], bootstrap_servers: "127.0.0.1:19092", topic: siem-raw-logs, encoding: {codec: json}, socket_timeout_ms: 8000, healthcheck: {enabled: true}}'
$External = Write-Config 'external' "{type: http, inputs: [d], uri: `"$ExternalUrl`", encoding: {codec: json}, healthcheck: {enabled: true, uri: `"$ExternalUrl`"}, request: {timeout_secs: 8}}"

function Test-Loopback([string] $Exe, [string] $Kind, [int] $Port) {
  if ($Kind -eq 'tcp') {
    $Listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $Listener.Start()
    $Config = Write-Config "loop-tcp-$Port" "{type: socket, inputs: [d], mode: tcp, address: `"127.0.0.1:$Port`", encoding: {codec: json}, healthcheck: {enabled: true}}"
    try { Test-Probe $Exe $Config } finally { $Listener.Stop() }
  } else {
    $Listener = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback, $Port))
    $Config = Write-Config 'loop-udp' "{type: socket, inputs: [d], mode: udp, address: `"127.0.0.1:$Port`", encoding: {codec: json}}"
    $Process = Start-Process $Exe -ArgumentList '--config', $Config, '--quiet' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 4
    $Got = $Listener.Available -gt 0
    if (-not $Process.HasExited) { Stop-Process -Id $Process.Id -Force }
    $Listener.Close()
    $Got
  }
}

# A low, unprivileged port, and one in the ephemeral range that an earlier draft left open.
$TcpPorts = 19500, 55000
$UdpPort = 19501

function Test-Baseline {
  Result 'protected binary reaches Kafka' (Test-Probe $Protected $Kafka) '127.0.0.1:9092'
  Result 'control copy reaches Kafka' (Test-Probe $Control $Kafka) '127.0.0.1:9092'
  Result 'negative control, closed port refused' (-not (Test-Probe $Control $Closed)) '127.0.0.1:19092'
  Result 'control copy reaches the external host' (Test-Probe $Control $External) $ExternalUrl
  $Reached = Test-Probe $Protected $External
  Result 'protected binary blocked from the external host' (-not $Reached) "reached=$Reached"
  foreach ($Port in $TcpPorts) {
    Result "control copy reaches loopback TCP $Port" (Test-Loopback $Control 'tcp' $Port) '127.0.0.1'
    $Reached = Test-Loopback $Protected 'tcp' $Port
    Result "protected binary blocked from loopback TCP $Port" (-not $Reached) "reached=$Reached"
  }
  Result "control copy reaches loopback UDP $UdpPort" (Test-Loopback $Control 'udp' $UdpPort) '127.0.0.1'
  $Reached = Test-Loopback $Protected 'udp' $UdpPort
  Result "protected binary blocked from loopback UDP $UdpPort" (-not $Reached) "reached=$Reached"
}

try {
  if (-not $Rule) {
    Test-Baseline
  } else {
    $Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Applying a rule needs elevation.' }
    $Ops = @{
      Exists         = { param($Name) [bool] (Get-NetFirewallRule -DisplayName $script:RuleNames[$Name] -ErrorAction SilentlyContinue) }
      Create         = { param($Name) $Definition = Get-VectorRuleDefinition $Name $Protected; New-NetFirewallRule @Definition | Out-Null }
      Remove         = { param($Name) Remove-NetFirewallRule -DisplayName $script:RuleNames[$Name] }
      Kafka          = { (Test-Probe $Protected $Kafka) -and -not (Test-Probe $Protected $Closed) }
      ControlReaches = {
        param($Name)
        switch ($Name) {
          'A' { Test-Probe $Control $External }
          'B' { ($TcpPorts | Where-Object { -not (Test-Loopback $Control 'tcp' $_) }).Count -eq 0 }
          'C' { Test-Loopback $Control 'udp' $UdpPort }
        }
      }
      Restricted     = {
        param($Name)
        switch ($Name) {
          'A' { -not (Test-Probe $Protected $External) }
          'B' { ($TcpPorts | Where-Object { Test-Loopback $Protected 'tcp' $_ }).Count -eq 0 }
          'C' { -not (Test-Loopback $Protected 'udp' $UdpPort) }
        }
      }
    }
    $Trial = Invoke-RuleTrial $Rule $Ops
    Result "rule $Rule $(if ($Trial.Kept) { 'kept' } else { 'removed' })" $Trial.Kept $Trial.Reason
    Result "Kafka reachable after rule $Rule" $Trial.KafkaAfter '127.0.0.1:9092'
  }
} finally {
  Remove-Item -LiteralPath $WorkFolder -Recurse -Force -ErrorAction SilentlyContinue
}
exit ([int] ($Failures -gt 0))
