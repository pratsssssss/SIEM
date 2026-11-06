# Writes a read-only inventory snapshot of this machine for the asset service. See docs/detection/asset-inventory.md.
# It changes nothing, needs no elevation, and scans no network. It keeps service names and file names, never a
# command line or service arguments, because those can hold credentials. A section that cannot be read is left
# out, so the service does not take a failed read for a removal.
param(
  [string] $Folder = (Join-Path $env:USERPROFILE 'SIEM-Lab\inventory')
)
$ErrorActionPreference = 'Stop'

function Read-Section([string] $Name, [scriptblock] $Reader, [hashtable] $Into) {
  try { $Into[$Name] = @(& $Reader) } catch { $script:Gaps += $Name }
}

$Gaps = @()
$System = Get-CimInstance Win32_OperatingSystem
$Computer = Get-CimInstance Win32_ComputerSystem
$Product = Get-CimInstance Win32_ComputerSystemProduct
$Crypto = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography'
$Type = switch ($System.ProductType) { 1 { 'workstation' } 2 { 'domain_controller' } 3 { 'server' } default { 'unknown' } }

$Snapshot = @{
  schema       = 'siem.asset.snapshot/1'
  collector    = 'windows-local'
  collected_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  host         = @{ hostname = $env:COMPUTERNAME; platform = 'windows'; asset_type = $Type; domain_joined = [bool] $Computer.PartOfDomain; virtual = ($Computer.Model -match 'Virtual|VMware'); vendor = [string] $Computer.Manufacturer; model = [string] $Computer.Model }
  identifiers  = @{ windows_machine_guid = [string] $Crypto.MachineGuid; hw_uuid = [string] $Product.UUID }
  os           = @{ name = [string] $System.Caption; version = [string] $System.Version; build = [string] $System.BuildNumber; arch = [string] $System.OSArchitecture }
}
if ($Computer.PartOfDomain) { $Snapshot.host.fqdn = "$($Computer.DNSHostName).$($Computer.Domain)" }

Read-Section 'interfaces' {
  $Addresses = Get-NetIPAddress
  foreach ($Adapter in Get-NetAdapter) {
    $Own = @($Addresses | Where-Object InterfaceIndex -EQ $Adapter.ifIndex)
    @{ name = [string] $Adapter.Name; mac = [string] $Adapter.MacAddress; up = ($Adapter.Status -eq 'Up'); virtual = [bool] $Adapter.Virtual; ips = @($Own | ForEach-Object { [string] $_.IPAddress }); cidrs = @($Own | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) }
  }
} $Snapshot

Read-Section 'software' {
  $Paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
  foreach ($Path in $Paths) {
    Get-ItemProperty $Path -ErrorAction SilentlyContinue | Where-Object DisplayName | ForEach-Object { @{ name = [string] $_.DisplayName; version = [string] $_.DisplayVersion; publisher = [string] $_.Publisher } }
  }
} $Snapshot

Read-Section 'services' {
  Get-CimInstance Win32_Service | ForEach-Object {
    # Only the program's own file name leaves this script.
    $Path = [string] $_.PathName
    $Binary = if ($Path -match '^"([^"]+)"') { $Matches[1] } elseif ($Path -match '^(\S+)') { $Matches[1] } else { '' }
    $File = if ($Binary) { ($Binary -split '[\\/]')[-1] } else { '' }
    @{ name = [string] $_.Name; display = [string] $_.DisplayName; state = [string] $_.State; start = [string] $_.StartMode; binary = $File }
  }
} $Snapshot

Read-Section 'users' {
  $Admins = @()
  try { $Admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch { $script:Gaps += 'local_admins' }
  Get-LocalUser | ForEach-Object { @{ name = [string] $_.Name; enabled = [bool] $_.Enabled; local_admin = ($Admins -contains $_.Name) } }
} $Snapshot

Read-Section 'listeners' {
  $Names = @{}
  Get-Process | ForEach-Object { $Names[[int] $_.Id] = $_.Name }
  foreach ($Row in Get-NetTCPConnection -State Listen) {
    $Address = [string] $Row.LocalAddress
    $Scope = if ($Address -in '0.0.0.0', '::') { 'any' } elseif ($Address -in '127.0.0.1', '::1') { 'loopback' } else { 'specific' }
    @{ proto = 'tcp'; port = [int] $Row.LocalPort; scope = $Scope; process = [string] $Names[[int] $Row.OwningProcess] }
  }
} $Snapshot

$Security = @{}
try {
  $Defender = Get-MpComputerStatus
  $Security.defender = @{ service = [bool] $Defender.AMServiceEnabled; realtime = [bool] $Defender.RealTimeProtectionEnabled }
} catch { $Gaps += 'defender' }
try {
  $Profiles = @(Get-NetFirewallProfile)
  $Security.firewall = @{ enabled = @($Profiles | Where-Object Enabled).Count; total = $Profiles.Count }
} catch { $Gaps += 'firewall' }
try {
  $Security.rdp_enabled = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0)
} catch { $Gaps += 'rdp' }
$Snapshot.security = $Security
$Snapshot.gaps = $Gaps

New-Item -ItemType Directory -Force $Folder | Out-Null
$Name = ($env:COMPUTERNAME.ToLowerInvariant() -replace '[^a-z0-9-]', '-') + '.json'
$Spare = Join-Path $Folder "$Name.tmp"
# Written beside the target and moved, so the service never reads half a file.
[IO.File]::WriteAllText($Spare, ($Snapshot | ConvertTo-Json -Depth 6 -Compress), (New-Object Text.UTF8Encoding $false))
Move-Item -Force $Spare (Join-Path $Folder $Name)
