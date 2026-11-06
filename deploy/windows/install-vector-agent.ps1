# Installs the Windows Vector agent as a LocalSystem service. Run in an elevated PowerShell, with
# the WSL stack up. Stops at the first failed check and removes what this run created. Never
# prints or logs key material. See docs/operations/vector-agent-deployment.md.
#
# -NoStart stops before starting, and leaves the service on manual start, so a reboot cannot begin
# collection. Run it first, prove the firewall with test-vector-firewall.ps1, then run this again
# without -NoStart. Existing keys, rules and the service are kept and checked on the second run.
param(
  [string] $Package = (Join-Path $env:USERPROFILE 'SIEM-Lab\installers\vector-0.61.0\vector-0.61.0-x86_64-pc-windows-msvc.zip'),
  [string] $ResultFile = (Join-Path $env:USERPROFILE 'SIEM-Lab\phase8\agent-install.txt'),
  [switch] $NoStart
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'vector-agent-lib.ps1')

$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an elevated PowerShell.'
}

$Distro = 'Ubuntu-24.04'
$WslFolder = '/home/linux/siem/config/verifier'
$WslGroup = 'siem-verifier'
$Program = 'C:\Program Files\Vector'
$State = 'C:\ProgramData\Vector'
$Paths = @{
  Package       = $Package
  PackageSha256 = '6a04e833f9a91f874688e8087d768f5cb35d40e3271c87df6258e271915d0f49'
  SourceConfig  = Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'config\windows\vector\vector-agent.yaml'
  Program       = $Program
  Bin           = Join-Path $Program 'bin'
  Config        = Join-Path $Program 'config'
  Exe           = Join-Path $Program 'bin\vector.exe'
  ConfigFile    = Join-Path $Program 'config\vector-agent.yaml'
  State         = $State
  Data          = Join-Path $State 'data'
  Secrets       = Join-Path $State 'secrets'
  Keys          = Join-Path $State 'secrets\field-keys.json'
}
New-Item -ItemType Directory -Force (Split-Path $ResultFile) | Out-Null

$Ops = @{
  Hash          = { param($Path) (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() }
  ServiceExists = { [bool] (Get-Service $ServiceName -ErrorAction SilentlyContinue) }
  StopService   = {
    $Service = Get-Service $ServiceName
    if ($Service.Status -ne 'Stopped') { Stop-Service $ServiceName; $Service.WaitForStatus('Stopped', '00:01:00') }
  }
  LockFolder    = { param($Path) Set-LockedFolder $Path }
  OwnFile       = { param($Path) Set-LockedFileOwner $Path }
  Unpack        = { param($Zip, $Folder) Expand-Archive -LiteralPath $Zip -DestinationPath $Folder }
  CheckVersion  = {
    param($Exe)
    $Version = (& $Exe --version) -join ' '
    if ($LASTEXITCODE -ne 0 -or $Version -notlike 'vector 0.61.0 *') { throw "Wrong binary: $Version" }
  }
  AssertLocked  = {
    param($Path)
    $Problems = @(Get-LockProblems $Path)
    if ($Problems.Count) { throw "Permissions on ${Path}: $($Problems -join '; ')" }
  }
  NewKeys       = { param($Path) New-FieldKeyFile $Path }
  DeliverKeys   = { param($Path) Send-KeysToWsl $Path $Distro $WslFolder $WslGroup }
  KeysMatch     = { param($Path) Test-KeysInWsl $Path $Distro $WslFolder }
  RemoveKeys    = { Send-BytesToWsl $Distro "rm -f $WslFolder/field-keys.json" ([byte[]] @()) | Out-Null }
  RuleExists    = { param($Name) [bool] (Get-NetFirewallRule -DisplayName $script:RuleNames[$Name] -ErrorAction SilentlyContinue) }
  NewRule       = { param($Name, $Exe) $Rule = Get-VectorRuleDefinition $Name $Exe; New-NetFirewallRule @Rule | Out-Null }
  RemoveRule    = { param($Name) Remove-NetFirewallRule -DisplayName $script:RuleNames[$Name] }
  CheckRule     = {
    param($Name, $Exe)
    $Rule = Get-NetFirewallRule -DisplayName $script:RuleNames[$Name]
    $Wanted = Get-VectorRuleDefinition $Name $Exe
    $Address = @(($Rule | Get-NetFirewallAddressFilter).RemoteAddress | Sort-Object)
    $Application = ($Rule | Get-NetFirewallApplicationFilter).Program
    if ("$($Rule.Enabled)" -ne 'True' -or "$($Rule.Action)" -ne 'Block' -or "$($Rule.Direction)" -ne 'Outbound' -or $Application -ne $Exe -or
      ($Address -join ',') -ne (@($Wanted.RemoteAddress | Sort-Object) -join ',')) { throw "Firewall rule $Name does not match its definition" }
  }
  # Offline syntax check only. --no-environment skips healthchecks, so it proves no connectivity.
  Validate      = { param($Exe, $Config) Invoke-Native $Exe @('validate', '--no-environment', $Config) 'Configuration validation' | Out-Null }
  CreateService = {
    param($Exe, $Config)
    Invoke-Native $Exe @('service', 'install', '--name', $ServiceName, '--display-name', 'SIEM Vector Agent', '--config', $Config) 'Service creation' | Out-Null
  }
  DeleteService = {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    Invoke-Native 'sc.exe' @('delete', $ServiceName) 'Service removal' | Out-Null
  }
  ConfigureService = {
    Invoke-Native 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/300000') 'Service recovery' | Out-Null
    # A path with a space must be quoted, or Windows may run C:\Program.exe as SYSTEM.
    $Path = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").PathName
    if ($Path -like 'C:\Program Files\Vector\bin\vector.exe*') {
      $Fixed = $Path.Replace('C:\Program Files\Vector\bin\vector.exe', '"C:\Program Files\Vector\bin\vector.exe"')
      Invoke-Native 'sc.exe' @('config', $ServiceName, 'binPath=', $Fixed) 'Service path' | Out-Null
    }
  }
  SetStartType  = { param($Type) Invoke-Native 'sc.exe' @('config', $ServiceName, 'start=', $Type) 'Service start type' | Out-Null }
  CheckService  = {
    $Service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($Service.StartName -ne 'LocalSystem') { throw "Service runs as $($Service.StartName)" }
    if ($Service.PathName -notlike '"C:\Program Files\Vector\bin\vector.exe"*') { throw "Unsafe service path: $($Service.PathName)" }
    $Problems = @(Get-ServiceSddlProblems ((Invoke-Native 'sc.exe' @('sdshow', $ServiceName) 'Reading service permissions').Trim()))
    if ($Problems.Count) { throw "Service permissions: $($Problems -join '; ')" }
  }
  StartService  = {
    Start-Service $ServiceName
    Start-Sleep -Seconds 10
    if ((Get-Service $ServiceName).Status -ne 'Running') { throw 'Service is not running after 10 s' }
  }
}

$Writer = { param($Message) Write-Output $Message; Add-Content -LiteralPath $ResultFile -Value $Message -Encoding UTF8 }
try {
  & $Writer "Started $(Get-Date -Format s), NoStart=$NoStart"
  Install-VectorAgent -Paths $Paths -Ops $Ops -NoStart:$NoStart -Log $Writer
  & $Writer "RESULT PASS $(Get-Date -Format s)"
  exit 0
} catch {
  & $Writer "RESULT FAIL: $($_.Exception.Message)"
  exit 1
}
