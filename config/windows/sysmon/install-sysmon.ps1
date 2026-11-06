# Installs pinned standalone Sysmon with the SIEM configuration. Safe to run again.
# Needs an elevated PowerShell and explicit owner approval. See docs/operations/sysmon-deployment.md.
# Without -Apply it only verifies the package and reports what it would do.
# If this pinned version is already installed, -Apply re-applies the configuration instead.
# -AcceptEula records that the owner has read and accepted the Sysinternals licence.
param(
  [Parameter(Mandatory)] [string] $ZipPath,
  [switch] $Apply,
  [switch] $AcceptEula
)
$ErrorActionPreference = 'Stop'

$Version = '15.22'
$ZipSha256 = '00ecf1b46aec99299d3ae0bca79dc621458bd014b20b509d7c5c8e8c8611aa54'
$ExeSha256 = '83d31f2478dc6716cfdbf69e5c384bf043072b5f0d8d7b2eea365f709fda4352'
$Config = Join-Path $PSScriptRoot 'sysmon-config.xml'
$Channel = 'Microsoft-Windows-Sysmon/Operational'
$MaxLogBytes = 134217728

# Redirected, so that stderr stays out of PowerShell's error stream.
function Invoke-Sysmon([string] $Path, [string[]] $Arguments) {
  $Out = New-TemporaryFile
  $Err = New-TemporaryFile
  $Process = Start-Process $Path -ArgumentList $Arguments -Wait -PassThru -NoNewWindow -RedirectStandardOutput $Out -RedirectStandardError $Err
  Get-Content $Out, $Err
  Remove-Item $Out, $Err
  if ($Process.ExitCode -ne 0) { throw "Sysmon failed: exit $($Process.ExitCode)" }
}

if ((Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLower() -ne $ZipSha256) {
  throw 'Sysmon.zip does not match the pinned SHA-256. Microsoft may have published a new version.'
}

$Work = Join-Path $env:TEMP "sysmon-$Version-install"
Expand-Archive -LiteralPath $ZipPath -DestinationPath $Work -Force
$Exe = Join-Path $Work 'Sysmon64.exe'
if ((Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower() -ne $ExeSha256) {
  throw 'Sysmon64.exe does not match the pinned SHA-256.'
}
$Signature = Get-AuthenticodeSignature $Exe
if ($Signature.Status -ne 'Valid' -or $Signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
  throw "Sysmon64.exe signature is not valid: $($Signature.Status)"
}
if ((Get-Item $Exe).VersionInfo.FileVersion -ne $Version) {
  throw 'Sysmon64.exe is not the pinned version.'
}
[xml] (Get-Content $Config -Raw) | Out-Null
Write-Output "Verified Sysmon $Version, signature, hashes and configuration XML."

$Service = Get-Service 'Sysmon*' -ErrorAction SilentlyContinue

if (-not $Apply) {
  Write-Output 'Verification only. Re-run elevated with -Apply -AcceptEula to install.'
  Remove-Item -LiteralPath $Work -Recurse -Force
  exit 0
}

$Principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Installation needs an elevated PowerShell.'
}

if ($Service) {
  $Installed = Join-Path $env:windir "$($Service.Name).exe"
  if (-not (Test-Path $Installed) -or (Get-FileHash $Installed -Algorithm SHA256).Hash.ToLower() -ne $ExeSha256) {
    throw 'A different Sysmon is already installed. Stopping.'
  }
  Invoke-Sysmon $Installed @('-c', "`"$Config`"")
  Remove-Item -LiteralPath $Work -Recurse -Force
  Write-Output 'Sysmon was already installed. Configuration re-applied.'
  exit 0
}

if (-not $AcceptEula) { throw 'Read the Sysinternals licence, then re-run with -AcceptEula.' }

# Standalone and built-in Sysmon cannot coexist.
$BuiltIn = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
if ($BuiltIn -and $BuiltIn.State -eq 'Enabled') {
  throw 'Built-in Sysmon is enabled. It cannot coexist with standalone Sysmon.'
}

Invoke-Sysmon $Exe @('-accepteula', '-i', "`"$Config`"")

wevtutil sl $Channel /ms:$MaxLogBytes /rt:false
if ($LASTEXITCODE -ne 0) { throw "Sysmon installed, but the log size was not set: exit $LASTEXITCODE" }

Remove-Item -LiteralPath $Work -Recurse -Force
Get-Service 'Sysmon*' | Select-Object Name, Status, StartType
Write-Output 'Installed. Follow the validation procedure in docs/operations/sysmon-deployment.md.'
