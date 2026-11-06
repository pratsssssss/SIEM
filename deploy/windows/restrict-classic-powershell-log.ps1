# Removes read access to the classic Windows PowerShell log from ordinary accounts, as Phase 7 did
# for the Operational log. Write access stays, because PowerShell logs under the caller's token.
# Reads the log's permissions only by default. -Apply and -Rollback need elevation.
# It never clears the log.
[CmdletBinding(DefaultParameterSetName = 'Show')]
param(
  [Parameter(ParameterSetName = 'Apply')] [switch] $Apply,
  [Parameter(ParameterSetName = 'Rollback')] [switch] $Rollback,
  [string] $Backup = (Join-Path $env:USERPROFILE 'SIEM-Lab\phase8\classic-log-access-before.txt')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'classic-log-lib.ps1')
$Log = 'Windows PowerShell'

function Get-Access {
  $Output = wevtutil gl $Log
  if ($LASTEXITCODE -ne 0) { throw "wevtutil gl failed: exit $LASTEXITCODE" }
  (($Output | Select-String '^channelAccess: (.+)$').Matches[0].Groups[1].Value).Trim()
}
function Set-Access([string] $Sddl) {
  wevtutil sl $Log /ca:$Sddl
  if ($LASTEXITCODE -ne 0) { throw "wevtutil sl failed: exit $LASTEXITCODE" }
  if ((Get-Access) -ne $Sddl) { throw 'The log permissions did not change as requested' }
}

$Before = Get-Access
$Wanted = Get-RestrictedAccess $Before
if ($Apply) {
  if (-not (Test-Path -LiteralPath $Backup)) {
    New-Item -ItemType Directory -Force (Split-Path $Backup) | Out-Null
    [IO.File]::WriteAllText($Backup, $Before)
  }
  Set-Access $Wanted
  Write-Output 'restricted'
} elseif ($Rollback) {
  Set-Access ([IO.File]::ReadAllText($Backup).Trim())
  Write-Output 'restored'
} else {
  Write-Output "current: $Before"
  Write-Output "wanted:  $Wanted"
}
