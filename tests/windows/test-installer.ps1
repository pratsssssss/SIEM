# Tests the installer unelevated. Runs the real step order with real ACLs on a temporary folder.
# Privileged actions are replaced by recording stand-ins, so nothing here touches the system.
# Key delivery runs for real, but only against the named temporary distribution.
# Usage: powershell -File tests/windows/test-installer.ps1 [-WslDistro siem-restore-test]
param([string] $WslDistro = '')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\..\deploy\windows\vector-agent-lib.ps1')

$Failures = 0
$Passes = 0
function Check([string] $Name, [bool] $Ok, [string] $Detail = '') {
  if ($Ok) { $script:Passes++ } else { $script:Failures++ }
  Write-Output "$(('FAIL', 'PASS')[[int]$Ok]) $Name$(if ($Detail) { " ($Detail)" })"
}
$Me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$Root = Join-Path $env:TEMP "vector-install-test-$PID"
New-Item -ItemType Directory $Root | Out-Null
$Allowed = @($SystemSid, $AdminSid, $Me)
$Owners = @($AdminSid, $SystemSid, $Me)

try {
  # Permission checks, on real ACLs.
  $Folder = Join-Path $Root 'locked'
  Set-LockedFolder $Folder -ExtraSids $Me -KeepOwner
  $File = Join-Path $Folder 'inherited.txt'
  Set-Content -LiteralPath $File 'x'
  Check 'locked folder passes' (@(Get-LockProblems $Folder $Allowed $Owners).Count -eq 0)
  Check 'file inheriting from a locked folder passes (the old check failed here)' (@(Get-LockProblems $File $Allowed $Owners).Count -eq 0) "protected=$((Get-Acl $File).AreAccessRulesProtected)"

  $Problems = @(Get-LockProblems $File @($SystemSid, $AdminSid) $Owners)
  Check 'unexpected account on a file fails' ($Problems -match 'access for').Count -gt 0

  $Open = Join-Path $Root 'open'
  New-Item -ItemType Directory $Open | Out-Null
  Check 'folder that inherits fails' (@(Get-LockProblems $Open @($SystemSid, $AdminSid, $Me, 'S-1-5-11', 'S-1-5-32-545', 'S-1-3-0') $Owners) -match 'inherits').Count -gt 0

  $Extra = Join-Path $Folder 'extra.txt'
  Set-Content -LiteralPath $Extra 'x'
  icacls $Extra /grant '*S-1-5-32-545:(R)' /Q | Out-Null
  Check 'Users group added to a file fails' (@(Get-LockProblems $Extra $Allowed $Owners) -match 'S-1-5-32-545').Count -gt 0

  $Denied = Join-Path $Folder 'denied.txt'
  Set-Content -LiteralPath $Denied 'x'
  icacls $Denied /deny '*S-1-5-18:(W)' /Q | Out-Null
  Check 'deny rule fails' (@(Get-LockProblems $Denied $Allowed $Owners) -match 'deny rule').Count -gt 0

  $Missing = Join-Path $Root 'nosystem'
  New-Item -ItemType Directory $Missing | Out-Null
  icacls $Missing /inheritance:r /grant:r "*${Me}:(OI)(CI)F" /Q | Out-Null
  Check 'missing SYSTEM access fails' (@(Get-LockProblems $Missing @($Me) $Owners) -match 'no access').Count -gt 0

  $Owned = @(Get-LockProblems $File $Allowed)
  Check 'ordinary-user owner fails with the production owner list' ($Owned -match 'owner is').Count -gt 0 "owner $Me"
  $Sysmon = 'C:\Windows\Sysmon64.exe'
  if (Test-Path $Sysmon) {
    $Owner = (Get-Acl $Sysmon).GetOwner([Security.Principal.SecurityIdentifier]).Value
    Check 'owner check accepts a real Administrators-owned file' (@(Get-LockProblems $Sysmon) -notmatch 'owner is').Count -eq @(Get-LockProblems $Sysmon).Count $Owner
  }

  # Service permissions.
  $Default = 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)'
  Check 'default service permissions pass' (@(Get-ServiceSddlProblems $Default).Count -eq 0)
  $Real = ((sc.exe sdshow EventLog) -join '').Trim()
  Check 'parses a real service descriptor' ($Real -match '^D:') $Real.Substring(0, 16)
  foreach ($Right in 'DC', 'WD', 'WO', 'RP', 'WP', 'GA') {
    Check "Users with $Right on the service fails" (@(Get-ServiceSddlProblems "D:(A;;CC$($Right)LC;;;BU)").Count -gt 0)
  }
  Check 'allowed rights containing look-alike letters pass' (@(Get-ServiceSddlProblems 'D:(A;;LCRCSW;;;WD)').Count -eq 0)

  # Return codes.
  $Threw = $false
  try { Invoke-Native 'cmd.exe' @('/c', 'exit 5') 'A failing command' | Out-Null } catch { $Threw = $_.Exception.Message -match 'exit code 5' }
  Check 'a non-zero exit code stops the install' $Threw

  # Key derivation against a Python reference for a fixed input.
  [byte[]] $Prk = 1..32
  Check 'HKDF expand matches the reference' ((New-DerivedKey $Prk 'siem-d22-k1-enc') -eq '77a7361a8130a43a336bcb4536ec9c5194fe028249eb6ba044676577aa726bd1')
  $KeyFile = Join-Path $Root 'keys.json'
  New-FieldKeyFile $KeyFile
  $Bytes = [IO.File]::ReadAllBytes($KeyFile)
  Check 'key file is exact ASCII JSON with no BOM or line ending' ($Bytes[0] -eq 123 -and $Bytes[-1] -eq 125 -and $Bytes.Length -eq 153) "$($Bytes.Length) bytes"
  Check 'key file passes its check' (Test-FieldKeyFile $KeyFile)
  $Bad = Join-Path $Root 'bad.json'
  [IO.File]::WriteAllText($Bad, '{"k1_enc":"aa","k1_mac":"aa"}')
  Check 'weak key file fails its check' (-not (Test-FieldKeyFile $Bad))

  # Firewall definitions.
  $A = Get-VectorRuleDefinition 'A' 'C:\x.exe'
  Check 'rule A blocks, outbound, one program' ($A.Action -eq 'Block' -and $A.Direction -eq 'Outbound' -and $A.Program -eq 'C:\x.exe' -and $A.Profile -eq 'Any')
  $Numbers = $A.RemoteAddress[0..1] | ForEach-Object { $_ -split '-' | ForEach-Object { [BitConverter]::ToUInt32(([Net.IPAddress]::Parse($_).GetAddressBytes()[3..0]), 0) } }
  $Target = [BitConverter]::ToUInt32(([Net.IPAddress]::Parse('127.0.0.1').GetAddressBytes()[3..0]), 0)
  Check 'rule A leaves exactly 127.0.0.1 open in IPv4' ($Numbers[1] -eq ($Target - 1) -and $Numbers[2] -eq ($Target + 1) -and $Numbers[0] -eq 0 -and $Numbers[3] -eq [uint32]::MaxValue)
  Check 'rule A blocks all IPv6, including ::1' ($A.RemoteAddress[2] -eq '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
  $B = Get-VectorRuleDefinition 'B' 'C:\x.exe'
  $Blocked = $B.RemotePort | ForEach-Object { $Low, $High = $_ -split '-'; 9092 -ge [int] $Low -and 9092 -le [int] $High }
  Check 'rule B does not cover port 9092' (-not ($Blocked -contains $true))
  Check 'no rule is an allow rule' ((@('A', 'B', 'C') | ForEach-Object { (Get-VectorRuleDefinition $_ 'x').Action } | Sort-Object -Unique) -eq 'Block')

  # Firewall trial decisions.
  function New-TrialOps([bool] $KafkaOk, [bool] $ControlOk, [bool] $Restricts, [bool] $KafkaAfterRemoval = $true) {
    $State = @{ Present = $false; Removed = 0 }
    $Ops = @{
      Exists = { param($N) $State.Present }.GetNewClosure()
      Create = { param($N) $State.Present = $true }.GetNewClosure()
      Remove = { param($N) $State.Present = $false; $State.Removed++ }.GetNewClosure()
      Kafka = { if ($State.Present) { $KafkaOk } else { $KafkaAfterRemoval } }.GetNewClosure()
      ControlReaches = { param($N) $ControlOk }.GetNewClosure()
      Restricted = { param($N) $Restricts }.GetNewClosure()
    }
    @{ Ops = $Ops; State = $State }
  }
  $T = New-TrialOps $true $true $true
  $R = Invoke-RuleTrial 'B' $T.Ops
  Check 'trial keeps a rule that works' ($R.Kept -and $T.State.Present -and $T.State.Removed -eq 0)
  $T = New-TrialOps $false $true $true
  $R = Invoke-RuleTrial 'B' $T.Ops
  Check 'trial removes a rule that breaks Kafka, and rechecks it' (-not $R.Kept -and -not $T.State.Present -and $R.KafkaAfter -and $R.Reason -match 'Kafka')
  $T = New-TrialOps $true $true $false
  $R = Invoke-RuleTrial 'C' $T.Ops
  Check 'trial removes a rule with no effect' (-not $R.Kept -and -not $T.State.Present -and $R.Reason -match 'does not restrict')
  $T = New-TrialOps $true $false $true
  $R = Invoke-RuleTrial 'A' $T.Ops
  Check 'trial removes a rule when the control proves nothing' (-not $R.Kept -and -not $T.State.Present -and $R.Reason -match 'control')
  $T = New-TrialOps $false $true $true $false
  $R = Invoke-RuleTrial 'B' $T.Ops
  Check 'trial reports Kafka still broken after removal' (-not $R.Kept -and -not $R.KafkaAfter)
  $B2 = (Get-VectorRuleDefinition 'B' 'x').RemotePort
  Check 'rule B leaves only 9092 open' (($B2 -join ',') -eq '1-9091,9093-65535')

  # The real step order, with a fault at each step.
  $Steps = 'package-hash', 'stop-service', 'folders', 'binary', 'version', 'permissions', 'keys', 'key-delivery', 'firewall', 'validate', 'service', 'start'
  function New-Sandbox([string] $Name) {
    $Base = Join-Path $Root $Name
    New-Item -ItemType Directory $Base | Out-Null
    $Zip = Join-Path $Base 'pkg'
    New-Item -ItemType Directory $Zip | Out-Null
    Set-Content -LiteralPath (Join-Path $Zip 'vector.exe') 'fake'
    $Source = Join-Path $Base 'source.yaml'
    Set-Content -LiteralPath $Source 'fake'
    $Program = Join-Path $Base 'Program'
    $State = Join-Path $Base 'State'
    @{ Package = $Zip; PackageSha256 = 'pin'; SourceConfig = $Source; Program = $Program; Bin = "$Program\bin"; Config = "$Program\config"
      Exe = "$Program\bin\vector.exe"; ConfigFile = "$Program\config\vector-agent.yaml"; State = $State; Data = "$State\data"; Secrets = "$State\secrets"; Keys = "$State\secrets\field-keys.json" }
  }
  function New-FakeOps($Paths, [string] $FailAt, [hashtable] $World) {
    $Allowed2 = $Allowed
    $Owners2 = $Owners
    $Me2 = $Me
    @{
      Before        = { param($Name) if ($Name -eq $FailAt) { throw "injected at $Name" } }.GetNewClosure()
      Hash          = { param($P) 'pin' }
      ServiceExists = { $World.Service }.GetNewClosure()
      StopService   = { $World.Calls.Add('stop') | Out-Null }.GetNewClosure()
      LockFolder    = { param($P) Set-LockedFolder $P -ExtraSids $Me2 -KeepOwner }.GetNewClosure()
      OwnFile       = { param($P) }
      Unpack        = { param($Z, $F) New-Item -ItemType Directory -Force $F | Out-Null; Copy-Item (Join-Path $Z 'vector.exe') $F }
      CheckVersion  = { param($E) }
      AssertLocked  = { param($P) $X = @(Get-LockProblems $P $Allowed2 $Owners2); if ($X.Count) { throw "locked: $($X -join ';')" } }.GetNewClosure()
      NewKeys       = { param($P) New-FieldKeyFile $P }
      DeliverKeys   = { param($P) $World.WslKeys = $true; $World.Calls.Add('deliver') | Out-Null }.GetNewClosure()
      KeysMatch     = { param($P) $World.WslKeys }.GetNewClosure()
      RemoveKeys    = { $World.WslKeys = $false }.GetNewClosure()
      RuleExists    = { param($N) $World.Rule }.GetNewClosure()
      NewRule       = { param($N, $E) $World.Rule = $true; $World.Calls.Add('rule') | Out-Null }.GetNewClosure()
      RemoveRule    = { param($N) $World.Rule = $false }.GetNewClosure()
      CheckRule     = { param($N, $E) }
      Validate      = { param($E, $C) }
      CreateService = { param($E, $C) $World.Service = $true; $World.Calls.Add('create') | Out-Null }.GetNewClosure()
      DeleteService = { $World.Service = $false }.GetNewClosure()
      ConfigureService = { $World.Calls.Add('recovery') | Out-Null }.GetNewClosure()
      SetStartType  = { param($T) $World.StartType = $T }.GetNewClosure()
      CheckService  = { }
      StartService  = { $World.Running = $true }.GetNewClosure()
    }
  }
  function New-World { @{ Service = $false; Rule = $false; WslKeys = $false; Running = $false; StartType = $null; Calls = (New-Object Collections.ArrayList) } }

  $Paths = New-Sandbox 'clean'
  $World = New-World
  Install-VectorAgent -Paths $Paths -Ops (New-FakeOps $Paths '' $World) -NoStart
  Check '-NoStart: all parts in place' ($World.Service -and $World.Rule -and $World.WslKeys -and (Test-Path $Paths.Exe) -and (Test-Path $Paths.Keys))
  Check '-NoStart: never started, and manual start only' (-not $World.Running -and $World.StartType -eq 'demand') $World.StartType
  Check 'no temporary unpack folder remains' (@(Get-ChildItem $Paths.State -Filter 'unpack-*').Count -eq 0)
  $KeyHash = (Get-FileHash $Paths.Keys).Hash
  $Order = $World.Calls -join ','
  Check 'keys reach WSL before the rule and the service' ($Order -eq 'deliver,rule,create,recovery') $Order

  $World.Calls.Clear()
  Install-VectorAgent -Paths $Paths -Ops (New-FakeOps $Paths '' $World)
  Check 'second run keeps the keys' ((Get-FileHash $Paths.Keys).Hash -eq $KeyHash)
  Check 'second run does not re-create or re-deliver' (($World.Calls -join ',') -eq 'stop,recovery') ($World.Calls -join ',')
  Check 'second run starts, on automatic start' ($World.Running -and $World.StartType -eq 'auto')

  $World.Rule = $false
  $World.Running = $false
  $Noted = $false
  $Ops = New-FakeOps $Paths '' $World
  $Ops.NewRule = { param($N, $E) }.GetNewClosure()
  $Ops.RuleExists = { param($N) $false }
  try { Install-VectorAgent -Paths $Paths -Ops $Ops } catch { $Noted = $_.Exception.Message -match 'Refusing to start' }
  Check 'refuses to start without rule A' ($Noted -and -not $World.Running)

  foreach ($Step in $Steps) {
    $Paths = New-Sandbox "fault-$Step"
    $World = New-World
    $Failed = $false
    $Lines = New-Object Collections.ArrayList
    try { Install-VectorAgent -Paths $Paths -Ops (New-FakeOps $Paths $Step $World) -Log { param($M) $Lines.Add($M) | Out-Null }.GetNewClosure() } catch { $Failed = $true }
    $Left = @()
    if ($Lines -match 'CLEANUP FAILED') { $Left += 'cleanup error' }
    if ($World.Service) { $Left += 'service' }
    if ($World.Rule) { $Left += 'rule' }
    if ($World.WslKeys) { $Left += 'WSL keys' }
    if (Test-Path $Paths.Keys) { $Left += 'keys' }
    if (Test-Path $Paths.Program) { $Left += 'program' }
    if (Test-Path $Paths.State) { $Left += 'state' }
    Check "fault at ${Step}: stops and leaves nothing" ($Failed -and $Left.Count -eq 0 -and -not $World.Running) ($Left -join ',')
  }

  # A failure on a later run must not touch what already existed.
  $Paths = New-Sandbox 'existing'
  $World = New-World
  Install-VectorAgent -Paths $Paths -Ops (New-FakeOps $Paths '' $World) -NoStart
  $KeyHash = (Get-FileHash $Paths.Keys).Hash
  try { Install-VectorAgent -Paths $Paths -Ops (New-FakeOps $Paths 'start' $World) } catch { }
  Check 'fault on a later run keeps the existing install' ($World.Service -and $World.Rule -and $World.WslKeys -and (Test-Path $Paths.Exe) -and (Get-FileHash $Paths.Keys).Hash -eq $KeyHash)

  # A wrong key must fail at the permission check, before delivery.
  $Paths = New-Sandbox 'badacl'
  $World = New-World
  $Ops = New-FakeOps $Paths '' $World
  $Ops.AssertLocked = { param($P) if ($P -like '*secrets*') { throw 'bad permissions' } }
  try { Install-VectorAgent -Paths $Paths -Ops $Ops } catch { }
  Check 'bad permissions stop before key delivery' (-not ($World.Calls -contains 'deliver') -and -not $World.WslKeys -and -not (Test-Path $Paths.Keys))

  # Exact key bytes, for real, through wsl.exe and against the temporary distribution only.
  if ($WslDistro) {
    if ($WslDistro -eq 'Ubuntu-24.04') { throw 'Tests must not write to the production distribution' }
    $Target = "/tmp/key-test-$PID"
    $OutputEncoding = New-Object Text.UTF8Encoding $true
    Send-KeysToWsl $KeyFile $WslDistro $Target 'siem-verifier-test'
    Check 'exact key bytes arrive, by SHA-256 on both sides' (Test-KeysInWsl $KeyFile $WslDistro $Target)
    $Mode = (wsl.exe -d $WslDistro -u root --exec stat -c '%U:%G %a' "$Target/field-keys.json") -join ''
    Check 'WSL file is root, verifier group, 640' ($Mode -eq 'root:siem-verifier-test 640') $Mode
    $First = (wsl.exe -d $WslDistro -u root --exec sh -c "head -c 3 $Target/field-keys.json | od -An -tx1") -join ''
    Check 'no BOM, even with a BOM-writing session encoding' ($First -notmatch 'ef bb bf') $First.Trim()
    $Tamper = $false
    wsl.exe -d $WslDistro -u root --exec sh -c "printf x >> $Target/field-keys.json"
    Check 'a changed WSL copy is detected' (-not (Test-KeysInWsl $KeyFile $WslDistro $Target))
    wsl.exe -d $WslDistro -u root --exec rm -rf $Target
  }
} finally {
  Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Output "`n$Passes passed, $Failures failed"
exit ([int] ($Failures -gt 0))
