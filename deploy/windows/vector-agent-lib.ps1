# Shared by install-vector-agent.ps1, test-vector-firewall.ps1 and tests/windows.
# Never prints or logs key material.

$script:SystemSid = 'S-1-5-18'
$script:AdminSid = 'S-1-5-32-544'
$script:ServiceName = 'Vector'
$script:RuleNames = @{
  A = 'SIEM Vector agent, block off-host'
  B = 'SIEM Vector agent, block other loopback TCP'
  C = 'SIEM Vector agent, block loopback UDP'
}

# Block rules only. Outbound defaults to Allow and Block beats Allow, so an allow rule adds nothing.
function Get-VectorRuleDefinition([string] $Name, [string] $Program) {
  $Common = @{ DisplayName = $script:RuleNames[$Name]; Direction = 'Outbound'; Action = 'Block'; Program = $Program; Profile = 'Any'; Enabled = 'True' }
  switch ($Name) {
    'A' { $Common + @{ Protocol = 'Any'; RemoteAddress = @('0.0.0.0-127.0.0.0', '127.0.0.2-255.255.255.255', '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') } }
    'B' { $Common + @{ Protocol = 'TCP'; RemoteAddress = @('127.0.0.1'); RemotePort = @('1-9091', '9093-65535') } }
    'C' { $Common + @{ Protocol = 'UDP'; RemoteAddress = @('127.0.0.1') } }
    default { throw "Unknown rule $Name" }
  }
}

# Applies one rule, and keeps it only if Kafka still works and the rule really restricts. Otherwise
# it removes the rule, then proves Kafka again. Each action comes from $Ops, so this can be tested.
function Invoke-RuleTrial([string] $Rule, $Ops) {
  $Existed = & $Ops.Exists $Rule
  if (-not $Existed) { & $Ops.Create $Rule }
  $Reason = ''
  if (-not (& $Ops.Kafka)) { $Reason = 'it breaks Kafka' }
  elseif (-not (& $Ops.ControlReaches $Rule)) { $Reason = 'the control copy could not connect, so the test proves nothing' }
  elseif (-not (& $Ops.Restricted $Rule)) { $Reason = 'it does not restrict the protected binary' }
  if (-not $Reason) { return @{ Rule = $Rule; Kept = $true; Reason = 'Kafka works and the restriction holds'; KafkaAfter = $true } }
  & $Ops.Remove $Rule
  @{ Rule = $Rule; Kept = $false; Reason = $Reason; KafkaAfter = [bool] (& $Ops.Kafka) }
}

function Invoke-Native([string] $Command, [string[]] $Arguments, [string] $What) {
  # Windows PowerShell can treat a tool's stderr as a terminating error. Only the exit code counts.
  $ErrorActionPreference = 'Continue'
  $Output = & $Command @Arguments 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE" }
  $Output
}

# SYSTEM and Administrators only, owned by Administrators. An owner keeps the right to change the
# permissions, so an ordinary user must never own these paths.
function Set-LockedFolder([string] $Path, [string[]] $ExtraSids = @(), [switch] $KeepOwner) {
  New-Item -ItemType Directory -Force $Path | Out-Null
  if (-not $KeepOwner) { Invoke-Native 'icacls' @($Path, '/setowner', "*$script:AdminSid", '/Q') "Setting the owner of $Path" | Out-Null }
  $Grants = @("*${script:SystemSid}:(OI)(CI)F", "*${script:AdminSid}:(OI)(CI)F") + @($ExtraSids | ForEach-Object { "*${_}:(OI)(CI)F" })
  Invoke-Native 'icacls' (@($Path, '/inheritance:r', '/grant:r') + $Grants + @('/Q')) "Locking $Path" | Out-Null
}

function Set-LockedFileOwner([string] $Path) {
  Invoke-Native 'icacls' @($Path, '/setowner', "*$script:AdminSid", '/Q') "Setting the owner of $Path" | Out-Null
}

# Folders must block inheritance. Files inherit from a locked folder, which is the intended state,
# so a file is judged by its effective rules and not by the protected flag.
function Get-LockProblems(
  [string] $Path,
  [string[]] $AllowedSids = @($script:SystemSid, $script:AdminSid),
  [string[]] $OwnerSids = @($script:AdminSid, $script:SystemSid)
) {
  $Acl = Get-Acl -LiteralPath $Path
  $Problems = @()
  $Owner = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($OwnerSids -notcontains $Owner) { $Problems += "owner is $Owner" }
  if ((Get-Item -LiteralPath $Path).PSIsContainer -and -not $Acl.AreAccessRulesProtected) { $Problems += 'folder inherits permissions' }
  $Rules = @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
  foreach ($Rule in $Rules) {
    if ($Rule.AccessControlType -ne 'Allow') { $Problems += "deny rule for $($Rule.IdentityReference.Value)" }
    if ($AllowedSids -notcontains $Rule.IdentityReference.Value) { $Problems += "access for $($Rule.IdentityReference.Value)" }
  }
  foreach ($Required in @($script:SystemSid, $script:AdminSid)) {
    if (@($Rules | Where-Object { $_.IdentityReference.Value -eq $Required }).Count -eq 0) { $Problems += "no access for $Required" }
  }
  $Problems
}

# Ordinary users may read service status, and nothing else.
function Get-ServiceSddlProblems([string] $Sddl) {
  $Problems = @()
  if ($Sddl -notmatch '^D:') { return @('no DACL in the service descriptor') }
  foreach ($Ace in [regex]::Matches($Sddl, '\(([^)]*)\)')) {
    $Fields = $Ace.Groups[1].Value -split ';'
    if ($Fields[0] -ne 'A' -or $Fields[5] -in @('SY', 'BA')) { continue }
    $Rights = $Fields[2]
    foreach ($Right in @('DC', 'WD', 'WO', 'SD', 'RP', 'WP', 'DT', 'GA', 'GW', 'FA', 'FW')) {
      for ($Index = 0; $Index -lt $Rights.Length - 1; $Index += 2) {
        if ($Rights.Substring($Index, 2) -eq $Right) { $Problems += "$($Fields[5]) has $Right" }
      }
    }
  }
  $Problems
}

function New-DerivedKey([byte[]] $Prk, [string] $Info) {
  $Mac = New-Object Security.Cryptography.HMACSHA256 (, $Prk)
  $Bytes = [Text.Encoding]::ASCII.GetBytes($Info) + [byte] 1
  $Out = $Mac.ComputeHash($Bytes)
  $Mac.Dispose()
  ($Out | ForEach-Object { $_.ToString('x2') }) -join ''
}

# HKDF-SHA-256. The input key is 32 bytes from the OS generator, and is never stored.
function New-FieldKeyFile([string] $Path) {
  $Rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
  $Ikm = New-Object byte[] 32
  $Salt = New-Object byte[] 32
  $Rng.GetBytes($Ikm)
  $Rng.GetBytes($Salt)
  $Rng.Dispose()
  $Extract = New-Object Security.Cryptography.HMACSHA256 (, $Salt)
  $Prk = $Extract.ComputeHash($Ikm)
  $Extract.Dispose()
  [Array]::Clear($Ikm, 0, 32)
  $Json = '{"k1_enc":"' + (New-DerivedKey $Prk 'siem-d22-k1-enc') + '","k1_mac":"' + (New-DerivedKey $Prk 'siem-d22-k1-mac') + '"}'
  [Array]::Clear($Prk, 0, $Prk.Length)
  [IO.File]::WriteAllBytes($Path, [Text.Encoding]::ASCII.GetBytes($Json))
}

function Test-FieldKeyFile([string] $Path) {
  $Keys = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
  ($Keys.k1_enc -match '^[0-9a-f]{64}$') -and ($Keys.k1_mac -match '^[0-9a-f]{64}$') -and ($Keys.k1_enc -ne $Keys.k1_mac)
}

# Writes exact bytes to stdin, because a PowerShell pipe can add a BOM and a line ending. Returns
# the hash computed by WSL of the file it wrote. Keys never appear on a command line.
function Send-BytesToWsl([string] $Distro, [string] $Script, [byte[]] $Bytes) {
  $Info = New-Object Diagnostics.ProcessStartInfo
  $Info.FileName = 'wsl.exe'
  $Info.Arguments = "-d $Distro -u root --exec sh -c `"$Script`""
  $Info.UseShellExecute = $false
  $Info.RedirectStandardInput = $true
  $Info.RedirectStandardOutput = $true
  $Info.RedirectStandardError = $true
  $Process = [Diagnostics.Process]::Start($Info)
  $Error_ = $Process.StandardError.ReadToEndAsync()
  $Output = $Process.StandardOutput.ReadToEndAsync()
  $Process.StandardInput.BaseStream.Write($Bytes, 0, $Bytes.Length)
  $Process.StandardInput.BaseStream.Flush()
  $Process.StandardInput.Close()
  $Process.WaitForExit()
  if ($Process.ExitCode -ne 0) { throw "WSL write failed with exit code $($Process.ExitCode)" }
  $Output.Result.Trim()
}

# The folder and group are created here because the verifier service does not exist yet.
function Send-KeysToWsl([string] $KeyPath, [string] $Distro, [string] $Folder, [string] $Group) {
  $Target = "$Folder/field-keys.json"
  $Script = "set -e; umask 027; getent group $Group >/dev/null || groupadd --system $Group; " +
    "install -d -o root -g $Group -m 750 $Folder; cat > $Target.new; chown root:$Group $Target.new; chmod 640 $Target.new; " +
    "mv $Target.new $Target; sha256sum $Target | cut -d' ' -f1"
  $Bytes = [IO.File]::ReadAllBytes($KeyPath)
  $Local = (Get-FileHash -LiteralPath $KeyPath -Algorithm SHA256).Hash.ToLower()
  $Remote = Send-BytesToWsl $Distro $Script $Bytes
  if ($Remote -ne $Local) { throw 'Key bytes differ between Windows and WSL' }
}

function Test-KeysInWsl([string] $KeyPath, [string] $Distro, [string] $Folder) {
  $Local = (Get-FileHash -LiteralPath $KeyPath -Algorithm SHA256).Hash.ToLower()
  $Remote = (Send-BytesToWsl $Distro "sha256sum $Folder/field-keys.json 2>/dev/null | cut -d' ' -f1" ([byte[]] @()))
  $Remote -eq $Local
}

# Runs every step in order. Each privileged action comes from $Ops, so tests can run the real order
# with real ACLs and inject a failure at any step. Anything this run created is removed on failure.
function Install-VectorAgent($Paths, $Ops, [switch] $NoStart, [scriptblock] $Log = { param($Message) }) {
  $Undo = New-Object Collections.Stack
  $RemovePath = { param($Path) Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue }
  $Step = {
    param([string] $Name, [scriptblock] $Action)
    if ($Ops.ContainsKey('Before')) { & $Ops.Before $Name }
    & $Action
    & $Log "PASS $Name"
  }
  try {
    & $Step 'package-hash' { if ((& $Ops.Hash $Paths.Package) -ne $Paths.PackageSha256) { throw 'Package hash does not match the pin' } }
    $Existing = & $Ops.ServiceExists
    & $Step 'stop-service' { if ($Existing) { & $Ops.StopService } }

    & $Step 'folders' {
      foreach ($Path in $Paths.Program, $Paths.Bin, $Paths.Config, $Paths.State, $Paths.Data, $Paths.Secrets) {
        if (-not (Test-Path -LiteralPath $Path)) {
          $Undo.Push(@{ Run = $RemovePath; With = @($Path) })
        }
        & $Ops.LockFolder $Path
      }
    }

    & $Step 'binary' {
      $script:TempDir = Join-Path $Paths.State "unpack-$PID"
      & $Ops.Unpack $Paths.Package $script:TempDir
      $Unpacked = Get-ChildItem $script:TempDir -Recurse -Filter vector.exe | Select-Object -First 1
      if (-not $Unpacked) { throw 'vector.exe is not in the package' }
      Copy-Item $Unpacked.FullName $Paths.Exe -Force
      Copy-Item $Paths.SourceConfig $Paths.ConfigFile -Force
      & $Ops.OwnFile $Paths.Exe
      & $Ops.OwnFile $Paths.ConfigFile
    }
    & $Step 'version' { & $Ops.CheckVersion $Paths.Exe }

    & $Step 'permissions' {
      foreach ($Path in $Paths.Program, $Paths.Bin, $Paths.Config, $Paths.State, $Paths.Data, $Paths.Secrets, $Paths.Exe, $Paths.ConfigFile) {
        & $Ops.AssertLocked $Path
      }
    }

    # Keys are created only after the folder that holds them has passed its check.
    $NewKeys = -not (Test-Path -LiteralPath $Paths.Keys)
    & $Step 'keys' {
      if ($NewKeys) {
        $Undo.Push(@{ Run = $RemovePath; With = @($Paths.Keys) })
        & $Ops.NewKeys $Paths.Keys
        & $Ops.OwnFile $Paths.Keys
      }
      if (-not (Test-FieldKeyFile $Paths.Keys)) { throw 'Key file is not two separate 256-bit keys' }
      & $Ops.AssertLocked $Paths.Keys
    }
    & $Step 'key-delivery' {
      if ($NewKeys) { $Undo.Push(@{ Run = $Ops.RemoveKeys; With = @() }) }
      if ($NewKeys -or -not (& $Ops.KeysMatch $Paths.Keys)) { & $Ops.DeliverKeys $Paths.Keys }
    }

    & $Step 'firewall' {
      if (-not (& $Ops.RuleExists 'A')) {
        $Undo.Push(@{ Run = $Ops.RemoveRule; With = @('A') })
        & $Ops.NewRule 'A' $Paths.Exe
      }
      & $Ops.CheckRule 'A' $Paths.Exe
    }
    & $Step 'validate' { & $Ops.Validate $Paths.Exe $Paths.ConfigFile }

    & $Step 'service' {
      if (-not $Existing) {
        $Undo.Push(@{ Run = $Ops.DeleteService; With = @() })
        & $Ops.CreateService $Paths.Exe $Paths.ConfigFile
      }
      & $Ops.ConfigureService
      # Manual until the final run, so that a reboot cannot start collection early.
      & $Ops.SetStartType $(if ($NoStart) { 'demand' } else { 'auto' })
      & $Ops.CheckService
    }

    if ($NoStart) {
      & $Log 'INFO not started, and start type is manual'
    } else {
      & $Step 'start' {
        if (-not (& $Ops.RuleExists 'A')) { throw 'Refusing to start without firewall rule A' }
        & $Ops.StartService
      }
    }
  } catch {
    & $Log "FAIL $($_.Exception.Message)"
    while ($Undo.Count -gt 0) {
      $Action = $Undo.Pop()
      try { & $Action.Run @($Action.With) } catch { & $Log "CLEANUP FAILED $($_.Exception.Message)" }
    }
    throw
  } finally {
    if ($script:TempDir -and (Test-Path -LiteralPath $script:TempDir)) { Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue }
    $script:TempDir = $null
  }
}
