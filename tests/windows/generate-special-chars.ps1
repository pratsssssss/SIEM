# Starts harmless processes whose exact command lines hold XML-special characters. No shell is
# involved, so & < > are plain text and do nothing. whoami.exe rejects the arguments and exits.
# Writes each case to -Out, so that the stored text can be compared with what was really launched.
param([Parameter(Mandatory)] [string] $Out)
$Tag = 'SIEMCHR' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$Fake = 'FAKEPW' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$Whoami = "$env:SystemRoot\System32\whoami.exe"
$Unicode = "caf$([char]0xE9) $([char]0x65E5)$([char]0x672C)$([char]0x8A9E) $([char]0x416) $([char]0xD83D)$([char]0xDE00) & done"
$Cases = [ordered] @{
  amp        = 'A & B'
  andand     = 'A && B'
  redirect   = 'tool 2>&1'
  tag        = '<test>'
  less       = 'A < B'
  spaces     = 'A   &   B   >   C   <   D'
  quoted     = '"quoted & arg" "x > y" "a < b"'
  entity     = 'literal &amp; &lt; &gt; &#38; &quot;'
  unicode    = $Unicode
  apostrophe = "it's & 'that' > x"
  pipe       = 'a | b ^& c %PATH% !x!'
  redaction  = "--password=$Fake & next > out"
}
$Results = [ordered] @{}
foreach ($Name in $Cases.Keys) {
  $Arguments = "$Tag-$Name $($Cases[$Name])"
  $Info = New-Object Diagnostics.ProcessStartInfo
  $Info.FileName = $Whoami
  $Info.Arguments = $Arguments
  $Info.UseShellExecute = $false
  $Info.CreateNoWindow = $true
  $Info.RedirectStandardError = $true
  $Info.RedirectStandardOutput = $true
  $Process = [Diagnostics.Process]::Start($Info)
  $Process.WaitForExit()
  $Results[$Name] = "`"$Whoami`" $Arguments"
}

# ParentCommandLine: the child of a parent whose own line holds the same characters.
$Comment = "$Tag-parent A && B 2>&1 <test>   & x"
$Info = New-Object Diagnostics.ProcessStartInfo
$Info.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Info.Arguments = "-NoProfile -Command `"whoami.exe /? | Out-Null # $Comment`""
$Info.UseShellExecute = $false
$Info.CreateNoWindow = $true
$Process = [Diagnostics.Process]::Start($Info)
$Process.WaitForExit()
$Results['parent'] = "`"$($Info.FileName)`" $($Info.Arguments)"

# ScriptBlockText, multi-line, from a script file. The fake secret must be redacted.
$Script = Join-Path $env:TEMP "$Tag.ps1"
$Body = "`$note = '$Tag-script A && B 2>&1 <test>   & x'`r`n`$password = '$Fake'`r`nif (1 -lt 2) { Get-Date | Out-Null }"
[IO.File]::WriteAllText($Script, $Body)
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Script
Remove-Item -LiteralPath $Script -ErrorAction SilentlyContinue

# Task Scheduler stores a name holding an ampersand, in a log that needs no elevation to read.
$TaskName = "$Tag A & B"
$Action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit'
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddDays(1)) -Force | Out-Null
Start-Sleep -Seconds 2
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false

@{ tag = $Tag; fake = $Fake; task = "\$TaskName"; lines = $Results } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Out -Encoding UTF8
Write-Output "generated $($Results.Count) cases"
