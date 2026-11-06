# Elevated test events: a temporary account and a temporary service. Both are removed in a finally
# block. The password is random and is never written anywhere. The service never starts. Never
# clears a log. Writes the marker to -Out, and what it did, as counts, to -Log.
param([Parameter(Mandatory)] [string] $Out, [Parameter(Mandatory)] [string] $Log)
$Marker = 'SIEMT' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$Account = $Marker.Substring(0, 13)
$Service = "SIEMCHK$($Marker.Substring(5))"
@{ marker = $Marker; account = $Account; service = $Service; started = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Out -Encoding ASCII
function Note([string] $Text) { Add-Content -LiteralPath $Log -Value "$(Get-Date -Format s) $Text" -Encoding UTF8 }

$Bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Bytes)
$Password = 'Aa1!' + [Convert]::ToBase64String($Bytes).Replace('/', 'x').Replace('+', 'y').Replace('=', 'z')
$Secure = ConvertTo-SecureString $Password -AsPlainText -Force
$AdminsGroup = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
try {
  # 5. Privilege escalation: added to Administrators, then removed.
  New-LocalUser -Name $Account -Password $Secure -AccountNeverExpires | Out-Null
  Note "account created"
  Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $Account
  Note "added to $AdminsGroup"
  Start-Sleep -Seconds 2
  Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $Account
  Note 'removed from the group'

  # 4. Failures, then a success, for an account that is deleted a moment later. Windows logs a repeat
  # of the same wrong password only once, so each attempt uses a different one.
  foreach ($Index in 1..4) { & net.exe use \\localhost\IPC$ "/user:$env:COMPUTERNAME\$Account" "not-the-password-$Index" 2>$null | Out-Null }
  & net.exe use \\localhost\IPC$ "/user:$env:COMPUTERNAME\$Account" $Password 2>$null | Out-Null
  Note "network logon exit $LASTEXITCODE"
  & net.exe use \\localhost\IPC$ /delete /y 2>$null | Out-Null

  # 6. New service, whose path runs a shell. It is never started.
  & sc.exe create $Service binPath= 'C:\Windows\System32\cmd.exe /c exit' start= demand | Out-Null
  Note "service created, exit $LASTEXITCODE"
} catch {
  Note "ERROR $($_.Exception.Message)"
} finally {
  & sc.exe delete $Service 2>$null | Out-Null
  Remove-LocalUser -Name $Account -ErrorAction SilentlyContinue
  $Password = $null
  Note "cleanup: account present $([bool](Get-LocalUser -Name $Account -ErrorAction SilentlyContinue)), service present $([bool](Get-Service $Service -ErrorAction SilentlyContinue))"
}
Note 'RUNNER DONE'
