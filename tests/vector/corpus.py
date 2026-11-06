"""Synthetic redaction corpus. Every secret is fake, and keep lines use harmless stand-ins for tool names."""
sec = [
    r'mysql.exe -u root -pFakeSecret1 -h db', r'tool.exe --password=FakeSecret1', r'tool.exe --password "Fake Secret1 x"',
    r'tool.exe /password:FakeSecret1', r'sqlcmd -S host -U sa -pass FakeSecret1', r'net use \\srv\c$ FakeSecret1 /user:corp\bob',
    r'net use Z: \\srv\share FakeSecret1 /user:bob', r'net use \\srv\ipc$ /user:corp\bob FakeSecret1', r'net user bob FakeSecret1 /add',
    r'net1 user bob FakeSecret1', r'curl -u bob:FakeSecret1 https://x.example', r'curl.exe -s --user "bob:FakeSecret1" https://x',
    r'git clone https://bob:FakeSecret1@git.example/r.git', r'curl -H "Authorization: Bearer FakeSecret1abc" https://x',
    r'$p = ConvertTo-SecureString "FakeSecret1" -AsPlainText -Force', r"$password = 'FakeSecret1'", r'$env:API_KEY = "FakeSecret1"',
    r'$h = @{ "x-api-key" = "FakeSecret1" }', r'{"client_secret":"FakeSecret1"}', r'set PASSWORD=FakeSecret1', r'export GITHUB_TOKEN=FakeSecret1',
    r'aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP', 'gh auth login --with-token ghp_' + 'a' * 36, 'x sk-ant-' + 'b' * 30,
    'eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefghijklmno', "-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\nfake\n-----END RSA PRIVATE KEY-----",
]
keep = [
    r'whoami /all', r'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AA==', r'sample-tool save registry-hive out.save',
    r'net user bob /add', r'net user bob /domain', r'net user bob *', r'net localgroup administrators bob /add',
    r'net use Z: \\srv\share /persistent:no', r'net use \\srv\c$ /user:corp\bob', r'findstr /si password *.txt',
    r'Get-ADUser -Filter * -Properties PasswordLastSet', r'Set-ADAccountPassword -Identity bob -Reset', r'$c = Get-Credential',
    r'$password = Read-Host -AsSecureString', r'tool -Password $cred', r'tool -Password (Read-Host -AsSecureString)', r'$token = $env:GH_TOKEN',
    r'schtasks /create /tn x /tr calc.exe /sc onlogon', r'mkdir -p /tmp/x', r'ssh -p 2222 bob@host', r'tar -pxzf a.tgz',
    r'sc.exe config x binPath= "cmd /c calc"', r'SELECT password FROM users', r'runas /user:admin cmd.exe', r'tool -Authentication Basic',
    r'https://user@host/path', r'tool --token-file C:\t\f.txt',
]
