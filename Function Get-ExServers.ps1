Function Get-ExServers {
    $configPartition = [regex]::Replace(((New-Object DirectoryServices.DirectorySearcher).SearchRoot.Parent), "LDAP://", "LDAP://CN=Configuration,", "ignorecase")
    $Search = New-Object DirectoryServices.DirectorySearcher([ADSI]$configPartition)
    $Search.filter = “(objectClass=msExchExchangeServer)"
    $msExchServer = $Search.Findall()
    Foreach ($server in $msExchServer) { 
        if ($server.properties.Keys -contains 'Admindisplayname') { 
            [pscustomobject]@{
            Name = [string]$server.Properties['adminDisplayName']
            InstallPath = [string]$server.Properties['msExchInstallPath']
            ActiveDirectorySite = [string]$server.Properties['msExchServerSite']
            }
        }
    }
}
