<#
VERSION: 1.2
    .SYNOPSIS
        NAME: Export-AndParseHipsFile
        AUTHOR: Eric Powers EricPow@microsoft.com 
        

        
        Notice: Any links, references, or attachments that contain sample scripts, code, or commands comes 
        with the following notification. 
        This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production 
        environment.  THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
        EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS
        FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to 
        reproduce and distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our name, 
        logo, or trademarks to market Your software product in which the Sample Code is embedded; (ii) to include a valid 
        copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless, 
        and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or
        result from the use or distribution of the Sample Code.

    .FUNCTIONALITY
         

    .DESCRIPTION
        
        The script downloads the required JSON files which detail the required O365 Endpoints 
        This data is then indexed and used to identify the O365 endpoints,ports, and urls that are required for application access to O365.
        The McAfee Hips file is then extract to the desktop of the currently logged in user, and then processed for blocks
        The Blocks are then checked against the Indexed O365 requirements Json for O365 blocks. If a block is detected
        it is then returned to the screen and saved to the users desktop. 


    .EXAMPLE
        .\Export-AndParseHipsforO365Blocks.ps1

    .NOTES
        202011105: v1.0 - Initial Release
        202011118: v1.1 - Initial Release
#>


function Export-AndParseHipsFile {
    param(
        $StartDate,
        $EndDate
    )
    $ParseThisHipsLogFile = "$env:userprofile\Desktop\McAfeeFireLog.txt"
    
    if (Test-Path $ParseThisHipsLogFile  -ErrorAction SilentlyContinue) {
        Remove-Item "$env:userprofile\Desktop\McAfeeFireLog.txt"
    }
    
    Write-Host -ForegroundColor DarkCyan 'Requesting HIPs log export...'
    & "C:\Program Files\McAfee\Host Intrusion Prevention\ClientControl.exe" /export /s "C:\ProgramData\McAfee\Host Intrusion Prevention\Event.log" $ParseThisHipsLogFile
    Write-Host -ForegroundColor DarkCyan 'Requested HIPs log export has been completed...'
    
    $AmountOfLogDataToParse = 500kb
    $File = New-Object System.IO.StreamReader -arg $ParseThisHipsLogFile
    $LineCounter = 0
    
    if ($File.BaseStream.Length -ge $AmountOfLogDataToParse) {
        [int]$Look = '-' + [string]$($AmountOfLogDataToParse)
        $File.BaseStream.seek($Look, [System.IO.SeekOrigin]::end) | Out-Null
    }
    
    $Seekcounter = 1; $stopprocessing = $false
    
    While ($File.EndOfStream -eq $false -and $stopprocessing -eq $false) {
        
        Write-Progress -activity 'Processing Exported HIPs Log...' -status "Seaching for Log Entires in the time range $StartDate - $EndDate"   
        do {
            $line = $File.ReadLine() 
            $line = $line -replace '\u0000'
        }until($line -match '^Time:\t+(.*)\d{4}\s+(\d{1,2}:){2}\d{1,2}\s\w{2}$')
        
        $seektmpObject = [PSCustomObject]@{ }
        $seektmpObject | Add-Member -MemberType NoteProperty -Name 'Time' -Value $([datetime]($line -replace "Time:", "").Trim()) -Force
    
        If ($seektmpObject.Time -le $StartDate) {
            $stopprocessing = $true
        }
        else { 
            $Seekcounter++
            $Seek = "-$($AmountOfLogDataToParse * $Seekcounter )"
            $File.BaseStream.seek($Seek, [System.IO.SeekOrigin]::end) | Out-Null
        }
    
        if ($File.EndOfStream) {
            $stopprocessing = $true
        }
    
    }
    
    do {
        $line = $File.ReadLine() -replace '\u0000' 
        $line = $line -replace '\u0000' 
    }until ( $line -match "Description:")
    
    
    $TotalTicksinTimespan = ($enddate.ticks - $startdate.ticks)
    Remove-Variable TmpObject -ErrorAction SilentlyContinue
    While ($File.EndOfStream -eq $false) {
        $line = $File.ReadLine() -replace '\u0000'
        $line = $line -replace '\u0000'
        switch -Regex ($line) {
            '^Time:\t+(.*)\d{4}\s+(\d{1,2}:){2}\d{1,2}\s\w{2}$' {
    
                if ($tmpObject) {
                    If ([datetime]$tmpObject.Time -ge [datetime]$StartDate -and [datetime]$tmpObject.Time -le [datetime]$EndDate) {
                        $tmpObject
                    }
                }
    
                [datetime]$timeStamp = $([datetime]($line -replace "Time:", "").Trim()) 
                $tmpObject = [PSCustomObject]@{ }
                $tmpObject | Add-Member -MemberType NoteProperty -Name 'Time' -Value  $timeStamp
                if (($timeStamp -ge [datetime]$StartDate) -and ($timeStamp -le [datetime]$EndDate)) {
                        
                    $tickpoint = (Get-Date $timeStamp).ticks
                    $PercentCompleted = (($tickpoint - $startdate.ticks) / $TotalTicksinTimespan) * 100
    
                    Write-Progress -activity 'Processing HIPs Log...' -status "Extracting data from file with a date range of $startdate through $enddate.... Current TimeStamp: $timeStamp" -percentcomplete $PercentCompleted
                    Write-Verbose "Line Number: $LineCounter"
                    Write-Verbose "LineText: `'$line`'"
                }
                if ([DateTime]$tmpObject.Time -gt [Datetime]$EndDate) {
                    $File.BaseStream.seek(0, [System.IO.SeekOrigin]::end) | Out-Null  
                }
                break
            }
            '^[\w\s]+\:\t+[\w\s\d\W\D\S]+$' {
                if ($tmpObject) {
    
                    $header = (([Regex]::match($line, "^[\w\s]+\:\t+").value) -replace ":", "").trim()
                    $value = ($line -replace "$header\:").trim()
                    $tmpObject | Add-Member -MemberType NoteProperty -Name $header -Value $value
                }
                break
            }
        }
        
        $LineCounter ++
    
    }
    
    Write-Progress -activity 'Processing HIPs Log...' -status "Extracting data from file with a date range of $startdate through $enddate.... Current TimeStamp: $timeStamp" -Completed
    $file.Close()
    $file.Dispose()
    
}
    
function Get-IPrangeInRange {
         
    param (  
        [string]$start,  
        [string]$end,  
        [string]$ip,
        [string]$isThisIPinRange,
        [string]$mask,  
        [int]$cidr  
    )  
          
    function IP-toINT64 () {  
        param ($ip)  
          
        $octets = $ip.split(".")  
        return [int64]([int64]$octets[0] * 16777216 + [int64]$octets[1] * 65536 + [int64]$octets[2] * 256 + [int64]$octets[3])  
    }  
          
    function INT64-toIP() {  
        param ([int64]$int)  
     
        return (([math]::truncate($int / 16777216)).tostring() + "." + ([math]::truncate(($int % 16777216) / 65536)).tostring() + "." + ([math]::truncate(($int % 65536) / 256)).tostring() + "." + ([math]::truncate($int % 256)).tostring() ) 
    }  
          
    if ($ip) { $ipaddr = [Net.IPAddress]::Parse($ip) }  
    if ($cidr) { $maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1" * $cidr + "0" * (32 - $cidr)), 2)))) }  
    if ($mask) { $maskaddr = [Net.IPAddress]::Parse($mask) }  
    if ($ip) { $networkaddr = New-Object net.ipaddress ($maskaddr.address -band $ipaddr.address) }  
    if ($ip) { $broadcastaddr = New-Object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address)) }  
          
    if ($ip) {  
        $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring  
        $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring  
    }
    else {  
        $startaddr = IP-toINT64 -ip $start  
        $endaddr = IP-toINT64 -ip $end  
    }  
    $Check = IP-toINT64   -ip $isThisIPinRange
    if ($Check -ge $startaddr -and $Check -le $endaddr) {
        $IsInRange = $true
    }
    Else {
        $IsInRange = $false
    
    }
          
    $temp = "" | Select-Object start, end, Ip, IsInRange 
    $temp.start = INT64-toIP -int $startaddr 
    $temp.end = INT64-toIP -int $endaddr 
    $temp.Ip = $isThisIPinRange
    $Temp.IsInRange = $IsInRange
    return $temp 
}
    
Function Get-WhoIs {
    [cmdletbinding()]
    [OutputType("WhoIsResult")]
    Param (
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to lookup with WhoIs",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]
        [ValidateScript( {
                #verify each octet is valid to simplify the regex
                $test = ($_.split(".")).where( { [int]$_ -gt 255 })
                if ($test) {
                    Throw "$_ does not appear to be a valid IPv4 address"
                    $false
                }
                else {
                    $true
                }
            })]
        [string]$IPAddress
    )
    
    Begin {
        Write-Verbose "Starting $($MyInvocation.Mycommand)"
        $baseURL = 'http://whois.arin.net/rest'
        #default is XML anyway
        $header = @{"Accept" = "application/xml" }
    
    } #begin
    
    Process {
        Write-Verbose "Getting WhoIs information for $IPAddress"
        $url = "$baseUrl/ip/$ipaddress"
        Try {
            $r = Invoke-RestMethod $url -Headers $header -ErrorAction stop
            Write-Verbose ($r.net | Out-String)
        }
        Catch {
            $errMsg = "Unable to retrieve WhoIs information for $IPAddress. $($_.exception.message)"
            $host.ui.WriteErrorLine($errMsg)
        }
    
        if ($r.net) {
            Write-Verbose "Creating result"
            [pscustomobject]@{
                PSTypeName             = "WhoIsResult"
                IP                     = $ipaddress
                Name                   = $r.net.name
                RegisteredOrganization = $r.net.orgRef.name
                City                   = (Invoke-RestMethod $r.net.orgRef.'#text').org.city
                StartAddress           = $r.net.startAddress
                EndAddress             = $r.net.endAddress
                NetBlocks              = $r.net.netBlocks.netBlock | ForEach-Object { "$($_.startaddress)/$($_.cidrLength)" }
                Updated                = $r.net.updateDate -as [datetime]
            }
        } #If $r.net
    } #Process
    
    End {
        Write-Verbose "Ending $($MyInvocation.Mycommand)"
    } #end
}
[Double]$scriptversion = 1.2 
if(Test-NetConnection -ComputerName raw.githubusercontent.com -Port 443 -ErrorAction SilentlyContinue -InformationLevel Quiet){
    [Double]$CurrentPublishedVersion = ((Invoke-WebRequest -uri 'https://raw.githubusercontent.com/ScriptingPFE/TroubleShooting/main/Export-AndParseHipsForO365Blocks.ps1' -MaximumRedirection 100  ).parsedhtml.body.innertext.substring(2,13).trim() -split ":")[1]

    if($CurrentPublishedVersion -gt $scriptversion){
        Write-host -ForegroundColor Yellow "The script you are currrently running has been updated. Please visit the Github link below for the current version of the code."
        Write-Host 'https://raw.githubusercontent.com/ScriptingPFE/TroubleShooting/main/Export-AndParseHipsForO365Blocks.ps1'
        pause
    }
}

$UniqueBlocks = @{ }
$O365URlIndex = @{ }
$O365IPIndex = @{ }
    
if (!(Test-Path "$env:USERPROFILE\Desktop\O365Networks\")) {
    New-Item "$env:USERPROFILE\Desktop\O365Networks\" -ItemType Directory | Out-Null
}
      
$webclient = [System.Net.WebClient]::new()
$webclient.DownloadFile('https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7', "$env:USERPROFILE\Desktop\O365Networks\O365CommonNetworkRequirements.json")
$webclient.DownloadFile('https://endpoints.office.com/endpoints/USGOVDoD?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7', "$env:USERPROFILE\Desktop\O365Networks\O365USDODNetworkRequirements.json")
$webclient.DownloadFile('https://endpoints.office.com/endpoints/USGOVGCCHigh?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7', "$env:USERPROFILE\Desktop\O365Networks\O365GCCHighNetworkRequirements.json")
$webclient.DownloadFile('https://endpoints.office.com/endpoints/China?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7', "$env:USERPROFILE\Desktop\O365Networks\O365ChinaNetworkRequirements.json")
$webclient.DownloadFile('https://endpoints.office.com/endpoints/Germany?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7', "$env:USERPROFILE\Desktop\O365Networks\O365GermanyNetworkRequirements.json")
    
    
Foreach ($Json  in(Get-ChildItem "$env:USERPROFILE\Desktop\O365Networks\" | Select-Object -ExpandProperty fullname)) {
    Write-Host -ForegroundColor DarkCyan "Processing O365 Network Requirements File: " -NoNewline; $json
    Start-Sleep 3
    $JsonFile = Get-Content $Json | ConvertFrom-Json
    $O365Network = ($Json -split '\\')[-1] -replace 'NetworkRequirements.json'
    Foreach ($JsonEntry in $JsonFile ) {
        if (($JsonEntry | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name) -contains 'urls') {
            foreach ($url in $JsonEntry.urls) {
                if (!$O365URlIndex.Containskey($url )) {
                    $O365URlIndex.add($url, [pscustomobject]@{
                            id                     = $JsonEntry.id
                            O365Network            = $O365Network
                            category               = $JsonEntry.category
                            expressRoute           = $JsonEntry.expressRoute
                            ips                    = $JsonEntry.ips
                            serviceArea            = [string]($JsonEntry | Select-Object -expandproperty serviceArea) + ';'
                            serviceAreaDisplayName = [string]($JsonEntry | Select-Object -expandproperty serviceAreaDisplayName) + ';' 
                            required               = $JsonEntry.required
                            tcpPorts               = $JsonEntry.tcpPorts
                            urls                   = $JsonEntry.urls 
                        })
                }
                Else {
                    if (($O365URlIndex[$url].O365Network -split ';') -notcontains $O365Network) {
                        $O365URlIndex[$url].O365Network = ($O365URlIndex[$url].O365Network.Clone()) + "`;$O365Network"
                    }
                }
            }
        }
        if (($JsonEntry | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name) -contains 'IPs') {
            foreach ($IP in $JsonEntry.IPs) {
                if (!$O365IPIndex.Containskey($IP)) {
                    $O365IPIndex.add($IP, [pscustomobject]@{
                            id                     = $JsonEntry.id
                            O365Network            = $O365Network
                            category               = $JsonEntry.category
                            expressRoute           = $JsonEntry.expressRoute
                            ips                    = $JsonEntry.ips
                            serviceArea            = [string]($JsonEntry | Select-Object -expandproperty serviceArea) + ';'
                            serviceAreaDisplayName = [string]($JsonEntry | Select-Object -expandproperty serviceAreaDisplayName) + ';' 
                            required               = $JsonEntry.required
                            tcpPorts               = $JsonEntry.tcpPorts
                            urls                   = $JsonEntry.urls
                        })
                }
                Else {
    
                    if (($O365IPIndex[$IP].serviceArea -split ";") -notcontains $JsonEntry.serviceArea) {
                        $O365IPIndex[$IP].serviceArea = ($O365IPIndex[$IP].serviceArea.Clone()) + "$($JsonEntry.serviceArea.Clone());"
                    }
                    if (($O365IPIndex[$IP].serviceAreaDisplayName -split ";") -notcontains $JsonEntry.serviceAreaDisplayName.Clone() ) {
                        $O365IPIndex[$IP].serviceAreaDisplayName = ($O365IPIndex[$IP].serviceAreaDisplayName.Clone()) + "$($JsonEntry.serviceAreaDisplayName.Clone());"
                    }
    
                }
            }
        }
    } 
}
    
$allResults = Export-AndParseHipsFile -StartDate (Get-Date).Addhours(-8) -EndDate (Get-Date) 
$IPBLOCKs = $allResults | Where-Object { $_.'IP Address' -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" -and $_.permit -eq $false }  
    
Write-Host -ForegroundColor DarkCyan "Creating unique block list from Hips Extraction..."
Foreach ($block in $IPBLOCKs ) {
    if (!$UniqueBlocks.ContainsKey($block.'IP Address')) {
        $whois = Get-WhoIs -IPAddress $block.'IP Address'
        $block | Add-Member -MemberType NoteProperty -Name RegisteredOrganization -Value $whois.RegisteredOrganization -Force
        $block | Add-Member -MemberType NoteProperty -Name BlockCount -Value 1
        $UniqueBlocks.Add($block.'IP Address', $block)
    }
    Else {
        if ($UniqueBlocks[$block.'IP Address'].Path -notcontains $block.Path) {
            $UniqueBlocks[$block.'IP Address'].Path = $($UniqueBlocks[$block.'IP Address'].Path, $block.Path)
        }
    
        $UniqueBlocks[$block.'IP Address'].BlockCount ++
    }
}
    
Write-Host -ForegroundColor DarkCyan "Processing unique block list for O365 endpoints..."
Remove-Item "$env:USERPROFILE\Desktop\Blocked_O365_Endpoints_$(Get-Date -Format MM-dd-yyyy).csv"  -ErrorAction SilentlyContinue -Force
Foreach ($UniqueBlock in $UniqueBlocks.Keys) {
    
    Foreach ($Network  in $O365IPIndex.Keys) {
        if ($Network -notmatch ":") {
            $lookup = (Get-IPrangeInRange -ip ($Network -split "/")[0] -cidr ($Network -split "/")[1] -isThisIPinRange $UniqueBlock  )
            if ($lookup.isinrange) {
                $BlockedO365Entry = [pscustomobject]@{
                    FirstObeservedTimeStamp = $UniqueBlocks[$UniqueBlock].Time
                    BlockedIPAddress        = $UniqueBlock
                    BlockCount              = $UniqueBlocks[$UniqueBlock].BlockCount
                    RegisteredOrganization  = $UniqueBlocks[$UniqueBlock].RegisteredOrganization
                    TcpPort                 = $UniqueBlocks[$UniqueBlock].'Remote Port'
                    RequiredNetworkRange    = "$($lookup.start) - $($lookup.end)"
                    Application             = [string]$UniqueBlocks[$UniqueBlock].path
                    HIPsEventType           = $UniqueBlocks[$UniqueBlock].'Event Type'
                    HIPsRule                = $UniqueBlocks[$UniqueBlock].'Rule ID'
                    HIPsRuleDescription     = $UniqueBlocks[$UniqueBlock].Description
                    O365Network             = $O365IPIndex[$network].O365Network
                    serviceArea             = $O365IPIndex[$network].serviceArea.Trimend(";")
                    serviceAreaDisplayName  = $O365IPIndex[$network].serviceAreaDisplayName.Trimend(";")
                    RequiredIPRange         = ([string]($O365IPIndex[$network].ips).trim() -replace " ", ", ")
                    RequiredtcpPorts        = $O365IPIndex[$network].tcpPorts
                    category                = $O365IPIndex[$network].category
                    Requiredurls            = if($O365IPIndex[$network].urls){([string]($O365IPIndex[$network].urls).trim() -replace " ", ", ")}else{""}
                }
                $BlockedO365Entry
                $BlockedO365Entry | Export-Csv "$env:USERPROFILE\Desktop\Blocked_O365_Endpoints_$(Get-Date -Format MM-dd-yyyy).csv" -NoTypeInformation -Append
            }
        }
    }
       
}
    
if (Test-Path "$env:userprofile\Desktop\McAfeeFireLog.txt" -erroraction silentlycontinue) {
    Remove-Item "$env:userprofile\Desktop\McAfeeFireLog.txt"-force -confirm:$false
}
