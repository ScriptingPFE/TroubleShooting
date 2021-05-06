Function Get-ApplicationsUsingNetwork {
Param (
[int]$DurationInMinutes,
[int]$TimeToSleepInSeconds

)

Write-progress -activity 'Monitoring applications accessing the network...' -status "Indexing executables in the system drive." -percentcomplete  0
[hashtable]$Exes = @{}
$Global:ObservedRunningExes = @{}

$LocatedExes = $(Get-ChildItem C:\WINDOWS\System  -Include *.Exe -Force -ErrorAction SilentlyContinue 
Get-ChildItem C:\WINDOWS\System32 -Include *.Exe -Force -Recurse  -ErrorAction SilentlyContinue
Get-ChildItem -Recurse 'C:\Program Files (x86)' -Include *.Exe -Force  -ErrorAction SilentlyContinue
Get-ChildItem -Recurse 'C:\Program Files' -Include *.Exe -Force  -ErrorAction SilentlyContinue)

Foreach ($SystemExe in $LocatedExes){
if(!$Exes.ContainsKey($SystemExe.name.ToUpper())){
        $Exes.Add($SystemExe.name.ToUpper(), $SystemExe.FullName)
        $Exes.Add(($SystemExe.name.ToUpper() -replace "\.exe","").ToUpper(), $SystemExe.FullName)
    }
}

$TaninumApplicationIndex = Get-childitem HKLM:"\SOFTWARE\WOW6432Node\Tanium\Tanium Client\Sensor Data\Applications" -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue
$ExeIndex = Get-WmiObject win32_process | where {$_.path -match "\w"} | Select ExecutablePath,ProcessName -Unique

Write-progress -activity 'Monitoring applications accessing the network...' -status "Indexing executables in the system drive." -percentcomplete  100

foreach ($Exe in $ExeIndex){
    if(!$Exes.ContainsKey($exe.ProcessName)){
        $Exes.Add($Exe.ProcessName.ToUpper(), $exe.ExecutablePath)
        $Exes.Add(($Exe.ProcessName -replace "\.exe","").ToUpper(), $exe.ExecutablePath)
    }
}

$StartingTimeStamp = (Get-Date) 
$EndingTimeStamp = (Get-Date).AddMinutes($DurationInMinutes)
$TotalTicksinTimespan= ($EndingTimeStamp.ticks -  $StartingTimeStamp.ticks)

foreach ($Exe in $TaninumApplicationIndex){
    if(!$Exes.ContainsKey($exe.Process.ToUpper()) -and $exe.Process -match "\.exe"){
        $Exes.Add($Exe.Process.ToUpper(), (Join-path $exe.Path $Exe.Process))
        $Exes.Add(($Exe.Process -replace "\.exe","").ToUpper(), (Join-path $exe.Path $Exe.Process))
    }
}

Do{
    $tickpoint = (Get-date).ticks
    $PercentCompleted = (($tickpoint - $StartingTimeStamp.ticks) / $TotalTicksinTimespan)*100
    Write-progress -activity 'Monitoring applications accessing the network...' -status "Watching traffic for $DurationInMinutes minutes resting for $TimeToSleepInSeconds seconds between data samples." -percentcomplete $PercentCompleted
    $Processes = (get-process -ErrorAction SilentlyContinue)

    foreach ($TcpConnection in (Get-NetTCPConnection | select owningProcess,*Address,*Port,state -Unique)){
        if(($Processes | where {$_.ID -eq $TcpConnection.owningProcess})){
            $ProcessName = ($Processes | where {$_.ID -eq $TcpConnection.owningProcess}).ProcessName.ToString().ToUpper()
        }
        Else{
           $Prc = (Get-Process -id $TcpConnection.owningProcess -ErrorAction SilentlyContinue)
           if( $Prc){
           $ProcessName = $Prc.ProcessName.ToString().ToUpper()
           }
        }
        Add-Member -InputObject $TcpConnection -Type NoteProperty -Name ProcessName -Value $ProcessName
        Add-Member -InputObject $TcpConnection -Type NoteProperty -Name ConnectionCount -Value 1
    
        if($Exes.ContainsKey($TcpConnection.ProcessName)){
            Add-Member -InputObject $TcpConnection -Type NoteProperty -Name ExecutablePath -Value ($Exes[$ProcessName])
        }
        Else{
            Add-Member -InputObject $TcpConnection -Type NoteProperty -Name ExecutablePath -Value 'Unknown'
        }

        $uniqueString= [string]$TcpConnection.ProcessName + [string]$TcpConnection.RemoteAddress +  [string]$TcpConnection.LocalPort + [string]$TcpConnection.RemotePort
        if(!$ObservedRunningExes.ContainsKey($uniqueString)){
            $ObservedRunningExes.Add($uniqueString,($TcpConnection | select ExecutablePath,ProcessName,*Address,*Port,state,ConnectionCount ))
        }
        Else{
             $ObservedRunningExes[$uniqueString].ConnectionCount ++
        }
    
    }
    Start-Sleep $TimeToSleepInSeconds
}
while( (Get-date).ticks -le $EndingTimeStamp.ticks)

    $ObservedRunningExes.Values.GetEnumerator() 

}

Get-ApplicationsUsingNetwork -DurationInMinutes 120 -TimeToSleepInSeconds 1