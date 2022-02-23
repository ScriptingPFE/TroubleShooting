Function Get-MTUFailurePoint {
[CMDLetBinding()]
param(        
[Parameter(Mandatory = $true,
ValueFromPipelineByPropertyName = $true,
Position = 0)] 
$ComputerName,
[Switch]$AutoTuneMTU )
$ComputerName = $ComputerName.ToUpper()
$MTUfailurePoint = $null
$Adjustment = [pscustomobject]@{
    Source = $env:COMPUTERNAME
    Target = $ComputerName
    FragmentationRequired = $false
    LastMTUSuccess = $null
    MTUFailureSize = $null
    RecommendedMTUSize = $null
    AutoTuneMTU =  $AutoTuneMTU

}

#Warm up
Write-Progress -Activity "Calculating Maximum MTU Size for communication with $Computername" -Status "Checking system availability" -PercentComplete 0
$SystemIsAvailable =  Test-Connection -ComputerName $ComputerName -ErrorAction SilentlyContinue

    if($SystemIsAvailable){
        Write-Progress -Activity "Calculating Maximum MTU Size for communication with $Computername" -Status "Confirmed system is available" -PercentComplete 5
        $packetsize = 500
        $PercentComplete = 10 

        do{
            Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Testing MTU size:$packetsize" -PercentComplete  $PercentComplete

            $PingRes = ping $ComputerName -l $packetsize -f -n 2 
            if( [string](($PingRes -split "\n")[2..3])  -match "Reply from"){
                $SuccessfullMTU = $packetsize
            }
            else{
                $MTUfailurePoint =  $packetsize
            }
            $PercentComplete = $PercentComplete + 5
            Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Testing MTU size:$packetsize; Status: $([string](($PingRes -split "\n")[2..3])  -match "Reply from")" -PercentComplete $PercentComplete 
            $packetsize =  ($packetsize + 100)

        }while(($packetsize  -lt 1600) -and !$MTUfailurePoint)

             
        $PercentComplete = $PercentComplete + 5
        Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Failure occurred at Maximum MTU size: $MTUfailurePoint" -PercentComplete  $PercentComplete
        Start-Sleep 1
            
        do{
            $PercentComplete = $PercentComplete + 5
            Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Gauging a better Maximum MTU size: $MTUfailurePoint" -PercentComplete  $PercentComplete
            $PingRes = ping $ComputerName -l $MTUfailurePoint -f -n 2 
            if( [string](($PingRes -split "\n")[2..3])  -match "Reply from"){
                    $FinetunedMTU = $MTUfailurePoint
            }
            Else{
                $MTUfailurePoint = $MTUfailurePoint - 10
            }

        }until($FinetunedMTU)

        $MTUfailurePoint = $FinetunedMTU
        Do{
            $PercentComplete = $PercentComplete + 5
            Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Fine Tuning a better Maximum MTU size: $MTUfailurePoint" -PercentComplete  $PercentComplete
            $PingRes = ping $ComputerName -l $FinetunedMTU -f -n 2 
            if( [string](($PingRes -split "\n")[2..3])  -notmatch "Reply from"){
                $FinetunedMTU = $MTUfailurePoint
            }
            Else{
                $MTUfailurePoint = $MTUfailurePoint  + 5
            }
                
            Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Fine Tuning a better Maximum MTU size: $MTUfailurePoint" -PercentComplete  $PercentComplete
            Start-Sleep -Milliseconds 300
        }until($FinetunedMTU)
            
        $PercentComplete = 100
        Write-Progress -Activity "Calculating Maximum MTU Size for communications with $Computername" -Status "Optimal Maximum MTU size: $FinetunedMTU" -PercentComplete  $PercentComplete

        [array]$AdaptersRequiringConfiguration = (get-NetIPInterface  -ErrorAction SilentlyContinue | where {$_.ifIndex -ne 1 -and $_.NlMtu -gt $FinetunedMTU -and $_.ConnectionState -eq 'Connected'})
        $Adjustment.FragmentationRequired = $AdaptersRequiringConfiguration.Count -ne 0
        $Adjustment.LastMTUSuccess = $FinetunedMTU
        $Adjustment.MTUFailureSize = $MTUfailurePoint 
        $Adjustment.RecommendedMTUSize = ($FinetunedMTU - 20)

        if($AutoTuneMTU -and $AdaptersRequiringConfiguration -ne $Adjustment.FragmentationRequired){
            $Adjustment | Add-Member -Name SuccessfullyConfigured -MemberType NoteProperty -Value $true
            
            Foreach ($Adapter in $AdaptersRequiringConfiguration){

                Try{
                        Set-NetIPInterface -InterfaceIndex $($adapter.ifIndex)  -NlMtuBytes $Adjustment.RecommendedMTUSize
                }
                Catch{
                    $Adjustment.SuccessfullyConfigured = $False
                }

            }
        }


        if($Adjustment.AutoTuneMTU -and $Adjustment.FragmentationRequired){
            if( $Adjustment.SuccessfullyConfigured){
                $Adjustment
                Write-host -ForegroundColor Green "Successfully adjusted the MTU size for " -nonewline; Write-host $env:COMPUTERNAME -nonewline; Write-host -ForegroundColor Green " to " -nonewline; Write-host  $($Adjustment.RecommendedMTUSize )
            }
            Else{
                $Adjustment
                Write-host -ForegroundColor Red "Failed to adjust the MTU size for " -nonewline; Write-host $env:COMPUTERNAME -nonewline; Write-host -ForegroundColor Green " to " -nonewline; Write-host  $($Adjustment.RecommendedMTUSize )
            }
        }
        Elseif(!$AutoTuneMTU  -and $Adjustment.FragmentationRequired){
                $Adjustment
                Write-host -ForegroundColor Yellow "Recommned adjusting the MTU size for " -nonewline; Write-host $env:COMPUTERNAME -nonewline; Write-host -ForegroundColor Yellow " to " -nonewline; Write-host  $($Adjustment.RecommendedMTUSize )
        }
        Else{
                $Adjustment
        }

    }    
    Else{
        Write-Error -Exception "TCP Connection" -Message "Unable to reach host $ComputerName" -Category ConnectionError -RecommendedAction "Check the Computer Name or IP address of the Target System" 
    }

}
