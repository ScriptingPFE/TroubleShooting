Function Get-MTUFailurePoint {
[CMDLetBinding()]
param(        
[Parameter(Mandatory = $true,
ValueFromPipelineByPropertyName = $true,
Position = 0)] 
$ComputerName )
$ComputerName = $ComputerName.ToUpper()
#Warm up
Remove-Variable *MTU*,PacketSize,bitBucket  -ErrorAction SilentlyContinue
$bitBucket = $(
    ((ping $ComputerName  -n 1) -split "\n")[2]  -match "Reply from"
    ((ping $ComputerName  -n 1) -split "\n")[2]  -match "Reply from"
    ((ping $ComputerName  -n 1) -split "\n")[2]  -match "Reply from"
    ((ping $ComputerName  -n 1) -split "\n")[2]  -match "Reply from"
)
    if($bitBucket -contains $true){
        
        $packetsize = 500
       
        do{
            $PingRes = ping $ComputerName -l $packetsize -f -n 2 
            if( [string](($PingRes -split "\n")[2..3])  -match "Reply from"){
                $SuccessfullMTU = $packetsize
                
            }
            else{
                $MTUfailurePoint =  $packetsize
            }
            $packetsize =  ($packetsize + 100)

        }while(($packetsize  -lt 1600) -and !$MTUfailurePoint)

        $mtuRequiresAdj = ($packetsize  -lt 1600) -and $MTUfailurePoint
        
        if ($mtuRequiresAdj){

            do{
            
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
                $PingRes = ping $ComputerName -l $FinetunedMTU -f -n 2 
                if( [string](($PingRes -split "\n")[2..3])  -notmatch "Reply from"){
                    $FinetunedMTU = $MTUfailurePoint
                }
                Else{
                    $MTUfailurePoint = $MTUfailurePoint  + 5
                }
                

            }until($FinetunedMTU)
        }

        if(!$mtuRequiresAdj){
            #no fragmentation was required
            [pscustomobject]@{
                Source = $env:COMPUTERNAME
                Target = $ComputerName
                FragmentationRequired = $false
                LastMTUSuccess = $SuccessfullMTU
                MTUFailureSize = "N/A"
                RecommendedMTUSize = "N/A"

            }
        }
        Else {
            #fragmentation was required
            [pscustomobject]@{
                Source = $env:COMPUTERNAME
                Target = $ComputerName
                FragmentationRequired = $true
                LastMTUSuccess = $FinetunedMTU
                MTUFailureSize = $MTUfailurePoint 
                RecommendedMTUSize = ($FinetunedMTU - 20)
            }

        }



    }    
    Else{
        Write-Error -Exception "TCP Connection" -Message "Unable to reach host $ComputerName" -Category ConnectionError -RecommendedAction "Check the Computer Name or IP address of the Target System" 
    }

}