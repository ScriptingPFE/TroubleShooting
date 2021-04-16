Function Download-UserCertificates {
<#
Version: 1.0
Author: Eric Powers
.Synopsis
   Locates all user certificates and downloads them to your desktop
.DESCRIPTION
   Checks Active Directory for userCertificate
   Checks Active Directory for userSmimeCertificate (local on prem mailbox)
   Checks O365 for userCertificate
   Checks O365 for userSmimeCertificate
   If any certificates are located, they are downloaded to the output directory (Default is Desktop\UserAlias Certificate Folder

.EXAMPLE
   Example of how to use this cmdlet
   Download-UserCertificates -UserAlias John.Smith 
   Download-UserCertificates -UserAlias John.Smith -OutputPath C:\Users\John.Smith\UserCerts\Jill.Toms
#>
[CmdletBinding()]
param(        
    [parameter(Position = 0,
    Mandatory,
    HelpMessage = "Enter the user's alias",
    ValueFromPipeline,
    ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]$EmailAlias,

    [parameter(Position = 1,
    HelpMessage = "Enter the Output Folder",
    ValueFromPipeline,
    ValueFromPipelineByPropertyName)]
    $OutputPath = "$env:userprofile\Desktop\$EmailAlias\",

    [parameter(Position = 2,
    HelpMessage = "Enter the Output Folder",
    ValueFromPipeline,
    ValueFromPipelineByPropertyName)]
    [switch]$ConnectToO365
)


DynamicParam {
    $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary

    if($ConnectToO365) {
        
          $attributes = New-Object -Type System.Management.Automation.ParameterAttribute
          #$attributes.ParameterSetName = "PSet1"
          $attributes.Mandatory = $false
          $attributeCollection = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
          $attributeCollection.Add($attributes)
          $dynParam1 = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("O365ConnectionURI", [String],$attributeCollection)
          $dynParam1.Value  ='https://outlook.office365.com/powershell-liveid/'
          paramDictionary.Add("O365ConnectionURI", $dynParam1)
          $attributes.Mandatory = $true
  }

     return $paramDictionary
}


    Process {

        if(!($OutputPath.EndsWith('\'))){
            $OutputPath =  $OutputPath + "\"
        }

        [string]$Alias = ($EmailAlias -split "@")[0].trim()
        
        $adUser = (([adsisearcher]"MailNickName=$Alias").FindOne())
        if($adUser){
            $certcounter = 0
            New-Item $OutputPath -ItemType Directory -Force | Out-Null         
            if($adUser.Properties['userCertificate'].Count -gt 0){   
                Write-host -ForegroundColor DarkCyan "Active Directory Certificate found for user: " -NoNewline;$Alias
                $UserCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $adUser.properties['userCertificate']
                $UserCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $adUser.properties['userCertificate']
                $output = New-Object System.IO.FileStream($($OutputPath + "AdUserCert.crt"),[System.IO.FileMode]::Create)
                $output.Write($UserCert.GetRawCertData(),0,$UserCert.GetRawCertData().length)
                $output.Close()
                $output.Dispose()
                $certcounter++
            }
            if($adUser.Properties['userSMIMECertificate'].Count -gt 0){    
                $UserCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $adUser.properties['userSMIMECertificate']
                Write-host -ForegroundColor DarkCyan "Smime Certificate found in Active Directory found for user: " -NoNewline;$Alias  
                $smimeCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $adUser.properties['userSMIMECertificate']
                $output = New-Object System.IO.FileStream($($OutputPath + "AdSmimeCert.crt"),[System.IO.FileMode]::Create)
                $output.Write($smimeCert.GetRawCertData(),0,$smimeCert.GetRawCertData().length)
                $output.Close()
                $output.Dispose()
                $certcounter++
            }
            if(!(Get-module ExchangeOnlineManagement)){

                if(Get-module ExchangeOnlineManagement -ListAvailable){
                
                    $Proxy = New-PSSessionOption -ProxyAccessType IEConfig
                    Import-Module ExchangeOnlineManagement
                    Connect-ExchangeOnline -ConnectionUri $PSBoundParameters['O365ConnectionURI'] -PSSessionOption $Proxy 
                    $user = Get-mailbox $Alias 
                    if($user.UserSMimeCertificate.Count -gt 0){    
                        Write-host -ForegroundColor DarkCyan "Smime Certificate found in O365 found for user: " -NoNewline:$Alias  
                        $smimeCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $user.UserSMimeCertificate
                        $output = New-Object System.IO.FileStream($($OutputPath + "O365SmimeCert.crt"),[System.IO.FileMode]::Create)
                        $output.Write($smimeCert.GetRawCertData(),0,$smimeCert.GetRawCertData().length)
                        $output.Close()
                        $output.Dispose()
                        $certcounter++
                    }
                }    

                if($certcounter -eq 0){
                    remove-item $OutputPath -Force 
                }
            } 
            Else{
                $user = Get-mailbox $Alias 
                if($user.UserCertificate.Count -gt 0){    
                    Write-host -ForegroundColor DarkCyan "User Certificate found in O365 found for user: " -NoNewline;$Alias  
                    $O365UserCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $user.UserCertificate
                    $output = New-Object System.IO.FileStream($($OutputPath + "O365UserCert.crt"),[System.IO.FileMode]::Create)
                    $output.Write($O365UserCert.GetRawCertData(),0,$O365UserCert.GetRawCertData().length)
                    $output.Close()
                    $output.Dispose()
                    $certcounter++
                }
                if($user.UserSMimeCertificate.Count -gt 0){    
                    Write-host -ForegroundColor DarkCyan "Smime Certificate found in O365 found for user: " -NoNewline;$Alias  
                    $smimeCert =  New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection $user.UserSMimeCertificate
                    $output = New-Object System.IO.FileStream($($OutputPath + "O365SmimeCert.crt"),[System.IO.FileMode]::Create)
                    $output.Write($smimeCert.GetRawCertData(),0,$smimeCert.GetRawCertData().length)
                    $output.Close()
                    $output.Dispose()
                    $certcounter++
                }        
            }
        }
        Else{

            Write-host -ForegroundColor Yellow "Unable to locate user: " -NoNewline;$EmailAlias
            Write-host -ForegroundColor Yellow "Verify the alias and try again" 

        }

        if($certcounter -ne 0){
            
            Write-host -ForegroundColor DarkCyan "Certicates have been exported to: " -NoNewline; $OutputPath
            
        }
    }    
}
