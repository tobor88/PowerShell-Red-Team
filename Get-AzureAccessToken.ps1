Function Get-AzureAccessToken {
<#
.SYNOPSIS
This cmdlet is used to retrieve an access token from Azure using a client secret or client certificate


.DESCRIPTION
Use a client secret or certificate to obtain an Azure access token


.PARAMETER ClientID
Define the Azure Client ID GUID value of your application that has a secret it can use to authenticate

.PARAMETER ClientSecret
Enter your Client Secret value which can only be obtained after first generating the secret

.PARAMETER ApplicationID
Define the Application ID that has the certificate associated with it for authentication (Client ID)

.PARAMETER CertificateThumbprint
Enter the certificate thumbprint value to use for authentication

.PARAMETER TenantId
Define your Azure tenant ID GUID value

.PARAMETER Resource
Define the resource to retrieve

.PARAMETER Scope
Define the scope to retrieve


.EXAMPLE
PS> Get-AzureAccessToken -ClientId '319d7802-578a-4705-bda7-b902ee2ecd65' -ClientSecret 'tYZ8Q~zs0h_OhYIekLmjVOK.vLshIJET8TPQccK-' -TenantId 'a3af5c78-3ebb-41d7-a295-81b464b6d923 -Scope 'https://vault.azure.net/.default'
# This example obtains an Azure Access Token using a client ID and Secret

.EXAMPLE
PS> Get-AzureAccessToken -ApplicationID '319d7802-578a-4705-bda7-b902ee2ecd65' -CertificateThumbprint 'a909502dd82ae41433e6f83886b00d4277a32a7b -TenantId 'a3af5c78-3ebb-41d7-a295-81b464b6d923' -Scope 'https://vault.azure.net/.default
# This example obtains an Azure Access Token using an Application ID and Certificate


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials
https://powershell.org/2020/11/writing-your-own-powershell-functions-cmdlets/
https://osbornepro.com
https://writeups.osbornepro.com
https://btpssecpack.osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
None


.OUTPUTS
None
#>
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Resource'
            )]  # End Parameter
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Scope'
            )]  # End Parameter
            [String]$ClientId,
        
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Resource'
            )]  # End Parameter
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Scope'
            )]  # End Parameter
            [String]$ClientSecret,
        
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Certificate'
            )]  # End Parameter
            [String]$ApplicationID,
        
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Certificate'
            )]  # End Parameter
            [String]$CertificateThumbprint,
        
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Certificate'
            )]  # End Parameter
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Resource'
            )]  # End Parameter
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Scope'
            )]  # End Parameter
            [String]$TenantId,
        
            [Parameter(
                Mandatory=$True,
                ParameterSetName='Resource'
            )]  # End Parameter
            [String]$Resource,
        
            [Parameter(
                Mandatory=$False,
                ParameterSetName='Certificate'
            )]  # End Parameter
            [Parameter(
                Mandatory=$False,
                ParameterSetName='Scope'
            )]  # End Parameter
            [ValidateSet('https://vault.azure.net/.default', 'https://management.azure.com/.default', 'https://graph.microsoft.com/.default')]
            [String]$Scope = 'https://vault.azure.net/.default'
        )  # End param

BEGIN {
        
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $ContentType = "application/x-www-form-urlencoded"
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox

} PROCESS {

    If ($CertificateThumbprint) {

        $Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My\$CertificateThumbprint"
        $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())

        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Creating JWT header"
        $JWTHeader = @{
            alg = "RS256"
            typ = "JWT"
            x5t = $CertificateBase64Hash -Replace '\+','-' -Replace '/','_' -Replace '='
        }  # End JWTHeader

        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Creating JWT payload"
        $JWTPayLoad = @{
            aud = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
            exp = ([System.DateTimeOffset](Get-date).AddMinutes(5)).ToUnixTimeSeconds()
            iss = $ApplicationID
            jti = [System.Guid]::NewGuid()
            nbf = ([System.DateTimeOffset](Get-Date).ToUniversalTime()).ToUnixTimeSeconds()
            sub = $ApplicationID  
        }  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Converting header and payload to base64"
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))  
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)  
  
        $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))  
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Joining header and Payload with '.' to create a valid (unsigned) JWT"
        $JWT = $EncodedHeader + "." + $EncodedPayload  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Obtain the private key object of your certificate"  
        $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Define RSA signature and hashing algorithm"
        $RSAPadding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1  
        $HashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256  
  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Creating a signature of the JWT"
        $Signature = [System.Convert]::ToBase64String(  
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)  
        ) -Replace '\+','-' -Replace '/','_' -Replace '='  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Joining the signature to the JWT with '.'"
        $JWT = $JWT + "." + $Signature  
  
        Write-Debug -Message "[D] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Creating a hash with body parameters" 
        $Body = @{  
            client_id = $ApplicationID  
            client_assertion = $JWT  
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"  
            scope = $Scope  
            grant_type = "client_credentials"  
        }  # End Body

    } Else {

        $Body = @{ 
            "grant_type"    = "client_credentials" 
            "client_id"     = $ClientId
            "client_secret" = $ClientSecret
        }  # End Body

    }  # End If Else

    Switch ($PSCmdlet.ParameterSetName) {

        "Resource" {

            $Body["Resource"] = $Resource

        } "Scope" {

            $Body["scope"] = $Scope

        }  # End Switch Options

    }  # End Switch

    $Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"    
    $Header = @{  
        Authorization = "Bearer $JWT"  
    }  # End Header
    $Token = Invoke-RestMethod -UseBasicParsing -Method POST -UserAgent $UserAgent -ContentType $ContentType -Uri $Uri -Headers $Header -Body $Body -Verbose:$False | Select-Object -ExpandProperty access_token

} END {

    $Script:GraphHeader = @{  
        Authorization = "Bearer $Token"  
    }  # End Header
    $Script:GraphAccessToken = $Token
    Return $Token

}  # End B P E

}  # End Function Get-AzureAccessToken
