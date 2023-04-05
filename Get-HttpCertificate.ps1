Function Get-HttpCertificate {
<#
.SYNOPSIS
This cmdlet is used to return information of a certificate that is attached to a port


.DESCRIPTION
Get the certificate object information from an SSL certificate that is attached to a reachable port


.PARAMETER ComputerName
Define the IP address, FQDN, or resolvable hostname of the server to retrieve the certificate information from


.PARAMETER Port
Define the TCP port you wish to grab the certificate information from


.EXAMPLE
Get-HttpCertificate -ComputerName osbornepro.com -Port 443
# This example attempts to retrieve the certificate information from osbornepro.com on port 443

.EXAMPLE
Get-HttpCertificate -ComputerName 10.0.0.1 -Port 8080
Get-HttpCertificate -IPAddress 10.0.0.1 -Port 8080
Get-HttpCertificate -IP 10.0.0.1 -Port 8080
# These examples attempt to retrieve the certificate information from 10.0.0.1 on port 8080

.EXAMPLE
Get-HttpCertificate
# This example attempts to retrieve the certificate information from the localhost on port 443


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
System.Security.Cryptography.X509Certificates.X509Certificate
#>
[OutputType([System.Security.Cryptography.X509Certificates.X509Certificate])]
[CmdletBinding()]
    param (
        [Parameter(
            Position=0,
            Mandatory=$False,
            ValueFromPipeline=$False
        )]  # End Parameter
        [Alias('IPAddress','IP')]
        [String]$ComputerName = 'localhost',

        [Parameter(
            Position=1,
            Mandatory=$False,
            ValueFromPipeline=$False
        )]  # End Parameter
        [Int]$Port = 443,

        [Parameter(
            Position=2,
            Mandatory=$False,
            ValueFromPipeline=$False
        )]  # End Parameter
        [Int]$Timeout = 300
    )  # End param

    Try {

        $ErrorActionPreference = "Stop"
        $TcpSocket = New-Object -TypeName System.Net.Sockets.TcpClient
        $TcpSocket.BeginConnect($ComputerName, $Port, $Null, $Null) | Out-Null
        Start-Sleep -Milliseconds $Timeout

        If ($TcpSocket.Connected) {

            Write-Verbose -Message "[v] TCP Client connected successfully"
            $TcpStream = $TcpSocket.GetStream()
            $Callback = { param($Caller, $Cert, $Chain, $Errors) Return $True }
            $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($TcpStream, $True, $Callback)
            Try {

                $SSLStream.AuthenticateAsClient($ComputerName)
                $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
    
            } Catch {
    
                Throw "[x] No Certificate connection created with remote computer $ComputerName on port $Port. Port may not be open"

            } Finally {

                $ErrorActionPreference = "Continue"
                $SSLStream.Dispose()
            
            }  # End Try Catch Finally
    
        } Else {

            Write-Verbose -Message "[v] TCP Client failed to establish"
            Throw "[x] Unable to connect to $ComputerName on TCP port $Port. Port is likely not open"
            $TcpClient.Close()

        }  # End If Else

    } Catch {

        Throw "[x] No TCP Stream could be created with $ComputerName on port $Port"

    } Finally {
        
        $ErrorActionPreference = "Continue"
        $SSLStream.Dispose()

    }  # End Try Finally

    Return $Certificate

}  # End Function Get-HttpCertificate
