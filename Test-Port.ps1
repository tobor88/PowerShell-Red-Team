Function Test-Port {
<#
.SYNOPSIS
This cmdlet is used to test for general TCP and UDP ports being open. Ports using SSL/TLS seem to require more error handling I have not added yet


.DESCRIPTION
Test to see if a TCP or UDP port is open. This may need some extra work performed when a remote port is using SSL/TLS


.PARAMETER ComputerName
Define the remote device(s) by IP address, hostname, or FQDN you want to test the port on

.PARAMEER Port
Define the port to check connectivity on

.PARAMETER Protocol
Define whether you are testing TCP or UDP. TCP is the default

.PARAMETER TimeoutMilliseconds
Define the timeout in milliseconds to wait for a response


.EXAMPLE
Test-Port -ComputerName dc.osbornepro.com -Port 389
# This example tests to see if port 389/tcp is open on dc.osbornepro.com with a 100 millisecond timeout

.EXAMPLE
Test-Port -ComputerName dc.osbornepro.com -Port 389 -Protocol TCP -TimeoutMilliseconds 100
# This example tests to see if port 389/tcp is open on dc.osbornepro.com with a 100 millisecond timeout

.EXAMPLE
Test-Port -ComputerName dc.osbornepro.com -Port 123 -Protocol UDP -TimeoutMilliseconds 1000
# This example checks to see if UDP port 123 is open on dc.osbornepro.com with a 1000 millisecond timeout


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


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


.INPUTS
System.String[]


.OUTPUTS
PSCustomObject
#>
    param(
        [Parameter(
            Position=0,
            Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$False)]  # End Parameter
        [String[]]$ComputerName,

        [Parameter(
            Position=1,
            Mandatory=$True,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [ValidateRange(1, 65535)]
        [Int]$Port,

        [Parameter(
            Position=2,
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [ValidateSet("TCP", "UDP")]
        [String]$Protocol = "TCP",

        [Parameter(
            Position=3,
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [ValidateRange(10, 99999)]
        [Int]$TimeoutMilliseconds = 100
    )  # End param

BEGIN {

    $Output = @()

} PROCESS {

    ForEach ($C in $ComputerName) {

        Switch ($Protocol) {

            "TCP" {

                Write-Verbose -Message "TCP Protocol will be used"
                $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
                $Connect = $TcpClient.BeginConnect($C, $Port, $Null, $Null)
                Start-Sleep -Milliseconds $TimeoutMilliseconds
    
                If ($TcpClient.Connected) { 

                    $PortOpen = "True"

                } Else { 

                    $PortOpen = "False"

                }  # End If Else

                Write-Verbose -Message "Closing connection to $C on port $Port"
                $TcpClient.Close()
    
                $Output += New-Object -TypeName PSCustomObject -Property @{ComputerName=$C;Port=$Port;Protocol=$Protocol;PortOpen=$PortOpen}

            }  # End Switch TCP

            "UDP" {
                
                $ErrorActionPreference = "SilentlyContinue"
                Write-Verbose -Message "UDP Protocol will be used"
                Write-Verbose -Message "Opening UDP Connection to $C"
                                 
                $SourcePort = Get-Random -Maximum 50000 -Minimum 11000
                $UdpClient = New-Object -TypeName System.Net.Sockets.Udpclient($SourcePort)
                $UdpClient.Client.ReceiveTimeout = $TimeoutMilliseconds
                $Connect = $UdpClient.Connect($C, $Port)

                Write-Verbose -Message "Attempting to catch returned UDP data"
                $AsciiText = New-Object -TypeName System.Text.AsciiEncoding
                $Byte = $AsciiText.GetBytes("$(Get-Date)")
                [Void]$UdpClient.Send($Byte, $Byte.Length)

                $RemoteEndpoint = New-Object -TypeName System.Net.IpEndpoint([System.Net.IPAddress]::Any,0)
                $ReceivedBytes = $UdpClient.Receive([Ref]$RemoteEndpoint)

                Try { 

                    $ReceiveBytes = $UdpClient.Receive([Ref]$RemoteEndpoint) 
                    $ReturnData = $AsciiText.GetString($ReceiveBytes)
                    If ($ReturnData) {
 
                            $UdpClient.Close()
                            $PortOpen = "True"
                            $Output += New-Object -TypeName PSCustomObject -Property @{ComputerName=$C;Port=$Port;Protocol=$Protocol;PortOpen=$PortOpen}

                    }  # End If

                } Catch { 

                    If ($Error[0].ToString() -match "\bRespond after a period of time\b") { 

                        $UdpClient.Close()
                        If (Test-Connection -ComputerName $C -Count 1 -Quiet) { 
                                
                            $PortOpen = "True"
                            $Output += New-Object -TypeName PSCustomObject -Property @{ComputerName=$C;Port=$Port;Protocol=$Protocol;PortOpen=$PortOpen}

                        } Else { 

                            $PortOpen = "Undetermined"
                            $Output += New-Object -TypeName PSCustomObject -Property @{ComputerName=$C;Port=$Port;Protocol=$Protocol;PortOpen=$PortOpen}
                               
                        }  # End If Else
                                              
                    } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) { 

                        $UdpClient.Close()
                        $PortOpen = "False"
                        $Output += New-Object -TypeName PSCustomObject -Property @{ComputerName=$C;Port=$Port;Protocol=$Protocol;PortOpen=$PortOpen}              
                    
                    } Else { 
                                        
                        $UdpClient.Close()

                    }  # End If ElseIf Else

                } Finally {
                
                    $ErrorActionPreference = "Continue"

                }  # End Try Catch     
  
            }  # End Switch UDP

        }  # End Switch

    }  # End ForEach

} END {

    $ErrorActionPreference = "Continue"
    Return $Output

}  # End BPE
        
}  # End Function Test-PortOpen
