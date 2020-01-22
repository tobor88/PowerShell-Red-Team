<#
.SYNOPSIS
    Invoke-PortScan is a port scanner that is used for scanning ports 1 through 65535 on a single host.DESCRIPTION


.DESCRIPTION
    Scan all possible ports on a target host you define.DESCRIPTION


.PARAMETER
    -IpAddress <string>

        This parameter defines the target you wish to perform the port scan on.

        Required?                    true
        Position?                    0
        Default value                none
        Accept pipeline input?       false
        Accept wildcard characters?  false


.SYNTAX
    Invoke-PortScan -IpAddress <string>


.EXAMPLE
    Invoke-PortScan -IpAddress 192.168.0.1
        This example performs a port scan on 192.168.0.1 fomr ports 1-65535


.INPUTS
    System.String


.OUTPUTS
    None. This only displays the results as text and does not return an object.

.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com
#>
Function Invoke-PortScan
{
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter an ipv4 address of the target machine you wish to perform a port scan on")]
            [IpAddress]$IpAddress
            )  # End param

    $ErrorActionPreference= 'SilentlyContinue'
    [array]$Range = 1..65535

    ForEach ($Port in $Range)
    {

        If (Test-Connection -BufferSize 16 -Count 1 -Quiet -ComputerName $IpAddress)
        {

             $Socket = New-Object System.Net.Sockets.TcpClient($IpAddress, $Port)

             If ($Socket.Connected)
             {

                “[*] $Port is open”

                $Socket.Close()

             }  # End If

         }  # End If
         Else
         {

            Write-Host "Host is not pingable" -ForegroundColor 'Yellow'

         }  # End Else

    }  # End ForEach

}  # End Function Invoke-PortScan
