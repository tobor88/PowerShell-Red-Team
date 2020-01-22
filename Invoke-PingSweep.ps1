<#
.SYNOPSIS
    Perform a pingsweep of a defiend subnet.


.SYNTAX
    Invoke-PingSweep -Subnet <string IP Address> -Start <Int> -End <Int> [-Count] <Int> [-Source { Singular | Multiple }]


.DESCRIPTION
    This cmdlet is used to perform a ping sweep of a defined subnet. Executioner is able to define the start and end IP range to use.DESCRIPTION
    Executioner is also able to define a source to mask where the ping sweep is coming from.


.EXAMPLES
    -------------------------- EXAMPLE 1 --------------------------
   C:\PS> Invoke-PingSweep -Subnet 192.168.1.0 -Start 1 -End 254 -Count 2 -Source Multiple
   This command starts a ping sweep from 192.168.1.1 through 192.168.1.254. It sends two pings to each address. It sends each ping from a random source address.


   -------------------------- EXAMPLE 2 --------------------------
  C:\PS> Invoke-PingSweep -Subnet 192.168.1.0 -Start 192 -End 224 -Source Singular
  This command starts a ping sweep from 192.168.1.192 through 192.168.1.224. It sends one ping to each address. It sends each ping from one source address that is different from the local IP addresses.


  -------------------------- EXAMPLE 3 --------------------------
 C:\PS> Invoke-PingSweep -Subnet 192.168.1.0 -Start 64 -End 192
 This command starts a ping sweep from 192.168.1.64 through 192.168.1.192. It sends one ping to each address. It sends each ping from the local computers IPv4 address.


.PARAMTERS
    -Subnet <string>
        Defines the Class C subnet range to perform the ping sweep

        Enter a string consisting of 1-3 digits followed by a . followed by 1-3 digits followed by a . followed by 1-3 digits followed by a . followed by a zero

        Required?                    True
        Position?                    0
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -Start <Int>
        Defines the start IPv4 address the ping sweep should begin the sweep from.

        Accepts a number between 1 and 254

        Required?                    True
        Position?                    1
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -End <Int>
        Defines the end IPv4 address the ping sweep should end at.

        Accepts a number between 1 and 254

        Required?                    True
        Position?                    2
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -Count <Int>
        Defines how many ICMP ping requests should be sent to each host's IPv4 address

        Accepts a number between 1 and 10

        Required?                    false
        Position?                    none
        Default value                1
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -Source <bool>
        Defines whether you want to mask the IP address you are pinging from.

        Accepts a value of Singular or Multiple

        Required?                    false
        Position?                    none
        Default value                none
        Accept pipeline input?       false
        Accept wildcard characters?  false


.INPUTS
    None. This command does not accept value from pipeline


.OUTPUTS
    System.Array

    The results of this command is an array of active IP Addresses.
    NOTE: Technically this does not output an object yet. This is something I will do in the future


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com

#>
Function Invoke-PingSweep
{
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Enter an IPv4 subnet ending in 0. Example: 10.0.9.0")]
            [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.0")]
            [string]$Subnet,

            [Parameter(
                Mandatory=$True,
                Position=1,
                HelpMessage="Enter the start IP of the range you want to scan.")]
            [ValidateRange(1,255)]
            [int]$Start = 1,

            [Parameter(
                Mandatory=$True,
                Position=2,
                HelpMessage="Enter the end IP of the range you want to scan.")]
            [ValidateRange(1,255)]
            [int]$End = 254,

            [Parameter(
                Mandatory=$False,
                Position=3)]
            [ValidateRange(1,10)]
            [int]$Count = 1,

            [Parameter(
                Mandatory=$False,
                Position=4)]
            [ValidateSet("Singular","Multiple")]
            [string]$Source
        ) # End param

        [array]$LocalIPAddress = Get-NetIPAddress -AddressFamily "IPv4" | Where-Object { ($_.InterfaceAlias -notmatch "Bluetooth|Loopback") -and ($_.IPAddress -notlike "169.254.*") }  | Select-Object -Property "IPAddress"
        [string]$ClassC = $Subnet.Split(".")[0..2] -Join "."
        [array]$Results = @()
        [int]$Timeout = 500

        Write-Host "The below IP Addressess are currently active." -ForegroundColor "Green"

        For ($i = 0; $i -le $End; $i++)
        {

            [string]$IP = "$ClassC.$i"

            # When Windows PowerShell is executing the command and source value is not defined
            If (($PsVersionTable.PSEdition -ne 'Core') -and (!$Source.IsPresent) -and ($IP -notlike $LocalIPAddress))
            {

                $Filter = 'Address="{0}" and Timeout={1}' -f $IP, $Timeout

                If ((Get-WmiObject "Win32_PingStatus" -Filter $Filter).StatusCode -eq 0)
                {

                    Write-Host $IP -ForegroundColor "Yellow"

                } # End If

            } # End If
            # When Core or Windows PowerShell is running or source is defined
            ElseIf (($PsVersionTable.PSEdition -eq 'Core') -or ($Source -ne $Null) -and ($IP -notlike $LocalIPAddress))
            {

                If ($Source -like 'Singular')
                {

                    $SourceIP = "$ClassC." + ($End - 1)

                    Try
                    {

                        Test-Connection -BufferSize 16 -ComputerName $IP -Count $Count -Source $SourceIP -Quiet

                    }  # End Try
                    Catch
                    {

                        Write-Host "Source routing may not be allowed on your device. Use ipconfig /all and check that Ip Routing Enabled is set to a value of YES. Otherwise this option will not work." -ForegroundColor 'Red'

                    }  # End Catch
                } # End If
                ElseIf ($Source -like 'Multiple')
                {

                    For ($x = ($Start - 1); $x -le ($End - $Start); $x++)
                    {

                        $SourceIP = "$ClassC.$x"

                        Try
                        {

                            Test-Connection -BufferSize 16 -ComputerName $IP -Count $Count -Source $SourceIP -Quiet

                        }  # End Try
                        Catch
                        {

                            Write-Host "Source routing may not be allowed on your device. Use ipconfig /all and check that Ip Routing Enabled is set to a value of YES. Otherwise this option will not work." -ForegroundColor 'Red'

                        }  # End Catch

                    } # End For

                } # End ElseIf

            }  # End ElseIf
            # When Core is running and source is not defined
            ElseIf (($PsVersionTable.PSEdition -eq 'Core') -and ($Source -eq $Null) -and ($IP -notlike $LocalIPAddress))
            {

                If (Test-Connection -BufferSize 16 -ComputerName $IP -Count $Count -Quiet)
                {

                    Write-Host $IP -ForegroundColor 'Yellow'

                }  # End If

            }  # End ElseIf

        } # End For

} # End Function Invoke-PingSweep
