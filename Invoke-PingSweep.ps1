Function Invoke-PingSweep {
<#
.SYNOPSIS
This cmdlet is used to perform a pingsweep for a range of IP addresses


.DESCRIPTION
This cmdlet is used to perform a ping sweep of a range of IP addresses. This can return only successful results and also return DNS lookups on the successfully pinged IP Addresses


.EXAMPLE
 Invoke-PingSweep -Start 192.168.1.1 -End 192.168.20.100
# This command starts a ping sweep from 192.168.1.1 through 192.168.20.100. It sends one ping to each address with a 4000 millisecond timeout

.EXAMPLE
 Invoke-PingSweep -Start 192.168.1.0 -End 192.168.20.100 -TimeoutMiliiSec 4000 -DnsLookup -OnlineOnly
 # This command starts a ping sweep from 192.168.1.1 through 192.168.1.254. It sends one ping to each address with a 4000 millisecond timeout and returns the DNS host name and only successfuly ping results. 

 .EXAMPLE
 Invoke-PingSweep -Start 192.168.0.45 -End 192.168.0.55 -TimeoutMillisec 4000 -DnsLookup -ExcludeAddresses "192.168.0.46","192.168.0.47","192.168.0.48"
 # This command starts a ping sweep from 192.168.0.45 through 192.168.0.55 and excludes sending ICMP requests to 192.168.0.46, 192.168.0.47, and 192.168.0.48

.EXAMPLE 
Invoke-PingSweep -IPAddresses 192.168.0.45,192.168.0.55 -TimeoutMillisec 4000
# This command only sends ICMP requests to the defined IP addresses 192.168.0.45,192.168.0.55 using a 4000 millisecond timeout


.PARAMETER Start
Defines the starting IPv4 address the ping sweep should begin the sweep from.

.PARAMETER End
Defines the ending IPv4 address the ping sweep should end at.

.PARAMETER IPAddresses
Manually define an array of IP addresses to perform a ping sweep against

.PARAMETER TimeoutMiliiSec
Define the ICMP timeout in milliseconds

.PARAMETER DnsLookup
This switch parameter is defined to attempt performing DNS lookups on IP addresses that were successfully pinged

.PARAMETER OnlineOnly
This switch parameter is used to only return devices that were successfully pinged


.INPUTS
None


.OUTPUTS
PSCustomObject


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://encrypit.osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
    [CmdletBinding(DefaultParameterSetName="Dynamic")]
        param(
            [Parameter(
                ParameterSetName="Dynamic",
                Mandatory=$True,
                Position=0,
                HelpMessage="Enter the IP address to start your scan from : ")]  # End Parameter
            [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")]
            [String]$Start,

            [Parameter(
                ParameterSetName="Dynamic",
                Mandatory=$True,
                Position=1,
                HelpMessage="Enter the last IP of the range you want to scan : ")]  # End Parameter
            [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")]
            [String]$End,

            [Parameter(
                ParameterSetName="List",
                Position=0,
                ValueFromPipeline=$False,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="Manually define an array of IP addresses to perform a ping sweep against. ")]  # End Parameter
            [ValidateScript({$_ | ForEach-Object { $_ -Match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" }})]
            [String[]]$IPAddresses,

            [Parameter(
                ParameterSetName="Dynamic",
                Mandatory=$False,
                Position=2,
                HelpMessage="Enter the last IP of the range you want to scan : ")]  # End Parameter
            [ValidateScript({$_ | ForEach-Object { $_ -Match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" }})]
            [String[]]$ExcludeAddresses,

            [Parameter(
                Mandatory=$False,
                Position=3,
                HelpMessage="Enter the number of milliseconds to wait between timeouts : ")]  # End Parameter
            [Int]$TimeoutMilliSec = 4000,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$DnsLookup,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$OnlineOnly
        ) # End param

BEGIN {

    $Return = @()
    $IPRange = @()
    $StringBuilder = @()

} PROCESS {
    
    If ($PSCmdlet.ParameterSetName -eq "Dynamic") {

        $ClassD1 = $Start.Split(".")[-1]
        $ClassD2 = $End.Split(".")[-1]
        $ClassC1 = $Start.Split(".")[2] -Join "."
        $ClassC2 = $End.Split(".")[2] -Join "."
        $ClassB1 = $Start.Split(".")[1] -Join "."
        $ClassB2 = $End.Split(".")[1] -Join "."
        $ClassA1 = $Start.Split(".")[0] -Join "."
        $ClassA2 = $End.Split(".")[0] -Join "."
        

        Write-Verbose "Validating subnet range"
        If ($ClassA1 -ne $ClassA2) {

            Throw "[x] I would suggest using masscan instead | $ClassA1 != $ClassA2"

        } ElseIf ($ClassB1 -gt $ClassB2) {

            Throw "[x] Starting subnet is greater than your ending subnet | $ClassB1 > $ClassB2"

        } ElseIf ($ClassB1 -ge $ClassB2 -and $ClassC1 -gt $ClassC2) {

            Throw "[x] Starting subnet is greater than your ending subnet | $ClassC1 > $ClassC2"
            
        } ElseIf ($ClassC1 -le $ClassC2 -and $ClassD1 -gt $ClassD2) {

            Throw "[x] Starting subnet is greater than your ending subnet | $ClassD1 > $ClassD2"
            
        } Else {

            Write-Verbose -Message "Starting and Ending Subnets are within the required parameters"

        } # End If

        Write-Verbose -Message "Building range of IP addresses to perform ICMP checks against"
        $IpOd = $Start -Split "\."
        $IpDo = $End -Split "\."
    
        [Array]::Reverse($IpOd)
        [Array]::Reverse($IpDo)
    
        $Starting = [BitConverter]::ToUInt32([Byte[]]$IpOd,0)
        $Ending = [BitConverter]::ToUInt32([Byte[]]$IpDo,0)
    
        For ($IP = $Starting; $IP -lt $Ending; $IP++) {
    
            $GetIP = [BitConverter]::GetBytes($IP)
            [Array]::Reverse($GetIP)
    
            $IPRange += $GetIP -Join "."
    
        }  # End For
    
        ForEach ($Ipv4 in $IPRange) {
    
            If ($Ipv4 -notin $ExcludeAddresses) {
    
                $StringBuilder += "Address='$($Ipv4)' or "
    
            }  # End If
    
        }  # End ForEach

        $StringBuilder += "Address='$($End)') and"

    } Else {
    
        $End = $IPAddresses[-1]
        ForEach ($Ipv4 in $IPAddresses) {
    
            $StringBuilder += "Address='$($Ipv4)' or "
    
        }  # End ForEach

        $StringBuilder += "Address='$($End)') and"
    
    }  # End If Else


    If ($StringBuilder.Count -lt 426) {

        $PingResults = Get-CimInstance -ClassName Win32_PingStatus -Filter "($StringBuilder Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $Results = $PingResults

    } ElseIf ($StringBuilder.Count -ge 426 -and $StringBuilder.Count -lt 852) {

        $MidIndex = [Int](($StringBuilder.Length + 1)/2)

        $Split1 = $StringBuilder[0..($MidIndex-1)]
        $Split2 = $StringBuilder[$MidIndex..($StringBuilder.Count-1)]

        $IpFilter1 = "$($Split1[-1].Replace("or","and"))"
        $IpFilter2 = "$($Split2[-1].Replace("or","and"))"

        $PingResults = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split1.Replace("$($Split1[-1])","$IpFilter1")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $PingResults2 = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split2.Replace("$($Split2[-1])","$IpFilter2")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        # 426 seems to be the max amount of devices with Win32_PingStatus

        $Results = $PingResults + $PingResults2

    } ElseIf ($StringBuilder.Count -ge 852 -and $StringBuilder.Count -lt 1278) {

        $ThirdsIndex = [int](($StringBuilder.Count + 1)/3)

        $Split1 = $StringBuilder[0..($ThirdsIndex-1)]
        $Split2 = $StringBuilder[$Split1.Count..($Split1.Count + $ThirdsIndex - 1)]
        $Split3 = $StringBuilder[($Split1.Count + $ThirdsIndex)..($StringBuilder.Count)]

        $IpFilter1 = "$($Split1[-1].Replace("or","and"))"
        $IpFilter2 = "$($Split2[-1].Replace("or","and"))"
        $IpFilter3 = "$($Split3[-1].Replace("or","and"))"

        $PingResults = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split1.Replace("$($Split1[-1])","$IpFilter1")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $PingResults2 = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split2.Replace("$($Split2[-1])","$IpFilter2")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $PingResults3 = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split3.Replace("$($Split3[-1])","$IpFilter3")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        # 426 seems to be the max amount of devices with Win32_PingStatus

        $Results = $PingResults + $PingResults2 + $PingResults3

    } ElseIf ($StringBuilder.Count -ge 1278 -and $StringBuilder.Count -lt 1704) {

        $FourthIndex = [Int](($StringBuilder.Count + 1)/4)

        $Split1 = $StringBuilder[0..($FourthIndex-1)]
        $Split2 = $StringBuilder[$Split1.Count..($Split1.Count + $FourthIndex - 1)]
        $Split3 = $StringBuilder[($Split1.Count + $FourthIndex)..($StringBuilder.Count)]

        $IpFilter1 = "$($Split1[-1].Replace("or","and"))"
        $IpFilter2 = "$($Split2[-1].Replace("or","and"))"
        $IpFilter3 = "$($Split3[-1].Replace("or","and"))"
        $IpFilter4 = "$($Split4[-1].Replace("or","and"))"

        $PingResults = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split1.Replace("$($Split1[-1])","$IpFilter1")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $PingResults2 = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split2.Replace("$($Split2[-1])","$IpFilter2")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $PingResults3 = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split3.Replace("$($Split3[-1])","$IpFilter3")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        $PingResults4 = Get-CimInstance -ClassName Win32_PingStatus -Filter "$($Split4.Replace("$($Split4[-1])","$IpFilter4")) Timeout=$TimeoutMillisec" | Select-Object -Property Address,StatusCode
        # 426 seems to be the max amount of devices with Win32_PingStatus

        $Results = $PingResults + $PingResults2 + $PingResults3 + $PingResults4

    } Else {

        Write-Error -Message "I have not created enough statements yet to handle more than 1278 IP Addresses"

    }  # End If ElseIf ElseIf ElseIf Else

    ForEach ($Device in $Results) {

        Switch ($Device.StatusCode) {
    
            0 { $StatusCode = "Online" }
            11001 { $StatusCode = 'Buffer Too Small' }
            11002 { $StatusCode = 'Destination Net Unreachable' }
            11003 { $StatusCode = 'Destination Host Unreachable' }
            11004 { $StatusCode = 'Destination Protocol Unreachable' }
            11005 { $StatusCode = 'Destination Port Unreachable' }
            11006 { $StatusCode = 'No Resources' }
            11007 { $StatusCode = 'Bad Option' }
            11008 { $StatusCode = 'Hardware Error' }
            11009 { $StatusCode = 'Packet Too Big' }
            11010 { $StatusCode = 'Request Timed Out' }
            11011 { $StatusCode = 'Bad Request' }
            11012 { $StatusCode = 'Bad Route' }
            11013 { $StatusCode = 'TimeToLive Expired Transit' }
            11014 { $StatusCode = 'TimeToLive Expired Reassembly' }
            11015 { $StatusCode = 'Parameter Problem' }
            11016 { $StatusCode = 'Source Quench' }
            11017 { $StatusCode = 'Option Too Big' }
            11018 { $StatusCode = 'Bad Destination' }
            11032 { $StatusCode = 'Negotiating IPSEC' }
            11050 { $StatusCode = 'General Failure' }
            Default { $StatusCode = "Undocumnted Result: $Code" }

        }  # End Switch

        If ($DnsLookup.IsPresent) {

            $Return += New-Object -TypeName PSCustomObject -Property @{
                IPAddress=$Device.Address;
                Hostname=$(If ($Device.StatusCode -eq 0) { Try { [System.Net.DNS]::GetHostByAddress($Device.Address).HostName } Catch {}  } Else { Try { [System.Net.DNS]::GetHostByName($Device.Address).HostName} Catch {} });
                Status=$StatusCode;
            }  # End New-Object -Property

        }  Else {

            $Return += New-Object -TypeName PSCustomObject -Property @{
                IPAddress=$Device.Address;
                Status=$StatusCode;
            }  # End New-Object -Property

        }  # End If Else

    }  # End ForEach

} END {

    If ($OnlineOnly.IsPresent) {

        $Return | Where-Object -Property Status -eq "Online"

    } Else {

        Return $Return
        
    }  # End If Else

}  # End END

} # End Function Invoke-PingSweep
