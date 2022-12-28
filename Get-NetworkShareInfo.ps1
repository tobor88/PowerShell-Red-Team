Function Get-NetworkShareInfo {
<#
.SYNOPSIS
This cmdlet is used to discover information associated with a network share such as the physical location of the network share, its creation date, and name.


.DESCRIPTION
This function returns information associated with the defined network share or shares based on the shares name. It can also be used to search multiple remote Windows machines for network shares


.PARAMETER ShareName
This parmater is used to define the name of the share or shares the executer wishes to obtain info on

.PARAMETER ComputerName
This parameter can be used to define a remote computer(s) name to check for the share names on


.EXAMPLE
Get-NetworkShareInfo -ShareName NETLOGON,SYSVOL
# The above example returns information on the network shares NETLOGON and SYSVOL if they exist on the local machine

.EXAMPLE
Get-NetworkShareInfo -ShareName NETLOGON,SYSVOL,C$ -ComputerName DC01.domain.com, DC02.domain.com, 10.10.10.1
# The above example returns share info on NETLOGON, SYSVOL, and C$ if they exist on 3 remote devices


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
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
System.String[]


.OUTPUTS
Microsoft.Management.Infrastructure.CimInstance

#>
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="Define the names of the share or shares you wish to discover the location of"
                )]  # End Parameter
            [Alias("Share","Name")]
            [String[]]$ShareName,

            [Parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Define the FQDN, hostname, or IP address of the device you wish to check for network share names on"
                )]  # End Parameter
            [Alias("Computer","cn")]
            [String[]]$ComputerName = $env:COMPUTERNAME
        )

BEGIN {

    $Obj = @()
    
    Function Test-SMBPort {
        [CmdletBinding()]
            param(
                [Parameter(
                    Mandatory=$True,
                    Position=0,
                    ValueFromPipeline=$False,
                    ValueFromPipelineByPropertyName=$False)]  # End Parameter
                [String[]]$ComputerName
            )  # End param

        $Output = @()
        ForEach ($C in $ComputerName) {

            $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
            $Connect = $TcpClient.BeginConnect($ComputerName, 445, $Null, $Null)
            Start-Sleep -Milliseconds 100

            If ($TcpClient.Connected) { 

                $Open = $True 

            } Else { 

                $Open = $False 

            }  # End If Else

            $TcpClient.Close()
            $Output += New-Object -TypeName PSCustomObject -Property @{ComputerName=$ComputerName;SMBOpen=$Open}

        }  # End ForEach

    }  # End Function Test-SMBPort

} PROCESS {

    ForEach ($C in $ComputerName) {

        If ((Test-SMBPort -ComputerName $C).SMBOpen -eq $True) {
        
            Write-Verbose -Message "SMB is open on $C"
            ForEach ($S in $ShareName) {

                $Result = Get-CimInstance -Class Win32_Share -Filter "Name LIKE '$S'" -ComputerName $C -ErrorAction SilentlyContinue -ErrorVariable Clear
                If ($Result) {

                    Write-Verbose -Message "Getting property values for $S"
                    $Name = $Result.Name
                    $Description = $Result.Description
                    $InstallDate = ((Get-CimInstance -ClassName Win32_Share -Filter "Name LIKE '$S'" -ComputerName $C -ErrorAction SilentlyContinue -ErrorVariable Clear).CimInstanceProperties | Where-Object -Property Name -like InstallDate).Value
                    $Path = $Result.Path
                    $Status =  $Result.Status

                    $Obj += New-Object -TypeName PSObject -Property @{ComputerName=$C; Name=$Name; Description=$Description; InstallDate=$InstallDate; Path=$Path; Status=$Status}

                    Clear-Variable -Name Name,Description,InstallDate,Path,Status,Result

                } ElseIf ($Clear) {
                
                    $Obj += New-Object -TypeName PSObject -Property @{ComputerName=$C; Name="Failed to connect"; Description="Verify service at destination is running and accepting requests"; InstallDate="NA"; Path="NA"; Status="NA"}

                } Else {

                    $Obj += New-Object -TypeName PSObject -Property @{ComputerName=$C; Name="Does not exist"; Description="Share with that name does not exist"; InstallDate="NA"; Path="NA"; Status="NA"}

                }  # End If Else

            }  # End ForEach
            
        } Else {
        
            Write-Verbose -Message "SMB is closed on $C"
            $Obj += New-Object -TypeName PSObject -Property @{ComputerName=$C; Name="SMB not open"; Description="SMB not reachable"; InstallDate="NA"; Path="NA"; Status="NA"}
        
        }  # End If Else

    }  # End ForEach

} END {

    Return $Obj

}  # End BPE

}  # End Function Get-NetworkShareInfo
