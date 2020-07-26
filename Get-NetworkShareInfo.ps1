<#
.NAME
    Get-NetworkShareInfo


.SYNOPSIS
    This cmdlet is used to discover information associated with a network share such as the physical
    location of the network share, its creation date, and name.


.DESCRIPTION
    This function returns information associated with the defined network share or shares based on
    the shares name. It can also be used to search multiple remote Windows machines for network shares


.PARAMETER ShareName
    This parmater is used to define the name of the share or shares the executer wishes to obtain info on

.PARAMETER ComputerName
    This parameter can be used to define a remote computer(s) name to check for the share names on


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    C:\PS> Get-NetworkShareInfo -ShareName NETLOGON,SYSVOL
    # The above example returns information on the network shares NETLOGON and SYSVOL if they exist on the local machine
    
    C:\PS> Get-NetworkShareInfo -ShareName NETLOGON,SYSVOL,C$ -ComputerName DC01.domain.com, DC02.domain.com, 10.10.10.1
    # The above example returns share info on NETLOGON, SYSVOL, and C$ if they exist on 3 remote devices


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.LINK
    https://roberthosborne.com
    https://github.com/tobor88
    https://gitlab.com/tobor88
    https://www.powershellgallery.com/profiles/tobor


.INPUTS
    System.String[]


.OUTPUTS
    Microsoft.Management.Infrastructure.CimInstance

#>
Function Get-NetworkShareInfo {
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
                )]
            [Alias("Computer","cn")]
            [String[]]$ComputerName
        )

BEGIN
{

    $Obj = @()

    If ($Null -eq $ComputerName)
    {

        $ComputerName = $env:COMPUTERNAME
        
    }   # End If

}  # End BEGIN
PROCESS
{

    ForEach ($C in $ComputerName)
    {

        ForEach ($S in $ShareName)
        {


            $Result = Get-WmiObject -Class Win32_Share -Filter "Name LIKE '$S'" -ComputerName $C -ErrorAction SilentlyContinue -ErrorVariable Clear

            If ($Result)
            {
                Write-Verbose "Getting property values for $S"
                $Name = $Result.Name
                $Description = $Result.Description
                $InstallDate = ((Get-CimInstance -ClassName Win32_Share -Filter "Name LIKE '$S'" -ComputerName $C -ErrorAction SilentlyContinue -ErrorVariable Clear).CimInstanceProperties | Where-Object -Property Name -like InstallDate).Value
                $Path = $Result.Path
                $Status =  $Result.Status

                $Obj += New-Object -TypeName PSObject -Property @{ComputerName=$C; Name=$Name; Description=$Description; InstallDate=$InstallDate; Path=$Path; Status=$Status}

                Clear-Variable -Name Name,Description,InstallDate,Path,Status,Result

            }  # End If
            Else
            {

                Write-Output "[!] $C does not host a share called $S"

            }  # End Else

        }  # End ForEach

    }  # End ForEach

}  # End PROCESS
END
{

        Write-Output $Obj

}  # End END

}  # End Function Get-NetworkShareInfo
