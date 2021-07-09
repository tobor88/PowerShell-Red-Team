<#
.SYNOPSIS
This cmdlet is used to brute force the password of a password protected zip file


.DESCRIPTION
Brute Force Zip Files in PowerShell using 7Zip


.PARAMETER PassFile
Defines the location of a file containing passwords to use to attempting unlocking a zip file

.PARAMETER Path
Defines the location of the password protected zip file

.PARAMETER 7zip
Defines the path and file name of the 7Zip applicaiton. If this value is not defined it will be searched for


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://roberthsoborne.com
https://writeups.osbornepro.com
https://btps-secpack.com
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
Function Test-BruteForceZipPassword {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Defines the path to a file containing possible passwords to attempt `n[E] EXAMPLE: C:\Temp\pass.txt")]  # End Parameter
            [String]$PassFile,

            [Parameter(
                Position=1,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define location of the password protected Zip file `n[E] EXAMPLE: C:\Temp\CrackMe.zip")]  # End Parameter
            [String]$Path,

            [Parameter(
                Position=2,
                Mandatory=$True,
                HelpMessage="`n[H] Download tool from https://www.7-zip.org/download.html `n[E] EXAMPLE: 'C:\Program Files\7-Zip\7z.exe'")]  # End Parameter
            [String]$ZipExe
        )  # End param

    $Passwords = Get-Content -Path $PassFile

    ForEach ($P in $Passwords)
    {

        Write-Verbose "Attempting password $P"

        $Attempt = & "$ZipExe" e "$Path" -p"$P" -y

        If ($Attempt -Contains "Everything is Ok")
        {

            Try
            {

                Write-Host "SUCCESS: $P" -ForegroundColor Green

            }  # End Try
            Catch
            {

                Write-Output "SUCCESS: $P"

            }  # End Catch

            $Result = 'False'

        } # Brute If
        Else
        {

            $Failed = 'True'

        }  # End Else

    } # Foreach Rule

    If (($Failed -eq 'True') -and ($Result -ne 'False'))
    {

        Write-Output "Password Not Found"

    }  # End If

}  # End Function Test-BruteForceZipPassword
