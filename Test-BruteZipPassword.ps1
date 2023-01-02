Function Test-BruteForceZipPassword {
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

    $Output = @()
    $Passwords = Get-Content -Path $PassFile
    ForEach ($P in $Passwords) {

        Write-Verbose -Message "Attempting password $P"
        $Attempt = & "$ZipExe" e "$Path" -p"$P" -y

        If ($Attempt -Contains "Everything is Ok") {

            $Output = New-Object -TypeName PSCustomObject -Property @{
                Password=$P;
                File=$Path;
            }  # End New-Object -Property
            
            Continue

        } Else {

            $Failed = 'True'

        }  # End If Else

    }  # End ForEach

    If (!($Output)) {

        $Output = New-Object -TypeName PSCustomObject -Property @{
            Password="Not found";
            File=$Path;
        }  # End New-Object -Property

    }  # End If
    
    Return $Output

}  # End Function Test-BruteForceZipPassword
