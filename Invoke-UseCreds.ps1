<#
.SYNOPSIS
This cmdlet is for easily using credentials to execute a program. PowerShell can be a lot of typing. Especially when you dont' have a shell that allows autocompletion. This is a huge time saver. This function DOES NOT accept command line arguments. It only executes an application.


.PARAMETER Username
Enter a string containing the domain or workgroup of the user and the username or in some cases just the username.


.PARAMETER Passwd
Enter the string value of the users password

.PARAMETER FilePath
Defines the location of the application that should execute as the user. Enter a string consisting of the absolute or relative path to the executable

.PARAMETER ComputerName
Define a single or multiple FQDN's or hostnames. The local file you specify will be executed on the remote devices you specify

.DESCRIPTION
This function is used to execute an application as another user. This DOES NOT accept command line arugments. This only executes an application.


.EXAMPLE
Invoke-UseCreds -Username 'OsbornePro\tobor' -Passwd 'P@ssw0rd1!' -FilePath 'C:\Windows\System32\spool\drivers\color\msf.exe'
# This command executes a msfvenom payload as the user tobor


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
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
[System.String]


.OUTPUTS
None

#>
Function Invoke-UseCreds {
    [CmdletBinding(DefaultParameterSetName='Local')]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter the username: ")]
            [String]$Username,

            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the password: ")]
            [String]$Passwd,

            [Parameter(
                Mandatory=$True,
                Position=2,
                ValueFromPipeline=$False,
                HelpMessage="Define the path to the executable you want run as this user: ")]
            [String]$FilePath,

            [Parameter(
              ParameterSetName='Remote',
              Mandatory=$False,
              ValueFromPipeline=$False)]  # End Parameter
            [String[]]$ComputerName,

            [Parameter(
              ParameterSetName='Remote',
              Mandatory=$False)]  # End Parameter
            [Switch][Bool]$UseSSL)  # End param

BEGIN
{

    Write-Verbose "[*] Building authenticated credential..."

    $Passw = ConvertTo-SecureString -String $Passwd -AsPlainText -Force
    $Cred = New-Object -TypeName System.Management.Automation.PSCredential($Username, $Passw)

}  # End BEGIN
PROCESS
{

    Switch ($PSCmdlet.ParameterSetName)
    {

      'Local' {

                Write-Verbose "Executing $FilePath"
                If (Test-Path -Path $FilePath)
                {

                    Try
                    {

                        Start-Process -FilePath $FilePath -Credential $Cred

                    }  # End Try
                    Catch [System.Security.Authentication.AuthenticationException]
                    {

                        Throw "The credentials you entered were incorrect"

                    }  # End Catch
                    Catch
                    {

                        $Error[0]

                    }  # End Catch

                }  # End If
                Else
                {

                    Throw "$FilePath could not be found at that location"

                }  # End Else

      }  # End Local Switch

      'Remote' {

                $Bool = $False
                If ($UseSSL.IsPresent)
                {

                    $Bool = $True

                }  # End If

                ForEach ($C in $ComputerName)
                {

                    Invoke-Command -HideComputerName $C -UseSSL:$Bool -FilePath $FilePath

                }  # End ForEach

      }  # End Remote Switch

    }  # End Switch

}  # End PROCESS
END
{

    Write-Output "[*] Program has been executed: $FilePath"

}  # End END

}  # End Function Invoke-UseCreds
