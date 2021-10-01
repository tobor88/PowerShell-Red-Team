<#
.SYNOPSIS
Use this cmdlet to host files for download. The idea of this is to have a PowerShell SimpleHTTPServer that is similar to Python's SimpleHTTPServer module.


.DESCRIPTION
Running this function will open a PowerShell web server hosting files in the current directory. The server can be accessed at http://localhost:8000 You can download files. The directories are not able to be traversed through the web server.


.PARAMETER Port
The port parameter is for easily defining what port the http server should listen on. The default value is 8000.


.EXAMPLE
Start-SimpleHTTPServer
# This example starts an HTTP server on port 8000 in the current directory.

.EXAMPLE
Start-SimpleHTTPServer -Port 80
# This example starts an HTTP server on port 80 in the current directory.


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
Int32


.OUTPUTS
None
#>
Function Start-SimpleHTTPServer {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port for the HTTP Server to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [int32]$Port = 8000)  # End param

    $Address = "http://localhost:$Port/"

    $WebServer = [System.Reflection.Assembly]::LoadWithPartialName("System.Web")
    $WebServer

    $Listener = New-Object -TypeName System.Net.HttpListener
    $Listener.Prefixes.Add("$Address")
    $Listener.Start()

    New-PSDrive -Name 'SimpleHTTPServer' -Root $Pwd.Path -PSProvider FileSystem -Scope Global

    $Root = $Pwd.Path

    Set-Location -Path 'SimpleHTTPServer:\'

    Do {

        $Context = $Listener.GetContext()
        $RequestUrl = $Context.Request.Url
        $Response = $Context.Response
        $Context.User.Identity.Impersonate()

        Write-Host $RequestUrl
        [array]$Content = @()

        $LocalPath = $RequestUrl.LocalPath

        Try
        {

            $RequestedItem = Get-Item -Path "SimpleHTTPServer:\$LocalPath" -Force -ErrorAction Stop

            $FullPath = $RequestedItem.FullName

            If($RequestedItem.Attributes -Match "Directory")
            {

                Function Get-DirectoryContent {
                    [CmdletBinding(SupportsShouldProcess = $True)]
                        param (
                            [Parameter(
                                Mandatory = $True,
                                HelpMessage = 'Directory Path')]
                            [string]$Path,

                            [Parameter(
                                Mandatory = $False,
                                HelpMessage = 'Header Name')]
                            [string]$HeaderName,

                            [Parameter(
                                Mandatory = $False,
                                HelpMessage = 'Request URL')]
                            [string]$RequestURL,

                            [Parameter(
                                Mandatory = $False,
                                HelpMessage = 'Subfolder Name')]
                            [string]$SubfolderName,

                            [string]$Root
                        )  # End param
@"
                <html>
                <head>
                <title>$($HeaderName)</title>
                </head>
                <body>
                <h1>$($HeaderName) - $($SubfolderName)</h1>
                <hr>
                "@
                @"
                <a href="./../">[To Parent Directory]</a><br><br>
                <table cellpadding="5">
"@
                $Files = (Get-ChildItem -Path "$Path")
                Foreach ($File in $Files)
                {
                    $FileURL = ($File.FullName -Replace [regex]::Escape($Root), "" ) -Replace "\\","/"
                    If (!$File.Length)
                    {
                        $FileLength = "[dir]"
                    }  # End If
                    Else
                    {
                        $FileLength = $File.Length
                    }  # End Else
@"
                <tr>
                <td align="right">$($File.LastWriteTime)</td>
                <td align="right">$($FileLength)</td>
                <td align="left"><a href="$($FileURL)">$($File.Name)</a></td>
                </tr>
"@
                } # End ForEach
@"
                </table>
                <hr>
                </body>
                </html>
"@
                }  # End Function Get-DirectoryContent

                $Content = Get-DirectoryContent -Path $FullPath -HeaderName "PowerShell Simple HTTP Server" -RequestURL "$Address" -SubfolderName $LocalPath -Root $Root

                $Encoding = [System.Text.Encoding]::UTF8
                $Content = $Encoding.GetBytes($Content)
                $Response.ContentType = "text/html"

            }  # End If
            Else
            {

                $Content = [System.IO.File]::ReadAllBytes($FullPath)

                $Response.ContentType = [System.Web.MimeMapping]::GetMimeMapping($FullPath)

            }  # End Else

        } # End Try
        Catch [System.UnauthorizedAccessException]
        {

            Write-Host "Access Denied" -ForegroundColor 'Red'
            Write-Host "Current user:  $env:USERNAME" -ForegroundColor 'Red'
            Write-Host "Requested File: SimpleHTTPServer:\$LocalPath" -ForegroundColor 'Cyan'
            $Response.StatusCode = 404
            $Content = [System.Text.Encoding]::UTF8.GetBytes("<h1>404 - Page Not Found</h1>")

        }  # End Catch
        Catch [System.Management.Automation.ItemNotFoundException]
        {

            Write-Host "Could not reach. Verify server is accessible over the network:  `n`tSimpleHTTPServer:\$LocalPath" -ForegroundColor 'Red' -BackgroundColor 'Yellow'
            $Response.StatusCode = 404
            $Content = [System.Text.Encoding]::UTF8.GetBytes("<h1>404 - Page Not Found</h1>")

        }  # End Catch
        Catch
        {

            $Error[0]
            $Content =  "$($_.InvocationInfo.MyCommand.Name) : $($_.Exception.Message)"
            $Content +=  "$($_.InvocationInfo.PositionMessage)"
            $Content +=  "    + $($_.CategoryInfo.GetMessage())"
            $Content +=  "    + $($_.FullyQualifiedErrorId)"

            $Content = [System.Text.Encoding]::UTF8.GetBytes($Content)
            $Response.StatusCode = 500

        }  # End Catch

        $Response.ContentLength64 = $Content.Length
        $Response.OutputStream.Write($Content, 0, $Content.Length)
        $Response.Close()

        $ResponseStatus = $Response.StatusCode
        Write-Host $ResponseStatus -ForegroundColor 'Cyan'

    } While ($Listener.IsListening)

}  # End Function Start-SimpleHTTPServer
