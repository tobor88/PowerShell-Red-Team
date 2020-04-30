<#
.NAME
    Invoke-UseCreds
    
    
.SYNOPSIS
    This cmdlet is for easily using credentials to execute a program. PowerShell can be a lot of typing.
    Especially when you dont' have a shell that allows autocompletion. This is a huge time saver.
    

.SYNTAX
    Invoke-UseCreds [-Username] <string> [-Passwd] <string> [-Path] <string> [<CommonParameters>]
    

.PARAMETERS
    -Username
        Enter a string containing the domain or workgroup of the user and the username or in some cases just the username.    
        Required?                    True
        Position?                    0
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false
               
    -Passwd
        Enter the string value of the users password    
        Required?                    True
        Position?                    1
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false
               
    -Path
        Defines the location of the application that should execute as the user.
        Enter a string consisting of the absolute or relative path to the executable
        Required?                    True
        Position?                    2
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false
             
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).
      

.DESCRIPTION
    This function is used to execute an application as another user. 
    

.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
   C:\PS> Invoke-UseCreds -Username 'OsbornePro\tobor' -Passwd 'P@ssw0rd1!' -Path 'C:\Windows\System32\spool\drivers\color\msf.exe'
   This command executes a msfvenom payload as the user tobor


.NOTES
    Author: Robert H. Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com
    
    
.INPUTS
    [System.String]
    
    
.OUTPUTS
    None

#>
Function Invoke-UseCreds {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter the username: ")]
            [string]$Username,
            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter the password: ")]
            [string]$Passwd,
            [Parameter(
                Mandatory=$True,
                Position=2,
                ValueFromPipeline=$False,
                HelpMessage="Define the path to the executable you want run as this user: ")]
            [string]$Path)  # End param

BEGIN 
{

    Write-Verbose "[*] Building authenticated credential..."

    $Passw = ConvertTo-SecureString $Passwd -AsPlainText -Force

    $Cred = New-Object -TypeName System.Management.Automation.PSCredential($Username, $Passw)

}  # End BEGIN
PROCESS 
{

    Write-Verbose "Executing $Path"

    If (!(Test-Path -Path $Path))
    { 
    
        Try 
        {
        
            Start-Process $Path -Credential $Cred 

        }  # End Try
        Catch [System.Security.Authentication.AuthenticationException]
        {

            Write-Host "The credentials you entered were incorrect"

        }  # End Catch
        Catch 
        {

            $Error[0] 

        }  # End Catch

    }  # End If 
    Else 
    {
     
        throw "$Path could not be found at that location"

    }  # End Else

}  # End PROCESS 
END 
{

    Write-Host "Program has been executed"

}  # End END

}  # End Function Invoke-UseCreds
