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
