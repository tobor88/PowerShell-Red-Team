Function Convert-SID {
<#
.SYNOPSIS
This cmdlet is for translating an SID to a username or a username to an SID.


.PARAMETER Username
If the username parameter value is specified it this cmdlet will result in the SID value of the user.

.PARAMETER SID
If the SID parameter value is specified this cmdlet will result in the username value associated with the SID.


.EXAMPLE
$Pipe = New-Object PSObject -Property @{SID='S-1-5-21-2860287465-2011404039-792856344-500'} ; $Pipe | Convert-SID
# This example uses the pipeline to convert an SID to a username

.EXAMPLE
Convert-SID -Username 'j.smith'
# This example gets the SID for j.smith

.EXAMPLE
Convert-SID -Username j.smith@domain.com
# This example gets the SID for user j.smith

.EXAMPLE
Convert-SID -SID S-1-5-21-2860287465-2011404039-792856344-500
# This example converts the SID value to a username

.EXAMPLE
Convert-SID -SID 'S-1-5-21-2860287465-2011404039-792856344-500'
# This example converts the SID value to a username


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
System.Array of Usernames or SIDs can be piped to this cmdlet based on property value name.


.OUTPUTS
System.Management.Automation.PSCustomObject
#>
    [CmdletBinding(DefaultParameterSetName = 'Username')]
        param(
            [Parameter(
                ParameterSetName='Username',
                Position=0,
                Mandatory=$True,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True)]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [Alias('User','SamAccountName')]
            [String[]]$Username,

            [Parameter(
                ParameterSetName='SID',
                Position=0,
                Mandatory=$True,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True)]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [ValidatePattern('S-\d-(?:\d+-){1,14}\d+')]
            [String[]]$SID)  # End param


BEGIN {

    $Obj = @()
    Write-Verbose -Message "[*] Obtaining username and SID information for defined value"

} PROCESS {

    For ($i = 0; $i -lt (Get-Variable -Name ($PSCmdlet.ParameterSetName) -ValueOnly).Count; $i++) {

        $Values = Get-Variable -Name ($PSCmdlet.ParameterSetName) -ValueOnly
        New-Variable -Name ArrayItem -Value ($Values[$i])

        Switch ($PSCmdlet.ParameterSetName) {
        
            SID {
            
                $ObjSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($ArrayItem)
                $ObjUser = $ObjSID.Translate([System.Security.Principal.NTAccount])
                
            }  # End Switch SID
            
            Username {
            
                $ObjUser = New-Object -TypeName System.Security.Principal.NTAccount($ArrayItem)
                $ObjSID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier])
                
            }  # End Switch Username
        
        }  # End Switch

        $Obj += New-Object -TypeName "PSObject" -Property @{
            Username = $ObjUser.Value
            SID = $ObjSID.Value
        }   # End Property

        Remove-Variable -Name ArrayItem

    }  # End For

} END {

    Return $Obj

}  # End BPE

}  # End Function Convert-SID
