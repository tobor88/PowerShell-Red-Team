<#
.NAME
    Convert-SID


.SYNOPSIS
    This cmdlet is for translating an SID to a username or a username to an SID.


.SYNTAX
    Convert-SID [-Username] <string[]> [<CommonParameters>]

    Convert-SID [-SID] <string[]> [<CommonParameters>]


.PARAMETER Username
    If the username parameter value is specified it this cmdlet will result in the SID value of the user.

.PARAMETER SID
    If the SID parameter value is specified this cmdlet will result in the username value associated with the SID.


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    C:\PS> $Pipe = New-Object PSObject -Property @{SID='S-1-5-21-2860287465-2011404039-792856344-500'}
    C:\PS> $Pipe | Convert-SID

    -------------------------- EXAMPLE 2 --------------------------
    C:\PS> Convert-SID -Username 'j.smith'
    C:\PS> Convert-SID -Username j.smith@domain.com

    -------------------------- EXAMPLE 3 --------------------------
    C:\PS> Convert-SID -SID S-1-5-21-2860287465-2011404039-792856344-500
    C:\PS> Convert-SID -SID 'S-1-5-21-2860287465-2011404039-792856344-500'


.NOTES
    Author: Robert H. Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.LINK
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com


.INPUTS
    System.Array of Usernames or SIDs can be piped to this cmdlet based on property value name.


.OUTPUTS
    System.Management.Automation.PSCustomObject

#>
Function Convert-SID {
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


BEGIN
{

    [array]$Obj = @()

    Write-Verbose "[*] Obtaining username and SID information for defined value"

}  # End BEGIN
PROCESS
{

    For ($i = 0; $i -lt (Get-Variable -Name ($PSCmdlet.ParameterSetName) -ValueOnly).Count; $i++)
    {

        $Values = Get-Variable -Name ($PSCmdlet.ParameterSetName) -ValueOnly

        New-Variable -Name ArrayItem -Value ($Values[$i])

        Switch ($PSCmdlet.ParameterSetName)
        {
            SID {$ObjSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier($ArrayItem); $ObjUser = $ObjSID.Translate([System.Security.Principal.NTAccount])}
            Username {$ObjUser = New-Object -TypeName System.Security.Principal.NTAccount($ArrayItem); $ObjSID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier])}
        }  # End Switch

        $Obj += New-Object -TypeName "PSObject" -Property @{
            Username = $ObjUser.Value
            SID = $ObjSID.Value
        }   # End Property

        Remove-Variable -Name ArrayItem

    }  # End For

}  # End PROCESS
END
{

    Write-Output $Obj

}  # End END

}  # End Function Convert-SID
