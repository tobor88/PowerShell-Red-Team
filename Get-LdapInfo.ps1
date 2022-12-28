Function Get-LdapInfo {
<#
.SYNOPSIS
Perform LDAP Queries of the current domain. This requires a user account in order to execute the cmdlet. Due to the amount of switches I have not provieded examples for each one. The names are pretty self explanatory.


.PARAMETER Domain
Define the domain that you want to connect to using your credentials

.PARAMETER Credential
Enter your credentials for the domain you are connecting too.

.PARAMETER LDAPS
This switch parameter will perform searches using LDAP over SSL

.PARAMETER Detailed
This switch parameter will display all properties of the rerturned objects

.PARAMETER DomainControllers
This switch is used to tell the cmdlet to get a list of the Domain's Controllers

.PARAMETER AllServers
This switch is used to obtain a list of all servers in the domain environment

.PARAMETER AllMemberServers
This switch is used to obtain a list of all member servers in the environment

.PARAMETER DomainTrusts
This switch is used to obtain a list of all trusted and federated domains for the domain

.PARAMETER DomainAdmins
The switch parameter is used to tell the cmdlet to obtain a list of members of the Domain Admins Group

.PARAMETER UACTrusted
This switch parameter is used to tell the cmdlet to get a list of UAC Permissions that can be delegated

.PARAMETER NotUACTrusted
This switch parameter is used to tell the cmdlet to get a list of UAC Permissions that can NOT be delegated

.PARAMETER SPNNamedObjects
This switch is used to obtain a list of Service Principal Named objects

.PARAMETER EnabledUsers
This switch parameter is used to tell the cmdlet to get a list of enabled user accounts in the domain

.PARAMETER PossibleExecutives
This switch is used to obtain a list of possible executives for the company

.PARAMETER LogonScript
This switch is used to tell the cmdlet to get a list of users who have logon scriprts assigned

.PARAMETER ListAllOu
This siwtch is meant to return a list of all OUs in the domain

.PARAMETER ListComputer
This switch is meant to return a list of all computers in the domain

.PARAMETER ListContacts
This switch is meant to return a list of contacts in the domain

.PARAMETER ListUsers
This switch is meant to return a list of all users in the domain

.PARAMETER ListGroups
This switch is meant to return a list of all groups in the domain

.PARAMETER -ListContainers
This switch is used to return a list of all containers in the domain

.PARAMETER ListDomainObjects
This switch is used to return a list of all objects in the domain

.PARAMETER ListBuiltInContainers
This switch is used to return a list of built in OU containers in the domain

.PARAMETER ChangePasswordAtNextLogon
This switch is used to return a list of users who are set to change their password at next logon

.PARAMETER PasswordNeverExpires
This switch is used to obtain a list of users who have passwords that never expire

.PARAMETER NoPasswordRequired
This switch parameter is used to get a list of users who do not require a password to sign in

.PARAMETER NoKerberosPreAuthRequired
This switch parameter is used to get a list of users who do not require preauthentication when being authenticated with Kerberos

.PARAMETER PasswordsThatHaveNotChangedInYears
This switch is used to obtain a list of user passwords that have not changed in years


.EXAMPLE
Get-LdapInfo -DomainControllers | Select-Object -Property 'Name','ms-Mcs-AdmPwd'
# This example gets a list of all the Domain Controllers and displays the local admin password. (Requires Administrator Execution to get password attribute ) If executed as an administrator you will also receive the local admin password under the ms-Mcs-AdmPwd attribute value.

.EXAMPLE
Get-LdapInfo -AllServers
# This example lists All Servers in the Domain

.EXAMPLE
Get-LdapInfo -AllMemberServers
# This example lists all Member Servers in the domain

.EXAMPLE
Get-LdapInfo -DomainTrusts
# This example lists Federated Trust Domains

.EXAMPLE
Get-LdapInfo -DomainAdmins
# This example lists all Domain Admins in the domain

.EXAMPLE
Get-LdapInfo -UACTrusted
# This example lists users who are trusted with UAC

.EXAMPLE
Get-LdapInfo -NotUACTrusted
# This example lists users who are not trusted for UAC

.EXAMPLE
Get-LdapInfo -SPNNamedObjects
# This example lists SPN users

.EXAMPLE
Get-LdapInfo -EnabledUsers
# This example lists all Enabled Users

.EXAMPLE
Get-LdapInfo -PossibleExecutives
# This example finds users with Direct Reports and no manager possibly indicating an executive

.EXAMPLE
Get-LdapInfo -LogonScript
# This example lists all users who have logon scripts that execute

.EXAMPLE
Get-LdapInfo -ListAllOU
# This example lists all of the Domains OUs in Acitve Directory

.EXAMPLE
Get-LdapInfo -ListComputers
# This example lists all Active Directory Computers

.EXAMPLE
Get-LdapInfo -ListContacts
# This example lists all Active Directory Contacts

.EXAMPLE
Get-LdapInfo -ListGroups
# This example lists all Active Directory Groups

.EXAMPLE
Get-LdapInfo -ListGroups
# This example lists all Active Directory Groups

.EXAMPLE
Get-LdapInfo -ListContainers
# This example lists Active Directory Containers

.EXAMPLE
Get-LdapInfo -ListDomainObjects
# This example lists Active Directory Domain Objects

.EXAMPLE
Get-LdapInfo -ListBuiltInObjects
# This example list Builtin In Active Directory Objects

.EXAMPLE
Get-LdapInfo -ListBuiltInContainers
# This example lists Built In Active Directory Containers

.EXAMPLE
Get-LdapInfo -ChangePasswordAtNextLogon
# This example lists users who are set to change their password at next logon.DESCRIPTION If a user does not have a "Logon Name" Configured in AD they will be returned with this results as well.

.EXAMPLE
Get-LdapInfo -PasswordNeverExpires
# This example list users who have passwords that never expire

.EXAMPLE
Get-LdapInfo -NoPasswordRequired
# This example lists users who do not require a password for sign in

.EXAMPLE
Get-LdapInfo -NoKerberosPreAuthRequired
# This example lists users where Kerberos Pre Authentication is not enabled

.EXAMPLE
Get-LdapInfo -PasswordsThatHaveNotChangedInYears | Where-Object -Property Path -notlike "*OU=Disabled*"
# This example lists users who have passwords that have not changed in years who are also not in a Disabled group

.EXAMPLE
Get-LdapInfo -DistributionGroups
# This example lists all the Distribution Groups in Active Directory

.EXAMPLE
Get-LdapInfo -SecurityGroups
# This example lists all the Security Groups in Active Directory

.EXAMPLE
Get-LdapInfo -BuiltInGroups
# This example lists all Built In Groups in Active Directory

.EXAMPLE
Get-LdapInfo -AllGlobalGroups
# This example lists all Global Groups in Active Directory

.EXAMPLE
Get-LdapInfo -DomainLocalGroups
# This example list Domain Local Groups from Active Directory

.EXAMPLE
Get-LdapInfo -UniversalGroups
# This example lists the Universal Groups from Active Directory

.EXAMPLE
Get-LdapInfo -GlobalSecurityGroups
# This example list Global Security Groups from Active Directory

.EXAMPLE
Get-LdapInfo -UniversalSecurityGroups
# This example lists Universal Security Gruops from Active Directory

.EXAMPLE
Get-LdapInfo -DomainLocalSecurityGroups
# This example lists Domain Local Security Groups from Active Directory

.EXAMPLE
Get-LdapInfo -GlobalDistributionGroups
# This example lists Global Distribution Groups from Acitve Directory

.EXAMPLE
Get-LdapInfo -GlobalDistributionGroups -Domain domain.com -Credential (Get-Credential)
# This example gets GlobalDistributionGroups for domain.com


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
None


.OUTPUTS
System.Array

#>
    [CmdletBinding()]
        param(
            [Parameter(
                ParameterSetName="Domain",
                Position=0,
                Mandatory=$False,
                ValueFromPipeline=$False
            )]  # End Parameter
            [String]$Domain,
            
            [Parameter(
                ParameterSetName="Domain"
            )]  # End Parameter
            [ValidateNotNull()]
            [System.Management.Automation.PSCredential]
            [System.Management.Automation.Credential()]
            $Credential = [System.Management.Automation.PSCredential]::Empty,
            
            [Parameter(
                Mandatory=$False)]
            [switch][bool]$Detailed,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$LDAPS,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainControllers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$AllServers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$AllMemberServers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainTrusts,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainAdmins,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$UACTrusted,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$NotUACTrusted,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$SPNNamedObjects,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$EnabledUsers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$PossibleExecutives,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$LogonScript,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListAllOU,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListComputers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListContacts,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListUsers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListContainers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListDomainObjects,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ListBuiltInContainers,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$ChangePasswordAtNextLogon,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$PasswordNeverExpires,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$NoPasswordRequired,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$NoKerberosPreAuthRequired,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$PasswordsThatHaveNotChangedInYears,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DistributionGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$SecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$BuiltInGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$AllGLobalGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainLocalGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$UniversalGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$GlobalSecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$UniversalSecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$DomainLocalSecurityGroups,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$GlobalDistributionGroups

        ) # End param

BEGIN {

    $Output = @()
    Write-Verbose -Message "Creating LDAP query..."

    If ($DomainControllers.IsPresent) {$LdapFilter = "(primaryGroupID=516)"}
    ElseIf ($AllServers.IsPresent) {$LdapFilter = '(&(objectCategory=computer)(operatingSystem=*server*))'}
    ElseIf ($AllMemberServers.IsPresent) {$LdapFilter = '(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'}
    ElseIf ($DomainTrusts.IsPresent) {$LdapFilter = '(objectClass=trustedDomain)'}

    ElseIf ($DomainAdmins.IsPresent) {$LdapFilter =  "(&(objectCategory=person)(objectClass=user)((memberOf=CN=Domain Admins,OU=Admin Accounts,DC=usav,DC=org)))"}
    ElseIf ($UACTrusted.IsPresent) {$LdapFilter =  "(userAccountControl:1.2.840.113556.1.4.803:=524288)"}
    ElseIf ($NotUACTrusted.IsPresent) {$LdapFilter = '(userAccountControl:1.2.840.113556.1.4.803:=1048576)'}
    ElseIf ($SPNNamedObjects.IsPresent) {$LdapFilter = '(servicePrincipalName=*)'}
    ElseIf ($EnabledUsers.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'}
    ElseIf ($PossibleExecutives.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(directReports=*)(!(manager=*)))'}
    ElseIf ($LogonScript.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(scriptPath=*))'}

    ElseIf ($ListAllOU.IsPresent) {$LdapFilter = '(objectCategory=organizationalUnit)'}
    ElseIf ($ListComputers.IsPresent) {$LdapFilter = '(objectCategory=computer)'}
    ElseIf ($ListContacts.IsPresent) {$LdapFilter = '(objectClass=contact)'}
    ElseIf ($ListUsers.IsPresent) {$LdapFilter = 'samAccountType=805306368'}
    ElseIf ($ListGroups.IsPresent) {$LdapFilter = '(objectCategory=group)'}
    ElseIf ($ListContainers.IsPresent) {$LdapFilter = '(objectCategory=container)'}
    ElseIf ($ListDomainObjects.IsPresent) {$LdapFilter = '(objectCategory=domain)'}
    ElseIf ($ListBuiltInContainers.IsPresent) {$LdapFilter = '(objectCategory=builtinDomain)'}

    ElseIf ($ChangePasswordAtNextLogon.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user)(pwdLastSet=0))'}
    ElseIf ($PasswordNeverExpires.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user) (userAccountControl:1.2.840.113556.1.4.803:=65536))'}
    ElseIf ($NoPasswordRequired.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user) (userAccountControl:1.2.840.113556.1.4.803:=32))'}
    ElseIf ($NoKerberosPreAuthRequired.IsPresent) {'(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'}
    ElseIf ($PasswordsThatHaveNotChangedInYears.IsPresent) {$LdapFilter = '(&(objectCategory=person)(objectClass=user) (pwdLastSet>=129473172000000000))'}

    ElseIf ($DistributionGroups.IsPresent) {$LdapFilter = '(&(objectCategory=group)(!(groupType:1.2.840.113556.1.4.803:=2147483648)))'}
    ElseIf ($SecurityGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=2147483648)'}
    ElseIf ($BuiltInGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=1)'}
    ElseIf ($AllGlobalGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=2)'}
    ElseIf ($DomainLocalGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=4)'}
    ElseIf ($UniversalGroups.IsPresent) {$LdapFilter = '(groupType:1.2.840.113556.1.4.803:=8)'}
    ElseIf ($GlobalSecurityGroups.IsPresent) {$LdapFilter = '(groupType=-2147483646)'}
    ElseIf ($UniversalSecurityGroups.IsPresent) {$LdapFilter = '(groupType=-2147483640)'}
    ElseIf ($DomainLocalSecurityGroups.IsPresent) {$LdapFilter = '(groupType=-2147483644)'}
    ElseIf ($GlobalDistributionGroups.IsPresent) {$LdapFilter = '(groupType=2)'}

    $Port = "389"
    If ($LDAPS.IsPresent) {

        $Port = "636"
        Write-Verbose -Message "[*] LDAP over SSL was specified. Using port $Port"
        
    }  # End If
    
    If ($Domain) {

        $DirectoryContext = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new("Domain", $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DirectoryContext)
        $PrimaryDC = ($DomainObj.PdcRoleOwner).Name
        $ObjDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry "LDAP://$($PrimaryDC)" ,$Credential.UserName,$($Credential.GetNetworkCredential().Password)

    } Else {

        $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $PrimaryDC = ($DomainObj.PdcRoleOwner).Name
        $ObjDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry

    }  # End If Else
    
    $DistinguishedName = "DC=$($DomainObj.Name.Replace('.',',DC='))"
    $SearchString = "LDAP://$PrimaryDC`:$Port/$DistinguishedName"
    $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.SearchRoot = $ObjDomain
    $Searcher.Filter = $LdapFilter
    $Searcher.SearchScope = "Subtree"

} PROCESS {

    $Results = $Searcher.FindAll()
    Write-Verbose -Message "[*] Getting results"

    If ($Detailed.IsPresent) {

        If ($Results.Properties) {

            ForEach ($Result in $Results) {

                $ObjProperties = @()
                ForEach ($Property in $Result.Properties) {

                    $ObjProperties += $Property

                }  # End ForEach

                $Output += $ObjProperties

            } # End ForEach

        } Else {

            ForEach ($Result in $Results) {

                $Output += $Result.GetDirectoryEntry()

            }  # End ForEach

        }  # End If Else

    } Else {

        ForEach ($Result in $Results) {

            $Output += $Result.GetDirectoryEntry()

        }  # End ForEach

    }  # End If Else

} END {

    Write-Verbose -Message "[*] LDAP Query complete. "
    Return $Output

} # End END

} # End Get-LdapInfo
