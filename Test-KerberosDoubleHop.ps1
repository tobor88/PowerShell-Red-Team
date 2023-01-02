Function Test-KerberosDoubleHop {
<#
.SYNOPSIS
This cmdlet is for finding AD Objects that are vulnerable to Kerberos Double Hop Vulnerability


.DESCRIPTION
This only works if run on a Domain Controller. If you find any users that are susceptible you can protect the user account by going to their properties in AD, Account Tab - Check the box User Account is Sensitive and Cannot be Delegated; Admin Credentials will be found in an lsass dump file. Lsass dump file can be analyzed without us knowing when the vulnerability is on an admin account and a computer.                                                                                       #


.PARAMETER All
This switch parameter indicates you want to recieve Kerberos Double Hop info on all Computers, Users, and Admins in Active Directory

.PARAMETER UserResults
This switch parameter indicates you want to recieve Kerberos Double Hop info on all Users in Active Directory

.PARAMETER AdminResults
This switch parameter indicates you want to recieve Kerberos Double Hop info on all Admins in Active Directory

.PARAMETER ComputerResults
This switch parameter indicates you want to recieve Kerberos Double Hop info on all Computers in Active Directory

.PARAMETER Server
This parameter is used to define the Domain Controller to run this check from. This allows you to execute this on a remote domain controller

.PARAMETER UseSSL
This parameter indicates you want to use WinRM over HTTPS to execute this cmdlet on the remote Domain Controller


.EXAMPLE
Test-KerberosDoubleHop -All
# This example checks for and displays Computers, Users, and Admin AD Objects vulnerable to a Kerberos Double Hop on the domain controller you are logged into

.EXAMPLE
Test-KerberosDoubleHop -Server DC01.domain.com -UserResults
# This example uses WinRM to display User AD Objects vulnerable to a Kerberos Double Hop on the remote domain controller DC01.domain.com

.EXAMPLE
Test-KerberosDoubleHop -Server DC01.domain.com -UseSSL -AdminResults
# This example uses WinRM over HTTPS to display Admin AD Objects vulnerable to a Kerberos Double Hop on the remote domain controller DC01.domain.com

.EXAMPLE
Test-KerberosDoubleHop -ComputerResults -AdminResults
# This example checks for and displays Computer and Admin AD Objects vulnerable to a Kerberos Double Hop on the domain controller you are logged into


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
    [CmdletBinding(DefaultParameterSetName='Local')]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$All,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UserResults,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$AdminResults,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$ComputerResults,

            [Parameter(
                Position=0,
                ParameterSetName='Remote',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter the hostname or FQDN of a domain controller in your environment. `n[E] EXAMPLE: DC01.domain.com")]  # End Parameter
            [String]$Server,

            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseSSL
        )  # End param

    $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $Domain = $DomainObj.Name
    $DCs = $DomainObj.DomainControllers.Name

    Switch ($PSCmdlet.ParameterSetName) {

        'Remote' {

            $Regex = ‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’
            If ($Server -match $Regex) {

                Throw "[x] Please use the hostname or FQDN of the domain controller"

            }  # End If


            If ($Server -notlike "*.$Domain") {

                $ComputerName = "$Server.$Domain"

            } Else {

                $ComputerName = $Server

            }  # End If Else

            If ($ComputerName -notin $DCs) {

                Throw "[x] $ComputerName is not a known domain controller for $Domain"

            }  # End If

            $Bool = $False
            If ($UseSSL.IsPresent) {

                $Bool = $True

            }  # End If

            Invoke-Command -ArgumentList $All,$UserResults,$AdminResults,$ComputerResults -HideComputerName $ComputerName -UseSSL:$Bool -ScriptBlock {

                $All = $Args[0]
                $UserResults = $Args[1]
                $AdminResults = $Args[2]
                $ComputerResults = $Args[3]

                If ($ComputerResults.IsPresent -or $All.IsPresent) {

                    Write-Verbose -Message "Getting information on computers in the domain that are vulnerable to a Kerberos Double Hop attack"
                    $ComputerResult = Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupId -eq 515)} -Properties TrustedforDelegation,TrustedtoAuthForDelegation,servicePrincipalName,Description | Select-Object -Property DistinguishedName,TrustedForDelegation,TrustedtoAuthForDelegation
                    Write-Output -InputObject "[*] The above computers are vulnerable to Kerberos Hop Attack. This vulnerability allows an attacker to pivot to other machines using TGT stored on a trusted device. This can than be forwarded to a server for authentication."

                }  # End If

                If ($UserResults.IsPresent -or $All.IsPresent) {

                    Write-Verbose -Message "Discovering accounts with the AD property 'Account is sensitive and cannot be delegated' selected. These accounts are protected against the Kerberos Double Hop vulnerability."
                    $UserResult = Get-ADGroupMember -Identity "Domain Users" | ForEach-Object {

                        Get-ADUser -Identity $_ -Properties AccountNotDelegated | Where-Object {$_.AccountNotDelegated -eq $False} | Select-Object -Property DistinguishedName,AccountNotDelegated

                    }  # End ForEach-Object

                    Write-Output -InputObject "[*] The above accounts are vulnerable to a Kerberos Double Hop"

                }  # End If

                If ($AdminResults.IsPresent -or $All.IsPresent) {

                    $AdminResult = @()
                    Write-Verbose -Message "Discovering any Admin Accounts vulnerable to Kerberos Hop Vulnerability"
                    $AdminResult += Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {

                        Get-ADUser -Identity $_ -Properties AccountNotDelegated | Where-Object {$_.AccountNotDelegated -eq $False} | Select-Object -Property DistinguishedName,AccountNotDelegated

                    }  # End ForEach-Object

                    Write-Output -InputObject "[*] The above admin accounts are vulnerable to a Kerberos Double Hop"

                }  # End If

                If ($ComputerResults.IsPresent -or $All.IsPresent) {

                    Write-Output -InputObjet "COMPUTER RESULTS"
                    $ComputerResult

                }  # End If

                If ($UserResults.IsPresent -or $All.IsPresent) {

                    Write-Output -InputObject "`nUSER RESULTS"
                    $UserResult

                }  # End If

                If ($AdminResults.IsPresent -or $All.IsPresent) {

                    Write-Output -InputObject "`nADMIN RESULTS"
                    $AdminResult

                }  # End If

            }  # End Invoke-Command

        }  # End Switch Remote

        'Local' {

            $ComputerName = "$env:COMPUTERNAME.$Domain"
            If ($ComputerName -notin $DCs) {

                Throw "[x] $ComputerName is not a known domain controller for $Domain"

            }  # End If


            If ($ComputerResults.IsPresent -or $All.IsPresent) {

                    Write-Verbose -Message "Getting information on computers in the domain that are vulnerable to a Kerberos Double Hop attack"
                    $ComputerResult = Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupId -eq 515)} -Properties TrustedforDelegation,TrustedtoAuthForDelegation,servicePrincipalName,Description | Select-Object -Property DistinguishedName,TrustedForDelegation,TrustedtoAuthForDelegation
                    Write-Output -InputObject "[*] The above computers are vulnerable to Kerberos Hop Attack. This vulnerability allows an attacker to pivot to other machines using TGT stored on a trusted device. This can than be forwarded to a server for authentication."

                }  # End If

                If ($UserResults.IsPresent -or $All.IsPresent) {

                    Write-Verbose -Message "Discovering accounts with the AD property 'Account is sensitive and cannot be delegated' selected. These accounts are protected against the Kerberos Double Hop vulnerability."
                    $UserResult = Get-ADGroupMember -Identity "Domain Users" | ForEach-Object {

                        Get-ADUser -Identity $_ -Properties AccountNotDelegated | Where-Object {$_.AccountNotDelegated -eq $False} | Select-Object -Property DistinguishedName,AccountNotDelegated

                    }  # End ForEach-Object

                    Write-Output -InputObject "[*] The above accounts are vulnerable to a Kerberos Double Hop"

                }  # End If

                If ($AdminResults.IsPresent -or $All.IsPresent) {

                    $AdminResult = @()
                    Write-Verbose -Message "Discovering any Admin Accounts vulnerable to Kerberos Hop Vulnerability"
                    $AdminResult += Get-ADGroupMember -Identity "Domain Admins" | ForEach-Object {

                        Get-ADUser -Identity $_ -Properties AccountNotDelegated | Where-Object {$_.AccountNotDelegated -eq $False} | Select-Object -Property DistinguishedName,AccountNotDelegated

                    }  # End ForEach-Object

                    Write-Output -InputObjet "[*] The above admin accounts are vulnerable to a Kerberos Double Hop"

                }  # End If

                If ($ComputerResults.IsPresent -or $All.IsPresent) {

                    Write-Output -InputObject "COMPUTER RESULTS"
                    $ComputerResult

                }  # End If

                If ($UserResults.IsPresent -or $All.IsPresent) {

                    Write-Output -InputObject "`nUSER RESULTS"
                    $UserResult

                }  # End If

                If ($AdminResults.IsPresent -or $All.IsPresent) {

                    Write-Output -InputObject "`nADMIN RESULTS"
                    $AdminResult

                }  # End If

        }  # End Switch Local

    }  # End Switch

}  # End Function Test-KerberosDoubleHop
