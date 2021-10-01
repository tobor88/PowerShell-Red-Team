<#
.SYNOPSIS
This cmdlet is used to allow RDP Connections to a device


.DESCRIPTION
This will enable RDP on the machine and disable Network Level Authentication if specified


.EXAMPLE
Enable-RDP


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
None
#>
Function Enable-RDP {
    [CmdletBinding()]
        param()

    Write-Verbose "Enabling RDP on $env:COMPUTERNAME"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

    Write-Verbose "Disabling NLA on $env:COMPUTERNAME"
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force | Out-Null
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value "00000000" -PropertyType DWORD -Force

    Write-Verbose "Enabling RDP Firewall rule"
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Set-NetFirewallRule -Enabled True

}  # End Function Enable-RDP
