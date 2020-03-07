# PowerShell-Red-Team-Enum
Collection of PowerShell functions a Red Teamer may use to collect data from a machine or gain access to a target.

- Convert-Base64.psm1 is a function as the name states for encoding and/or decoding text into Base64 format.
```powershell
C:\PS> Convert-Base64 -Value "Convert me to base64!" -Encode

C:\PS> Convert-Base64 -Value "Q29udmVydCBtZSB0byBiYXNlNjQh" -Decode
```

- Get-LdapInfo.psm1 is a function I am very proud of for performing general LDAP queries. Although only two properties will show in the output, all of the properties associated with object can be seen by piping to Select-Object -Property *.
```powershell
 C:\PS> Get-LdapInfo -DomainControllers | Select-Object -Property 'Name','ms-Mcs-AdmPwd'
```

- Test-PrivEsc.ps1 is a function that can be used for finding whether WSUS updates over HTTP are vulnerable to PrivEsc, Clear Text credentials are stored in common places,  AlwaysInstallElevated is vulnerable to PrivEsc, Unquoted Service Paths exist, and enum of possible weak write permissions for services.
```powershell
 C:\PS> Test-PrivEsc
```

- Get-InitialEnum.ps1 is a function for enumerating the basics of a Windows Operating System to help better display possible weaknesses.
```powershell
 C:\PS> Get-InitialEnum
```

- Start-SimpleHTTPServer is a function used to host an HTTP server for downloading files. It is meant to be similart to pythons SimpleHTTPServer module. Directories are not traversable through the web server. The files that will be hosted for download will be from the current directory you are in when issuing this command.
```powershell
C:\PS> Start-SimpleHTTPServer
Open HTTP Server on port 8000

#OR
C:\PS> Start-SimpleHTTPServer -Port 80
# Open HTTP Server on port 80
```

- Invoke-PingSweep is a function used for performing a ping sweep of a subnet range. 
```powershell
Invoke-PingSweep -Subnet 192.168.1.0 -Start 192 -End 224 -Source Singular
# NOTE: The source parameter only works if IP Source Routing value is "Yes"

Invoke-PingSweep -Subnet 10.0.0.0 -Start 1 -End 20 -Count 2
# Default value for count is 1

Invoke-PingSweep -Subnet 172.16.0.0 -Start 64 -End 128 -Count 3 -Source Multiple
```
