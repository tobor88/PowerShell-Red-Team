# PowerShell-Red-Team-Enum
Collection of PowerShell functions a Red Teamer may use to collect data from a machine or gain access to a target.

- Convert-Base64.psm1 is a function as the name states for encoding and/or decoding text into Base64 format.
```powershell
C:\PS> Convert-Base64 -Value "Convert me to base64!" -Encode

C:\PS> Convert-Base64 -Value "Q29udmVydCBtZSB0byBiYXNlNjQh" -Decode
```

- Get-LdapInfo.psm1 is a a function I am very proud of for performing general LDAP queries. Althouhg only 2 properties will show in the output, all of the properties associated with object can be seen by pipeing to Select-Object -Prroperty *.
```powershell
 C:\PS> Get-LdapInfo -DomainControllers | Select-Object -Property 'Name','ms-Mcs-AdmPwd'
```

- Start-SimpleHTTPServer is a function used to host an HTTP server for downloading files. It is meant to be similart to pythons SimpleHTTPServer module. Directories are not traversable through the web server. The files that will be hosted for download will be from the current directory you are in when issuing this command.
```powershell
C:\PS> Start-SimpleHTTPServer
Open HTTP Server on port 8000

#OR
C:\PS> Start-SimpleHTTPServer -Port 80
# Open HTTP Server on port 80
```
