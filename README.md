# PowerShell-Red-Team-Enum
Collection of PowerShell functions a Red Teamer may use to collect data from a machine

- Convert-Base64.psm1 is a function as the name states for encoding and/or decoding text into Base64 format.
```powershell
Convert-Base64 [-Value <string[]>] [{-Decode | -Encode}]
```

- Get-LdapInfo.psm1 is a a function I am very proud of for performing general LDAP queries. Althouhg only 2 properties will show in the output, all of the properties associated with object can be seen by pipeing to Select-Object -Prroperty *.
```powershell
 C:\PS> Get-LdapInfo -DomainControllers | Select-Object -Property 'Name','ms-Mcs-AdmPwd'
```
