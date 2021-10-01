<#
.SYNOPSIS
This cmdlet is used to convert a string value in ASCII, BigEndianUnicode, Unicode, UTF7, UTF8, UTF32 to one or all MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD160 hash values


.DESCRIPTION
Define a string and the encoding of that string you wish to view the hashed value of


.PARAMETER String
Specifies the text value to hash

.PARAMETER Encoding
Specifies the file encoding. The default is UTF8. Valid values are:
    - ASCII:  Uses the encoding for the ASCII (7-bit) character set.
    - BigEndianUnicode:  Encodes in UTF-16 format using the big-endian byte order.
    - Unicode:  Encodes in UTF-16 format using the little-endian byte order.
    - UTF7:   Encodes in UTF-7 format.
    - UTF8:  Encodes in UTF-8 format.
    - UTF32:  Encodes in UTF-32 format.
    
.PARAMETER Algorithm
Specifies the cryptographic hash function to use for computing the hash value of the specified string. A cryptographic hash function includes the property that it is not possible to find two distinct inputs that generate the same hash values. The acceptable values for this parameter are:
    - SHA1
    - SHA256
    - SHA384
    - SHA512
    - MD5
    - RIPEMD160

.PARAMETER All
Returns a PSObject of the hash algorithm and the hash value of the string you converted


.EXAMPLE
Convert-StringToHash -String "Password123" -Encoding UTF8 -Algorithm MD5
Convert-StringToHash -String "Password123" -Encoding UTF8
Convert-StringToHash -String "Password123"
Convert-StringToHash "Password123" "UTF8"
Convert-StringToHash "Password123"
# The above examples all return the UTF8 string Password123 as an MD5 Hash value

.EXAMPLE
Convert-StringToHash -String "Password123" -All
Convert-StringToHash "Password123" -All
# The above examples all return Password123 in each of the offered hashing algorithm formats


.INPUTS
System.String


.OUTPUTS
System.String, System.PSObject


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
#>
Function Convert-StringToHash {
    [CmdletBinding(DefaultParameterSetName='Single')]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False)]  # End Parameter
            [String]$String,

            [Parameter(
                Position=1,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet("UTF8","ASCII","BigEndianUnicode","Unicode","UTF32","UTF7")]
            [String]$Encoding = "UTF8",

            [Parameter(
                ParameterSetName="Single",
                Position=2,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160")]
            [String]$Algorithm = "MD5",

            [Parameter(
                ParameterSetName="All",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$All
        )  # End param


    Switch ($PSCmdlet.ParameterSetName) {

    'All' {

        $Results = @()
        $Algorithms = "MD5","SHA1","SHA256","SHA384","SHA512","RIPEMD160"
        ForEach ($Algorithm in $Algorithms) {

            Remove-Variable -Name Result -ErrorAction SilentlyContinue
            Switch ($Algorithm) {
        
                "RIPEMD160" { $HashObj = New-Object -TypeName System.Security.Cryptography.RIPEMD160Managed }

                Default { $HashObj = New-Object -TypeName System.Security.Cryptography.$($Algorithm)CryptoServiceProvider }

            }  # End Switch

            $ToHash = [System.Text.Encoding]::$($Encoding).GetBytes($String)
            $Bytes = $HashObj.ComputeHash($ToHash)
            Foreach ($Byte in $Bytes) {

              $Result += "{0:X2}" -f $Byte

            }  # End ForEach

            $Results += New-Object -TypeName PSObject -Property @{Algorithm=$Algorithm;Hash=$Result}

        }  # End ForEach

        $Results

    }  # End Switch All

    'Single' {

        Switch ($Algorithm) {
        
            "RIPEMD160" { $HashObj = New-Object -TypeName System.Security.Cryptography.RIPEMD160Managed }

            Default { $HashObj = New-Object -TypeName System.Security.Cryptography.$($Algorithm)CryptoServiceProvider }

        }  # End Switch
    

        $ToHash = [System.Text.Encoding]::$($Encoding).GetBytes($String)
        $Bytes = $HashObj.ComputeHash($ToHash)


        Foreach ($Byte in $Bytes) {

          $Result += "{0:X2}" -f $Byte

        }  # End ForEach

        $Result

    }  # End Switch Single

    }  # End Switch

 }  # End Function Convert-StringToHash