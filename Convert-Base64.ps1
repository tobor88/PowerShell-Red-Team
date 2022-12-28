Function Convert-Base64 {
<#
.SYNOPSIS
This cmdlet is used to Encode or Decode Base64 strings.


.DESCRIPTION
Convert a string of text to or from Base64 format. Pipeline input is accepted in string format. Use the switch parameters Encode or Decode to define which action you wish to perform on your string


.PARAMETER Value
Defines the string to be encoded or decoded with base64.

.PARAMETER Encode
This switch parameter is used to tell the cmdlet to encode the base64 string

.PARAMETER Decode
This switch parameter is used to tell the cmdlet to decode the base64 string

.PARAMETER TextEncoding
This parameter is used to define the type of Unicode Character encoding to convert with Base64. This value you can be ASCII, BigEndianUnicode, Default, Unicode, UTF32, UTF7, or UTF8. The default value is UTF8


.EXAMPLE
Convert-Base64 -Value 'Hello World!'' -Encode
# This example encodes "Hello World into Base64 format.

.EXAMPLE
Convert-Base64 -Value 'SGVsbG8gV29ybGQh' -Decode -TextEncoding ASCII
# This example decodes Base64 to a string in ASCII format


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://powershell.org/2020/11/writing-your-own-powershell-functions-cmdlets/
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
System.String, -Value accepts strings from pipeline.


.OUTPUTS
System.String

#>
    [CmdletBinding(DefaultParameterSetName='Encode')]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                HelpMessage="Enter a string you wish to encode or decode using Base64. Example: Hello World!")] # End Parameter
            [String]$Value,

            [Parameter(
                ParameterSetName='Encode',
                Mandatory=$True)]
            [Switch][Bool]$Encode,

            [Parameter(
                ParameterSetName='Decode',
                Mandatory=$True)]
            [Switch][Bool]$Decode,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateSet('ASCII', 'BigEndianUnicode', 'Default', 'Unicode', 'UTF32', 'UTF7', 'UTF8')]
            [String]$TextEncoding = 'UTF8'
        ) # End param

PROCESS {

    Switch ($PSCmdlet.ParameterSetName) {

        'Encode' {

            Switch ($TextEncoding) {

                'ASCII' {$StringValue  = [System.Text.Encoding]::ASCII.GetBytes("$Value")}

                'BigEndianUnicode' {$StringValue  = [System.Text.Encoding]::BigEndianUnicode.GetBytes("$Value")}

                'Default' {$StringValue  = [System.Text.Encoding]::Default.GetBytes("$Value")}

                'Unicode' {$StringValue  = [System.Text.Encoding]::Unicode.GetBytes("$Value")}

                'UTF32'  {$StringValue  = [System.Text.Encoding]::UTF32.GetBytes("$Value")}

                'UTF7' {$StringValue  = [System.Text.Encoding]::UTF7.GetBytes("$Value")}

                'UTF8' {$StringValue  = [System.Text.Encoding]::UTF8.GetBytes("$Value")}

            }  # End Switch

            Try {

                [System.Convert]::ToBase64String($StringValue)

            } Catch {

                Throw "String could not be converted to Base64. The value entered is below. `n$Value"
                $Error[0]

            } # End Catch

        }  # End Switch Encode

        'Decode' {

            $EncodedValue = [System.Convert]::FromBase64String("$Value")

            Switch ($TextEncoding) {

                'ASCII' {

                    Try {

                        [System.Text.Encoding]::ASCII.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    }  # End Try Catch

                }  # End Switch ASCII

                'BigEndianUnicode' {

                    Try {

                        [System.Text.Encoding]::BigEndianUnicode.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    } # End Try Catch

                }  # End Switch BigEndianUnicode

                'Default' {

                    Try {

                        [System.Text.Encoding]::Default.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    } # End Try Catch

                }  # End Switch Default

                'Unicode' {

                    Try {

                        [System.Text.Encoding]::Unicode.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    } # End Try Catch

                }  # End Switch Unicode

                'UTF32'  {

                    Try {

                        [System.Text.Encoding]::UTF32.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    } # End Try Catch

                }  # End Switch UTF32

                'UTF7' {

                    Try {

                        [System.Text.Encoding]::UTF7.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    } # End Catch

                }  # End Swithc UTF7

                'UTF8' {

                    Try {

                        [System.Text.Encoding]::UTF8.GetString($EncodedValue)

                    } Catch {

                        Throw "[x] Base64 entered was not in a correct format. The value received is below. `n$Value"

                    } # End Catch

                }  # End Switch UTF8

            }  # End Switch

        }  # End Switch Decode

    }  # End Switch

}  # End PROCESS

} # End Function Convert-Base64
