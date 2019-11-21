<#
    .SYNOPSIS
    Encode or Decode Base64 strings.

    .NOTES
    Author: Rob Osborne
    ALias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthsoborne.com

    .SYNTAX
    Convert-Base64 [-Value <string[]>] [{-Decode | -Encode}]

    .PARAMETER
    -Value
        Specifies a string to be encoded or decoded with base64.

        Enter a string consisting of spaces and special charcters if desired.DESCRIPTION

        Required?                    True
        Position?                    name
        Default value                None
        Accept pipeline input?       True
        Accept wildcard characters?  false

    -Encode
     This switch is used to tell the cmdlet to encode the base64 string

    -Decode
    This switch parameter is used to tell the cmdlet to decode the base64 string

    .INPUTS
    -Value accepts strings from pipeline.
    System.String

    .OUTPUTS
    System.String

    .EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    C:\PS> Convert-Base64 -Value 'Hello World!'' -Encode
    # This example encodes "Hello World into Base64 format.

    C:\PS> Convert-Base64 -Value 'SGVsbG8gV29ybGQh' -Decode
    # This example decodes Base64 to a string.
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

        throw "Switch parameter -Decode or -Encode needs to be defined. "

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

            throw "String could not be converted to Base64. The value entered is below. `n$Value"

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
