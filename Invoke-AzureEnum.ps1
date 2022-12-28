Function Invoke-AzureEnum {
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="`n[H] Enter the absolute path and file name to save info too. `n[E] EXAMPLE: C:\Temp\enum.txt")]  # End Parameter
            [String]$Path
        )  # End param


    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Warning "For best results maximize your PowerShell window"
    Write-Output "[*] Please wait while the Az and MsOnline modules are installed and imported"
    If (!(Get-Module -ListAvailable -Name Az)) {

        Install-Module -Name Az -Force

    }  # End If
    
    If (!(Get-Module -ListAvailable -Name MsOnline)) {

        Install-Module -Name MSOnline -Force

    }  # End If

    Import-Module -Name Az,MSOnline -Force

    Write-Output -InputObject "[*] If MFA is not required in the environment the above connections should work fine. If Modern Auth is required you will be prompted with another credential window."
    $Credential = Get-Credential -Message "Enter your Azure credentials" -UserName "$env:USERDNSDOMAIN\$env:USERNAME"

    Write-Output -InputObject "[*] Connecting to Azure and Office365"
    Connect-AzAccount -Credential $Credential
    Connect-MsolService -Credential $Credential

    New-Item -Path $Path -ItemType File -Force

    $AzureContexts = Get-AzContext -ListAvailable
    $TenantId = $AzureContexts.Tenant.id
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                  AZURE CONTEXTS                    |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $AzureContexts | Format-List | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "[*] Above is a list of the available Azure contexts" | Add-Content -Path $Path -PassThru

    $Answer1 = Read-Host -Prompt "`tWould you like to export a Context file from the list above? [y/N]"
    While ($Answer1 -like "y*") {

        $ContextFile = Read-Host -Prompt "Enter the absolute path to save context file too. EXAMPLE: C:\Temp\Live Tokens\StolenToken.json"
        Save-AzContext -Path $ContextFile

        $Answer1 = Read-Host -Prompt "`tWould you like to export another Context file from the list above? [y/N]"

    }  # End If

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|             ORGANIZATION INFORMATION               |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Get-MSolCompanyInformation | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                    USER LIST                       |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Get-MSolUser -All | Select-Object -Property ObjectId,SignInName,Department,Title,PhoneNumber | Sort-Object -Property Department,DisplayName | Format-Table | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                   GROUP LIST                       |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Get-MSolGroup -All | Select-Object -Property GroupType,DisplayName,EmailAddress,ObjectId | Sort-Object -Property GroupType,DisplayName | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|            GLOBAL ADMINISTRATORS LIST              |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $Role = Get-MsolRole -RoleName "Company Administrator"
    Get-MsolRoleMember -RoleObjectId $Role.ObjectId | Select-Object -Property DisplayName,EmailAddress,ObjectId,RoleMemberType | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "`n======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                SERVICE PRINCIPALS                  |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Get-MsolServicePrincipal | Select-Object -Property DisplayName,AccountEnabled,ObjectId,TrustedForDelegation | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    If ($Null -eq $AzureContexts.SubscriptionName) {

        Write-Output -InputObject "[*] This Azure Tenant does not have any Azure subscriptions to enumerate" | Add-Content -Path $Path -PassThru

    }  # End If


    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|               AZURE SUBSCRIPTIONS                  |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $AzSubscription = Get-AzSubscription
    $AzSubscription | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                 AZURE RESOURCE                     |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $AzureResources = Get-AzResource
    $AzureResources | Sort-Object -Property Location,ResourceGroupName | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                 AZURE GROUPS                       |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $AzureResourceGroups = Get-AzResourceGroup | Sort-Object -Property Location,ResourceGroupName | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                 AZURE STORAGE ACCOUNTS             |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $AzureResourceGroups | ForEach-Object { Get-AzStorageAccount -ResourceGroupName $_.ResourceGroupName } | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|                   AZURE WEB APPS                   |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    $AzureResourceGroups | ForEach-Object { Get-AzWebApp -ResourceGroupName $_.ResourceGroupName } | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    $AzureSQL = Get-AzSQLServer
    If ($AzureSQL) {

        Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
        Write-Output -InputObject "|                 AZURE SQL SERVERS                  |" | Add-Content -Path $Path -PassThru
        Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
        $AzureSQL | Out-String | Add-Content -Path $Path -PassThru

        ForEach ($Asql in $AzureSQL) {

            Write-Output -InputObject "--------------- Azure SQL Database ---------------" | Add-Content -Path $Path -PassThru
            Get-AzSqlDatabase -ServerName $Asql.ServerName -ResourceGroupName $Asql.ResourceGroupName | Out-String | Add-Content -Path $Path -PassThru

            Write-Output -InputObject "------------ Azure SQL Firewall Rules ------------" | Add-Content -Path $Path -PassThru
            Get-AzSqlServerFirewallRule –ServerName $Asql.ServerName -ResourceGroupName $Asql.ResourceGroupName | Out-String | Add-Content -Path $Path -PassThru

            Write-Output -InputObject "---------------- Azure SQL Admins ----------------" | Add-Content -Path $Path -PassThru
            Get-AzSqlServerActiveDirectoryAdminstrator -ServerName $Asql.ServerName -ResourceGroupName $Asql.ResourceGroupName | Out-String | Add-Content -Path $Path -PassThru

            Write-Output -InputObject "--------------------------------------------------" | Add-Content -Path $Path -PassThru

        }  # End ForEach
        
    }  # End If
    
    $AzureVMs = Get-AzVM
    If ($AzureVMs) {

        Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
        Write-Output -InputObject "|                     AZURE VMs                      |" | Add-Content -Path $Path -PassThru
        Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru

        $AzureVMs | ForEach-Object { Get-AzVM -Name $_.Name } | Out-String | Add-Content -Path $Path -PassThru

    }  # End If

    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "|             AZURE Virtual Network Info             |" | Add-Content -Path $Path -PassThru
    Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
    Get-AzVirtualNetwork | Out-String | Add-Content -Path $Path -PassThru
    Get-AzPublicIpAddress | Out-String | Add-Content -Path $Path -PassThru
    Get-AzExpressRouteCircuit | Out-String | Add-Content -Path $Path -PassThru
    Get-AzVpnConnection | Out-String | Add-Content -Path $Path -PassThru

    $AzAdApplication = Get-AzAdApplication
    If ($AzAdApplication) {

        Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
        Write-Output -InputObject "|      AZURE SSO INTEGRATION AND CUSTOM APPS         |" | Add-Content -Path $Path -PassThru
        Write-Output -InputObject "======================================================" | Add-Content -Path $Path -PassThru
        $AzAdApplication | Select-Object -Property DisplayName,ObjectId,IdentifierUris,HomePage,ObjectType | Format-Table -AutoSize | Out-String | Add-Content -Path $Path -PassThru

    }  # End If

    $Answer3 = Read-Host -Prompt "Would you like to download the MicroBurst assessment tool import the cmdlet module? [y/N]"
    If ($Answer3 -like "y*") {

        $Save = Read-Host -Prompt "Enter the absolute path to save the file too. EXAMPLE: C:\Temp"
        Invoke-WebRequest -Uri "https://github.com/NetSPI/MicroBurst/archive/refs/heads/master.zip" -OutFile "$Save\master.zip"
        Expand-Archive -Path "$Save\master.zip" -DestinationPath $Save

        Import-Module "$Save\MicroBurst-master\MicroBurst.psm1"
        Get-Command -Module MicroBurst
        Write-Output -InputObject "[*] The commands provided by Microburst https://github.com/NetSPI/MicroBurst don't seem to be available. I listed the available commands in that module above."
        Write-Warning -Message "The next command takes a while to execute and may prevent you from see the begining of your PowerShell history above"
        Pause
        Invoke-EnumerateAzureBlobs -Base $BaseName

    }  # End If

}  # End Function Invoke-AzureEnum
