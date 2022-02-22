<#
.SYNOPSIS
	Creates an Azure SQL single instance.
.DESCRIPTION
    Creates an Azure SQL single instance in the subscription and resource group specified.

    The script will: 
        Validate that the subscription and resource group exist. The script will find the approproiate virtuall network and sub-network for deployment. It these are not found the script will end.
        Validate that the key vault is a Premium SKU. If it is not the script will end. A Premium SKU key vault is required.
        Create a Premium SKU key vault in the resource group if the key vault does not exist.
        Validate that the key and certificate meet security requirements.
        Create the key and/or certificate if they do not exist in the key vault.
        Modify the key and/or certificate if they do not meet security requirements.
        Create a SQL server with TDE using customer managed key for encryption.
        Create a private endpoint for the key vault if the key vault does not have a private endpoint.
        Create the SQL server in the resource group if it does not exist.

.NOTES
	File Name : Create-Azure-SQL.ps1
	Author    : Phil Schroder - phillip.schroder@fiserv.com
	Requires  : PowerShell Version 2.0
	Born      : 02/20/2020 - Phil Schroder
.EXAMPLE
	.\Create-Azure-SQL.ps1 -subscriptionName BusinessUnit-Lower -resourceGroupName bu-centralus-lower-sql-rg1 -keyVaultName sql-kv01 -sqlServerRootName application 

    Deploys a SQL Server named bu-centralus-lowe-application-sqlsvr into the resource group bu-centralus-lower-sql-rg1 within the BusinessUnit-Lower subscription.

    The SQL Server is deployed with Advanced Transparent Encryption enabled using the key SQLEncryptKey-HSM in key vault sql-kv01. Both are created if necessary. 

.PARAMETER subscriptionName
    Required: The name of the subscription that will contain the VM.
.PARAMETER resourceGroupName
    Required: The name of the resouce group within which the SQL server will be created.
.PARAMETER keyVaultName
    Required: The name of the key vault that will be used to encrypt the SQL database If the key vault does not exist it will be created.
.PARAMETER sqlServerRootName
    Required: The root name of the SQL server. The name of the SQL will be <bu-identifier>-<azure-region>-<location>-$sqlServerRootName-sqlsvr. For example: bs-centralus-lower-myserver-sqlsvr
.PARAMETER sqlEncryptKeyName
    Optional: The name of the key within keyvault that will be used for SQL encryption. Defaults to SQLEncryptKey-HSM
.PARAMETER sqlEncryptCertName
    Optional: The name of the certificate within keyvault that will be used for SL encryption. Defaults to SQLEncryptCert-HSM
.PARAMETER subnetName
    Optional: The name of the subnet within the vnet within which the sql server will be created.
.PARAMETER privateDNSZoneSubscription
    Optional: The name of the subscription that has the privatelink.database.windows.net private DNS zone.
.PARAMETER privateDNSZoneResourceGroupName
    Optional: The name of the resource group that has the privatelink.database.windows.net private DNS zone.
#>

param
(
    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the subscription that will contain the Azure SQL.")] 
    [string]
    $subscriptionName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the resource group witin which the Azure SQL will be created.")] 
    [string]
    $resourceGroupName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the key vault to contain the key and certficate for encryption of the Azure SQL.")] 
    [string]
    $keyVaultName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the root name of the SQL server.")]
    [ValidateLength(3,24)] 
    [string]
    $sqlServerRootName,

    [Parameter(Mandatory=$false, HelpMessage="Enter the name of the key within keyvault that will be used for SQL encryption.")] 
    [string]
    $sqlEncryptKeyName = "SQLEncryptKey-HSM",

    [Parameter(Mandatory=$false, HelpMessage="Enter the name of the certificate within keyvault that will be used for SL encryption.")] 
    [string]
    $sqlEncryptCertName = "SQLEncryptCert-HSM",

    [Parameter(HelpMessage="Enter the name of the subnet within the vnet in which the KeyVault's Private endpoint will be created. ")] 
    [ValidateSet("BKE","App-BKE")]
    [string]
    $subnetName = "BKE",

    [Parameter(HelpMessage="Enter the name of the subnet within the vnet in which the sql server will be created. ")] 
    [ValidateSet("DB","AXIOM-DB","AXIOM-PROD-DB-db")]
    [string]
    $sqlsubnetName = "DB",

    [Parameter(HelpMessage="Enter the name of the subscription that has the privatelink.database.windows.net private DNS zone for database private link registration. Defaults to ETG-Hub-Production-East2.")] 
    [string]
    $privateDNSZoneSubscription = "ETG-Hub-Production-East2",

    [Parameter(HelpMessage="Enter the name of the resource group that has the privatelink.database.windows.net private DNS zone for database private link registration. Defaults to rg-dns-prod-etg-hub-useast2-1.")] 
    [string]
    $privateDNSZoneResourceGroupName = "rg-dns-prod-etg-hub-useast2-1"
)    

#
# Set the file system directory from the Powershell FileSystem provider location.
#
# When you change directory in Powershell it does not change the underlying file system
# directory but instead changes the location in the Powershell FileSystem provider.
#
[IO.Directory]::SetCurrentDirectory((Convert-Path (Get-Location -PSProvider FileSystem)))

$sytemWebAssemblyLoad = [Reflection.Assembly]::LoadWithPartialName("System.Web") 2>$null

$success = $false
$currentDate = Get-Date
$currentDateString = $currentDate.ToString("yyyyMMdd")
$sqlAdmin = "sqladmin"
$sqlAdminPassword = [System.Web.Security.Membership]::GeneratePassword(8,4) + "Wa1"
$sqlAADAdmin = "PAE_SQL_Core_AZ"

function Log-Line
{
    param
    (
        [Parameter(Mandatory=$false)]
        [string]
        $logMessage
    )

    $timeStamp = Get-Date

    Write-Host -NoNewline -Separator '' -ForegroundColor Green $timeStamp.Hour.ToString("00") ":" $timeStamp.Minute.ToString("00") ":" $timeStamp.Second.ToString("00") "." $timeStamp.Millisecond.ToString("000") " "
    Write-Host $logMessage
}

function Log-VersionTable
{
    foreach ($key in $psVersionTable.Keys)
    {
        $value = $psVersionTable[$key]
        Log-Line "$key : $value"
    }
}

#
# Establish the Azure context.
#
function Establish-AzureContext
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [string]
        $subscriptionName
    )

    $retVal = $false

    Log-Line "Setting Azure context to subscription [$subscriptionName]."

    try
    {
        $subscription = Get-AzSubscription -SubscriptionName $subscriptionName -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Response.StatusCode -ne "NotFound")
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($null -ne $subscription)
    {
        #
        # Set the Azure context to point to the subscription so that all subsequent commands will be within the subscription.
        #   
        $context = Set-AzContext -SubscriptionObject $subscription
        Log-Line $context.Name

        $retVal = $true
    }
    else
    {
        Log-Line "Subscription [$subscriptionName] not found."
    }

    return $retVal
}

#
# Get the resource group to verify it exists and use it throughout the script.
#
function Acquire-ResourceGroup
{
    param 
    (
        [Parameter(Mandatory=$true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory=$true)]
        [string]
        $subscriptionName
    )

    $retVal = $false

    #
    # Get the resource group to verify it exists and use it throughout the script.
    #
    Log-Line "Verifying resource group [$resourceGroupName] exists in subscription [$subscriptionName]."
    try
    {
        $script:resourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Message.EndsWith("does not exist.") -eq $false)
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($null -ne $script:resourceGroup)
    {
        Log-Line "Resource group [$resourceGroupName] found in subscription [$subscriptionName]."
        $retVal = $true
    }
    else
    {
        Log-Line "Resource group [$resourceGroupName] not found in subscription [$subscriptionName]."
    }

    return $retVal
}

function Establish-Resource-Names
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResourceGroup]
        $resourceGroup
    )

    $retVal = $false

    $resourceGroupParts = $resourceGroup.ResourceGroupName.Split('-')
    $buIdentifier = $resourceGroupParts[3]
    $azureRegion = $resourceGroup.Location
    $location = $resourceGroupParts[2]

    #
    # Set the name of the SQL server.
    #
    $script:sqlServerName = "sql-$buIdentifier-$azureRegion-$location-$sqlServerRootName"
    Log-Line "Using [$script:sqlServerName] for SQL server name."

    #
    # Set the name of the private SQL endpoint connection.
    #
    $script:privateSqlEndpointConnectionName = "sqlpec-$buIdentifier-$azureRegion-$location-$sqlServerRootName"
    Log-Line "Using [$script:privateSqlEndpointConnectionName] for the private SQL endpoint connection name."

    #
    # Set the name of the private SQL endpoint.
    #
    $script:privateSqlEndpointName = "sqlpe-$buIdentifier-$azureRegion-$location-$sqlServerRootName"
    Log-Line "Using [$script:privateSqlEndpointName] for the private SQL endpoint name."

    #
    # Set the name of the private KeyVault endpoint connection.
    #
    $script:privateKeyVaultEndpointConnectionName = "pec-$keyVaultName"
    Log-Line "Using [$script:privateKeyVaultEndpointConnectionName] for the private KeyVault endpoint connection name."

    #
    # Set the name of the private KeyVault endpoint.
    #
    $script:privateKeyVaultEndpointName = "pe-$keyVaultName"
    Log-Line "Using [$script:privateKeyVaultEndpointName] for the private KeyVault endpoint name."

    $retVal = $true

    return $retVal
}

#
# Get the virtual network to verify it exists and to use it later in the script.
#
function Acquire-VirtualNetwork
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $subscriptionName
    )

    $retVal = $false

    Log-Line "Verifying virtual network exists in subscription [$subscriptionName]."

    try
    {
        $script:vnet = Get-AzVirtualnetwork -ErrorAction Stop | where {$_.Name.Contains("spoke")} 
    }
    catch
    {
        if ($_.Exception.Response.StatusCode -ne "NotFound")
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($null -ne $script:vnet)
    {
        Log-Line "Virtual network found in subscription [$subscriptionName]."
        $retVal = $true
    }
    else
    {
        Log-Line "Cant find virtual network in subscription [$subscriptionName]."
    }

    return $retVal
}

# 
# Get the subnet to verify ot exists and to use in the script.
#
function Acquire-SubNet
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory=$true)]
        [string]
        $subnetName
    )

    $retVal = $false
    $vnetName = $vnet.Name

    Log-Line "Verifying subnet [$subnetName] exists in virtual network [$vnetName]."
    $script:subnet = $vnet.Subnets | where-object { $_.name -eq $subnetName }

    if ($null -ne $script:subnet)
    {
        Log-Line "Subnet [$subnetName] in virtual network [$vnetName] found."
        $retVal = $true
    }
    else
    {
        Log-Line "Cant find subnet [$subnetName] in virtual network [$vnetName]."
    }


    return $retVal
}

function Acquire-SqlSubNet
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory=$true)]
        [string]
        $subnetName
    )

    $retVal = $false
    $vnetName = $vnet.Name

    Log-Line "Verifying subnet [$sqlsubnetName] exists in virtual network [$vnetName]."
    $script:sqlsubnet = $vnet.Subnets | where-object { $_.name -eq $sqlsubnetName }

    if ($null -ne $script:sqlsubnet)
    {
        Log-Line "Subnet [$sqlsubnetName] in virtual network [$vnetName] found."
        $retVal = $true
    }
    else
    {
        Log-Line "Cant find subnet [$sqlsubnetName] in virtual network [$vnetName]."
    }


    return $retVal
}


function Acquire-KeyVault
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory=$true)] 
        [string]
        $keyVaultName
    )

    $retVal = $false
    $keyVaultNotFound = $false

    Log-Line "Verifying key vault [$keyVaultName] exists in resource group [$resourceGroupName]."

    try
    {
        $script:keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Message.Contains("not found") -eq $true)
        {
            $keyVaultNotFound = $true
        }
        else
        {
            Log-Line $_.Exception.Message
        }
    }


    if ($keyVaultNotFound -eq $true)
    {
        #
        # If the key vault is not found then create it,
        #
        Log-Line "key vault [$keyVaultName] not found in resource group [$resourceGroupName]. Creating."

        try
        {
            $script:keyVault = New-AzKeyVault -ResourceGroupName $resourceGroupName -Name $keyVaultName -Location $vnet.Location -EnabledForDiskEncryption -Sku premium -ErrorAction Stop
        }
        catch
        {
            Log-Line $_.Exception.Message
        }

        if ($null -ne $script:keyVault)
        {
            Log-Line "key vault [$keyVaultName] created."
            $script:keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties
        }
        else
        {
            Log-Line "Error creating key vault [$keyVaultName] in resource group [$resourceGroupName]."
        }
    }
    elseif ($null -ne $script:keyVault)
    {
        Log-Line "key vault [$keyVaultName] found in resource group [$resourceGroupName]."
    }

    if ($script:keyVault -ne $null)
    {
        $retVal = $true

        Update-AzKeyVaultNetworkRuleSet -VaultName $keyVaultName -DefaultAction Allow 

    }

    return $retVal
}

function Acquire-KeyVault-Private-Endpoint
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]
        $subnet,

        [Parameter(Mandatory=$true)] 
        [string]
        $privatekeyVaultEndpointConnectionName,

        [Parameter(Mandatory=$true)] 
        [string]
        $privateKeyVaultEndpointName
    )

    $retVal = $false

    $script:privateKeyVaultEndpoint = Get-AzPrivateEndpoint -Name $privateKeyVaultEndpointName

    if ($script:privateKeyVaultEndpoint -eq $null)
    {
        $keyVaultName = $keyVault.ResourceName

        Log-Line "Private endpoint [$privateKeyVaultEndpointName] for key vault [$keyVaultName] not found."
        Log-Line "Creating private endpoint connection [$privatekeyVaultEndpointConnectionName] for key vault [$keyVaultName]."
        $privateKeyVaultEndpointConnection = New-AzPrivateLinkServiceConnection -Name $privatekeyVaultEndpointConnectionName -PrivateLinkServiceId $keyVault.ResourceId -GroupId "vault" -ErrorAction Stop

        if ($privateKeyVaultEndpointConnection -ne $null)
        {
            Log-Line "Creating private endpoint [$privatekeyVaultEndpointName] for key vault [$keyVaultname]."
            $privateKeyVaultEndpoint = New-AzPrivateEndpoint -ResourceGroupName $resourceGroupName -Name $privateKeyVaultEndpointName -Location $vnet.Location -Subnet $subnet -PrivateLinkServiceConnection $privateKeyVaultEndpointConnection -ErrorAction Stop
            if ($script:privateKeyVaultEndpoint -ne $null)
            {
                Log-Line "Private endpoint [$privatekeyVaultEndpointName] for key vault [$keyVaultname] created."
                $retVal = $true
            }
            else
            {
                Log-Line "Error creating private KeyVault endpoint. KeyVault is insecure."
            }
        }
        else
        {
            Log-Line "Error creating private endpoint KeyVault connection. KeyVault is insecure."
        }
    }
    else
    {
        Log-Line "Private endpoint [$privateKeyVaultEndpointName] key vault [$keyVaultName] found."
        $retVal = $true
    }

    return $retVal
}


#
# Configure the key vault SKU and other properties.
#
function Configure-KeyVault
{
    param
    (
        [Parameter(Mandatory=$true)]
        #[Microsoft.Azure.Commands.KeyVault.Models.PSKeyVault]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault
    )

    $keyVaultName = $keyVault.Name

    Log-Line "Verifying key vault [$keyVaultName] is the premium SKU."
    if ($keyVault.Properties.sku.name -ne "Premium")
    {
        Log-Line "Premium SKU is required for hardware encryption keys. Upgrading key vault [$keyVaultName] to premium."

        $keyVault.Properties.sku.name = "Premium"
        $keyVault | Set-AzResource -Force
    }
    else
    {
        Log-Line "key vault [$keyVaultName] is a premium SKU."
    }

    Log-Line "Verifying key vault [$keyVaultName] supports disk encryption."
    if ($keyVault.Properties.enabledForDiskEncryption -ne $true)
    {
        Log-Line "key vault [$keyVaultName] does not support disk encryption. Enabling."

        $keyVault.Properties.enabledForDiskEncryption = $true
        $keyVault | Set-AzResource -Force
    }
    else
    {
        Log-Line "key vault [$keyVaultName] supports disk encryption."
    }

    Log-Line "Verifying key vault [$keyVaultName] is enabled for soft delete."
    if ($keyVault.Properties.enableSoftDelete -ne $true)
    {
        Log-Line "key vault [$keyVaultName] is not enabled for soft delete. Enabling."
    
        $softDelete = Add-Member -InputObject $keyVault.Properties -MemberType "NoteProperty" -Name "enableSoftDelete" -Value "true"
        $keyVault | Set-AzResource -Force
    }
    else
    {
        Log-Line "key vault [$keyVaultName] is enabled for soft delete."
    }

    Log-Line "Verifying key vault [$keyVaultName] is enabled for purge protection."
    if ($keyVault.Properties.enablePurgeProtection -ne $true)
    {
        Log-Line "key vault [$keyVaultName] is not enabled for purge protection. Enabling."

        $purgeProtection = Add-Member -InputObject $keyVault.Properties -MemberType "NoteProperty" -Name "enablePurgeProtection" -Value "true"
        $keyVault | Set-AzResource -Force
    }
    else
    {
        Log-Line "key vault [$keyVaultName] is enabled for purge protection."
    }

    Log-Line "Set key vault [$keyVaultName] to deny public access."

    Update-AzKeyVaultNetworkRuleSet -VaultName $keyVault.ResourceName -DefaultAction Deny

}

#
# Get the key to determine if it exists or should be created and insure it meets policy requirements.
#
function Acquire-KeyVaultKey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlEncryptKeyName
    )

    $retVal = $false
    $keyVaultName = $keyVault.Name

    Log-Line "Verifying Key [$sqlEncryptKeyName] exists in key vault [$keyVaultName]."
    $script:key = Get-AzKeyVaultKey -VaultName $keyVaultName -Name $sqlEncryptKeyName

    if ($null -eq $key)
    {
        #
        # If the key is not found create it.
        #
        Log-Line "Key [$sqlEncryptKeyName] not found in key vault [$keyVaultName]. Creating."
        $expiryDate = (Get-Date).AddYears(2)
       
        Log-Line "Key [$sqlEncryptKeyName] being created will expire on [$expiryDate]."

        $script:key = Add-AzKeyVaultKey -VaultName $keyVaultName -Name  $sqlEncryptKeyName -Destination HSM -Expires $expiryDate
        
        if ($null -ne $key)
        {
            Log-Line "Key [$sqlEncryptKeyName] created."
        }
        else
        {
            Log-Line "Error creating Key [$sqlEncryptKeyName]."
        }         
    }
    else
    {
        Log-Line "Key [$sqlEncryptKeyName] found in key vault [$keyVaultName]."
    }

    #
    # Verify the key type.
    #
    if ($null -ne $script:key)
    {
        Log-Line "Verifying Key [$sqlEncryptKeyName] is of the correct type."
        $keyType = $script:key.Attributes.KeyType

        if ($keyType -eq "RSA-HSM")
        {
            $retVal = $true
        }
        else
        {
            Log-Line "Key [$sqlEncryptKeyName] is of type [$keyType] and cannot be used. Please specify a different key that is of type RSA-HSM. You may also specify a key that does not exist and it will be created with the proper type."
        }
    }

    return $retVal
}

#
# Get the certificate to verify it exists or should be created and insure it meets policy requirements
#
function Acquire-KeyVaultCertificate
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlEncryptCertName
    )

    $retVal = $false
    $keyVaultName = $keyVault.Name

    Log-Line "Verifying Certificate [$sqlEncryptCertName] exists in key vault [$sqlEncryptCertName]."
    $certificate = Get-AzKeyVaultCertificate -VaultName $keyVaultName -Name $sqlEncryptCertName 2>$null

    if ($null -eq $certificate)
    {
        Log-Line "Certificate [$sqlEncryptCertName] not found in key vault [$keyVaultName]. Creating."

        #
        # If the certificate must be created first a policy must be established.
        #
        $policy = New-AzKeyVaultCertificatePolicy `
            -SecretContentType "application/x-pkcs12" `
            -KeyType "RSA-HSM" `
            -RenewAtPercentageLifetime 80 `
            -SubjectName "CN=onefiserv.net" `
            -IssuerName "self" `
            -KeyNotExportable `
            -ValidityInMonths 12

        #
        # Create the certificate with the established policy.
        #
        $certificateOperation = Add-AzKeyVaultCertificate -VaultName $keyVaultName -Name $sqlEncryptCertName -CertificatePolicy $policy 2>$null

        if ($certificateOperation.Status -eq "completed")
        {
            Log-Line "Certificate [$sqlEncryptCertName] created."
        }
        elseif ($certificateOperation.Status -eq "inProgress")
        {
            do
            {
                Start-Sleep -Milliseconds 500

                $certificateOperation = Get-AzKeyVaultCertificateOperation -VaultName $keyVaultName -Name $sqlEncryptCertName
            } while ($certificateOperation.Status -eq "inProgress")

            Log-Line "Certificate [$sqlEncryptCertName] created."
        }
        else
        {
            Log-Line "Error creating Certificate [$sqlEncryptCertName]."
        }         
    }
    else
    {
        Log-Line "Certificate [$sqlEncryptCertName] found in key vault [$keyVaultName]."
    }

    if ($null -ne $certificate -or ($null -ne $certificateOperation -and $certificateOperation.Status -eq "completed"))
    {
        Log-Line "Verifying Certificate [$sqlEncryptCertName] has a compliant policy."

        $certificatePolicy = Get-AzKeyVaultCertificatePolicy -VaultName $keyVaultName -Name $sqlEncryptCertName

        $policyCompliant = $true

        if ($certificatePolicy.Exportable -ne $false)
        {
            Log-Line "Certificate [$sqlEncryptCertName] policy key cannot be exportable."
            $policyCompliant = $false
        }
                
        if ($certificatePolicy.Kty -ne "RSA-HSM")
        {
            Log-Line "Certificate [$sqlEncryptCertName] policy key type must be RSA-HSM."
            $policyCompliant = $false
        }

        if ($certificatePolicy.ReuseKeyOnRenewal -ne $false)
        {
            Log-Line "Certificate [$sqlEncryptCertName] policy key cannot be reusable."
            $policyCompliant = $false
        }

        if ($policyCompliant -eq $true)
        {
            Log-Line "Certificate [$sqlEncryptCertName] policy is compliant."
            $retVal = $true
        }
        else
        {
            Log-Line "Certificate [$sqlEncryptCertName] policy is not compliant. Please specify a different certificate that has a compliant policy. You may also specify a certificate that does not exist and it will be created with the proper policy."
        }
    }

    return $retVal
}

function Acquire-Sql-Server
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlServerName,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlAdmin,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlAdminPassword
    )

    $retVal = $false
    $sqlServerNotFound = $false

    try
    {
        $script:sqlServer = Get-AzSqlServer -ResourceGroupName $resourceGroupName -ServerName $sqlServerName -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Response.StatusCode -eq "NotFound")
        {
            $sqlServerNotFound = $true
        }
        else
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($sqlServerNotFound -eq $true)
    {
        Log-Line "Creating SQL server [$sqlServerName]. This will take a few minutes."

        $sqlServerCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $sqlAdmin, $(ConvertTo-SecureString -String $sqlAdminPassword -AsPlainText -Force)
        Log-Line $sqlServerCredentials
        try
        {
            $script:sqlServer = New-AzSqlServer -ResourceGroupName $resourceGroupName -ServerName $sqlServerName -Location $resourceGroup.Location -SqlAdministratorCredentials $sqlServerCredentials -AssignIdentity -ErrorAction Stop
            Log-Line $script:sqlServer
        }
        catch
        {
            Log-Line $_.Exception.Message
        }

        if ($script:sqlServer -ne $null)
        {
            $retVal = $true

            Log-Line "Setting [$sqlAADAdmin] the SQL server active directory administrator."

            try
            {
                $sqlServerAdmin = Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $resourceGroupName -ServerName $sqlServerName -DisplayName $sqlAADAdmin -ErrorAction Stop
            }
            catch
            {
                Log-Line $_.Exception.Message
            }

            if ($sqlServerAdmin -ne $null)
            {
                Log-Line "Azure SQL server [$sqlServerName] created in resource group [$resourceGroupName] with credentials stored in KeyVault [$keyVaultName] and Azure Active Directory Admin of [$sqlAADAdmin]. Please note these credentials for use in the connection string."
            }
            else
            {
                Log-Line "Error setting the SQL server Azure active directory admin. It is not recommended to use the SQL server without platform administration set."
                Log-Line "Azure SQL server [$sqlServerName] created in resource group [$resourceGroupName] with credentials stored in KeyVault [$keyVaultName]. Please note these credentials for use in the connection string."
            }
            Add-SQLCredentialsToKeyVault -sqlServerName $sqlServerName -keyVaultName $keyVaultName -secretValue $sqlAdmin/$sqlAdminPassword
        }
        else
        {
            Log-Line "Error creating SQL server [$sqlServerName]."
        }
    }
    elseif ($null -ne $script:sqlServer)
    {
        Log-Line "Using existing SQL server [$sqlServerName]."
        $retVal = $true
    }

    return $retVal
}

function Add-SQLCredentialsToKeyVault(){
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $sqlServerName,
        [Parameter(Mandatory=$true)]
        [string]
        $keyVaultName,
        [Parameter(Mandatory=$true)]
        [string]
        $secretValue
    )
    $retval = $true
    try{
            log-line "Converting generated client Secret to secure string"
            $secureSecretvalue = ConvertTo-SecureString  $secretValue -AsPlainText -Force
            Log-Line "Checking for KeyVault [$keyVaultName]"
            $keyVault = Get-AzKeyVault -name $keyVaultName
            if ($null -eq $keyVault){
                Log-Line "KeyVault [$keyVaultName] Not Found , create KeyVault [$keyVaultName] first"
            }else{
                Log-Line "KeyVault [$keyVaultName] Found"
                $secretName = $sqlServerName+"Secret"
                log-line "Adding secure client secret [$secretName] to Key vault[$keyVaultName]"
                $secret = Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -SecretValue $secureSecretvalue
                if ($null -ne $secret){
                    Log-Line "[$secretName]Secret has been added to Keyvault[$keyVaultName] "
                }
            }
        }
    catch{
        $retval = $false
        Log-Line $_.Exception.Message
    }
    return $retVal
}

function Acquire-Sql-Private-Endpoint
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Sql.Server.Model.AzureSqlServerModel]
        $sqlServer,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]
        $subnet,

        [Parameter(Mandatory=$true)] 
        [string]
        $privateSqlEndpointConnectionName,

        [Parameter(Mandatory=$true)] 
        [string]
        $privateSqlEndpointName
    )

    $retVal = $false

    Log-Line "Verifying private endpoint [$privateSqlEndpointName] the SQL server [$sqlServer.ServerName]."

    try
    {
        $script:privateSqlEndpoint = Get-AzPrivateEndpoint -Name $privateSqlEndpointName -ErrorAction Stop
    }
    catch
    {
        Log-Line $_.Exception.Message
    }

    if ($script:privateSqlEndpoint -eq $null)
    {
        Log-Line "Private endpoint [$privateSqlEndpointName] the SQL server [$sqlServerName] not found."
        Log-Line "Creating private endpoint connection [$privateSqlEndpointConnectionName] for SQL server [$sqlServerName]."

        $privateSqlEndpointConnection = New-AzPrivateLinkServiceConnection -Name $privateSqlEndpointConnectionName -PrivateLinkServiceId $sqlServer.ResourceId -GroupId "sqlServer"

        if ($privateSqlEndpointConnection -ne $null)
        {
            Log-Line "Creating private endpoint [$privateSqlEndpointName] for SQL server [$sqlServerName]."
            $script:privateSqlEndpoint = New-AzPrivateEndpoint -ResourceGroupName $resourceGroupName -Name $privateSqlEndpointName -Location $vnet.Location -Subnet $sqlsubnet -PrivateLinkServiceConnection $privateSqlEndpointConnection
            if ($script:privateSqlEndpoint -ne $null)
            {
                Log-Line "Private endpoint [$privateSqlEndpointName] for SQL server [$sqlServerName] created."

                $retVal = $true
            }
        }
        else
        {
            Log-Line "Error creating private SQL endpoint. SQL server is insecure."
        }
    }
    else
    {
        Log-Line "Private endpoint [$privateSqlEndpointName] the SQL server [$sqlServerName] found."
        $retVal = $true
    }

    return $retVal
}

function Establish-Sql-TDE
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlServerName,

        [Parameter(Mandatory=$true)] 
        [string]
        $keyVaultName,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlEncryptKeyName
    )

    $retVal = $false

    $tde = Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $resourceGroupName -ServerName $sqlServerName
    if (($tde -eq $null) -or ($tde.Type -eq "ServiceManaged"))
    {
        Log-Line "Setting permissions on key vault [$keyVaultName] for SQL server [$sqlServerName]."
        Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $script:sqlServer.Identity.PrincipalId -PermissionsToKeys get, wrapKey, unwrapKey -BypassObjectIdValidation

        Log-Line "Adding key [$sqlEncryptKeyName] to SQL server [$sqlServerName]."
        $sqlServerKeyVaultKey = Add-AzSqlServerKeyVaultKey -ResourceGroupName $resourceGroupName -ServerName $sqlServerName -KeyId $script:key.Id

        Log-Line "Setting key [$sqlEncryptKeyName] as the TDE protector for SQL server [$sqlServerName]."
        $sqlServerTDEProtector = Set-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $resourceGroupName -ServerName $sqlServerName -Type AzureKeyVault -KeyId $script:key.Id -Force

        Log-Line "Verifying TDE protector was configured as intended."
        $tde = Get-AzSqlServerTransparentDataEncryptionProtector -ResourceGroupName $resourceGroupName -ServerName $sqlServerName
        $retVal = $true
    }
    else{
        if ($tde -eq $null){
            Log-Line "TDE was not configured. Please review the created resources."
        }else {
            Log-Line "TDE is already configured to use Customer Encrypted Key"
            $retVal = $true
        }
    }
    return $retVal
}

function Establish-PrivateDNS-Registration
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $privateDNSZoneResourceGroupName,

        [Parameter(Mandatory=$true)] 
        [string]
        $sqlServerName,

        [Parameter(Mandatory=$true)] 
        [Microsoft.Azure.Commands.Network.Models.PSPrivateEndpoint]
        $privateSqlEndpoint
    )

    $dnsRecordSet = $false
    $retVal = $false

    try
    {
        Log-Line "Verifying private DNS record set [$sqlServerName] in private zone [privatelink.database.windows.net] in resource group [$privateDNSZoneResourceGroupName]."

        $dnsRecordSet = Get-AzPrivateDnsRecordSet -ResourceGroupName $privateDNSZoneResourceGroupName -ZoneName privatelink.database.windows.net -RecordType A -Name $sqlServerName -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Response.StatusCode -eq "NotFound")
        {
            $dnsRecordSetNotFound = $true
        }
        else
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($dnsRecordSetNotFound -eq $true)
    {
        try
        {
            Log-Line "Private DNS record set [$sqlServerName] in private zone [privatelink.database.windows.net] in resource group [$privateDNSZoneResourceGroupName] not found. Creating."

            $sqlPrivateEndpointCustomDnsConfig = $privateSqlEndpoint.CustomDnsConfigs | where {$_.Fqdn -eq "$sqlServerName.database.windows.net"}
            $privateDnsRecordConfig = New-AzPrivateDnsRecordConfig -IPv4Address $sqlPrivateEndpointCustomDnsConfig.IpAddresses[0]

            New-AzPrivateDnsRecordSet -Name $sqlServerName -RecordType A -ZoneName privatelink.database.windows.net -ResourceGroupName $privateDNSZoneResourceGroupName -Ttl 3600 -PrivateDnsRecords $privateDnsRecordConfig -ErrorAction Stop

            Log-Line "Private DNS record set [$sqlServerName] in private zone [privatelink.database.windows.net] in resource group [$privateDNSZoneResourceGroupName] created."

            $retVal = $true
        }
        catch
        {
            Log-Line $_.Exception.Message
        }
    }
    else
    {
        Log-Line "Private DNS record set [$sqlServerName] in private zone [privatelink.database.windows.net] in resource group [$privateDNSZoneResourceGroupName] found."
        $retVal = $true
    }

    return $retVal
}

function Establish-KeyVault-PrivateDNS-Registration
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $privateDNSZoneResourceGroupName,

        [Parameter(Mandatory=$true)] 
        [string]
        $zoneName,

        [Parameter(Mandatory=$true)] 
        [Microsoft.Azure.Commands.Network.Models.PSPrivateEndpoint]
        $privateEndpoint
    )

    $dnsRecordSet = $false
    $retVal = $true

    foreach ($custromDnsConfig in $privateEndpoint.CustomDnsConfigs)
    {
        $dnsRecordSetName = $custromDnsConfig.Fqdn.Substring(0, ($custromDnsConfig.Fqdn.IndexOf($zoneName.Substring(12))) - 1)

        try
        {
            Log-Line "Verifying private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName]."

            $dnsRecordSet = Get-AzPrivateDnsRecordSet -ResourceGroupName $privateDNSZoneResourceGroupName -ZoneName $zoneName -RecordType A -Name $dnsRecordSetName -ErrorAction Stop
        }
        catch
        {
            if ($_.Exception.Response.StatusCode -eq "NotFound")
            {
                $dnsRecordSetNotFound = $true
            }
            else
            {
                Log-Line $_.Exception.Message
                $retVal = $false
            }
        }

        if ($dnsRecordSetNotFound -eq $true)
        {
            try
            {
                Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName] not found. Creating."

                $privateDnsRecordConfig = New-AzPrivateDnsRecordConfig -IPv4Address $custromDnsConfig.IpAddresses[0]

                New-AzPrivateDnsRecordSet -Name $dnsRecordSetName -RecordType A -ZoneName $zoneName -ResourceGroupName $privateDNSZoneResourceGroupName -Ttl 3600 -PrivateDnsRecords $privateDnsRecordConfig -ErrorAction Stop

                Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName] created."

                $retVal = $true
            }
            catch
            {
                Log-Line $_.Exception.Message
                $retVal = $false
            }
        }
        else
        {
            $retVal = $true
            Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName] found."
        }
    }


    return $retVal
}

Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line "Powershell executing Create-Azure-SQL Version v1.0.0.0 on $currentDate ($currentDateString)"
Log-Line ""
Log-Line "Powershell Version Information"
Log-Line ""
Log-VersionTable
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""
Log-Line "subscriptionName: [$subscriptionName]"
Log-Line "resourceGroupName: [$resourceGroupName]"
Log-Line "keyVaultName: [$keyVaultName]"
Log-Line "sqlServerRootName: [$sqlServerRootName]"
Log-Line "sqlEncryptKeyName: [$sqlEncryptKeyName]"
Log-Line "sqlEncryptCertName: [$sqlEncryptCertName]"
Log-Line "subnetName: [$subnetName]"
Log-Line "sqlsubnetName: [$sqlsubnetName]"
Log-Line "privateDNSZoneSubscription: [$privateDNSZoneSubscription]"
Log-Line "privateDNSZoneResourceGroupName: [$privateDNSZoneResourceGroupName]"
Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""


    if ((Establish-AzureContext -subscriptionName $subscriptionName) -and
        (Acquire-ResourceGroup -resourceGroupName $resourceGroupName -subscriptionName $subscriptionName) -and
        (Establish-Resource-Names -resourceGroup $resourceGroup) -and
        (Acquire-VirtualNetwork -subscriptionName $subscriptionName) -and
        (Acquire-SubNet -vnet $vnet -subnetName $subnetName) -and
        (Acquire-KeyVault -resourceGroupName $resourceGroupName -vnet $vnet -keyVaultName $keyVaultName) -and
        (Acquire-KeyVault-Private-Endpoint -resourceGroupName $resourceGroupName -keyvault $keyVault -vnet $vnet -subnet $subnet -privateKeyVaultEndpointConnectionName $privateKeyVaultEndpointConnectionName -privateKeyVaultEndpointName $privateKeyVaultEndpointName) -and 
		(Establish-AzureContext -subscriptionName $privateDNSZoneSubscription) -and
        (Establish-KeyVault-PrivateDNS-Registration -privateDNSZoneResourceGroupName $privateDNSZoneResourceGroupName -zoneName "privatelink.vaultcore.azure.net" -privateEndpoint $privateKeyVaultEndpoint) -and
        (Establish-AzureContext -subscriptionName $subscriptionName))
    {
        $vnetName = $vnet.name

        if ((Acquire-KeyVaultKey -keyVault $keyVault -sqlEncryptKeyName $sqlEncryptKeyName) -and
            (Acquire-KeyVaultCertificate -keyVault $keyVault -sqlEncryptCertName $sqlEncryptCertName) -and
            (Acquire-SqlSubNet -vnet $vnet -subnetName $subnetName))
        {
            Configure-KeyVault -keyVault $keyVault

            if ((Acquire-Sql-Server -resourceGroupName $resourceGroupName -sqlServerName $sqlServerName -sqlAdmin $sqlAdmin -sqlAdminPassword $sqlAdminPassword) -and
                (Acquire-Sql-Private-Endpoint -resourceGroupName $resourceGroupName -sqlServer $sqlServer -vnet $vnet -subnet $sqlsubnet -privateSqlEndpointConnectionName $privateSqlEndpointConnectionName -privateSqlEndpointName $privateSqlEndpointName) -and
                (Establish-Sql-TDE -resourceGroupName $resourceGroupName -sqlServerName $sqlServerName -keyVaultName $keyVaultName -sqlEncryptKeyName sqlEncryptKeyName))
            {
                if ((Establish-AzureContext -subscriptionName $privateDNSZoneSubscription) -and
                    (Establish-PrivateDNS-Registration -privateDNSZoneResourceGroupName $privateDNSZoneResourceGroupName -sqlServerName $sqlServerName -privateSqlEndpoint $privateSqlEndpoint))
                {
                    Log-Line "created on SQL server [$sqlServerName] in resource group [$resourceGroupName]."
                    $success = $true
                }
            }
        }
    }


if ($success -eq $true)
{
    Log-Line "Execution completed successfully."
}
else
{
    throw "Execution failed. Review logs."
}
