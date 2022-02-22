<#
.SYNOPSIS
	Creates an Azure Kubernetes Service.
.DESCRIPTION
    Creates an Azure Kubernetes Service with availability zones and encrypted with customer managed keys.

    Fiserv security requires that:
        Key vault is not accessable from a public endpoint.
        Keys must be RSA-HSM
        AKS us a customer managed key for encryption.
        AKS is not accessable from a public endpoint.

    The script will: 
        Validate that the subscription and resource group exist. 
        Find the appropriate virtual network and sub-network for deployment. It these are not found the script will end.
        Ensure that there is a key vault to hold the final key encryption key for the AKS.
        Ensure that there is a key encryption key in the key vault and that the key meets Fiserv security requirements.
        Ensure that there is a disk encryption set for encryption of the AKS.
        Ensure that there is a correct access policy for the disk encryption set system-assigned identity to the key encryption key in the key vault.
        Ensure that there is a private endpoint for the key vault.
        Ensure that there is a DNS entry for the key vault.
        Ensure that private access for the key vault is disabled.
        Verifies that the ACR specified is found in the resource group.
        Create a private AKS with customer managed key for encryption.
        Assign the acrPull role to the managed identity of the AKS to the ACR if specified.
        Assign the Network Contrinutor role to the managed identity of the AKS.
        Assign the owner, contributor and reader groups their respective roles on the AKS, ACR and MC_ (managed cluser) resource group.
		Enable AAD for AKS.

.NOTES
	File Name : Create-Azure-AKS.ps1
	Author    : Phil Schroder - phillip.schroder@fiserv.com
	Requires  : PowerShell Version 2.0
	Born      : 07/09/2020 - Phil Schroder
.EXAMPLE
.PARAMETER subscriptionName
    Required: The name of the subscription that will contain the VM.
.PARAMETER applicationId
    Required: The application id of the application registration that will be used to deploy the AKS cluster.
.PARAMETER applicationSecret
    Required: The application secret for the application registration that will be used to deploy the AKS cluster.
.PARAMETER resourceGroupName
    Required: The name of the resouce group within which the SQL server will be created.
.PARAMETER aksName
    Required: The name of the AKS cluster.
.PARAMETER aksOwnersGroupName
    Optional: The name of ad Azure Active Directory group that will be assigned as an owner of the cluster..
.PARAMETER aksContributorsGroupName
    Optional: The name of ad Azure Active Directory group that will be assigned as a contributor of the cluster..
.PARAMETER aksReadersGroupName
    Optional: The name of ad Azure Active Directory group that will be assigned as a reader of the cluster..
.PARAMETER subnetName
    Required: The name of the subnet within the vnet within which the AKS and ACR will be created.
.PARAMETER keyVaultName
    Required: The name of the key vault that contains the encrypting key for the AKS. If not found the key vault and/or key will be created.
.PARAMETER aksEncryptKeyName
    Optional: The name of the key within key vault that will be used for AKS encryption. Defaults to AKSEncryptKey-HSM. 
.PARAMETER acrName
    Optional: The name of an ACR. If specified and the ACR is found the managed identity of the AKS will be given acrPull role to the ACR.
.PARAMETER privateDNSZoneSubscription
    Optional: The name of the subscription that has the privatelink.azurecr.iot private DNS zone.
.PARAMETER privateDNSZoneResourceGroupName
    Optional: The name of the resource group that has the privatelink.azurecr.iot private DNS zone.
.PARAMETER servicePrincipalName
    Required: The name of the service principal.
#>

param
(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the subscription that will contain the Azure SQL.")] 
    [string]
    $subscriptionName,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the applicaiton id of the application registration that will be used to deploy the AKS cluster.")] 
    [string]
    $applicationId,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the secret for the application registration that will be used to deploy the AKS cluster.")] 
    [string]
    $applicationSecret,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the resource group witin which the Azure SQL will be created.")] 
    [string]
    $resourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the AKS cluster.")]
    [string]
    $aksName,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the name of ad Azure Active Directory group that will be assigned as an owner of the cluster.")]
    [string]
    $aksOwnersGroupName,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the name of ad Azure Active Directory group that will be assigned as a contributor of the cluster.")]
    [string]
    $aksContributorsGroupName,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the name of ad Azure Active Directory group that will be assigned as a reader of the cluster.")]
    [string]
    $aksReadersGroupName,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the subnet within the vnet in which the AKS will be created.")] 
    [string]
    $subnetName,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the key vault that will store the encrypting key for the AKS.")] 
    [string]
    $keyVaultName,

    [Parameter(Mandatory = $false)] 
    [string]
    $aksEncryptKeyName = "AKSEncryptKey-HSM",

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the ACR.")]
    [string]
    $acrName,

    [Parameter(HelpMessage = "Enter the name of the subscription that has the privatelink.azurecr.io private DNS zone for the ACR private link registration. Defaults to ETG-Hub-Production-East2.")] 
    [string]
    $privateDNSZoneSubscription = "ETG-Hub-Production-East2",

    [Parameter(HelpMessage = "Enter the name of the resource group that has the privatelink.azurecr.io private DNS zone for ACR private link registration. Defaults to rg-dns-prod-etg-hub-useast2-1.")] 
    [string]
    $privateDNSZoneResourceGroupName = "rg-dns-prod-etg-hub-useast2-1",
	
    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the Service Principal.")] 
    [string]
    $servicePrincipalName,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the VM size for nodes in the pool")] 
    [string]
    $nodeVmSize = 'Standard_D4s_v3',
    
    [Parameter(Mandatory = $false, HelpMessage = "Enter number of nodes to be created")]
    [ValidateRange(1, 1000)] 
    [int]
    $nodeCount = 1
)    

#
# Set the file system directory from the Powershell FileSystem provider location.
#
# When you change directory in Powershell it does not change the underlying file system
# directory but instead changes the location in the Powershell FileSystem provider.
#
[IO.Directory]::SetCurrentDirectory((Convert-Path (Get-Location -PSProvider FileSystem)))

$success = $false
$currentDate = Get-Date
$currentDateString = $currentDate.ToString("yyyyMMdd")

function Log-Line {
    param
    (
        [Parameter(Mandatory = $false)]
        [string]
        $logMessage
    )

    $timeStamp = Get-Date -Format 'HH:mm:ss.fff';

    Write-Host -NoNewline -Separator '' -ForegroundColor Green $timeStamp " "
    Write-Host $logMessage
}

function Log-Lines {
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        $logMessages,

        [string]
        $color
    )

    process {
        foreach ($logMessage in $logMessages) {
            $timeStamp = Get-Date -Format 'HH:mm:ss.fff';

            Write-Host -NoNewline -Separator '' -ForegroundColor $color $timeStamp " "
            Write-Host $logMessage -ForegroundColor $color
        }
    }
}

function Log-VersionTable {
    foreach ($key in $psVersionTable.Keys) {
        $value = $psVersionTable[$key]
        Log-Line "$key : $value"
    }
}

function Establish-AzureContext {
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]
        $subscriptionName
    )

    $retVal = $false

    Log-Line "Setting Azure context to subscription [$subscriptionName]."

    try {
        $subscription = Get-AzSubscription -SubscriptionName $subscriptionName -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne "NotFound") {
            Log-Line $_.Exception.Message
        }
    }

    if ($null -ne $subscription) {
        #
        # Set the Azure context to point to the subscription so that all subsequent commands will be within the subscription.
        #   
        $context = Set-AzContext -SubscriptionObject $subscription
        Log-Line $context.Name
		
        $script:azContext = az account set --subscription $subscriptionName
        $script:azContextDisplay = az account show
        Log-Line "az CLI context [$script:azContextDisplay]"

        $retVal = $true
    }
    else {
        Log-Line "Subscription [$subscriptionName] not found."
    }

    return $retVal
}

function Acquire-ResourceGroup {
    param 
    (
        [Parameter(Mandatory = $true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory = $true)]
        [string]
        $subscriptionName
    )

    $retVal = $false

    #
    # Get the resource group to verify it exists and use it throughout the script.
    #
    Log-Line "Verifying resource group [$resourceGroupName] exists in subscription [$subscriptionName]."
    try {
        $script:resourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message.EndsWith("does not exist.") -eq $false) {
            Log-Line $_.Exception.Message
        }
    }

    if ($null -ne $script:resourceGroup) {
        Log-Line "Resource group [$resourceGroupName] found in subscription [$subscriptionName]."
        $retVal = $true
    }
    else {
        Log-Line "Resource group [$resourceGroupName] not found in subscription [$subscriptionName]."
    }

    return $retVal
}

function Acquire-VirtualNetwork {
    param
    (
        [Parameter(Mandatory = $true)] 
        [string]
        $subscriptionName
    )

    $retVal = $false

    Log-Line "Verifying virtual network exists in subscription [$subscriptionName]."

    try {
        $script:vnet = Get-AzVirtualnetwork -ErrorAction Stop | where { $_.Name.Contains("spoke") } 
    }
    catch {
        if ($_.Exception.Response.StatusCode -ne "NotFound") {
            Log-Line $_.Exception.Message
        }
    }

    if ($null -ne $script:vnet) {
        Log-Line "Virtual network found in subscription [$subscriptionName]."
        $retVal = $true
    }
    else {
        Log-Line "Cant find virtual network in subscription [$subscriptionName]."
    }

    return $retVal
}

function Acquire-SubNet {
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory = $true)]
        [string]
        $subnetName
    )

    $retVal = $false
    $vnetName = $vnet.Name

    Log-Line "Verifying subnet [$subnetName] exists in virtual network [$vnetName]."
    $script:subnet = $vnet.Subnets | where-object { $_.name -eq $subnetName }

    if ($null -ne $script:subnet) {
        Log-Line "Subnet [$subnetName] in virtual network [$vnetName] found."
        $retVal = $true
    }
    else {
        Log-Line "Cant find subnet [$subnetName] in virtual network [$vnetName]."
    }


    return $retVal
}

function Acquire-KeyVault {
    param
    (
        [Parameter(Mandatory = $true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory = $true)] 
        [string]
        $keyVaultName,
		
        [Parameter(Mandatory = $true)] 
        [string]
        $servicePrincipalName,

        #
        # Kludge: Refer to Description above.
        #
        [switch]
        $isTempKeyVault
    )

    $retVal = $false
    $keyVaultNotFound = $false
    $removedKeyVaultFound = $false
    
    Log-Line "Verifying key vault [$keyVaultName] exists in resource group [$resourceGroupName]."

    try {
        $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults `
            -ExpandProperties -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message.Contains("not found") -eq $true) {
            $removedKeyVault = Get-AzKeyVault -VaultName $keyVaultName -Location $vnet.Location -InRemovedState
            if ($null -eq $removedKeyVault) {
                $keyVaultNotFound = $true
            }
            else {
                $removedKeyVaultFound = $true
            }
        }
        else {
            Log-Line $_.Exception.Message
        }
    }


    if ($keyVaultNotFound -eq $true) {
        Log-Line "Key vault [$keyVaultName] not found in resource group [$resourceGroupName]. Creating."

        try {
            $keyVault = New-AzKeyVault -ResourceGroupName $resourceGroupName -Name $keyVaultName -Location $vnet.Location `
                -EnabledForDiskEncryption -Sku premium -ErrorAction Stop
        }
        catch {
            Log-Line $_.Exception.Message
        }

        if ($null -ne $keyVault) {
            Log-Line "key vault [$keyVaultName] created."
            $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults `
                -ExpandProperties -ErrorAction Stop
        }
        else {
            Log-Line "Error creating key vault [$keyVaultName] in resource group [$resourceGroupName]."
        }
    }
    elseif ($true -eq $removedKeyVaultFound) {
        Log-Line "Key vault [$keyVaultName] found in removed state. Undoing removal."
        Undo-AzKeyVaultRemoval -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -Location $vnet.Location
        $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults `
            -ExpandProperties -ErrorAction Stop
        if ($null -ne $keyVault) {
            Log-Line "key vault [$keyVaultName] removal undone."
        }
    }
    elseif ($null -ne $keyVault) {
        Log-Line "key vault [$keyVaultName] found in resource group [$resourceGroupName]."
    }

    if ($null -ne $keyVault) {
        $retVal = $true
        $azADServicePrincipal = Get-AzADServicePrincipal -DisplayName $servicePrincipalName;
        # Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -ObjectId $servicePrincipalId `
        #     -BypassObjectIdValidation -PermissionsToKeys wrapKey, unwrapKey, get -ErrorAction Stop
        Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -ObjectId $azADServicePrincipal.Id `
            -BypassObjectIdValidation -PermissionsToKeys wrapKey, unwrapKey, get, create -ErrorAction Stop;

        Update-AzKeyVaultNetworkRuleSet -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -DefaultAction Allow -ErrorAction Stop;

        if ($isTempKeyVault -eq $true) {
            $script:tempKeyVault = $keyVault
        }
        else {
            $script:keyVault = $keyVault
        }
    }
    return $retVal
}
function Acquire-KeyVault-Private-Endpoint {
    param
    (
        [Parameter(Mandatory = $true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]
        $subnet
    )

    $retVal = $false
    $keyVaultName = $keyVault.Name
    $privatekeyVaultEndpointConnectionName = "pec-$keyVaultName"
    $privateKeyVaultEndpointName = "pe-$keyVaultName"

    $script:privateKeyVaultEndpoint = Get-AzPrivateEndpoint -Name $privateKeyVaultEndpointName

    if ($script:privateKeyVaultEndpoint -eq $null) {
        $keyVaultName = $keyVault.ResourceName

        Log-Line "Private endpoint [$privateKeyVaultEndpointName] for key vault [$keyVaultName] not found."
        Log-Line "Creating private endpoint connection [$privatekeyVaultEndpointConnectionName] for key vault [$keyVaultName]."
        $privateKeyVaultEndpointConnection = New-AzPrivateLinkServiceConnection -Name $privatekeyVaultEndpointConnectionName `
            -PrivateLinkServiceId $keyVault.ResourceId -GroupId "vault" 2>$null

        if ($privateKeyVaultEndpointConnection -ne $null) {
            Log-Line "Creating private endpoint [$privatekeyVaultEndpointName] for key vault [$keyVaultname]."
            $script:privateKeyVaultEndpoint = New-AzPrivateEndpoint -ResourceGroupName $resourceGroupName -Name $privateKeyVaultEndpointName `
                -Location $vnet.Location -Subnet $subnet -PrivateLinkServiceConnection $privateKeyVaultEndpointConnection
            if ($script:privateKeyVaultEndpoint -ne $null) {
                Log-Line "Private endpoint [$privatekeyVaultEndpointName] for key vault [$keyVaultname] created."
                $retVal = $true
            }
            else {
                Log-Line "Error creating private KeyVault endpoint. KeyVault is insecure."
            }
        }
        else {
            Log-Line "Error creating private endpoint KeyVault connection. KeyVault is insecure."
        }
    }
    else {
        Log-Line "Private endpoint [$privateKeyVaultEndpointName] key vault [$keyVaultName] found."
        $retVal = $true
    }

    return $retVal
}

function Configure-KeyVault {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $keyVaultName,

        [Parameter(Mandatory = $true)] 
        [string]
        $identityName,

        [Parameter(Mandatory = $true)] 
        [string]
        $identityId
    )

    $retVal = $false

    try {
        Log-Line "Setting access policy for identity [$identityName] to wrapKey, unwrapKey, get, create."

        Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -ObjectId $identityId `
            -PermissionsToKeys wrapKey, unwrapKey, get, create -ErrorAction Stop -BypassObjectIdValidation

        Log-Line "Access policy for identity [$identityName] set."

        $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties

        try {
            Log-Line "Verifying key vault [$keyVaultName] is the premium SKU."
            if ($keyVault.Properties.sku.name -ne "Premium") {
                Log-Line "Premium SKU is required for hardware encryption keys. Upgrading key vault [$keyVaultName] to premium."

                $keyVault.Properties.sku.name = "Premium"
                $keyVault | Set-AzResource -Force
            }
            else {
                Log-Line "key vault [$keyVaultName] is a premium SKU."
            }

            Log-Line "Verifying key vault [$keyVaultName] supports disk encryption."
            if ($keyVault.Properties.enabledForDiskEncryption -ne $true) {
                Log-Line "key vault [$keyVaultName] does not support disk encryption. Enabling."

                $keyVault.Properties.enabledForDiskEncryption = $true
                $keyVault | Set-AzResource -Force
            }
            else {
                Log-Line "key vault [$keyVaultName] supports disk encryption."
            }

            Log-Line "Verifying key vault [$keyVaultName] is enabled for soft delete."
            if ($keyVault.Properties.enableSoftDelete -ne $true) {
                Log-Line "key vault [$keyVaultName] is not enabled for soft delete. Enabling."
    
                $softDelete = Add-Member -InputObject $keyVault.Properties -MemberType "NoteProperty" -Name "enableSoftDelete" -Value "true"
                $keyVault | Set-AzResource -Force
            }
            else {
                Log-Line "key vault [$keyVaultName] is enabled for soft delete."
            }

            Log-Line "Verifying key vault [$keyVaultName] is enabled for purge protection."
            if ($keyVault.Properties.enablePurgeProtection -ne $true) {
                Log-Line "key vault [$keyVaultName] is not enabled for purge protection. Enabling."

                $purgeProtection = Add-Member -InputObject $keyVault.Properties -MemberType "NoteProperty" -Name "enablePurgeProtection" -Value "true"
                $keyVault | Set-AzResource -Force
            }
            else {
                Log-Line "key vault [$keyVaultName] is enabled for purge protection."
            }

            $script:keyVault = $keyVault

            $retVal = $true
        }
        catch {
            Log-Line $_.Exception.Message
            Log-Line "Error configuring key vault [$keyVaultName]."
        }
    }
    catch {
        Log-Line $_.Exception.Message
        Log-Line "Error setting access policy for user-assigned identity [$acrName]."
    }
    
    return $retVal
}

function Acquire-KeyVaultKey {
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory = $true)] 
        [string]
        $aksEncryptKeyName
    )

    $retVal = $false
    $keyVaultName = $keyVault.Name

    Log-Line "Verifying Key [$aksEncryptKeyName] exists in key vault [$keyVaultName]."
    $script:key = Get-AzKeyVaultKey -VaultName $keyVaultName -Name $aksEncryptKeyName

    if ($null -eq $key) {
        #
        # If the key is not found create it.
        #
        Log-Line "Key [$aksEncryptKeyName] not found in key vault [$keyVaultName]. Creating."
        $expiryDate = (Get-Date).AddYears(2)

        Log-Line "Key [$aksEncryptKeyName] being created will expire on [$expiryDate]."
		
        $script:key = Add-AzKeyVaultKey -VaultName $keyVaultName -Name  $aksEncryptKeyName -Destination HSM -Expires $expiryDate
        
        if ($null -ne $key) {
            Log-Line "Key [$aksEncryptKeyName] created."
        }
        else {
            Log-Line "Error creating Key [$aksEncryptKeyName]."
        }         
    }
    else {
        Log-Line "Key [$aksEncryptKeyName] found in key vault [$keyVaultName]."
    }

    #
    # Verify the key type.
    #
    if ($null -ne $script:key) {
        Log-Line "Verifying Key [$aksEncryptKeyName] is of the correct type."
        $keyType = $script:key.Attributes.KeyType

        if ($keyType -eq "RSA-HSM") {
            $retVal = $true
        }
        else {
            Log-Line "Key [$aksEncryptKeyName] is of type [$keyType] and cannot be used. Please specify a different key that is of type RSA-HSM. You may also specify a key that does not exist and it will be created with the proper type."
        }
    }

    return $retVal
}

function Acquire-ACR {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory = $true)] 
        [string]
        $acrName
    )

    $retVal = $false

    if ($null -ne $acrName) {
        try {
            Log-Line "Verifying ACR [$acrName] exists in resource group [$resourceGroupName]."

            $script:acr = Get-AzContainerRegistry -ResourceGroupName $resourceGroupName -Name $acrName -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message.Contains("not found.") -eq $false) {
                Log-Line $_.Exception.Message
            }
        }

        if ($null -ne $script:acr) {
            Log-Line "ACR [$acrName] found in resource group [$resourceGroupName]."
            $retVal = $true
        }
        else {
            Log-Line "Cant find ACR [$acrName] in resource group [$resourceGroupName]."
        }
    }
    else {
        Log-Line "No ACR specified. AKS will not be given acrPull access to any registry."
        $retVal = $true
    }

    return $retVal
}

function Acquire-DiskEncryptionSet {
    param
    (
        [Parameter(Mandatory = $true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory = $true)] 
        [string]
        $aksName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.KeyVault.Models.PSKeyVaultKey]
        $key
    )

    $retVal = $false
    $desNotFound = $false
    $desName = "des-$aksName"
    
    Log-Line "Verifying disk encryption set [$desName] exists in resource group [$resourceGroupName]."

    try {
        $script:diskEncryptionSet = Get-AzDiskEncryptionSet -ResourceGroupName $resourceGroupName -Name $desName -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message.Contains("Not Found") -eq $true) {
            $desNotFound = $true
        }
        else {
            Log-Line $_.Exception.Message
        }
    }


    if ($desNotFound -eq $true) {
        try {
            Log-Line "Creating disk encryption set [$desName] in resource group [$resourceGroupName]"
            $diskEncryptionSetConfig = New-AzDiskEncryptionSetConfig -Location $vnet.Location -SourceVaultId $keyVault.ResourceId -KeyUrl $key.Id -IdentityType SystemAssigned
            $script:diskEncryptionSet = New-AzDiskEncryptionSet -Name $desName -ResourceGroupName $resourceGroupName -InputObject $diskEncryptionSetConfig
        }
        catch {
            Log-Line $_.Exception.Message
        }

        if ($null -ne $script:diskEncryptionSet) {
            Log-Line "Disk encryption set [$desName] in resource group [$resourceGroupName] created."

            $retVal = $true
        }
        else {
            Log-Line "Error creating disk encryption set [$desName] in resource group [$resourceGroupName]."
        }
    }
    else {
        Log-Line "Disk encryption set [$desName] in resource group [$resourceGroupName] found."
        $retVal = $true
    }

    return $retVal
}

function Acquire-AKS {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory = $true)] 
        [string]
        $aksName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]
        $subnet,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSDiskEncryptionSet]
        $diskEncryptionSet,

        [Parameter(Mandatory = $true)] 
        [string]
        $nodeVmSize,
    
        [Parameter(Mandatory = $true)]
        [int]
        $nodeCount
    )

    $retVal = $false
    $aksNotFound = $false
    $diskEncryptionSetId = $diskEncryptionSet.Id
    $location = $resourceGroup.Location
    Log-Line "Acquire-AKS Location is [$location]"
	
    try {
        $script:aks = Get-AzAks -ResourceGroupName $resourceGroupName -Name $aksName -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message.Contains("not found.") -eq $true) {
            $aksNotFound = $true
        }
        else {
            Log-Line $_.Exception.Message
        }
    }

    if ($aksNotFound -eq $true) {

        $subnetId = $subnet.Id
        $loginSuccessfull = $true

        $azLogin = "az login --service-principal -u $applicationId -p $applicationSecret --tenant cdf226d7-79fd-4290-a3a7-996968201a26"
        Log-Line "Azure CLI login [$azLogin]."

        #
        # Direct std out and std-err to null otherwise, because of certificate error on local laptop - 
        # which is the self-hosted agent, script will show failure in pipeline even though login worked.
        #
        $arguments = @(
            "login",
            "--service-principal",
            "-u", "$applicationId", 
            "-p", "$applicationSecret",
            "--tenant", "cdf226d7-79fd-4290-a3a7-996968201a26"
        );

        $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
            -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
        
        if ($process.ExitCode -ne 0) {
            $loginSuccessfull = $false
            Log-Line "az login exited with a non 0 exit code";
            $errorMessage = Get-Content "stderr.txt" -Raw
            Log-Line "$errorMessage"
        }
        
        if ($loginSuccessfull -eq $true) {
            Log-Line "Azure CLI login [$azLogin] succeeded."

            $script:azContextDisplay = az account show
            Log-Line "az CLI context [$script:azContextDisplay]"

            try {
                Log-Line "Creating AKS [$aksName]. This will take some time (10-20 minutes). The script will check status every 3 minutes.";
               				
                #
                # Must use Azure CLI here because Azure Powershell does not support zones.
                #
                $arguments = @(
                    "aks", "create",
                    "--resource-group", "$resourceGroupName", 
                    "--name", "$aksName",
                    "--location", "$location",
                    "--load-balancer-sku", "standard", 
                    "--vm-set-type", "VirtualMachineScaleSets",
                    "--node-osdisk-diskencryptionset-id", "$diskEncryptionSetId",
                    "--node-count", "$nodeCount", 
                    "--node-vm-size", "$nodeVmSize",
                    "--zones", "1 2 3", 
                    "--enable-private-cluster",
                    "--enable-managed-identity",
                    "--network-plugin", "azure",
                    "--vnet-subnet-id", "$subnetId",
                    "--docker-bridge-address", "172.17.0.1/16",
                    "--dns-service-ip", "10.2.0.10",
                    "--service-cidr", "10.2.0.0/24",
                    "--no-wait",
                    "--no-ssh-key",
                    "--yes"                    
                );
                Log-Line "az $($arguments -join ' ')";
                $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
                    -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";

                if ($process.ExitCode -eq 0) {
                    #
                    # Check provisioning state. One of: Succeeded / Failed / Upgrading / Updating / Creating / Scaling / Deleting / Migrating
                    #
                    $attempts = 0
                    do {
                        if ($attempts -ge 60) {
                            Log-Line "Timed out checking provisioning state" 
                            return false;
                        }
                        $script:aks = Get-AzAks -ResourceGroupName $resourceGroupName -Name $aksName -ErrorAction Stop
                        $aksProvisioningState = $script:aks.ProvisioningState

                        Log-Line "AKS [$aksName] is [$aksProvisioningState]."
                        Start-Sleep -Milliseconds 30000
                        $attempts++;
                    }
                    while ($script:aks.ProvisioningState -ne "Failed" -and $script:aks.ProvisioningState -ne "Succeeded" -and $attempts -lt 60)

                    if ($script:aks -ne $null -and $script:aks.ProvisioningState -eq "Succeeded") {
                        $retVal = $true
                        Log-Line "AKS [$aksName] created in resource group [$resourceGroupName]."
                    }
                }
                else {
                    Log-Line "az aks create exited with a non 0 exit code";
                    Log-Line "Error creating AKS [$aksName]."
                    $errorMessage = Get-Content "stderr.txt" -Raw
                    Log-Line "$errorMessage"
                }
            }
            catch {
                Log-Line $_.Exception.Message
            }
        }
        else {
            Log-Line "Error on az login."
        }
    }
    elseif ($null -ne $script:aks) {
        Log-Line "AKS [$aksName] already exists."

        $retVal = $true
    }

    return $retVal
}

function Acquire-KeyVaultAccessPolicyAndRole {
    param
    (
        [Parameter(Mandatory = $true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory = $true)] 
        [string]
        $virtualMachineName,


        [Parameter(Mandatory = $true)] 
        [string]
        $keyVaultName,

        [Parameter(Mandatory = $true)] 
        [Microsoft.Azure.Commands.Compute.Automation.Models.PSDiskEncryptionSet]
        $diskEncryptionSet
    )
    $retVal = $false

    Log-Line "Setting key vault access policy for disk encryption set [$virtualMachineName-des] on key vault [$keyVaultName]."
    $keyVaultAccessPolicy = Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ObjectId $diskEncryptionSet.Identity.PrincipalId -PermissionsToKeys wrapkey, unwrapkey, get

    Log-Line "Key vault access policy for disk encryption set [$virtualMachineName-des] on key vault[$keyVaultName] set."

    Get-AzRoleAssignment -ResourceName $keyVaultName -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.KeyVault/vaults" `
        -ObjectId $diskEncryptionSet.Identity.PrincipalId -RoleDefinitionName "Reader"

    Log-Line "Creating reader role assignmnet on keyvault [$keyVaultName] for disk encryption set [$virtualMachineName-des]."

    $keyVaultRoleAssignment = New-AzRoleAssignment -ResourceName $keyVaultName -ResourceGroupName $resourceGroupName -ResourceType "Microsoft.KeyVault/vaults" `
        -ObjectId $diskEncryptionSet.Identity.PrincipalId -RoleDefinitionName "Reader"
    if ($null -ne $keyVaultRoleAssignment) {
        Log-Line "Reader role assignmnet on keyvault [$keyVaultName] for disk encryption set [$virtualMachineName-des] created."

        $retVal = $true
    }

    return $retVal
}

function Establish-AKS-ManagedIdentity-Roles {
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Aks.Models.PSKubernetesCluster]
        $aks,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.ContainerRegistry.PSContainerRegistry]
        $acr,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet
    )

    $retVal = $false
    $roleAssignmentNotFound = $false
    $aksName = $aks.Name
    $agentPoolManagedIdentity = Get-AzADServicePrincipal -DisplayName "$aksName-agentpool"
    Log-Line "Establish-AKS-ManagedIdentity-Roles vnet: [$vnet.Id] "
    Log-Line "Establish-AKS-ManagedIdentity-Roles function end"
    if ((Establish-Role -ObjectName $aks.Name -objectId $aks.Identity.PrincipalId -roleName "Network Contributor" -scope $vnet.Id) -and
        (Establish-Role -ObjectName $agentPoolManagedIdentity.DisplayName -objectId $agentPoolManagedIdentity.Id -roleName "acrPull" -scope $acr.Id)) {
        $retVal = $true
    }

    return $retVal
}

function Establish-Aks-Group-Role {
    param
    (
        [Parameter(Mandatory = $false)]
        [string]
        $groupName,

        [Parameter(Mandatory = $true)]
        [string]
        $roleName,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Aks.Models.PSKubernetesCluster]
        $aks
    )

    $retVal = $false

    if ([System.String]::IsNullOrEmpty($groupName) -ne $true) {
        Log-Line "Establish-Aks-Group-Role groupName: [$groupName] "
        $group = Get-AzADGroup -DisplayName  $groupName
        $nodeResourceGroup = Get-AzResourceGroup -Name $aks.NodeResourceGroup
        Log-Line "Establish-Aks-Group-Role group: [$group] nodeResourceGroup: [$nodeResourceGroup]"
        if ($group -ne $null) {
            if ((Establish-Role -ObjectName $groupName -objectId $group.Id -roleName $roleName -scope $aks.Id) -and
                (Establish-Role -ObjectName $groupName -objectId $group.Id -roleName $roleName -scope $nodeResourceGroup.ResourceId)) {
                $retVal = $true
            }
        }
        else {
            Log-Line "Group [$groupName] not found."
        }
    }
    else {
        $retVal = $true
    }

    return $retVal
}

function Establish-Role {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $objectName,

        [Parameter(Mandatory = $true)]
        [string]
        $objectId,

        [Parameter(Mandatory = $true)]
        [string]
        $roleName,

        [Parameter(Mandatory = $true)]
        [string]
        $scope
    )

    $retVal = $false
    Log-Line "Establish-Role role [$roleName] ObjectId:[$objectId] scope:[$scope]"
    $role = Get-AzRoleDefinition -Name $roleName

    if ($role -ne $null) {
        try {
            #$roleAssignment = Get-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop
            $roleAssignment = $null

            if ($roleAssignment -eq $null) {
                try {
                    Log-Line "Assgining role [$roleName] for scope [$scope] to object [$objectName]."

                    $roleAssignment = New-AzRoleAssignment -ObjectId $objectId -RoleDefinitionName $roleName -Scope $scope -ErrorAction Stop
                }
                catch {
                    
                    if ($_.Exception.Message.Contains("already exists") -eq $true) {
                        Log-Line "Role [$roleName] for scope [$scope] to object [$objectName] already assigned."
                        $retVal = $true
                    }
                    else {
                        Log-Line $_.Exception.Message
                        #$retVal = $true
                    }
                }

                if ($roleAssignment -ne $null) {
                    Log-Line "Role [$roleName] for scope [$scope] to object [$objectName] assigned."
                    $retVal = $true
                }
                elseif ($retVal -eq $false) {
                    Log-Line "Error assigning [$roleName] for scope [$scope] to object [$objectName]."
                }
            }
            else {
                Log-Line "Role [$roleName] for scope [$scope] to object [$objectName] already assigned."
                $retVal = $true
            }
        }
        catch {
            Log-Line $_.Exception.Message
            Log-Line "Error checking for role assignment."
        }
    }
    else {
        Log-Line "Role [$roleName] not found."
    }

    return $retVal
}

function Establish-PrivateDNS-Registration {
    param
    (
        [Parameter(Mandatory = $true)] 
        [string]
        $privateDNSZoneResourceGroupName,

        [Parameter(Mandatory = $true)] 
        [string]
        $zoneName,

        [Parameter(Mandatory = $true)] 
        [Microsoft.Azure.Commands.Network.Models.PSPrivateEndpoint]
        $privateEndpoint
    )

    $dnsRecordSet = $false
    $retVal = $true

    foreach ($custromDnsConfig in $privateEndpoint.CustomDnsConfigs) {
        $dnsRecordSetName = $custromDnsConfig.Fqdn.Substring(0, ($custromDnsConfig.Fqdn.IndexOf($zoneName.Substring(12))) - 1)

        try {
            Log-Line "Verifying private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName]."

            $dnsRecordSet = Get-AzPrivateDnsRecordSet -ResourceGroupName $privateDNSZoneResourceGroupName -ZoneName $zoneName `
                -RecordType A -Name $dnsRecordSetName -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq "NotFound") {
                $dnsRecordSetNotFound = $true
            }
            else {
                Log-Line $_.Exception.Message
                $retVal = $false
            }
        }

        if ($dnsRecordSetNotFound -eq $true) {
            try {
                Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName] not found. Creating."

                $privateDnsRecordConfig = New-AzPrivateDnsRecordConfig -IPv4Address $custromDnsConfig.IpAddresses[0]

                New-AzPrivateDnsRecordSet -Name $dnsRecordSetName -RecordType A -ZoneName $zoneName -ResourceGroupName $privateDNSZoneResourceGroupName `
                    -Ttl 3600 -PrivateDnsRecords $privateDnsRecordConfig -ErrorAction Stop

                Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [$zoneName] in resource group [$privateDNSZoneResourceGroupName] created."
            }
            catch {
                Log-Line $_.Exception.Message
                $retVal = $false
            }
        }
        else {
            Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [privatelink.azurecr.io] in resource group [$privateDNSZoneResourceGroupName] found."
        }
    }


    return $retVal
}

function Enable-Aks-AAD {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $resourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $aksName
    )

    $retVal = $true
    $azLogin = "az login --service-principal -u $applicationId -p $applicationSecret --tenant cdf226d7-79fd-4290-a3a7-996968201a26"
    $loginSuccessfull = $false
    Log-Line "Azure CLI login [$azLogin]."

    #
    # Direct std out and std-err to null otherwise, because of certificate error on local laptop - 
    # which is the self-hosted agent, script will show failure in pipeline even though login worked.
    #

    $arguments = @(
        "login",
        "--service-principal",
        "-u", "$applicationId", 
        "-p", "$applicationSecret",
        "--tenant", "cdf226d7-79fd-4290-a3a7-996968201a26"
    );

    $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
        
    if ($process.ExitCode -ne 0) {
        $loginSuccessfull = $false
        Log-Line "az login exited with a non 0 exit code";
        $errorMessage = Get-Content "stderr.txt" -Raw
        Log-Line "$errorMessage"
    }
    else {
        $loginSuccessfull = $true
    }

    if ($loginSuccessfull -eq $true) {
        Log-Line "Azure CLI login successful "
        try {
            $enableAAD = "az aks update -g $resourceGroupName -n $aksName --enable-aad"
            Log-Line "$enableAAD"
            
            $arguments = @(
                "aks",
                "update",
                "-g", "$resourceGroupName", 
                "-n", "$aksName",
                "--enable-aad"
            );

            $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
                -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";

            if ($process.ExitCode -ne 0) {
                Log-Line "az aks update exited with a non 0 exit code";
                $errorMessage = Get-Content "stderr.txt" -Raw
                Log-Line "$errorMessage"
                if ($errorMessage.Contains("AAD is already enabled")) {
                    Log-Line "AAD is already enabled."
                    $retVal = $true
                }
                else {
                    $retVal = $false        
                }
            }
            else {
                $retVal = $true
            }

        }
        catch {
            Log-Line $_.Exception.Message
            if ($_.Exception.Message.Contains("AAD is already enabled") -eq $true) {
                Log-Line "AAD is already enabled."
                $global:LASTEXITCODE = 0
                $error.clear()
                $retVal = $true
            }
            else {
                $retVal = $false
            }
        }
    }
    return $retVal
}


Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line "Powershell executing Create-Azure-AKS Version v1.0.0.0 on $currentDate ($currentDateString)"
Log-Line ""
Log-Line "Powershell Version Information"
Log-Line ""
Log-VersionTable
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""
Log-Line "subscriptionName: [$subscriptionName]"
Log-Line "applicationId: [$applicationId]"
Log-Line "applicationSecret: [$applicationSecret]"
Log-Line "resourceGroupName: [$resourceGroupName]"
Log-Line "aksName: [$aksName]"
Log-Line "aksOwnersGroupName: [$aksOwnersGroupName]"
Log-Line "aksContributorsGroupName: [$aksContributorsGroupName]"
Log-Line "aksReadersGroupName: [$aksReadersGroupName]"
Log-Line "subnetName: [$subnetName]"
Log-Line "acrName: [$acrName]"
Log-Line "keyVaultName: [$keyVaultName]"
Log-Line "privateDNSZoneSubscription: [$privateDNSZoneSubscription]"
Log-Line "privateDNSZoneResourceGroupName: [$privateDNSZoneResourceGroupName]"
Log-Line "servicePrincipalName: [$servicePrincipalName]"
Log-Line "nodeVmSize: [$nodeVmSize]"
Log-Line "nodeCount: [$nodeCount]"
Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""

if ((Establish-AzureContext -subscriptionName $subscriptionName) -and
    (Acquire-ResourceGroup -resourceGroupName $resourceGroupName -subscriptionName $subscriptionName) -and
    (Acquire-VirtualNetwork -subscriptionName $subscriptionName) -and
    (Acquire-SubNet -vnet $vnet -subnetName $subnetName) -and
    (Acquire-KeyVault -resourceGroupName $resourceGroupName -vnet $vnet -keyVaultName $keyVaultName -servicePrincipalName $servicePrincipalName) -and
    (Acquire-KeyVaultKey -keyVault $keyVault -aksEncryptKeyName $aksEncryptKeyName) -and
    (Acquire-KeyVault-Private-Endpoint -resourceGroupName $resourceGroupName -keyvault $keyVault -vnet $vnet -subnet $subnet) -and
    (Establish-AzureContext -subscriptionName $privateDNSZoneSubscription) -and
    (Establish-PrivateDNS-Registration -privateDNSZoneResourceGroupName $privateDNSZoneResourceGroupName `
            -zoneName "privatelink.vaultcore.azure.net" -privateEndpoint $privateKeyVaultEndpoint) -and
    (Establish-AzureContext -subscriptionName $subscriptionName) -and
    (Acquire-ACR -resourceGroupName $resourceGroupName -acrName $acrName) -and
    (Acquire-DiskEncryptionSet -resourceGroupName $resourceGroupName -aksName $aksName -keyVault $keyVault -key $key) -and
    (Configure-KeyVault -keyVaultName $keyVaultName -identityName $diskEncryptionSet.Name -identityId $diskEncryptionSet.Identity.PrincipalId) -and
    (Acquire-AKS -resourceGroupName $resourceGroupName -aksName $aksName -subnet $subnet `
            -diskEncryptionSet $diskEncryptionSet -nodeVmSize $nodeVmSize -nodeCount $nodeCount) -and
    (Establish-AKS-ManagedIdentity-Roles -aks $aks -acr $acr -vnet $vnet) -and
    (Establish-Aks-Group-Role -groupName $aksOwnersGroupName -roleName "Owner" -aks $aks) -and
    (Establish-Aks-Group-Role -groupName $aksContributorsGroupName -roleName "Contributor" -aks $aks) -and
    (Establish-Aks-Group-Role -groupName $aksReadersGroupName -roleName "Reader" -aks $aks) -and
    (Enable-Aks-AAD -resourceGroupName $resourceGroupName -aksName $aksName)) {
    $success = $true
}

if ($success -eq $true) {
    Log-Line "Execution completed successfully."
}
else {
    throw "Execution failed. Review logs."
}
