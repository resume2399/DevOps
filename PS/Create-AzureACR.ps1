<#
.SYNOPSIS
    Creates an Azure Container Registry.
.DESCRIPTION
    Creates an Azure Container Registry encrypted with customer managed key.

    Fiserv security requires that:
        Key vault is not accessable from a public endpoint.
        Keys must be RSA-HSM
        ACR use a customer managed key for encryption.
        ACR is not accessable from a public endpoint.

    The script will: 
        Validate that the subscription and resource group exist. 
        Find the appropriate virtuall network and sub-network for deployment. It these are not found the script will end.
        Ensure that there is a temporary key vault to hold a temporary key encryption key for the ACR.
        Ensure that there is a key vault to hold the final key encryption key for the ACR.
        Ensure that there is a temporary key encryption key in the temporary key vault and that the key meets Fiserv security requirements.
        Ensure that there is a final key encryption key in the final key vault and that the key meets Fiserv security requirements.
        Ensure that there is a user-assigned identity with the correct access policy to the key encryption key in the temporary key vault.
        Ensure that there is a correct access policy for the ACR system-assigned identity to the key encryption key in the final key vault.
        Ensure that there is a private endpoint for the final key vault.
        Ensure that there is a DNS entry for the final key vault.
        Ensure that private access for the final key vault is disabled.
        Create an ACR in the resource group if it does not exist. The ACR will use customer managed keys for encryption.
            NOTE: ACR with CMK will not work with a key vault that denies public access unless a system assigned managed identity is used as the encryption identity. However the identity
                  used by the ACR must be given the appropriate key access policy in the key vault. The identity and key used by the ACR MUST be assigned during creation of the ACR
                  and therefore a user-assigned identity must be used. This results in a catch-22. The ACR cannot be created with a CMK stored in a private linked key vault unless 
                  a system managed identity is used but the system managed identity is not known until after the ACR is created.

                  To work around this brilliant bit of engineering by Microsoft the script creates two key vaults: one temporary key vault with public access and one private linked
                  key vault that will finally be the key vault that is used for encrypting the ACR. The ACR is initially created with a user-assigned idenity and a key from the public
                  key vault. Next a system-assigned identity is added to the ACR. This system-assigned identity is given access to the key in the final key vault. The key in the ACR
                  is then rotated to use the system-assigned identity and the key in the final key vault. Finally the temporary key vault and user-assigned identity are removed and 
                  the final key vault is set to deny public access.
        Ensure public access to the ACR is disabled.                  
        Ensure that private private endpoint for the ACR. 
        Ensure that there is are DNS entries for ACR privatelink.

.NOTES
	File Name : Create-Azure-ACR.ps1
	Author    : Phil Schroder - phillip.schroder@fiserv.com
	Requires  : PowerShell Version 2.0
	Born      : 08/20/2020 - Phil Schroder
.EXAMPLE
.PARAMETER subscriptionName
    Required: The name of the subscription that will contain the VM.
.PARAMETER applicationId
    Required: The application id of the application registration that will be used to deploy the AKS cluster.
.PARAMETER applicationSecret
    Required: The application secret for the application registration that will be used to deploy the AKS cluster.
.PARAMETER resourceGroupName
    Required: The name of the resouce group within which the SQL server will be created.
.PARAMETER subnetName
    Required: The name of the subnet within the vnet within which the ACR will be created.
.PARAMETER acrName
    Required: The name of the ACR to be created if it does not exist. The managed identity of the AKS will be given acrPull role to the ACR. The name will be prefixed with acr
.PARAMETER keyVaultName
    Required: The name of the key vault that will be used for the keys used to encrypt ACR.
.PARAMETER acrEncryptKeyName
    Optional: The name of the key within keyvault that will be used for ACR encryption. Defaults to ACREncryptKey-HSM
.PARAMETER privateDNSZoneSubscription
    Optional: The name of the subscription that has the privatelink.azurecr.iot private DNS zone.
.PARAMETER privateDNSZoneResourceGroupName
    Optional: The name of the resource group that has the privatelink.azurecr.iot private DNS zone.
.PARAMETER servicePrincipalName
    Required: The name of the service principal.
#>

param
(
    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the subscription that will contain the Azure SQL.")] 
    [string]
    $subscriptionName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the applicaiton id of the application registration that will be used to deploy the AKS cluster.")] 
    [string]
    $applicationId,

    [Parameter(Mandatory=$true, HelpMessage="Enter the secret for the application registration that will be used to deploy the AKS cluster.")] 
    [string]
    $applicationSecret,

    
	[Parameter(Mandatory=$true, HelpMessage="Enter the name of the resource group witin which the Azure SQL will be created.")] 
    [string]
    $resourceGroupName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the subnet within the vnet in which the AKS will be created.")] 
    [string]
    $subnetName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the ACR. The name will be prefixed with acr")]
    [string]
    $acrName,

    [Parameter(Mandatory=$true, HelpMessage="Enter the name of the key vault used by to encrypt ACR.")] 
    [string]
    $keyVaultName,

    [Parameter(Mandatory=$false, HelpMessage="Enter the name of the key within keyvault that will be used for ACR encryption.")] 
    [string]
    $acrEncryptKeyName = "JVCACREncryptKey-HSM",

    [Parameter(HelpMessage="Enter the name of the subscription that has the private DNS zones for the ACR and Key Vault private link registration. Defaults to ETG-Hub-Production-East2.")] 
    [string]
    $privateDNSZoneSubscription = "ETG-Hub-Production-East2",

    [Parameter(HelpMessage="Enter the name of the resource group that has the private DNS zones for the ACR and Key Vault private link registration. Defaults to rg-dns-prod-etg-hub-useast2-1.")] 
    [string]
    $privateDNSZoneResourceGroupName = "rg-dns-prod-etg-hub-useast2-1",
	
	[Parameter(Mandatory=$true, HelpMessage="Enter the name of the Service Principal.")] 
    [string]
    $servicePrincipalName
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
$currentDateTSString = $currentDate.ToString("yyyyMMdd-HHmmss")

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

function Log-Lines
{
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        $logMessages,

        [string]
        $color
    )

    process
    {
        foreach ($logMessage in $logMessages)
        {
            $timeStamp = Get-Date

            Write-Host -NoNewline -Separator '' -ForegroundColor $color $timeStamp.Hour.ToString("00") ":" $timeStamp.Minute.ToString("00") ":" $timeStamp.Second.ToString("00") "." $timeStamp.Millisecond.ToString("000") " "
            Write-Host $logMessage -ForegroundColor $color
        }
    }
}

function Log-VersionTable
{
    foreach ($key in $psVersionTable.Keys)
    {
        $value = $psVersionTable[$key]
        Log-Line "$key : $value"
    }
}

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
        $script:context = Set-AzContext -SubscriptionObject $subscription
        Log-Line $script:context.Name
		
		$script:azContext = az account set --subscription $subscriptionName
		$script:azContextDisplay = az account show
		Log-Line "az CLI context [$script:azContextDisplay]"

        $retVal = $true
    }
    else
    {
        Log-Line "Subscription [$subscriptionName] not found."
    }

    return $retVal
}

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
        $keyVaultName,
		
		[Parameter(Mandatory=$true)] 
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

    try
    {
        $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Message.Contains("not found") -eq $true)
        {
            $removedKeyVault = Get-AzKeyVault -VaultName $keyVaultName -Location $vnet.Location -InRemovedState
            if ($null -eq $removedKeyVault)
            {
                $keyVaultNotFound = $true
            }
            else 
            {
                $removedKeyVaultFound = $true
            }
        }
        else
        {
            Log-Line $_.Exception.Message
        }
    }


    if ($keyVaultNotFound -eq $true)
    {
        Log-Line "Key vault [$keyVaultName] not found in resource group [$resourceGroupName]. Creating."

        try
        {
            $keyVault = New-AzKeyVault -ResourceGroupName $resourceGroupName -Name $keyVaultName -Location $vnet.Location -EnabledForDiskEncryption -Sku premium -ErrorAction Stop
        }
        catch
        {
            Log-Line $_.Exception.Message
		}

        if ($null -ne $keyVault)
        {
            Log-Line "key vault [$keyVaultName] created."
            $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties -ErrorAction Stop
        }
        else
        {
            Log-Line "Error creating key vault [$keyVaultName] in resource group [$resourceGroupName]."
        }
    }
    elseif ($true -eq $removedKeyVaultFound)
    {
        Log-Line "Key vault [$keyVaultName] found in removed state. Undoing removal."
        Undo-AzKeyVaultRemoval -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -Location $vnet.Location
        $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties -ErrorAction Stop
        if ($null -ne $keyVault)
        {
            Log-Line "key vault [$keyVaultName] removal undone."
        }
    }
    elseif ($null -ne $keyVault)
    {
        Log-Line "key vault [$keyVaultName] found in resource group [$resourceGroupName]."
    }

    if ($null -ne $keyVault)
    {
        $retVal = $true
		$azADServicePrincipal = Get-AzADServicePrincipal -DisplayName $servicePrincipalName
		#Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -ObjectId $servicePrincipalId -BypassObjectIdValidation -PermissionsToKeys wrapKey, unwrapKey, get -ErrorAction Stop
        Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -ObjectId $azADServicePrincipal.Id -BypassObjectIdValidation -PermissionsToKeys wrapKey, unwrapKey, get, create -ErrorAction Stop

        Update-AzKeyVaultNetworkRuleSet -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -DefaultAction Allow -ErrorAction Stop

        if ($isTempKeyVault -eq $true)
        {
            $script:tempKeyVault = $keyVault
        }
        else
        {
            $script:keyVault = $keyVault
        }
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
        $subnet
    )

    $retVal = $false
    $keyVaultName = $keyVault.Name
    $privatekeyVaultEndpointConnectionName = "pec-$keyVaultName"
    $privateKeyVaultEndpointName = "pe-$keyVaultName"


    $script:privateKeyVaultEndpoint = Get-AzPrivateEndpoint -Name $privateKeyVaultEndpointName

    if ($script:privateKeyVaultEndpoint -eq $null)
    {
        $keyVaultName = $keyVault.ResourceName

        Log-Line "Private endpoint [$privateKeyVaultEndpointName] for key vault [$keyVaultName] not found."
        Log-Line "Creating private endpoint connection [$privatekeyVaultEndpointConnectionName] for key vault [$keyVaultName]."
        $privateKeyVaultEndpointConnection = New-AzPrivateLinkServiceConnection -Name $privatekeyVaultEndpointConnectionName -PrivateLinkServiceId $keyVault.ResourceId -GroupId "vault" 2>$null

        if ($privateKeyVaultEndpointConnection -ne $null)
        {
            Log-Line "Creating private endpoint [$privatekeyVaultEndpointName] for key vault [$keyVaultname]."
            $script:privateKeyVaultEndpoint = New-AzPrivateEndpoint -ResourceGroupName $resourceGroupName -Name $privateKeyVaultEndpointName -Location $vnet.Location -Subnet $subnet -PrivateLinkServiceConnection $privateKeyVaultEndpointConnection
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

function Acquire-User-Assigned-Identity
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)] 
        [string]
        $userAssignedIdentityName
    )

    $retVal = $false
    $userAssignedIdentityNotFound = $false

    try
    {
        Log-Line "Verifying user-assigned identity [$userAssignedIdentityName]."

        $script:userAssignedIdentity = Get-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $userAssignedIdentityName -ErrorAction Stop

        Log-Line "User-assigned identity [$userAssignedIdentityName] found."
    }
    catch
    {
        if ($_.Exception.Message.Contains("not found") -eq $true)
        {
            $userAssignedIdentityNotFound = $true
        }
        else
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($userAssignedIdentityNotFound -eq $true)
    {
        Log-Line "User-assigned identity [$userAssignedIdentityName] not found. Creating."

        try
        {
            $script:userAssignedIdentity = New-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $userAssignedIdentityName -ErrorAction Stop

            #
            # Sleep for a while otherwise access policy assignment will fail because it is unable to find the identity.
            #
            Start-Sleep -Milliseconds 30000

            Log-Line "User-assigned identity [$userAssignedIdentityName]. Created."
        }
        catch
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($script:userAssignedIdentity -ne $null)
    {
        $retVal = $true
    }
    else
    {
        Log-Line "Error acquiring user-assigned identity."
    }

    return $retVal
}

function Configure-KeyVault
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $keyVaultName,

        [Parameter(Mandatory=$true)] 
        [string]
        $identityName,

        [Parameter(Mandatory=$true)] 
        [string]
        $identityId,

        #
        # Kludge: Refer to Description above.
        #
        [switch]
        $isTempKeyVault
    )

    $retVal = $false

    try
    {
        Log-Line "Setting access policy for identity [$identityName] to wrapKey, unwrapKey, get."
        Set-AzKeyVaultAccessPolicy -ResourceGroupName $resourceGroupName -VaultName $keyVaultName -BypassObjectIdValidation -ObjectId $identityId -PermissionsToKeys wrapKey, unwrapKey, get, create -ErrorAction Stop
        Log-Line "Access policy for identity [$identityName] set."

        $keyVault = Get-AzResource -ResourceGroupName $resourceGroupName -ResourceName $keyVaultName -ResourceType Microsoft.KeyVault/vaults -ExpandProperties

        try
        {
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

            if ($isTempKeyVault -eq $true)
            {
                $script:tempKeyVault = $keyVault
            }
            else
            {
                $script:keyVault = $keyVault
            }

            $retVal = $true
        }
        catch
        {
            Log-Line $_.Exception.Message
            Log-Line "Error configuring key vault [$keyVaultName]."
        }
    }
    catch
    {
        Log-Line $_.Exception.Message
        Log-Line "Error setting access policy for user-assigned identity [$acrName]."
    }

    return $retVal
}

function Acquire-KeyVaultKey
{
    param
    (
        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory=$true)] 
        [string]
        $acrEncryptKeyName
    )

    $retVal = $false
    $keyVaultName = $keyVault.Name

    Log-Line "Verifying Key [$acrEncryptKeyName] exists in key vault [$keyVaultName]."
    $script:key = Get-AzKeyVaultKey -VaultName $keyVaultName -Name $acrEncryptKeyName

    if ($null -eq $key)
    {
        #
        # If the key is not found create it.
        #
        Log-Line "Key [$acrEncryptKeyName] not found in key vault [$keyVaultName]. Creating."
		$expiryDate = (Get-Date).AddYears(2)
		
		Log-Line "Key [$acrEncryptKeyName] being created will expire on [$expiryDate]."

        $script:key = Add-AzKeyVaultKey -VaultName $keyVaultName -Name $acrEncryptKeyName -Destination HSM -Expires $expiryDate

        if ($null -ne $key)
        {
            Log-Line "Key [$acrEncryptKeyName] created."
        }
        else
        {
            Log-Line "Error creating Key [$acrEncryptKeyName]."
        }         
    }
    else
    {
        Log-Line "Key [$acrEncryptKeyName] found in key vault [$keyVaultName]."
    }

    #
    # Verify the key type.
    #
    if ($null -ne $script:key)
    {
        Log-Line "Verifying Key [$acrEncryptKeyName] is of the correct type."
        $keyType = $script:key.Attributes.KeyType

        if ($keyType -eq "RSA-HSM")
        {
            $retVal = $true
        }
        else
        {
            Log-Line "Key [$acrEncryptKeyName] is of type [$keyType] and cannot be used. Please specify a different key that is of type RSA-HSM. You may also specify a key that does not exist and it will be created with the proper type."
        }
    }

    return $retVal
}

function Acquire-ACR
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory=$true)] 
        [string]
        $acrName,

        [Parameter(Mandatory=$true)] 
        [string]
        $identityId,

        [Parameter(Mandatory=$true)] 
        [string]
        $keyId
    )

    $retVal = $false
    $acrNotFound = $false

    try
    {
        $script:acr = Get-AzContainerRegistry -ResourceGroupName $resourceGroupName -Name $acrName -ErrorAction Stop
    }
    catch
    {
        if ($_.Exception.Message.Contains("not found.") -eq $true)
        {
            $acrNotFound = $true
        }
        else
        {
            Log-Line $_.Exception.Message
        }
    }

    if ($acrNotFound -eq $true)
    {
        $subnetId = $subnet.Id
        $loginSuccessfull = $true

        $azLogin = "az login --service-principal -u $applicationId -p $applicationSecret --tenant cdf226d7-79fd-4290-a3a7-996968201a26"
        Log-Line "Azure CLI login [$azLogin]."

        #
        # Direct std out and std-err to null otherwise, because of certificate error on local laptop - which is the self-hosted agent, script will show failure in pipeline even though login worked.
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

        if ($loginSuccessfull -eq $true)
        {
            Log-Line "Azure CLI login [$azLogin] succeeded."

            try
            {
                Log-Line "Creating ACR [$acrName]. This will take a few minutes. The script will check status every 30 seconds."

                #
                # Must use Azure CLI here because Azure Powershell does not identity or key-encryption-key on ACR.
                #
                $azAcrCreate =  "az acr create --resource-group $resourceGroupName --name $acrName --identity $identityId --key-encryption-key $keyId --sku Premium --public-network-enabled false"

                Log-Line "$azAcrCreate"

                $arguments = @(
                    "acr",
                    "create",
                    "--resource-group", "$resourceGroupName", 
                    "--name", "$acrName",
                    "--identity", "$identityId",
                    "--key-encryption-key", "$keyId",
                    "--sku", "Premium",
                    "--public-network-enabled", "false"
                );

                $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
                if ($process.ExitCode -eq 0) {
                    #
                    # Check provisioning state. One of: Succeeded / Failed / Upgrading / Updating / Creating / Scaling / Deleting / Migrating
                    #
                    do
                    {
                        Start-Sleep -Milliseconds 30000
                        $script:acr = Get-AzContainerRegistry -ResourceGroupName $resourceGroupName -Name $acrName -ErrorAction Stop
                        $acrProvisioningState = $script:acr.ProvisioningState

                        Log-Line "ACR [$acrName] is [$acrProvisioningState]."
                    
                    }
                    while ($script:acr.ProvisioningState -ne "Failed" -and $script:acr.ProvisioningState -ne "Succeeded")
                }
                else
                {
                    Log-Line "az acr create exited with a non 0 exit code";
                    $errorMessage = Get-Content "stderr.txt" -Raw
                    Log-Line "$errorMessage"
                }                
            }
            catch
            {
                Log-Line $_.Exception.Message
            }

            if ($script:acr -ne $null -and $script:acr.ProvisioningState -eq "Succeeded")
            {
                Log-Line "ACR [$acrName] created in resource group [$resourceGroupName]."
                Log-Line "Creating system-assgined managed identity for [$acrName] in resource group [$resourceGroupName]."

                #
                # Must use Azure CLI here because Azure Powershell does not support identities on ACR.
                #
                $azAcrIdentityAssign =  "az acr identity assign --resource-group $resourceGroupName --name $acrName --identities [system] "
                Log-Line "$azAcrIdentityAssign"

                $arguments = @(
                    "acr",
                    "identity",
                    "assign",
                    "--resource-group", "$resourceGroupName", 
                    "--name", "$acrName",
                    "--identities", "[system]"
                );

                $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";

                if ($process.ExitCode -eq 0)
                {
                    #
                    # Wait 30 seconds to make sure the system-assigned managed identity is available.
                    #
                    Start-Sleep -Milliseconds 30000

                    $script:systemAssignedIdentity = Get-AzADServicePrincipal -DisplayName $acrName

                    if ($script:systemAssignedIdentity -ne $null)
                    {
                        Log-Line "System-assgined identity for [$acrName] in resource group [$resourceGroupName] created."
                        $retVal = $true
                    }
                    else
                    {
                        Log-Line "Error creating system-assgined identity for [$acrName] in resource group [$resourceGroupName]."
                    }
                }
                else
                {
                    Log-Line "az acr identity assign exited with a non 0 exit code";
                    Log-Line "Error creating system-assgined managed identity for [$acrName] in resource group [$resourceGroupName]."
                    $errorMessage = Get-Content "stderr.txt" -Raw
                    Log-Line "$errorMessage"
                }
            }
            else
            {
                Log-Line "Error creating ACR [$acrName]."
            }
        }
        else
        {
            Log-Line "Error on az login."
        }
    }
    elseif ($null -ne $script:acr)
    {
        Log-Line "ACR [$acrName] already exists."
		$script:systemAssignedIdentity = Get-AzADServicePrincipal -DisplayName $acrName
		$retVal = $true
    }

    return $retVal
}

function Rotate-ACR-Encryption-Key
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ContainerRegistry.PSContainerRegistry]
        $acr,

        [Parameter(Mandatory=$true)] 
        [string]
        $identityId,

        [Parameter(Mandatory=$true)] 
        [string]
        $userAssignedidentityName,

        [Parameter(Mandatory=$true)] 
        [string]
        $keyId,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $keyVault,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $tempKeyVault
    )

    $acrName = $acr.Name
    $retVal = $false
    $keyVaultName = $keyVault.Name
    $tempKeyVaultName = $tempKeyVault.Name

    $azLogin = "az login --service-principal -u $applicationId -p $applicationSecret --tenant cdf226d7-79fd-4290-a3a7-996968201a26"

    Log-Line "Azure CLI login [$azLogin]."

    #
    # Direct std out and std-err to null otherwise, because of certificate error on local laptop - which is the self-hosted agent, script will show failure in pipeline even though login worked.
    #

    $arguments = @(
        "login",
        "--service-principal",
        "-u", "$applicationId", 
        "-p", "$applicationSecret",
        "--tenant", "cdf226d7-79fd-4290-a3a7-996968201a26"
    );

    $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
    if ($process.ExitCode -ne 0) 
    {
        $loginSuccessfull = $false
        Log-Line "az login exited with a non 0 exit code";
        $errorMessage = Get-Content "stderr.txt" -Raw
        Log-Line "$errorMessage"
    }
    else 
    {
		$loginSuccessfull = $true
	}

    if ($loginSuccessfull -eq $true)
	{
		Log-Line "Rotating key to use system-assigned managed identity for [$acrName] in resource group [$resourceGroupName]. KeyVaultName $keyVaultName Temp: $tempKeyVaultName "
		Log-Line "Rotating key identityId $identityId keyId: $keyId UAName: $userAssignedidentityName"

		#
		# Must use Azure CLI here because Azure Powershell does not support encryption operations for ACR.
		#
		$azAcrRotateEncryptionKey =  "az acr encryption rotate-key --resource-group $resourceGroupName --name $acrName --identity $identityId --key-encryption-key $keyId"
        Log-Line "$azAcrRotateEncryptionKey"
        
        $arguments = @(
            "acr",
            "encryption",
            "rotate-key",
            "--resource-group", "$resourceGroupName", 
            "--name", "$acrName",
            "--identity", "$identityId",
            "--key-encryption-key", "$keyId"
        );

        $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";        

		if ($process.ExitCode -eq 0)
		{
			Log-Line "Key rotated to use system-assgined managed identity for [$acrName] in resource group [$resourceGroupName]."
			Log-Line "Removing user-assigned identity [$userAssignedidentityName] from [$acrName] in resource group [$resourceGroupName]."
			$retVal = $true
			#
			# Must use Azure CLI here because Azure Powershell does not support identities for ACR.
			#
			try
			{
				$azAcrRemoveIdentity =  "az acr identity remove --resource-group $resourceGroupName --name $acrName --identities $userAssignedidentityName"
                Log-Line "$azAcrRemoveIdentity"

                $arguments = @(
                    "acr",
                    "identity",
                    "remove",
                    "--resource-group", "$resourceGroupName", 
                    "--name", "$acrName",
                    "--identities", "$userAssignedidentityName"
                );

                $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";        

                if ($process.ExitCode -ne 0)
                {
                    $errorMessage = Get-Content "stderr.txt" -Raw
                    if($errorMessage.Contains("The registry does not have specified user identity"))
				    {
					    Log-Line "User-assigned identity [$userAssignedidentityName] has already been removed from [$acrName] in resource group [$resourceGroupName]."
					    $retVal = $true
				    }
				    else
				    {
                        Log-Line "az acr identity remove exited with a non 0 exit code";
                        Log-Line "$errorMessage"
					    $retVal = $false
				    }
                }
                else
                {
                    $retVal = $true
				}
			}catch{
				Log-Line $_.Exception.Message
				if($_.Exception.Message.Contains("The registry does not have specified user identity") -eq $true)
				{
					Log-Line "User-assigned identity [$userAssignedidentityName] has already been removed from [$acrName] in resource group [$resourceGroupName]."
					$global:LASTEXITCODE = 0
					$error.clear()
					$retVal = $true
				}
				else
				{
					$retVal = $false
				}			
			}			
		}
		else
		{
			Log-Line "az acr encryption rotate-key exited with a non 0 exit code";
            $errorMessage = Get-Content "stderr.txt" -Raw
            Log-Line "$errorMessage"
		}
	
	}
	else
	{
		$errorMessage = Get-Content "stderr.txt" -Raw
        Log-Line "$errorMessage"
	
	}
	
    return $retVal
}

function Finalize
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
        [Microsoft.Azure.Commands.ResourceManager.Cmdlets.SdkModels.PSResource]
        $tempKeyVault,

        [Parameter(Mandatory=$true)] 
        [string]
        $userAssignedIdentityName
    )

    $retVal = $true
    $keyVaultName = $keyVault.Name
    $tempKeyVaultName = $tempKeyVault.Name

    try
    {
        Log-Line "Seting key vault [$keyVaultName] in resource group [$resourceGroupName] to deny public access."

        Update-AzKeyVaultNetworkRuleSet -ResourceGroupName $resourceGroupName -VaultName $keyVault.ResourceName -DefaultAction Deny -ErrorAction Stop

        Log-Line "Key vault [$keyVaultName] in resource group [$resourceGroupName] set to deny public access."

        try
        {
            Log-Line "Removing temporary key vault [$tempKeyVaultName] in resource group [$resourceGroupName]."

            Remove-AzKeyVault -ResourceGroupName $resourceGroupName -VaultName $tempKeyVaultName -Force -ErrorAction Stop

            Log-Line "Temporary key vault [$tempKeyVaultName] in resource group [$resourceGroupName] removed."

            try
            {
                Log-Line "Removing useer-assigned identity [$userAssignedIdentityName] in resource group [$resourceGroupName]."

                Remove-AzUserAssignedIdentity -ResourceGroupName $resourceGroupName -Name $userAssignedIdentityName -Force -ErrorAction Stop

                $retVal = $true

                Log-Line "User-assgined identity [$userAssignedIdentityName] in resource group [$resourceGroupName] removed."
            }
            catch
            {
                Log-Line $_.Exception.Message
                Log-Line "Error removing user-assigned identity [$userAssignedIdentityName] in resource group [$resourceGroupName]."
            }
        }
        catch
        {
            Log-Line $_.Exception.Message
            Log-Line "Error removing key vault [$tempKeyVaultName] in resource group [$resourceGroupName]."
        }
    }
    catch
    {
        Log-Line $_.Exception.Message
        Log-Line "Error setting key vault [$keyVaultName] in resource group [$resourceGroupName] to deny public access."
    }

    return $retVal
}

function Acquire-ACR-Private-Endpoint
{
    param
    (
        [Parameter(Mandatory=$true)] 
        [string]
        $resourceGroupName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.ContainerRegistry.PSContainerRegistry]
        $acr,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSVirtualNetwork]
        $vnet,

        [Parameter(Mandatory=$true)]
        [Microsoft.Azure.Commands.Network.Models.PSSubnet]
        $subnet
    )

    $retVal = $false
    $acrName = $acr.Name
    $privateAcrEndpointConnectionName = "pec-$acrName"
    $privateAcrEndpointName = "pe-$acrName"

    Log-Line "Verifying private endpoint [$privateAcrEndpointName] for ACR [$acrName]."

    try
    {
        $script:privateAcrEndpoint = Get-AzPrivateEndpoint -Name $privateAcrEndpointName -ErrorAction Stop
    }
    catch
    {
        Log-Line $_.Exception.Message
    }

    if ($script:privateAcrEndpoint -eq $null)
    {
        Log-Line "Private endpoint [$privateAcrEndpointName] for ACR [$acrName] not found."
        Log-Line "Creating private endpoint connection [$privateAcrEndpointConnectionName] for ACR [$acrName]."

        $privateAcrEndpointConnection = New-AzPrivateLinkServiceConnection -Name $privateAcrEndpointConnectionName -PrivateLinkServiceId $acr.Id -GroupId "registry"

        if ($privateAcrEndpointConnection -ne $null)
        {
            Log-Line "Creating private endpoint [$privateAcrEndpointName] for ACR [$acrName]."
            $script:privateAcrEndpoint = New-AzPrivateEndpoint -ResourceGroupName $resourceGroupName -Name $privateAcrEndpointName -Location $vnet.Location -Subnet $subnet -PrivateLinkServiceConnection $privateAcrEndpointConnection
            if ($script:privateAcrEndpoint -ne $null)
            {
                Log-Line "Private endpoint [$privateAcrEndpointName] for ACR [$acrName] created."
                Log-Line "Disabling public access for ACR [$acrName]."

                $acrDenyPublicAccess = "az acr update --name $acrName --public-network-enabled false"
                Log-Line "$acrDenyPublicAccess"

                $arguments = @(
                    "acr",
                    "update",
                    "--name", "$acrName", 
                    "--public-network-enabled", "false"
                );

                $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
                
                if ($process.ExitCode -eq 0)
                {
                    Log-Line "Public access for ACR [$acrName] disabled."
                    $retVal = $true
                }
                else
                {
                    Log-Line "az acr update exited with a non 0 exit code";
                    Log-Line "Error disabling public access for ACR [$acrName]."
                    $errorMessage = Get-Content "stderr.txt" -Raw
                    Log-Line "$errorMessage"
                }
            }
        }
        else
        {
            Log-Line "Error creating private ACR endpoint. ACR is insecure."
        }
    }
    else
    {
        Log-Line "Private endpoint [$privateAcrEndpointName] for ACR [$acrName] found."
        $retVal = $true
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
            }
            catch
            {
                Log-Line $_.Exception.Message
                $retVal = $false
            }
        }
        else
        {
            Log-Line "Private DNS record set [$dnsRecordSetName] in private zone [privatelink.azurecr.io] in resource group [$privateDNSZoneResourceGroupName] found."
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
Log-Line "subnetName: [$subnetName]"
Log-Line "acrName: [$acrName]"
Log-Line "keyVaultName: [$keyVaultName]"
Log-Line "acrEncryptKeyName: [$acrEncryptKeyName]"
Log-Line "privateDNSZoneSubscription: [$privateDNSZoneSubscription]"
Log-Line "privateDNSZoneResourceGroupName: [$privateDNSZoneResourceGroupName]"
Log-Line "servicePrincipalName: [$servicePrincipalName]"
Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""

if ((Establish-AzureContext -subscriptionName $subscriptionName) -and
    (Acquire-ResourceGroup -resourceGroupName $resourceGroupName -subscriptionName $subscriptionName) -and
    (Acquire-VirtualNetwork -subscriptionName $subscriptionName) -and
    (Acquire-SubNet -vnet $vnet -subnetName $subnetName) -and
    (Acquire-KeyVault -resourceGroupName $resourceGroupName -vnet $vnet -keyVaultName "$keyVaultName-tmp" -servicePrincipalName $servicePrincipalName -isTempKeyVault) -and
    (Acquire-KeyVault -resourceGroupName $resourceGroupName -vnet $vnet -keyVaultName $keyVaultName -servicePrincipalName $servicePrincipalName) -and
    (Acquire-KeyVault-Private-Endpoint -resourceGroupName $resourceGroupName -keyvault $keyVault -vnet $vnet -subnet $subnet) -and
    (Establish-AzureContext -subscriptionName $privateDNSZoneSubscription) -and
	(Establish-PrivateDNS-Registration -privateDNSZoneResourceGroupName $privateDNSZoneResourceGroupName -zoneName "privatelink.vaultcore.azure.net" -privateEndpoint $privateKeyVaultEndpoint) -and
    (Establish-AzureContext -subscriptionName $subscriptionName) -and
    (Acquire-User-Assigned-Identity -resourceGroupName $resourceGroupName -userAssignedIdentityName "uaid-$acrname") -and
    (Acquire-KeyVaultKey -keyVault $tempKeyVault -acrEncryptKeyName $acrEncryptKeyName) -and
    (Configure-KeyVault -keyVaultName $tempKeyVault.Name -identityName $userAssignedIdentity.Name -identityId $userAssignedIdentity.PrincipalId -isTempKeyVault) -and
    (Acquire-ACR -resourceGroupName $resourceGroupName -acrName $acrName -identityId $userAssignedIdentity.Id -keyId $key.Id) -and
    (Acquire-KeyVaultKey -keyVault $keyVault -acrEncryptKeyName $acrEncryptKeyName) -and
    (Configure-KeyVault -keyVaultName $keyVault.Name -identityName $systemAssignedIdentity.DisplayName -identityId $systemAssignedIdentity.Id) -and
    (Rotate-ACR-Encryption-Key -resourceGroupName $resourceGroupName -acr $acr -identityId "[system]" -userAssignedIdentityName $userAssignedIdentity.Name -keyId $key.Id -keyVault $keyVault -tempKeyVault $tempKeyVault) -and
    (Acquire-ACR-Private-Endpoint -resourceGroupName $resourceGroupName -acr $acr -vnet $vnet -subnet $subnet) -and
    (Establish-AzureContext -subscriptionName $privateDNSZoneSubscription) -and
    (Establish-PrivateDNS-Registration -privateDNSZoneResourceGroupName $privateDNSZoneResourceGroupName -zoneName "privatelink.azurecr.io" -privateEndpoint $privateAcrEndpoint) -and
    (Establish-AzureContext -subscriptionName $subscriptionName) -and
    (Finalize -resourceGroupName $resourceGroupName  -keyVault $keyVault -tempKeyVault $tempKeyVault -userAssignedIdentityName $userAssignedIdentity.Name))
{
    $success= $true
}

if ($success -eq $true)
{
    Log-Line "Execution completed successfully."
}
else
{
    throw "Execution failed. Review logs."
}
