<#
.SYNOPSIS
    Creates AKS Node Pools for Herbie
.DESCRIPTION
    Creates Node pools for given cluster
	1) Windows OS
	2) Auto scaler enabled
	3) Min Node Count 1
	4) Max node Count 10
	5) Node count 1
        

.NOTES
	File Name : Create-AKS-NodePools.ps1
	Author    : Formation ACE
	Requires  : PowerShell Version 2.0
	Born      : 12/11/2020 - Jacob Vaidyan
.EXAMPLE
.PARAMETER subscriptionName
    Required: The name of the subscription that will contain the AKS.
.PARAMETER applicationId
    Required: The application id of the application registration that will be used to deploy the AKS cluster.
.PARAMETER applicationSecret
    Required: The application secret for the application registration that will be used to deploy the AKS cluster.
.PARAMETER resourceGroupName
    Required: The name of the resouce group within which the AKS is located .
.PARAMETER aksName
    Required: The name of the AKS cluster.
.PARAMETER nodePoolName
    Required: The name of Node Pool.

#>

param
(
    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the subscription that will contain the AKS.")] 
    [string]
    $subscriptionName,
	
    [Parameter(Mandatory = $true, HelpMessage = "Enter the applicaiton id of the application registration that will be used to deploy the AKS cluster.")] 
    [string]
    $applicationId,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the secret for the application registration that will be used to deploy the AKS cluster.")] 
    [string]
    $applicationSecret,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the resource group witin which the AKS is located.")] 
    [string]
    $resourceGroupName,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the name of the AKS cluster")]
    [string]
    $aksName,
	
    [Parameter(Mandatory = $true, HelpMessage = "Enter the Node Pool name.")] 
    [string]
    $nodePoolName,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the VM size for nodes in the pool")] 
    [string]
    $nodeVmSize = 'Standard_D4s_v3',
    
    [Parameter(Mandatory = $false, HelpMessage = "Enter min number of nodes in pool")]
    [ValidateRange(1, 1000)] 
    [int]
    $minNodeCount = 1,

    [Parameter(Mandatory = $false, HelpMessage = "Enter max number of nodes in pool")]
    [ValidateRange(1, 1000)]
    [int]
    $maxNodeCount = 10,

    [Parameter(Mandatory = $false, HelpMessage = "Enter max number of pods that can run on a node")]
    [ValidateRange(10, 250)]
    [int]
    $maxPodCount = 30
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

    Write-Host -NoNewline -Separator '' -ForegroundColor Green $timeStamp " ";
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

            Write-Host -NoNewline -Separator '' -ForegroundColor $color $timeStamp " ";
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
        $script:context = Set-AzContext -SubscriptionObject $subscription
        Log-Line $script:context.Name
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

function Acquire-AKS-NodePool {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory = $true)] 
        [string]
        $aksName,
		
        [Parameter(Mandatory = $true)] 
        [string]
        $nodePoolName
    )

    $retVal = $false
    $aksClusterNotFound = $false

    try {
        Log-Line "Checking for Cluster [$aksName]"
        $script:aksClusterInfo = Get-AzAks -ResourceGroupName $resourceGroupName -Name $aksName -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message.Contains("not found.") -eq $true) {
            $aksClusterNotFound = $true
        }
        else {
            Log-Line $_.Exception.Message
        }
    }

    if ($aksClusterNotFound -eq $false) {

        $loginSuccessfull = $true
        $arguments = @(
            "login",
            "--service-principal",
            "-u", "$applicationId", 
            "-p", "$applicationSecret",
            "--tenant", "cdf226d7-79fd-4290-a3a7-996968201a26"
        );
        Log-Line "Azure CLI login [$($arguments -join ' ')]."
        $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
            -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
        
        if ($process.ExitCode -ne 0) {
            $loginSuccessfull = $false
            Log-Line "az login exited with a non 0 exit code";
            $errorMessage = Get-Content "stderr.txt" -Raw
            Log-Line "$errorMessage";
        }
        if ($loginSuccessfull -eq $true) {
            Log-Line "Azure CLI login succeeded."
            
            try {
                Log-Line "Looking For Node pool ...";
                $arguments = @(
                    "aks", "nodepool", "show",
                    "--resource-group", "$resourceGroupName", 
                    "--cluster-name", "$aksName",
                    "--name", "$nodePoolName"
                );
                Log-Line "az $($arguments -join ' ')";
                $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
                    -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";

                if ($process.ExitCode -eq 0) {
                    Log-Line "Node pool with name [$nodePoolName] found.";
                    $retVal = $true;
                }
                else {
                    $errorMessage = Get-Content "stderr.txt" -Raw
                    if ($errorMessage.Contains("Not Found") -eq $true) {
                        Log-Line "Node pool with name [$nodePoolName] NOT found.";
                        $retVal = $false;
                    }
                    else {
                        throw $errorMessage;
                    }
                }
            }
            catch {
                Log-Line "$($_.Exception.Message)";
                throw $_;
            }
        }
        else {
            throw "Azure CLI login failed";
        }
		
    }
    else {
        throw "Cluster Not Found";
    }

    return $retVal
}

function New-AKS-NodePool {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $resourceGroupName, 

        [Parameter(Mandatory = $true)] 
        [string]
        $aksName,
		
        [Parameter(Mandatory = $true)] 
        [string]
        $nodePoolName,

        [Parameter(Mandatory = $true)] 
        [string]
        $nodeVmSize,
    
        [Parameter(Mandatory = $true)]
        [int]
        $minNodeCount,

        [Parameter(Mandatory = $true)]
        [int]
        $maxNodeCount,

        [Parameter(Mandatory = $true)]
        [int]
        $maxPodCount
    )

    try {
        Log-Line "Creating Node pool ..."
        $arguments = @(
            "aks", "nodepool", "add",
            "--resource-group", "$resourceGroupName", 
            "--cluster-name", "$aksName",
            "--name", "$nodePoolName",
            "--node-count", "$minNodeCount",
            "--enable-cluster-autoscaler",
            "--min-count", "$minNodeCount",
            "--max-count", "$maxNodeCount",
            "--max-pods", "$maxPodCount",
            "--node-vm-size", "$nodeVmSize",
            "--os-type", "Windows",
            "--zones", "1 2 3",
            "--no-wait"
        );
        Log-Line "az $($arguments -join ' ')";
        $process = Start-Process -FilePath "az" -ArgumentList $arguments -NoNewWindow -PassThru -Wait `
            -RedirectStandardOutput "stdout.txt" -RedirectStandardError "stderr.txt";
                
        if ($process.ExitCode -eq 0) {
            Log-Line "Checking for Provisioning state as it takes a while to create the Nodepool."
            do {
                $aksNodePool = az aks nodepool show --cluster-name $aksName --name $nodePoolName --resource-group $resourceGroupName | ConvertFrom-Json
                $aksNPProvisioningState = $aksNodePool.ProvisioningState
                Log-Line "AKS Nodepool [$nodePoolName] is [$aksNPProvisioningState]."
                Start-Sleep -Milliseconds 30000
            }
            while ($aksNodePool.ProvisioningState -ne "Failed" -and $aksNodePool.ProvisioningState -ne "Succeeded")

            if ($aksNodePool -ne $null -and $aksNodePool.ProvisioningState -eq "Succeeded") {
                Log-Line "AKS Nodepool [$nodePoolName] created in AKS cluster [$aksName]."
            }
        }
        else {
            Log-Line "az aks nodepool add exited with a non 0 exit code";

            #$aksCreateErrMsg is Arraylist, convert to String.
            $errorMessage = Get-Content "stderr.txt" -Raw
            if ($errorMessage.Contains("already exists") -eq $true) {
                Log-Line "Node Pool [$nodePoolName] already exists.";
                throw "Node Pool already exists.";
            }
            else {
                $errorMessage | Log-Lines -color Red
            }
        }
    }
    catch {
        Log-Line $_.Exception.Message;
        throw $_;
    }    
}

if ($minNodeCount -ge $maxNodeCount) {
    throw "Min node count must be less than max node count";
}

Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line "Powershell executing Create AKS Node Pool Version v2.0.0.0 on $currentDate ($currentDateString)"
Log-Line ""
Log-Line "Powershell Version Information"
Log-Line ""
Log-VersionTable
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""
Log-Line "subscriptionName: [$subscriptionName]"
Log-Line "resourceGroupName: [$resourceGroupName]"
Log-Line "applicationId: [$applicationId]"
Log-Line "applicationSecret: [$applicationSecret]"
Log-Line "aksName: [$aksName]"
Log-Line "nodePoolName: [$nodePoolName]"
Log-Line "nodeVmSize: [$nodeVmSize]"
Log-Line "minNodeCount: [$minNodeCount]"
Log-Line "maxNodeCount: [$maxNodeCount]"
Log-Line "maxPodCount: [$maxNodeCount]"
Log-Line ""
Log-Line "-----------------------------------------------------------------------------------------------------------------"
Log-Line ""

if ((Establish-AzureContext -subscriptionName $subscriptionName) -and
    (Acquire-ResourceGroup -resourceGroupName $resourceGroupName -subscriptionName $subscriptionName)) {
    if (!(Acquire-AKS-NodePool -resourceGroupName $resourceGroupName -aksName $aksName -nodePoolName $nodePoolName)) {
        New-AKS-NodePool -resourceGroupName $resourceGroupName -aksName $aksName -nodePoolName $nodePoolName `
            -nodeVmSize $nodeVmSize -minNodeCount $minNodeCount -maxNodeCount $maxNodeCount -maxPodCount $maxPodCount;        
    }
    else {
        Log-Line "Node pool [$nodePoolName] already exists on [$aksName]. If you wish to change its configuration you will need to delete the node pool first.";
    }
    $success = $true;
}

if ($success -eq $true) {
    Log-Line "Execution completed successfully."
}
else {
    throw "Execution failed. Review logs."
}
