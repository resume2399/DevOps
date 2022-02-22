[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Azure subscription ID")]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,
    [Parameter(Mandatory = $true, HelpMessage = "Azure Resource Group")]
    [ValidateNotNullOrEmpty()]
    [string]$ResourceGroupName,
    [Parameter(Mandatory = $true, HelpMessage = "FQDN or IP address of database server")]
    [ValidateNotNullOrEmpty()]
    [string]$DbServer,
    [Parameter(Mandatory = $true, HelpMessage = "Name of elastic pool")]
    [string]$ElasticPoolName,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Standard", "Premium")]
    [string]$Edition,
    [Parameter(Mandatory = $true)]
    [ValidateSet(50, 100, 125, 200, 250, 300, 400, 500, 800, 1000, 1200, 1500, 1600, 2000, 2500, 3000, 3500, 4000)]
    [int]$Dtu,
    [Parameter(Mandatory = $false)]
    [int]$MaxDatabaseDtu = 0
)

<#
    Write out log messages with timestamp
#>
function Write-Log {
    param (
        [Parameter(Mandatory = $false)]
        [string]$msg,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warn', 'Error', 'Verbose')]
        [string]$type = 'Info'
    )

    $timeStamp = Get-Date -Format 'HH:mm:ss.fff';
    switch ($type) {
        'Warn' {
            Write-Host -ForegroundColor Yellow "$timeStamp  [WARNING]: $msg";
            break;
        }
        'Error' {
            Write-Host -ForegroundColor Red "$timeStamp  [ERROR]: $msg";
            break;
        }
        'Verbose' {
            if ($VerbosePreference -ne 'SilentlyContinue') {
                Write-Host -ForegroundColor Yellow "$timeStamp  [VERBOSE]: $msg";
            }
            break;
        }
        Default {
            Write-Host -ForegroundColor Green "$timeStamp  $msg";
        }
    }
}

<#
    Set Azure Subscription Context
#>
function Set-Subscription {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SubscriptionId
    )
    try {
        Write-Log "Setting Azure subscription to subscription with ID: [$SubscriptionId]";
        $sub = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop;
        Write-Log "Now working in Azure subscription [$($sub.Name)]";
    }
    catch {
        Write-Log "Error setting subscription. $($_.Exception.Message)" -type Error;
        throw $_;
    }    
}

function New-ElasticPool {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        [Parameter(Mandatory = $true)]
        [string]$ElasticPoolName,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Standard", "Premium")]
        [string]$Edition,
        [Parameter(Mandatory = $true)]
        [ValidateSet(50, 100, 125, 200, 250, 300, 400, 500, 800, 1000, 1200, 1500, 1600, 2000, 2500, 3000, 3500, 4000)]
        [int]$PoolDtu,
        [Parameter(Mandatory = $false)]
        [int]$MinDatabaseDtu = 0,
        [Parameter(Mandatory = $false)]
        [int]$MaxDatabaseDtu = 0
    )
    try {
        if ($Edition -eq 'Standard') {
            if (($PoolDtu -ne 50) -and
                ($PoolDtu -ne 100) -and
                ($PoolDtu -ne 200) -and
                ($PoolDtu -ne 300) -and
                ($PoolDtu -ne 400) -and
                ($PoolDtu -ne 800) -and
                ($PoolDtu -ne 1200) -and
                ($PoolDtu -ne 1600) -and
                ($PoolDtu -ne 2000) -and
                ($PoolDtu -ne 2500) -and
                ($PoolDtu -ne 3000)) {
                throw "Invalid DTU value for Standard edition";
            }
            if ($MaxDatabaseDtu -eq 0) { $MaxDatabaseDtu = 100; }
        }
        elseif ($Edition -eq 'Premium') {
            if (($PoolDtu -ne 125) -and
                ($PoolDtu -ne 250) -and
                ($PoolDtu -ne 500) -and
                ($PoolDtu -ne 1000) -and
                ($PoolDtu -ne 1500) -and
                ($PoolDtu -ne 2000) -and
                ($PoolDtu -ne 2500) -and
                ($PoolDtu -ne 3000) -and
                ($PoolDtu -ne 3500) -and
                ($PoolDtu -ne 4000)) {
                throw "Invalid DTU value for Premium edition";
            }
            if ($MaxDatabaseDtu -eq 0) { $MaxDatabaseDtu = 125; }
        }
        Write-Log "Create elastic pool [$ElasticPoolName] on database server [$ServerName]";
        
        New-AzSqlElasticPool -ResourceGroupName $ResourceGroupName -ServerName $ServerName -ElasticPoolName $ElasticPoolName `
            -Edition $Edition -Dtu $PoolDtu -DatabaseDtuMin $MinDatabaseDtu -DatabaseDtuMax $MaxDatabaseDtu | Out-Host;

        Write-Log "Done.";
    }
    catch {
        Write-Log "Error creating elastic pool.`n $($_.Exception.Message)" -type Error;
        throw $_;
    }
}

######
## Uncomment login lines if you want to be prompted to login
## during script runtime.
######
# Login
# Connect-AzAccount;

# Set subscription
Set-Subscription -SubscriptionId $SubscriptionId;

# Try to find resource group
$resourceGroup = (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue);

if ($resourceGroup -eq $NULL) {
    Write-Log "Could not find resource group $ResourceGroupName" -type Error;
    throw "Invalid resource group provided.";
}

Write-Log "Found resource group [$ResourceGroupName]";

$dbServerName = ($DbServer.Split('.')[0]);

$pool = Get-AzSqlElasticPool -ElasticPoolName $ElasticPoolName -ServerName $dbServerName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue;

if ($pool -ne $NULL) {
    Write-Log "Found existing elastic pool with name [$ElasticPoolName] on database server [$dbServerName].";
    return;
}

New-ElasticPool -ResourceGroupName $ResourceGroupName -ServerName $dbServerName -ElasticPoolName $ElasticPoolName `
    -Edition '' -PoolDtu $Dtu -MaxDatabaseDtu $MaxDatabaseDtu;
