<#
Script: MigrateFailedBatchToMD
Purpose: 
    Purpose of this script is to migrate a batch of vm's that are in a failed state to MD. Failed from a previous MD migration attempt.
    
Version 1.04   2017-03-06

Example execution: .\MigrateFailedBatchToMD.ps1 -VmListCsv VmList.csv -SubscriptionID a97a235d-55f9-4382-856a-e38f8b5b6d31 -AzureAdTenant microsoft.onmicrosoft.com 

In the CSV there are 2 fields. 
    1. resourcegroupname = name of the resourcegroup containing the VM
    2. vmname = the name of the VM. 
#>

Param
(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionID,      # subscription ID
    [Parameter(Mandatory=$true)] 
    [string]$VmListCsv,           # Batch of vm's to be migrated to MD (i.e. VmList.csv). Each row lists the resource group and vmname.
    [Parameter(Mandatory=$true)]          
    [string]$AzureAdTenant        # AAD tenant name -- needed to establish a bearer token. i.e. xxxx.onmicrosoft.com. For Microsoft subscriptions, use: microsoft.onmicrosoft.com
)

$global:ScriptStartTime = (Get-Date -Format hh-mm-ss.ff)
$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))


if((Test-Path "Output") -eq $false)
{
	md "Output" | Out-Null
}

function GetAuthToken
{
    # Obtained from: https://blogs.technet.microsoft.com/stefan_stranger/2016/10/21/using-the-azure-arm-rest-apin-get-access-token/
    param
    (
            [Parameter(Mandatory=$true)]
            $ApiEndpointUri,
         
            [Parameter(Mandatory=$true)]
            $AADTenant
    )
  
    $adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\" + `
                "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\" + `
                    "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $authorityUri = “https://login.windows.net/$aadTenant”
    
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authorityUri
    
    $authResult = $authContext.AcquireToken($ApiEndpointUri, $clientId,$redirectUri, "Auto")
  
    return $authResult
}

function Write-Log
{
	param(
        [string]$logMessage,
	    [string]$color="White"
    )

    $timestamp = ('[' + (Get-Date -Format hh:mm:ss.ff) + '] ')
	$message = $timestamp + $logMessage
    Write-Host $message -ForeGroundColor $color
	$fileName = "Output\Log-" + $global:ScriptStartTime + ".log"
	Add-Content $fileName $message -ErrorAction SilentlyContinue
}

function ParseStorageAccount
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$uri
    )

    $i = $uri.IndexOf(".blob.core.windows.net")
    return $uri.Substring(8, $i - 8)
}

function CheckVmStatus
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $vm = $null
    $retry = 1
	while($retry -le 4) 
    {
		try {
            Write-Host "check VM status....Get-AzureRmVM"
			$vm = Get-AzureRmVM -Name $Name -ResourceGroupName $ResourceGroupName -Status -WarningAction Ignore
			break
		}
		catch
		{
			Write-Log "Retry Get-AzureRmVM. $retry/4. Exception in Get-AzureRmVM. ResourceGroupName $ResourceGroupName vmName $Name : Message: $_.Exception.Message." -color "Yellow" 
			$retry = $retry + 1
			Start-Sleep -Seconds 5
		}
	}

    return $vm
}

# MAIN CODE BODY

try
{
    $scriptStage = 0
    Write-Log "-----------------------------------------------------------------------------------------"
    Write-Log "starting the MigrateToMD.ps1 script"

    Select-AzureRmSubscription -SubscriptionId $SubscriptionID

    # Get an auth token needed for making a REST call to asynchronously invoke an ARM API and remove VMs without waiting
    $ApiEndpointUri = "https://management.core.windows.net/"
    $token = GetAuthToken -ApiEndPointUri $ApiEndpointUri -AADTenant $AzureAdTenant
    $header = @{
        'Content-Type'='application/json'
        'Authorization'=$token.CreateAuthorizationHeader()
    }

    Write-Log "Load and read the list of VMs to be moved to MD"
    $csvItems = Import-Csv $VmListCsv -ErrorAction Stop
    Write-Log "Success: Imported $VmListCsv" -color Green

    <#
    # STEP 1 -- validate the data passed in from the CSV
    #>

    Write-Log "Validating the batch data passed in from the CSV" 
    $vmNameMap = @{}  # vm's to be moved to MD

    foreach($csvItem in $csvItems)
    {
        Write-Log "Inspecting VM: $($csvItem.vmname.Trim())"
        $vmname = $csvItem.vmname.Trim()
        $resourceGroupName = $csvItem.resourcegroupname.Trim()

        $vm = CheckVmStatus -ResourceGroupName $resourceGroupName -Name $vmname    

        # validate that each VM is in a failed state from migrating to MD.
        if ($vm.Statuses[0].Code -eq 'ProvisioningState/failed/InternalExecutionError')
        {
            Write-Log "Status for VM: $($vmname): $($vm.Statuses[0].Code). Will retry."
            $vmNameMap.Add($vmname + '|' + $resourceGroupName, $vmname)
        }
        elseif ($vm.Statuses[0].Code -eq 'ProvisioningState/succeeded')
        {
            Write-Log "Status for VM: $($vmname): $($vm.Statuses[0].Code)"
        }
        else
        {
            Write-Log "Status for VM: $($vmname): $($vm.Statuses[0].Code)" -color Magenta
        }
    }

    if ($vmNameMap.Count -eq 0)
    {
        Write-Log "There are no VMs with a failed status to retry. Exiting."
        Exit
    }
    
    
    <#
    # STEP 2 -- Now attempt to migrte the failed vm's to Managed Disks.
    #>   

    $message = "Migrate the failed VMs to Managed Disks"
    Write-Log $message -color Yellow
    $question = "Retry migration of the VMs with a failed status to Managed Disks. Should the script continue?" 
            
    $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
    if ($decision -eq 0) 
    {
        Write-Log "Confirmed. Continuing with the script"
    } 
    else 
    {
        Write-Log "Exiting. No changes have been to VMs or disks." -color Magenta
        Exit
    }

    $scriptStage = 3

    foreach($vm in $vmNameMap.Keys)
    {
        $vmpair = $vm.Split('|')
        $vmname = $vmpair[0]
        $resourceGroupName = $vmpair[1]
        Write-Log "Managed Disks migration of VM: $($vmname) from Resource Group: $($resourceGroupName)" 
        
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachines/$vmname/convertToManagedDisks?api-version=2016-04-30-preview"
        Write-Log "convertToManagedDisks: $uri"

        $response = try {Invoke-RestMethod -Uri $uri -Method Post -Headers $header} catch {$_.exception.response}

        if (($response -eq $null) -or ($response -eq ""))
        {
            Write-Log -color Green "Successfully executed api for VM: $($vmname)"
        }
        elseif (($response.StatusCode.value__ -eq 202) -or ($response.StatusCode.value__ -eq 200) -or ($response.StatusCode.value__ -eq $null) -or ($response.StatusCode.value__ -eq ""))
        {
            Write-Log -color Green "Successfully executed api for VM: $($vmname). Status Code: $($response.StatusCode.value__)"
        }
        elseif ($response.StatusCode.value__ -eq 409)
        {
            Write-Log -color Red "convertToManagedDisks API returned error. Status Code: $($response.StatusCode), Status Code Value: $($response.StatusCode.value__), for VM: $($vmname)"
            Write-Log -color Red "Likely need to Stop-Deallocate the VM. If the VM is running, this is the reason."
            Write-Log -color Magenta "Look at this VM: $($vmname) in more detail"
        }
        else
        {
            Write-Log -color Red "convertToManagedDisks API returned error. Status Code: $($response.StatusCode) for VM: $($vmname)"
            Write-Log -color Red "Status Code Value: $($response.StatusCode.value__) for VM: $($vmname)"
            Write-Log -color Magenta "Look at this VM: $($vmname) in more detail"
        }

        Write-Log ""
        Start-Sleep -Seconds 1
    }

    Write-Log "Migration api invoked for each VM. As final validation, now wait for all VMs to fully restart. Will loop until migration is completed (either successful or failed)." -color Cyan

    $restartFinished = $false
    $migrationErrorOccurred = $false
    while (!$restartFinished)
    {
        $restartFinished = $true
        Write-Log "Wait 2 minutes, then check/report status on all VMs being updated in parallel..."
        Start-Sleep -Seconds 120
        foreach ($vm in $vmNameMap.Keys)
        {
            $vmpair = $vm.Split('|')
            $vmname = $vmpair[0]
            $resourceGroupName = $vmpair[1]

            $updatedvm = CheckVmStatus -Name $vmname -ResourceGroupName $resourceGroupName
            if ($updatedvm.Statuses[0].Code -eq 'ProvisioningState/succeeded') 
            {
                Write-Log "VM: $vmname has successfully started" -color Green
            }
            elseif ($updatedvm.Statuses[0].Code.ToLower().Contains('fail')) 
            {
                Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName has the status of failed. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message)" -color Red
                Write-Log "Please run this cmdlet individually on the VM to see if this completes the migration. If it does not, a support ticket will be needed : ConvertTo-AzureRmVMManagedDisk -ResourceGroupName $($resourceGroupName) -VMName $($vmname)" -color Magenta
                $migrationErrorOccurred = $true
            }
            else
            {
                Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is still in the process of being updated. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message)" -color Yellow
                $restartFinished = $false
            }
        }
    }

    Write-Log ""
    if ($migrationErrorOccurred)
    {
        Write-Log "Migration completed, but some VMs may still have a failed migration status needing retry." -color "Yellow"
    }
    else
    {
        Write-Log "Migration Success! Script completed. Migrated VM's are running succesfully. Verify VMs in the Azure Portal." -color "Green"
    }
}
catch
{
    Write-Log "Error executing the script. Resource group $resourceGroupName. VM: $vmname.  Following exception was caught:" -color "Red"
    Write-Log "$($_.Exception.Message) ... $($_.Exception.GetType().FullName) ... LineNumber: $($error[0].InvocationInfo.ScriptLineNumber): Offset: $($error[0].InvocationInfo.OffsetInLine)" -color "Red"

    if ($scriptStage -eq 0)
    {
        Write-Log "The script has not made any changes yet to the Azure deployment. It is possible the input CSV may has mistakes (depends on the error) or invalid parameters were passed into the script. Look at the error msg, check the CSV and rerun the script." -color Magenta
    }
    elseif ($scriptStage -eq 1)
    {
        Write-Log "The script errored out in the stage updating Availability Sets for Managed Disks. It's ok if an AvSet is updated for MD, but it's VMs are not using MD. Next determine what went wrong with the script and rerun." -color Magenta
    }
    elseif ($scriptStage -eq 2)
    {
        Write-Log "The script errored out in the stage where we stop-deallocate the VMs to prepare them for MD. No changes have been made to VMs. Simply figure out what caused the error, then rerun. To rollback, restart each stopped VM from the portal. Rollback is not necessary to rerun/continue." -color Magenta
    } 
    elseif ($scriptStage -eq 3)
    {
        Write-Log "The script errored out in the the final stage where each VM is updated for Managed Disks. Determine what went wrong, then rerun the script again for the VM's that have not been migrated to Managed Disks after modifying the CSV. If some VMs are in a stuck/locked state updating, a support call will be needed to resolve and unlock." -color Magenta
        Write-Log "Each resource group with VM's being modified has been exported, so that manual steps can be taken to restore the previous unmanaged disk state. Manual work will be required as part of this step." -color Cyan
    } 
}