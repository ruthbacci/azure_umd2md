<#
Script: MigrateBatchToMD
Purpose: 
    Purpose of this script is to migrate a batch of vm's to MD. Script will perform the following steps
        1. Pre-validation
            Validate the inbound csv containing a batch of vm names and resource groups. Ensure all csv data is valid.
            Validate all the storage accounts used by the VM's disks are not SSE enabled. 
            Validate the calculated MD names will be less than 80 characters
            Validate all VM extensions on the VM are in working order
        2. Update any Availability Sets used by the VMs to "Managed"
        3. Deallocate all the VMs in the batch in parallel using REST. Then wait for all VMs to fully shutdown.
        4. Convert the batch of VMs to Managed Disks in parallel using REST.
            Includes appropriate retry logic for common retriable failures.
        5. Wait for all VMs to restart.
    
Version 1.07   2017-03-16

Author
    Colin Cole, Cloud Solution Architect, Microsoft
    colinco@microsoft.com

Example execution: .\MigrateBatchToMD.ps1 -VmListCsv VmList.csv -SubscriptionID a97a235d-55f9-4382-856a-e38f8b5b6d31 -AzureAdTenant microsoft.onmicrosoft.com -Unattended

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
    [string]$AzureAdTenant,       # AAD tenant name -- needed to establish a bearer token. i.e. xxxx.onmicrosoft.com. For Microsoft subscriptions, use: microsoft.onmicrosoft.com
    [Parameter(Mandatory=$false)]
    [switch]$Unattended = $false  # Set this flag to avoid being prompted between stages
)

$global:ScriptStartTime = (Get-Date -Format hh-mm-ss.ff)
$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
$token = $null
$header = $null


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
	param
    (
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
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$uri
    )

    $i = $uri.IndexOf(".blob.core.windows.net")
    return $uri.Substring(8, $i - 8)
}

function MigrateVmToManagedDisks
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$resourceGroupName,
        [Parameter(Mandatory=$true)]
        [string]$vmname
    )

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
}

function CheckVmStatus
{
    param
    (
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

function GetVmRetry
{
    param
    (
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
            Write-Host "check VM....Get-AzureRmVM"
			$vm = Get-AzureRmVM -Name $Name -ResourceGroupName $ResourceGroupName -WarningAction Ignore
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
    Write-Log "parameters: $SubscriptionID : $AzureAdTenant"

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
    $rgNameMap = @{}  # set of resource groups owning VMs being moved
    $asNameMap = @{}  # set of AS's to be moved to MD
    $validatedSAs = @{}  # validated storage accounts (do not have SSE enabled)
    $stoppedVmNameMap = @{}  # vm's to be moved to MD

    foreach($csvItem in $csvItems)
    {
        Write-Log "Inspecting VM: $($csvItem.vmname.Trim())"
        $vmname = $csvItem.vmname.Trim()
        $resourceGroupName = $csvItem.resourcegroupname.Trim()

        $vmNameMap.Add($vmname + '|' + $resourceGroupName, $vmname)
        $vm = GetVmRetry -ResourceGroupName $resourceGroupName -Name $vmname
        $vmstatus = CheckVmStatus -ResourceGroupName $resourceGroupName -Name $vmname
        if ($vmstatus.Statuses[1].Code -eq 'PowerState/deallocated') 
        {
            $stoppedVmNameMap.Add($vmname + '|' + $resourceGroupName, $vmname)
            Write-Log "VM: $vmname from $resourceGroupName is in a stopped state. Stop VM after MD migration." -color Cyan
        }

        $avSet = ""
        if ($vm.AvailabilitySetReference -ne $null)
        {
            $avSetPair = $vm.AvailabilitySetReference.Id.Split('/')
            $avSet = $avSetPair[$avSetPair.Length-1]

            if (!($asNameMap.ContainsKey($avSet + '|' + $resourceGroupName)))
            {
                Write-Log "Inspecting Availability Set: $($avSet)"
                $as = Get-AzureRmAvailabilitySet -ResourceGroupName $resourceGroupName -Name $avSet -ErrorAction Stop -WarningAction Ignore
                $asNameMap.Add($avSet + '|' + $resourceGroupName, $avSet)
            }
        }

        if (!($rgNameMap.ContainsKey($resourceGroupName)))
        {
            $rgNameMap.Add($resourceGroupName, $resourceGroupName)
        }

        # validate the VM hasn't already been migrated to MD.
        if ($vm.StorageProfile.OsDisk.ManagedDisk -ne $null)
        {
            Write-Log "VM: $vmname from Resource Group: $resourceGroupName appears to already run on Managed Disks. Fix CSV. Exiting script" -color Red
            Exit
        }

        # validate all extensions have a successful status. This is a requirement for managed disks migration.
        foreach ($ext in $vm.Extensions)
        {
            if ($ext.ProvisioningState -ne "Succeeded")
            {
                Write-Log "VM: $vmname from Resource Group: $resourceGroupName has an extension in a bad state: $($ext.Name). State: $($ext.ProvisioningState). Fix the extension. Exiting script" -color Red
                Exit 
            }
        }

        # validate the length of the current disk name + the vm name is less than 80 chars. This is a current requirement for MD migration.
        if (($vm.StorageProfile.OsDisk.Name.Length + $vm.Name.Length) -ge 80)
        {
            Write-Log "VM: $vmname from Resource Group: $resourceGroupName has an OS disk name that is too long for Managed Disks: $($vm.StorageProfile.OsDisk.Name)." -color Red
            Exit 
        }

        foreach ($datadisk in $vm.StorageProfile.DataDisks)
        {
            if (($datadisk.Name.Length + $vm.Name.Length) -ge 80)
            {
                Write-Log "VM: $vmname from Resource Group: $resourceGroupName has a data disk name that is too long for Managed Disks: $($datadisk.Name)." -color Red
                Exit 
            }
        }

        # Validate that the storage accounts used for the VM's OS and data disks are not SSE enabled (which will currently freeze up a migration requiring a support call).    
        $osSaName = ParseStorageAccount($vm.StorageProfile.OsDisk.Vhd.Uri)
        if (!$validatedSAs.ContainsKey($osSaName))
        {
            Write-Log "Inspecting storage account: $($osSaName)"
            $sa = Get-AzureRmStorageAccount | where {$_.StorageAccountName -eq $osSaName}
            if ($sa -ne $null)  # $null if $sa is a v1 storage account -- which is fine as it's not SSE enabled
            {
                $validatedSAs.Add($sa.StorageAccountName, $sa.StorageAccountName)
                if ($sa.Encryption.Services.Blob.Enabled -eq $true)
                {
                    Write-Log "VM: $vmname from Resource Group: $resourceGroupName has its os disk in an SSE enabled storage account: $($sa.StorageAccountName)." -color Red
                    Exit 
                }
            }
        }

        foreach ($datadisk in $vm.StorageProfile.DataDisks)
        {
            $dataSaName = ParseStorageAccount($datadisk.Vhd.Uri)
            if (!$validatedSAs.ContainsKey($dataSaName))
            {
                Write-Log "Inspecting storage account: $($dataSaName)"
                $sa = Get-AzureRmStorageAccount | where {$_.StorageAccountName -eq $dataSaName}
                if ($sa -ne $null)
                {
                    $validatedSAs.Add($sa.StorageAccountName, $sa.StorageAccountName)
                    if ($sa.Encryption.Services.Blob.Enabled -eq $true)
                    {
                        Write-Log "VM: $vmname from Resource Group: $resourceGroupName has its data disk in an SSE enabled storage account: $($sa.StorageAccountName)." -color Red
                        Exit 
                    }
                }
            }
        }
    }

    Write-Log "Validation complete. Now export each of the resource groups being modified for backup/restore failsafe." -color Green
    foreach($rg in $rgNameMap.Keys)
    {
        Write-Log "Exporting $rg"
        try
        {
            Export-AzureRmResourceGroup -ResourceGroupName $rg -IncludeParameterDefaultValue -WarningAction Ignore -Force -ErrorAction Ignore
        }
        catch {}
    }
    
    <#
    # STEP 2 -- Update availability sets to MD.
    #>   

    if (!$Unattended)
    {
        $message = "Update all availability sets?"
        Write-Log $message -color Yellow
        $question = "Update all availability sets to managed. No changes have been made yet. Should the script continue?" 
            
        $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
        if ($decision -eq 0) 
        {
            Write-Log "Confirmed. Continuing with the script"
        } 
        else 
        {
            Write-Log "Exiting. No changes have been made to any Azure resources." -color Magenta
            Exit
        }
    }
    else
    {
        Write-Log "Update availability sets if any exist."
    }

    $scriptStage = 1

    foreach($as in $asNameMap.Keys)
    {
        $aspair = $as.Split('|')
        $avSetName = $aspair[0]
        $resourceGroupName = $aspair[1]
        Write-Log "Migrate AvailabilitySet: $($avSetName) from Resource Group: $($resourceGroupName)" 
        $as = Get-AzureRmAvailabilitySet -ResourceGroupName $resourceGroupName -Name $avSetName -ErrorAction Stop -WarningAction Ignore
        if ($as.Managed -ne $true)
        {
            Write-Log "Availability set $($as.Name) not set to Managed. Updating availability set..." 
            Update-AzureRmAvailabilitySet -AvailabilitySet $as -Managed -ErrorAction Stop
            Write-Log "Availability set $($as.Name) successfully updated to Managed." -color Green
        }
    }

    Write-Log "Completed availablity set updates to Managed (if any). Now ready to stop-deallocate VMs."

    <#
    # STEP 3 -- Stop-deallocate all of the VMs to be moved to MD.
    #>
    
    if (!$Unattended)
    {
        $message = "Stop-deallocate all VMs?"
        Write-Log $message -color Yellow
        $question = "Stop-deallocate all VMs being migrated to MD. No changes to VM's have been made yet. Should the script continue?" 
            
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
    }
    else
    {
        Write-Log "Stop-deallocate all VMs"
    }

    $scriptStage = 2

    foreach($vm in $vmNameMap.Keys)
    {
        $vmpair = $vm.Split('|')
        $vmname = $vmpair[0]
        $resourceGroupName = $vmpair[1]
        Write-Log "Shutdown VM: $($vmname) from Resource Group: $($resourceGroupName)" 
        
        $uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Compute/virtualMachines/$vmname/deallocate?api-version=2016-03-30"
        Write-Host "deallocate: $uri"

        $response = try {Invoke-RestMethod -Uri $uri -Method Post -Headers $header} catch {$_.exception.response}

        if (($response -eq $null) -or ($response -eq ""))
        {
            Write-Log -color Green "Successfully executed api for VM: $($vmname)"
        }
        elseif (($response.StatusCode.value__ -eq 202) -or ($response.StatusCode.value__ -eq 200) -or ($response.StatusCode.value__ -eq $null) -or ($response.StatusCode.value__ -eq ""))
        {
            Write-Log -color Green "Successfully executed api for VM: $($vmname). Status Code: $($response.StatusCode.value__)"
        }
        else
        {
            Write-Log -color Red "Shutoown VM Error with asynch REST call. Status Code: $($response.StatusCode), Status Code Value: $($response.StatusCode.value__) for VM: $($vmname)"
            Write-Log "Attempting to shutdown the VM vmname using synchronous cmdlet. This will take a few minutes...."
            Start-Sleep -Seconds 5
            Stop-AzureRmVM -Name $vmname -ResourceGroupName $resourceGroupName -Force -ErrorAction Stop
            Write-Log "Retry success: Stopped VM: $(vmname)" -color Green
        }

        Write-Log ""
        Start-Sleep -Milliseconds 500
    }
    

    Write-Log "Deallocation api called for each VM. Now wait for all VMs to fully stop...then continue with next step" -color Cyan

    $shutdownFinished = $false
    while (!$shutdownFinished)
    {
        $shutdownFinished = $true
        Write-Log "Wait 2 minutes, then check status on all VMs being stopped in parallel..."
        Start-Sleep -Seconds 120
        foreach ($vm in $vmNameMap.Keys)
        {
            $vmpair = $vm.Split('|')
            $vmname = $vmpair[0]
            $resourceGroupName = $vmpair[1]

            $stoppedvm = CheckVmStatus -ResourceGroupName $resourceGroupName -Name $vmname
            if ($stoppedvm.Statuses[1].Code -eq 'PowerState/deallocated') 
            {
                Write-Log "VM: $($vmname) has successfully stopped"
            }
            else
            {
                Write-Log "VM: $($vmname) is still in the process of being stopped. Provisioning state: $($stoppedvm.Statuses[1].Code)"
                $shutdownFinished = $false
                break
            }
        }
    }

    Write-Log "Dellocation of VMs is complete. Now ready to migrate VM's to MD." -color Green

    <#
    # STEP 4 -- Now migrate the stopped vm's to Managed Disks.
    #>
    
    if (!$Unattended)
    {
        $message = "Migrate the VMs to Managed Disks?"
        Write-Log $message -color Yellow
        $question = "Migrate the VMs to Managed Disks. No changes to VM's have been made yet to VM's or disks other than shutting down the VM's. Should the script continue?" 
            
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
    }
    else
    {
        Write-Log "Migrate each VM to use Managed Disks"
    }

    $scriptStage = 3

    foreach($vm in $vmNameMap.Keys)
    {
        $vmpair = $vm.Split('|')
        $vmname = $vmpair[0]
        $resourceGroupName = $vmpair[1]
        
        MigrateVmToManagedDisks -resourceGroupName $resourceGroupName -vmname $vmname

        Write-Log ""
        Start-Sleep -Milliseconds 500
    }

    Write-Log "Migration API invoked for each VM. Now wait for all VMs to fully restart. Will loop until migration is completed (either successful or failed)." -color Cyan

    $vmRetryNameMap = @{}  # vm's to reattempt migration
    $restartFinished = $false
    while (!$restartFinished)
    {
        $restartFinished = $true
        $vmRetryNameMap.Clear()
        Write-Log "Wait 8 minutes, then check/report status on all VMs being updated in parallel. Retry migration if necessary..."
        Write-Log "-------------------------------------------------------------------------------------------------------------------"
        Start-Sleep -Seconds 480
        foreach ($vm in $vmNameMap.Keys)
        {
            $vmpair = $vm.Split('|')
            $vmname = $vmpair[0]
            $resourceGroupName = $vmpair[1]

            $updatedvm = CheckVmStatus -ResourceGroupName $resourceGroupName -Name $vmname
            if ($updatedvm.Statuses[0].Code -eq 'ProvisioningState/succeeded') 
            {
                Write-Log "VM: $vmname has successfully started" -color Green
            }
            elseif ($updatedvm.Statuses[0].Code.ToLower().Contains('fail')) 
            {       
                if (!$vmRetryNameMap.ContainsKey($vmname + '|' + $resourceGroupName))
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName was marked with a status of failed. We will now automatically retry the migration on this VM. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message)" -color Magenta
                    MigrateVmToManagedDisks -resourceGroupName $resourceGroupName -vmname $vmname
                    Write-Log "Retry executed. Status will be rechecked."
                    $vmRetryNameMap.Add($vmname + '|' + $resourceGroupName, $vmname)
                }
                else
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName was marked with a status of failed. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message)" -color Magenta
                }
            }
            elseif (($updatedvm.VMAgent.Statuses[0].Code -eq 'ProvisioningState/Unavailable') -and ($updatedvm.VMAgent.Statuses[0].Message.Contains("VM status blob is found but not yet populated."))) 
            {       
                if (!$vmRetryNameMap.ContainsKey($vmname + '|' + $resourceGroupName))
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName has an agent status of ProvisioningState/Unavailable. We will retry the migration on this VM. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message). Agent status: $($updatedvm.VMAgent.Statuses[0].Code). Agent Message: $($updatedvm.VMAgent.Statuses[0].Message)" -color Magenta
                    MigrateVmToManagedDisks -resourceGroupName $resourceGroupName -vmname $vmname
                    Write-Log "Retry executed. Status will be rechecked."
                    $vmRetryNameMap.Add($vmname + '|' + $resourceGroupName, $vmname)
                }
                else
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is still has an Unavailable status. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message). Agent status: $($updatedvm.VMAgent.Statuses[0].Code). Agent Message: $($updatedvm.VMAgent.Statuses[0].Message)" -color Magenta
                }
            }
            else
            {
                $updatedvm2 = GetVmRetry -ResourceGroupName $resourceGroupName -Name $vmname
                if (($updatedvm2.StorageProfile.OsDisk.ManagedDisk -ne $null) -and ($updatedvm2.StorageProfile.OsDisk.ManagedDisk.Id -eq $null))
                {
                    if (!$vmRetryNameMap.ContainsKey($vmname + '|' + $resourceGroupName))
                    {
                        Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is converted to Managed Disks, but has not linked the disk resources to the VM. We will retry the migration on this VM. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message)." -color Magenta
                        MigrateVmToManagedDisks -resourceGroupName $resourceGroupName -vmname $vmname
                        Write-Log "Retry executed. Status will be rechecked."
                        $vmRetryNameMap.Add($vmname + '|' + $resourceGroupName, $vmname)
                    }
                    else
                    {
                        Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is converted to Managed Disks, but hasn't linked the MD resources to the VM. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message). Agent status: $($updatedvm.VMAgent.Statuses[0].Code). Agent Message: $($updatedvm.VMAgent.Statuses[0].Message)" -color Magenta
                    }
                }
                else
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is still in the process of being updated. Status code: $($updatedvm.Statuses[0].Code)." -color Yellow
                    $restartFinished = $false   # loop another round
                }
            }
        }
    }

    # In case there was a failure/retry in the last round of status checks, go through one more time and wait for those final retries to report status, then end.
    if ($vmRetryNameMap.Count -gt 0)
    {
        $restartFinished = $false
        $migrationErrorOccurred = $false
        while (!$restartFinished)
        {
            $restartFinished = $true
            Write-Log "-------------------------------------------------------------------------------------------------------------------"
            Write-Log "Some VMs needed a managed disks migration retry. Wait 4 minutes, check/report status on the VM's being retried, then end the script."
            Start-Sleep -Seconds 240
            foreach ($vm in $vmRetryNameMap.Keys)
            {
                $vmpair = $vm.Split('|')
                $vmname = $vmpair[0]
                $resourceGroupName = $vmpair[1]

                $updatedvm = CheckVmStatus -ResourceGroupName $resourceGroupName -Name $vmname
                $updatedvm2 = GetVmRetry -ResourceGroupName $resourceGroupName -Name $vmname

                if ($updatedvm2.StorageProfile.OsDisk.ManagedDisk -eq $null)
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is not set to MD. Run ConvertTo-AzureRmVMManagedDisk cmdlet on this VM to complete migration." -color Red 
                }
                elseif ($updatedvm2.StorageProfile.OsDisk.ManagedDisk.Id -eq $null)
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is set to MD but not linked to the disk resources. Run ConvertTo-AzureRmVMManagedDisk cmdlet on this VM to complete migration." -color Red 
                }

                if ($updatedvm.Statuses[0].Code -eq 'ProvisioningState/succeeded') 
                {
                    Write-Log "VM: $vmname has successfully started" -color Green

                }
                elseif ($updatedvm.Statuses[0].Code.ToLower().Contains('fail')) 
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName has the status of failed. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message)" -color Red
                    Write-Log "Please run MigrateFailedBatchToMD.ps1, or individually run the ConvertTo-AzureRmVMManagedDisk cmdlet on the VM to see if migration will complete. If it does not, a support ticket will be needed." -color Magenta
                    $migrationErrorOccurred = $true
                }
                elseif (($updatedvm.VMAgent.Statuses[0].Code -eq 'ProvisioningState/Unavailable') -and ($updatedvm.VMAgent.Statuses[0].Message.Contains("VM status blob is found but not yet populated."))) 
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName has the status of Unavailable. Status code: $($updatedvm.Statuses[0].Code). Message: $($updatedvm.Statuses[0].Message). Agent status: $($updatedvm.VMAgent.Statuses[0].Code). Agent Message: $($updatedvm.VMAgent.Statuses[0].Message)" -color Red
                    Write-Log "Please run MigrateFailedBatchToMD.ps1, or individually run the ConvertTo-AzureRmVMManagedDisk cmdlet on the VM to see if migration will complete. If it does not, a support ticket will be needed." -color Magenta
                    $migrationErrorOccurred = $true
                }
                else
                {
                    Write-Log "VM: $vmname from ResourceGroup: $resourceGroupName is still in the process of being updated. Status code: $($updatedvm.Statuses[0].Code)." -color Yellow
                    $restartFinished = $false
                }
            }
        }

        if ($migrationErrorOccurred)
        {
            Write-Log ""
            Write-Log "The script has completed with with some migration errors. Please retry ConvertTo-AzureRmVMManagedDisk on the failed VMs, and/or invovle support as appropriate if the VM's control plane is locked out." -color "Yellow"
            Exit
        }
    }
    
    Write-Log ""
    Write-Log "Migration Success! Script completed. Migrated VM's are running succesfully. Verify VMs in the Azure Portal." -color "Green"
    foreach ($stoppedvm in $stoppedVmNameMap.Keys)
    {
        Write-Log "When ready, stop-deallocate VM: $stoppedvm" -color Cyan
    }  
}
catch
{
    Write-Log "Error executing the script. Resource group $resourceGroupName. VM: $vmname.  Following exception was caught:" -color "Red"
    Write-Log "$($_.Exception.Message) ... $($_.Exception.GetType().FullName) ... LineNumber: $($error[0].InvocationInfo.ScriptLineNumber): Offset: $($error[0].InvocationInfo.OffsetInLine)" -color "Red"

    if ($scriptStage -eq 0)
    {
        Write-Log "The script has not made any changes yet to the Azure deployment. It is possible the input CSV has mistakes (depends on the error) or invalid parameters were passed into the script. Look at the error msg, check the CSV and rerun the script." -color Magenta
    }
    elseif ($scriptStage -eq 1)
    {
        Write-Log "The script errored out in the stage updating Availability Sets for Managed Disks. It's ok if an AvSet is updated for MD, but it's VMs are not yet using MD. Next determine what went wrong with the script and rerun." -color Magenta
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