<#
.SYNOPSIS
    Enable Scheduled Tasks
#>


function Enable-UsoTask {
    [CmdletBinding()]
    param(
        [string[]] $names
    )

    Enable-Task -path '\Microsoft\Windows\UpdateOrchestrator\' -names $names 
}

function Enable-WUTask {
    [CmdletBinding()]
    param(
        [string[]] $names
    )

    Enable-Task -path '\Microsoft\Windows\WindowsUpdate\' -names $names     
}

function Enable-Task {
    [CmdletBinding()]
    param(
        [string] $path,
        [string[]] $names

    )

    Write-Message "Checking the tasks under '$path'."
    $tasks = Get-ScheduledTask -TaskPath $path
	
    foreach ($name in $names) {
        Write-Output "Looking for Task: $name"
        $task = $tasks | Where-Object {$_.TaskName -eq $name}

        if ($null -eq $task) {
            Write-Output "$name task not found."
            continue;
        }
       
        try {
            if ($task.State -eq 'Disabled') {
                Enable-ScheduledTask -InputObject $task | Out-Null
                Write-Message "FIXED: $name task was disabled, so enabled it." -ForegroundColor "Yellow"
            }
            else {
                Write-Message "$name task is already enabled." -ForegroundColor "Green"
            }
        }
        catch {
            Write-Message "Unable to modify $name task." -ForegroundColor "Yellow"
            Write-Message $_ -ForegroundColor "Yellow"
        }
     }
}

