<#
.SYNOPSIS
    Sets service startup type.
#>


function Set-ServiceStartupType {
    [CmdletBinding()]
    param (
        [string[]] $names,
        [string] $startupType = 'manual'
    )

    Foreach($name in $names) {
        $service = Get-WmiObject -Class Win32_Service | Where-Object {$_.name -eq $name}

        if ($null -eq $service) {
            Write-Output "$name service not found."
            continue;
        }

        $startMode = $service.StartMode
        
        if ($startMode -ne $startupType) {
            Set-Service $name -startuptype $startupType

            Write-Message "FIXED: Startup type for $name service was $startMode, now set to $startupType." -ForegroundColor "Yellow"
        }
        else {
            Write-Message "Startup type for $name service is already set to $startupType." -ForegroundColor "Green"
        }
    }
}