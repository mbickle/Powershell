<#
    .SYNOPSIS
        Powershell Script to get the current AU settings for USO
#>

$AUOptionsRegkey = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

<#
    .SYNOPSIS
        Powershell Script to get the current AU settings for USO, needs administrative privileges
		    
#>
function Get-AUOptions {
[CmdletBinding()]
param()

    if (Test-Path $AUOptionsRegKey) {
        $keys = Get-ItemProperty $AUOptionsRegKey
        if ($null -ne $keys -and $keys.PSObject.Properties.Match('AUOptions').Count)
        {
            return $keys.AUOptions
        }
    }
}

<#
    .SYNOPSIS
        Powershell Script to set the current AU settings for USO, needs administrative privileges		    
#>
function Set-AUOptions {
[CmdletBinding()]
param(
		[int] $option
	 )
    
    if (Test-Path $AUOptionsRegKey) {
        Set-ItemProperty -Path $AUOptionsRegKey -Name AUOptions -Value $option -Force
    }
}