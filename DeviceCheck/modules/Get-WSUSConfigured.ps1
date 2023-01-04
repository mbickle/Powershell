<#
    .SYNOPSIS
        Powershell Script to get the current WSUS configuration settings for Windows Update
#>
function Test-RegKey {
[CmdletBinding()]
	param(
		[string] $path,
		[string] $key
	)

    if (-not (Test-Path $path -PathType Container)) {
		"false"
        return $false
    }

    $properties = Get-ItemProperty -Path $path
    if (-not $properties) {
		"false"
        return $false
    }

    $member = Get-Member -InputObject $properties -Name $key
    if ($member) {
        "true"
        return $true
    }
    else {
        "false"
        return $false
    }
}

function Get-WSUSConfigured {
[CmdletBinding()]
	param()
	
    $result = Test-RegKey "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
    
    if ($result -eq $true) {
    	$value = Get-ItemPropertyValue "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "WUServer"
        return $value
    }
    else {
        return $false
    }
}
