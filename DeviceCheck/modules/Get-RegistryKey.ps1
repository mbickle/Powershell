<#
.SYNOPSIS
    Get Registry Key
#>
function Get-RegistryKey {
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string] $regPath
    )

    "Get-RegistryKey $regPath" | Write-Debug

    return   Get-Item $regPath -ErrorAction Ignore |
             Select-Object -ExpandProperty property | ForEach-Object {
                New-Object psobject -Property @{"property"=$_;"Value" = (Get-ItemProperty -Path $regPath  -Name $_).$_}
             }
}
