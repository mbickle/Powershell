<#
.SYNOPSIS
    Download and install latest Microsoft Edge.

.PARAMETER Channel
    'Dev', 'Beta', 'Stable', 'EdgeUpdate', 'Policy'

.PARAMETER Folder
    Download Folder (Default: C:\Temp)

.PARAMETER Platform
    'Windows', 'MacOS', 'any'

.PARAMETER Architecture
    'x86', 'x64', 'arm64', 'any'

.PARAMETER ProductVersion
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false, HelpMessage = 'Channel to download, Valid Options are: Dev, Beta, Stable, EdgeUpdate, Policy')]
  [ValidateSet('Dev', 'Beta', 'Stable', 'EdgeUpdate', 'Policy')]
  [string]$Channel = "Stable",    
  [Parameter(Mandatory = $false, HelpMessage = 'Folder where the file will be downloaded')]
  [ValidateNotNullOrEmpty()]
  [string]$Folder = "C:\Temp",
  [Parameter(Mandatory = $false, HelpMessage = 'Platform to download, Valid Options are: Windows or MacOS')]
  [ValidateSet('Windows', 'MacOS', 'any')]
  [string]$Platform = "Windows",
  [Parameter(Mandatory = $false, HelpMessage = "Architecture to download, Valid Options are: x86, x64, arm64, any")]
  [ValidateSet('x86', 'x64', 'arm64', 'any')]
  [string]$Architecture = "x64",
  [parameter(Mandatory = $false, HelpMessage = "Specifies which version to download")]
  [ValidateNotNullOrEmpty()]
  [string]$ProductVersion
)

$EdgeURL = "https://edgeupdates.microsoft.com/api/products?view=enterprise"

# This helps with download speed by not displaying the Progress.
# Without this it would take nearly an hour+ at times to download, with this it takes seconds.
$ProgressPreference = 'SilentlyContinue'

Write-Output "Getting available files from $EdgeURL"
$response = Invoke-WebRequest -Uri "$EdgeURL" -Method Get -ContentType "application/json" -ErrorAction Stop -UseBasicParsing
$jsonObj = ConvertFrom-Json $([String]::new($response.Content))
Write-Output "Succefully retreived data"

$SelectedIndex = [array]::indexof($jsonObj.Product, "$Channel")

if ([string]::IsNullOrEmpty($ProductVersion)) {
    Write-Output "No version specified, getting the latest for $Channel"
    $SelectedVersion = (([Version[]](($jsonObj[$SelectedIndex].Releases | 
        Where-Object {
            $_.Architecture -eq $Architecture -and $_.Platform -eq $Platform 
        }).ProductVersion) | 
        Sort-Object -Descending)[0]).ToString(4)
  
    Write-Output "Latest Version for Chanel $Channel is $SelectedVersion"
    $SelectedObject = $jsonObj[$SelectedIndex].Releases | 
        Where-Object {
            $_.Architecture -eq $Architecture -and $_.Platform -eq $Platform -and $_.ProductVersion -eq $SelectedVersion 
        }
}
else {
    Write-Output "Matching $ProductVersion on Channel $Channel"
    $SelectedObject = ($jsonObj[$SelectedIndex].Releases | 
    Where-Object { 
        $_.Architecture -eq $Architecture -and $_.Platform -eq $Platform -and $_.ProductVersion -eq $ProductVersion 
    })
  
    $SelectedObject
  
    if ($null -eq $SelectedObject) {
        Write-Error -Message "No version matching $ProductVersion found using Channel $channel and Arch $Architecture!"
        break
    }
    else {
        Write-Output "Found matchings version"
        $SelectedObject
    }
}

$FileName = ($SelectedObject.Artifacts.Location -split "/")[-1]
Write-Output "File to be downloaded $FileName"

if (!(Test-Path $Folder)) {
    New-Item -ItemType Directory -Force -Path $Folder > $null
}

if (Test-Path $Folder\$FileName) {
    Write-Output "Removing old $Folder\$FileName"
    Remove-Item "$Folder\$FileName"
}

if (Test-Path $Folder) {
    Write-Output "Starting download of $($SelectedObject.Artifacts.Location)"
    Invoke-WebRequest -Uri $SelectedObject.Artifacts.Location -OutFile "$Folder\$FileName" -ErrorAction Stop  
}
else {
    Write-Error -Message "Folder $Folder does not exist"
    break
}

if (((Get-FileHash -Algorithm $SelectedObject.Artifacts.HashAlgorithm -Path "$Folder\$FileName").Hash) -eq $SelectedObject.Artifacts.Hash) {
    Write-Output "CheckSum OK"
}
else {
    Write-Output "Checksum mismatch!"
    Write-Output "Expected Hash : $($SelectedObject.Artifacts.Hash)"
    Write-Error -Message "Downloaded file Hash : $((Get-FileHash -Algorithm $SelectedObject.Artifacts.HashAlgorithm -Path "$Folder\$FileName").Hash)"
}

# Update Chromium Edge
# /quiet
Write-Output "Launching $Folder\$FileName /quiet"
$InstallerUpdateProcess = Start-Process -FilePath $Folder\$FileName -Wait -PassThru -ArgumentList @("/quiet");
$InstallerUpdateProcess.WaitForExit();

Write-Output "$FileName exited with code: $($InstallerUpdateProcess.ExitCode)"

# Cleanup            
Write-Output "Cleanup..."
if (Test-Path "$Folder\$FileName") {
    Write-Output "Removing $Folder\$FileName"
    Remove-Item "$Folder\$FileName"
}

if ($InstallerUpdateProcess.ExitCode -ne 0) {
    # This is read by the calling script to know if the job failed so it's reported correctly.
    Write-Error -Message "Installation failed with $($InstallerUpdateProcess.ExitCode)"
}

Write-Output " -- Completed --"