<#
.SYNOPSIS
Updates SQL Server Management Studio to latest version

https://aka.ms/ssmsfullsetup

SSMS-Setup-ENU.exe /install /quiet /norestart

.PARAMETER DownloadPath
    C:\TEMP
.PARAMETER SSMSVersion
    18
.PARAMETER SSMSFile
    "SSMS-Setup-ENU"
.PARAMETER SSMSDownloadURL
    "https://aka.ms/ssmsfullsetup"
#>

[CmdletBinding()]
param(
  [string]$DownloadPath = "C:\Temp",
  [string]$SSMSVersion = "18",
  [string]$SSMSFile = "SSMS-Setup-ENU",
  [string]$SSMSDownloadURL = "https://aka.ms/ssmsfullsetup"
)

Write-Output ("Updating SQL Server Management Studio... on " + $env:COMPUTERNAME)

if (!(Test-Path $DownloadPath)) {
    New-Item -ItemType Directory -Force -Path $DownloadPath > $null
}

if (Test-Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server Management Studio\$SSMSVersion") {
    Write-Output "Found SSMS RegKey x64"
    $ssmsRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server Management Studio\$SSMSVersion"
}
elseif (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server Management Studio\$SSMSVersion") {
    Write-Output "Found SSMS RegKey x86"
    $ssmsRegKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server Management Studio\$SSMSVersion" 
}

if ($ssmsRegKey) {
    $SSMSInstallPath = $ssmsRegKey.SSMSInstallRoot

    if (Test-Path -Path $SSMSInstallPath) {
        Write-Output ("Found SSMS $SSMSVersion in $SSMSInstallPath")  
       
        $SSMSSetupPath = "$DownloadPath$SSMSFile";
        # Ensuring an older file doesn't exist
        if (Test-Path "$SSMSSetupPath") {
            Write-Output "Removing old $SSMSSetupPath"
            Remove-Item "$SSMSSetupPath"
        }

        Write-Output "Downloading $SSMSFile to $DownloadPath from $SSMSDownloadURL"
        
        # This helps with download speed by not displaying the Progress.
        # Without this it would take nearly an hour+ at times to download, with this it takes seconds.
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -uri $SSMSDownloadURL -Method GET -UseBasicParsing -OutFile "$SSMSSetupPath"
        
        # Reset Progress
        $ProgressPreference = 'Continue'

        # Update SSMS
        # /install /quiet /norestart
        Write-Output "Launching $SSMSSetupPath /install /quiet /norestart"
        $InstallerUpdateProcess = Start-Process -FilePath $SSMSSetupPath -Wait -PassThru -ArgumentList @("/install","/quiet","/norestart");
        $InstallerUpdateProcess.WaitForExit();

        Write-Output "$SSMSFile exited with code: $($InstallerUpdateProcess.ExitCode)"

        # Cleanup            
        Write-Output "Cleanup..."
        if (Test-Path "$SSMSSetupPath") {
            Write-Output "Removing $SSMSSetupPath"
            Remove-Item "$SSMSSetupPath"
        }

        if ($InstallerUpdateProcess.ExitCode -ne 0) {
            # This is read by the calling script to know if the job failed so it's reported correctly.
            Write-Error -Message "Installation failed with $($InstallerUpdateProcess.ExitCode)"
        }
    }
    else {
        Write-Output ("SQL Server Management Studio $SSMSVersion not found.")
    }
}
else {
    Write-Output ("Unable to find SQL Server Management Studio $SSMSVersion RegKey for Installation Path.")
}
