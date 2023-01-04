#-------------------------------------------------------------------------------
# Copyright (c) Michael Bickle
#-------------------------------------------------------------------------------
<#
.SYNOPSIS
    Used to check a Device to make sure WindowsUpdates are installed and device is current.
    Can be used to repair known issues that are preventing WindowsUpdate from working.
    Can be used to collect a set of device logs and information to be used for analysis later.

.PARAMETER LogDir
    Directory for the log files from the device - usually the serial number for the device

.PARAMETER LeaveLogDir
    If true, the log directory LogDir will not be removed after zipping up the logs

.PARAMETER Repair
    If true, attempts to repair issues.

.PARAMETER Full
    If true, runs full repair options.

.PARAMETER CollectLogs
    If true, collects device detail logs for analysis.
    
.PARAMETER RunAll
    If true, Runs Repair and CollectLogs    

.PARAMETER UpdateID
    Finds updates of a specific UUID (or sets of UUIDs) 
#>

param( 
    [Parameter(Mandatory=$false,Position=0,HelpMessage="Directory for the log files from the device - usually the serial number for the device.")]
    [string] $LogDir = (Get-WmiObject win32_computersystemproduct).IdentifyingNumber,
    
    [Parameter(Mandatory=$false)]
    [string] $FailureText = "DeviceCheck",
    
    [Parameter(Mandatory=$false)]
    [switch] $LeaveLogDir,

    [Parameter(Mandatory=$false, ParameterSetName='Repair', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [switch] $Repair,
    [switch] $Full,
    
    [Parameter(Mandatory=$false)]
    [switch] $CollectLogs,
    
    [Parameter(Mandatory=$false)]
    [switch] $RunAll,
    
    [string[]]$UpdateID = @()
)

###################################################################################################
# Global Error Handler
###################################################################################################
trap {
    Write-Output "----- TRAP ----" |  Tee-Object -Append $LogFile
    Write-Output "Unhandled Exception: $_.Exception.GetType().Name" |  Tee-Object -Append $LogFile
    Write-Output $_.Exception | Tee-Object -Append $LogFile
    $_ | Format-List -Force | Tee-Object -Append $LogFile
    continue
}

###################################################################################################
# Globals
###################################################################################################
$global:ErrorActionPreference = "stop"
Set-StrictMode -Version Latest

###################################################################################################
# Main
###################################################################################################
$scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition
Push-Location $scriptPath

Write-Host "Checking for elevation... " -NoNewline
$CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
if (($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) -eq $false){
    $ArgumentList = "-noprofile -noexit -file `"{0}`""    
    if ($LogDir) {$ArgumentList = $ArgumentList + " -LogDir $LogDir"}
    if ($LeaveLogDir) {$ArgumentList = $ArgumentList + " -LeaveLogDir"}
    if ($FailureText) {$ArgumentList = $ArgumentList + " -FailureText $FailureText"}
    if ($Repair) {$ArgumentList = $ArgumentList + " -Repair $Repair"}
    if ($Full) {$ArgumentList = $ArgumentList + " -Full $Full"}
    if ($CollectLogs) {$ArgumentList = $ArgumentList + " -CollectLogs $CollectLogs"}
    if ($RunAll) {$ArgumentList = $ArgumentList + " -RunAll $RunAll"}

    Write-Host "Elevating"
    Start-Process powershell.exe -Verb RunAs -ArgumentList ($ArgumentList -f ($myinvocation.MyCommand.Definition))

    Write-Host "Exiting, please refer to console window" -ForegroundColor DarkRed
    break
}

#Check to see if we ended up running in a 32-bit context on 64-bit and fix
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Write-Output "Re-launching 64-bit Powershell"
    if ($myInvocation.Line) {
        & "$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -ExecutionPolicy remotesigned -NoProfile $myInvocation.Line
    } else {
        & "$env:WINDIR\sysnative\windowspowershell\v1.0\powershell.exe" -ExecutionPolicy remotesigned -NoProfile -file "$($myInvocation.InvocationName)" $args
    }
    
    exit $LASTEXITCODE
}

#Fully resolve path for LogDir
$LogDir = Resolve-Path $LogDir -ErrorAction SilentlyContinue -ErrorVariable _frperror
if (-not $LogDir) {
    $LogDir = $_frperror[0].TargetObject
}

#Check for non-local Path
$newPath = Convert-Path $scriptPath
$RootPath = [System.IO.Path]::GetPathRoot($newPath)
try {
    $DriveInfo = [System.IO.DriveInfo]::new($RootPath)
} catch {
    $DriveInfo = $null
}

if (($null -eq $DriveInfo) -or ($DriveInfo.DriveType -ne [System.IO.DriveType]::Fixed)) {
    $LogDir = "$($env:USERPROFILE)\Desktop\$(Split-Path -Leaf $LogDir)"
    "Putting logs at $LogDir"
}

#Create temporary directory to collect data
if (Test-Path "$LogDir") {
   Write-Host "Remove $LogDir"
   Remove-Item $LogDir -Recurse -Force
}

Write-Host "mkdir $LogDir"
mkdir "$LogDir" | Out-Null
$serial = (Get-WmiObject win32_computersystemproduct).IdentifyingNumber
$model  = (Get-WmiObject win32_computersystem).SystemSKUNumber
$LogFile = "$LogDir\$model`_$serial`.txt"

#Import all modules
Write-Host "Import modules..."
Get-ChildItem $scriptPath\modules\*.ps1 | ForEach-Object {
    . $_
}

if ($RunAll) {
    $CollectLogs = $true
    $Repair = $true
}

"DeviceCheck $(Get-Content "$scriptPath\version.txt")" | Tee-Object -Append $LogFile
"" | Tee-Object -Append $LogFile
"" | Tee-Object -Append $LogFile
if (-not $FailureText) {
    $Summary = Read-Host -Prompt "Please enter the failure reason for this device"
} else {
    $Summary = $FailureText
}

"Summary" | LogSectionHeader | Tee-Object -Append $LogFile
Write-Output "$Summary" | Tee-Object -Append $LogFile

"Device Time" | LogSectionHeader | Tee-Object -Append $LogFile
$DUTTime = Get-Date
Write-Output "Local:     $("{0:u}" -f $DUTTime)" | Tee-Object -Append $LogFile
$DUTTime = $DUTTime.ToUniversalTime()
Write-Output "Universal: $("{0:u}" -f $DUTTime)" | Tee-Object -Append $LogFile

"Check for Pending Reboot" | LogSectionHeader | Tee-Object -Append $LogFile
CheckPendingReboot | Tee-Object -Append $LogFile

"Check for Battery Level" | LogSectionHeader | Tee-Object -Append $LogFile
CheckBatteryLevel 40 | Tee-Object -Append $LogFile

if (Get-WSUSConfigured) {
    Write-Message "You appear to be configured for WSUS and may not have access to all the latest updates." -ForegroundColor "Yellow"
}

if ($Repair)
{
    "Enable USO and WU services" | LogSectionHeader | Tee-Object -Append $LogFile
    Set-ServiceStartupType 'usosvc' | Tee-Object -Append $LogFile
    Set-ServiceStartupType 'dosvc', 'wuauserv' -startupType 'auto' | Tee-Object -Append $LogFile

    "Enable USO scheduled tasks for automatic update" | LogSectionHeader | Tee-Object -Append $LogFile
    $usoTasks = 'Schedule Scan','Reboot','Refresh Settings'
    Enable-UsoTask $usoTasks | Tee-Object -Append $LogFile

    "Check Defer Updates" | LogSectionHeader | Tee-Object -Append $LogFile
    if (Get-IsFeatureUpdatesDefered)
    {
        Write-Message "Updates Paused, turning them back on." -ForegroundColor "Yellow"  | Tee-Object -Append $LogFile
        Set-FeatureUpdatesDeferedOff  | Tee-Object -Append $LogFile
    }

    if (Get-IsUpdatesPaused)
    {
        Write-Message "Updates Paused, turning them back on." -ForegroundColor "Yellow"  | Tee-Object -Append $LogFile
        Set-UpdatesPausedOff  | Tee-Object -Append $LogFile
    }
    
    $auoptions = Get-AUOptions
	$recommendedAUOption = 4
    if ($null -ne $auoptions)
    {
        if ($auoptions -lt $recommendedAUOption)
        {
            Write-Message ("AUOptions is set to " + $auoptions + ", seting it to the recommended setting of 4") -ForegroundColor "Yellow"  | Tee-Object -Append $LogFile
			Write-Message ("AUOptions is typically controlled through Group Policy, this may get changed if your system is managed.") -ForegroundColor "Yellow"  | Tee-Object -Append $LogFile
            Set-AUOptions $recommendedAUOption	 | Tee-Object -Append $LogFile
     		Write-Output "FIXED: Set AUOptions to the recommended option: $recommendedAUOption (May be changed later by Group Policy)"
        }
    }
    else 
    {
        Write-Message "AUOptions have not been set, everything should be good, nothing to do here." -ForegroundColor "Green"  | Tee-Object -Append $LogFile
    }
    
    "Invoke WindowsUpdate Diagnostics Pack" | LogSectionHeader | Tee-Object -Append $LogFile
    $diagPack = Get-TroubleshootingPack $env:SystemRoot\diagnostics\system\WindowsUpdate
    Invoke-TroubleshootingPack $diagpack -Unattended -Result $LogDir\WindowsUpdateTroubleshooter
    TroubleShooterResults -ResultsPath $LogDir\WindowsUpdateTroubleshooter | Tee-Object -Append $LogFile
	
    "Invoke BITS Diagnostics Pack" | LogSectionHeader | Tee-Object -Append $LogFile
    $diagPack = Get-TroubleshootingPack $env:SystemRoot\diagnostics\system\BITS
    Invoke-TroubleshootingPack $diagpack -Unattended -Result $LogDir\BITSTroubleshooter
	TroubleShooterResults -ResultsPath $LogDir\BITSTroubleshooter | Tee-Object -Append $LogFile
    
	"Unhide hidden updates" | LogSectionHeader | Tee-Object -Append $LogFile
    UnHideUpdates | Tee-Object -Append $LogFile
    
    "Register System Files" | LogSectionHeader | Tee-Object -Append $LogFile
    RegisterFiles  | Tee-Object -Append $LogFile
    
    if ($Full) {    
        "ResetWinsock" | LogSectionHeader | Tee-Object -Append $LogFile
        ResetWinsock | Tee-Object -Append $LogFile
        
        "Scan and Repair System" | LogSectionHeader | Tee-Object -Append $LogFile
        ScanRepairSystem -All | Tee-Object -Append $LogFile
    }

	"Repair Summary" | LogSectionHeader | Tee-Object -Append $LogFile	
	Get-Content -Path $LogFile | Select-String "FIXED:"
}

"WindowsUpdate" | LogSectionHeader | Tee-Object -Append $LogFile
Get-WindowsUpdate -InstallUpdates:$true -UpdateID $UpdateID | Tee-Object -Append $LogFile

if ($CollectLogs)
{
    "Collecting Device Details" | LogSectionHeader | Tee-Object -Append $LogFile
    CollectDeviceDetails    
            
    $zipFile = "$(Split-Path -Parent $LogDir)\$(Split-Path -Leaf $LogDir).zip"
    Write-Output "Compress Logs to $zipFile"
    if (Test-Path $zipFile) {
        Remove-Item -force $zipFile
    }

    Add-Type -assembly "system.io.compression.filesystem" | Out-Null
    [io.compression.zipfile]::CreateFromDirectory($LogDir, $zipFile) 

    if (-not $LeaveLogDir) {
        Remove-Item -Path "$LogDir" -Recurse -Force | Out-Null
    } 

    Write-Host "Please share or attach to a bug: $zipFile"
}

"Feedback" | LogSectionHeader
while ($true)
{
    $submitFeedback = Read-Host 'Submit feedback to Microsoft via Feedback Hub - Y/N?'
    if ($submitFeedback -eq 'y') {
        Submit-FeedbackHub -title '<describe the problem here>' | Tee-Object -Append $LogFile
        break
    }
    elseif ($submitFeedback -eq 'n') {
        break
    }
    else {
        Write-Host "$submitFeedback is not a valid input. Please try again."
    }
}

"DONE" | LogSectionHeader

$retval = 0

Pop-Location
exit $retval
