<#
.SYNOPSIS
    Various untility methods to support other scripts. 
#>

<#
.SYNOPSIS
    Log Section Header

.PARAMETER SectionTitle
    Title for Section (Mandatory)
#>
function LogSectionHeader {
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$True)]
        [string] $SectionTitle
    )
    
return @"

**************************************************************************************
Section: $SectionTitle
**************************************************************************************
"@
}

<#
.SYNOPSIS
    Write-Message

.PARAMETER Message
    The Message to write.

.PARAMETER ForegroundColor
    Set Foreground Color
#>
function Write-Message {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory=$false, ParameterSetName='Message')]
        [string]$Message,
        [string]$ForegroundColor = $host.ui.RawUI.ForegroundColor
    )
    
	if (-not $Message) {
		$Message = "" 
	}

    $defaultColor = $host.ui.RawUI.ForegroundColor
    $host.ui.RawUI.ForegroundColor = $ForegroundColor       
    Write-Output $Message
    $host.ui.RawUI.ForegroundColor = $defaultColor
}

<#
.SYNOPSIS
    Check Battery Level

.PARAMETER Level
    Level to validate
#>
function CheckBatteryLevel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [int] $level
    )
    
    $Battery = Get-wmiobject win32_battery
    if ($Battery)
    {
        $BatteryLevel = $Battery.EstimatedChargeRemaining
        Write-Output "BatteryLevel: $BatteryLevel%"
        if ($BatteryLevel -le $level)
        {
            Write-Message "Updates won't install when Battery below $level%." -ForegroundColor "Yellow"
            Write-Message "Please plug in your device and let it charge and try again."  -ForegroundColor "Yellow"
            Write-Message ""  -ForegroundColor "Yellow"
            Write-Message "Press any key to continue or X to exit."  -ForegroundColor "Yellow"
            $continue = Read-Host
            if ($continue -eq "X") {
                return;
            }
            else {
                Write-Output "Continuing..."
            }
        }
    }
}

<#
.SYNOPSIS
    Check for pending reboot
#>
function CheckPendingReboot {
   [CmdletBinding()]
   param()
   
   $Machine = $env:ComputerName
   $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine", $Machine)
   $keyRebootPending = $baseKey.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
   $keyRebootRequired = $baseKey.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
   $keyPendingFileRenameOperations = $baseKey.OpenSubKey("SYSTEM\CurrentControlSet\Control\Session Manager\")
   $RebootPending = $keyRebootPending.GetSubKeyNames() | Where-Object {$_ -eq "RebootPending"}    
   $RebootRequired = $keyRebootRequired.GetSubKeyNames() | Where-Object {$_ -eq "RebootRequired"}
   $PendingFileRenameOperations = $keyRebootRequired.GetSubKeyNames() | Where-Object {$_ -eq "PendingFileRenameOperations"}
   
   $keyRebootPending.Close()
   $keyRebootRequired.Close()   
   $keyPendingFileRenameOperations.Close()
   $baseKey.Close()

   if ($RebootRequired -Or $RebootPending -Or $PendingFileRenameOperations) {
      Write-Message ("There is a pending reboot for " + $Machine) -ForegroundColor "Yellow"
      Restart-Computer -ComputerName $Machine -confirm
   }
   else {
      Write-Message ("No reboot pending for " + $Machine)  -ForegroundColor "Green"
   }
}

<#
.SYNOPSIS
    Stop or Start Service
.PARAMETER ServiceName
    Name of Service
.PARAMETER Stop
    Set to stop
.PARAMETER Start
    Set to start
#>
function StopOrStartService {
    [CmdletBinding()]
    param(
        [string] $ServiceName,
        [switch] $Stop,
        [switch] $Start
    )

    $status = Get-Service -Name $ServiceName
    Write-Host $ServiceName $status.Status
    if ($Stop) {
        if ($status.Status -eq "Running") {
            Write-Host "Stopping $ServiceName"
            Stop-Service $ServiceName -ErrorAction SilentlyContinue
        }
    }

    if ($Start) {
        if ($status.Status -ne "Running") {
            Write-Host "Starting $ServiceName"
            Start-Service $ServiceName -ErrorAction SilentlyContinue
        }
    }
}

<#
.SYNOPSIS
	Reads the ResultsReport.xml produced from the Troubleshooters
	and outputs what was reported as fixed.
#>
function TroubleShooterResults 
{
    [CmdletBinding()]
    param(
        $ResultsPath
    )
    
    if (Test-Path $ResultsPath\ResultReport.xml) {    
        [xml]$xml = Get-Content $ResultsPath\ResultReport.xml
        $nodes = Select-Xml "//ResultReport/Package/Problem/RootCauseInformation/RootCause[Data/@name='Status' and Data='Fixed']" $xml    
        
        $nodes | ForEach-Object { 
            $msg1 = ($_.Node.name)
			[string[]]$msg2 = @()

			if ($null -ne $_.Node.Data.PSObject.Properties.Match('#text')) {
				$msg2 += ($_.Node.Data.'#text'[0])
			}
			
			$msg2 += ("FIXED: " + $_.Node.ResolutionInformation.Resolution.name)
			
			if ($null -ne $_.Node.ResolutionInformation.Resolution.Data.PSObject.Properties.Match('#text')) {
				$msg2 += ($_.Node.ResolutionInformation.Resolution.Data.'#text'[0])
				$msg2 += ($_.Node.ResolutionInformation.Resolution.Data.'#text'[1])
			}
			
            Write-Message ($msg1) -ForegroundColor "Yellow" 
			$msg2 | ForEach-Object {Write-Output $_}
        }
    }
}