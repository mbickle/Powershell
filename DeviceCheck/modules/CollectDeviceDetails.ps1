<#
.SYNOPSIS
    Collects a set of Device details used for debugging.
#>

function CollectDeviceDetails {
    [CmdletBinding()]
    param(
    )

    begin {
    }

    process {
        "Registry Information" | LogSectionHeader | Tee-Object -Append $LogFile
        $RegistryKeysOfInterest = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion"
            "HKLM:\Software\Microsoft\Windows NT\CurrentVersion"
            "HKLM:\Software\Microsoft\Surface\OSImage",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\store"
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
            "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"    
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate"
            "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
            "HKLM:\Software\Policies\Microsoft\WindowsStore"
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate"    
            "HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources"
            "HKLM:\Software\Microsoft\WindowsSelfhost"
            "HKLM:\Software\Microsoft\WindowsUpdate"    
            )

        $RegistryKeysOfInterest | ForEach-Object{
            $_ | Out-File -Append $LogFile
            Get-RegistryKey $_ | Format-Table property,value -AutoSize | Out-File -Append $LogFile
        }

        Get-ItemProperty "HKLM:\Software\Microsoft\SQMClient" > $LogDir\SqmId.txt

        "Check if WSUS is configured" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-WSUSConfigured | Out-File -Append $LogFile
        
        "AUOptions" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-AUOptions | Out-File -Append $LogFile
        
        "Get Hidden Updates" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-HiddenUpdates | Out-File -Append $LogFile
        
        "OS Install Date" | LogSectionHeader | Tee-Object -Append $LogFile
        $SecondsSinceInstall = (Get-ItemProperty "HKLM:\software\microsoft\windows nt\currentversion" -Name installdate).installdate
        $InstDate = ([datetime]"1/1/1970").AddSeconds($SecondsSinceInstall)
        "OS Install date:  {0}" -f $InstDate | Out-File -Append $LogFile 
        "System UUID: {0}" -f ((Get-WmiObject win32_computersystemproduct -ErrorAction Ignore).uuid) | Out-File -Append $LogFile 

        "Capsules (Firmware)" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-CapsuleFirmware | Format-Table -AutoSize -Property Name, Version, PNPVersion, LastAttemptVersion, LowestSupportedVersion, LastAttemptStatus, ESRT | Out-File -Append $Logfile

        "Device Board Version Info" | LogSectionHeader | Tee-Object -Append $LogFile
        "MB info     : {0}" -f (Get-WmiObject win32_computersystemproduct).version | Out-File -Append $LogFile

        "DISM Driver Information" | LogSectionHeader | Tee-Object -Append $LogFile
        #use dism to dump drivers
        & "$($env:SystemRoot)\system32\dism.exe" /online /get-drivers | Out-File -Append $LogFile

        "Copy additional Windows Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        Copy-Item -Recurse "$($env:SystemRoot)\System32\Logfiles" "$LogDir\Windows_Logfiles" -ErrorAction SilentlyContinue

        "Event Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        $InterestingEvents = @()

        #Any and all signs of disk corruption
        $InterestingEvents += @(get-winevent -ProviderName Chkdsk -ErrorAction Ignore)

        #health state of NTFS and file corruption
        $InterestingEvents += @(get-winevent -ProviderName Microsoft-Windows-Ntfs -ErrorAction Ignore | Where-Object id -in (100,55))

        #bugcheck events
        $InterestingEvents += @(Get-WinEvent -ProviderName Microsoft-Windows-WER-SystemErrorReporting -ErrorAction Ignore)    

        #startup repair events
        $InterestingEvents += @(get-winevent -ProviderName Microsoft-Windows-Startuprepair -ErrorAction Ignore)

        $kernelP   = @(Get-WinEvent -ProviderName microsoft-windows-kernel-Power -ErrorAction Ignore)
        #unexpected shutdown events
        $InterestingEvents += @($kernelP | Where-Object id -in 41,506,507,13,12)

        #provisioning and MCT
        $Provision = @()
        $Provision += @(Get-WinEvent -ProviderName eventlog   | Where-Object {$_.id -eq 318})
        $Provision | ForEach-Object {$_.message = $_.properties.value }

        $InterestingEvents += $Provision

        #make it pretty
        $InterestingEvents | Sort-Object -Property TimeCreated | Format-Table -Property timecreated, ID, Message -AutoSize -wrap |  Out-File -Append $LogFile

        "Copy Event Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:SystemRoot)\System32\winevt\Logs" "$LogDir\EVT" | Out-Null

        "Copy Panther Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:SystemRoot)\Panther" "$LogDir\PANTHER" | Out-Null

        "Copy Sysprep Panther Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:SystemRoot)\System32\sysprep\Panther" "$LogDir\Sysprep_PANTHER" | Out-Null

        "Copy Windows Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:SystemRoot)\Logs" "$LogDir\Windows_Logs" | Out-Null

        "Copy SetupAPI Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" "$($env:SystemRoot)\INF" "$LogDir\Windows_INF" /if *.log | Out-Null

        "Get Service State" | LogSectionHeader | Tee-Object -Append $LogFile
        Invoke-Expression "sc.exe query wuauserv" > "$LogDir\wuauserv-state.log"
        Invoke-Expression "sc.exe query usosvc" > "$LogDir\usosvc-state.log"
        Invoke-Expression "sc.exe query dosvc" > "$LogDir\dosvc-state.log"

        "Get installed update list" | LogSectionHeader | Tee-Object -Append $LogFile
        Invoke-Expression "wmic qfe get hotfixid" > "$LogDir\InstalledUpdates.log"

        "Copy USO Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        StopOrStartService -ServiceName "usosvc" -Stop
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:ProgramData)\UsoPrivate\UpdateStore" "$LogDir\USO" | Out-Null
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:ProgramData)\UsoShared\Logs" "$LogDir\USO" | Out-Null
        Invoke-Expression "schtasks /query /v /TN \Microsoft\Windows\UpdateOrchestrator\" > "$LogDir\USO\updatetaskschedules.txt" | Out-Null
        Invoke-Expression "schtasks /query /v /TN \Microsoft\Windows\WindowsUpdate\" > "$LogDir\WUScheduledTasks.txt" | Out-Null

        "Copy WU ETLs" | LogSectionHeader | Tee-Object -Append $LogFile
        StopOrStartService -ServiceName "wuauserv" -Stop
        & "$($env:SystemRoot)\system32\robocopy.exe" "$($env:SystemRoot)\Logs\WindowsUpdate" "$LogDir\WU_ETL" /if *.etl | Out-Null
        & "$($env:SystemRoot)\system32\robocopy.exe" "$($env:SystemDrive)\" "$LogDir\WU_ETL" WindowsUpdateVerbose.etl | Out-Null

        "Copy DeliveryOptimization (DO) Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        StopOrStartService -ServiceName "dosvc" -Stop
        & "$($env:SystemRoot)\system32\robocopy.exe" "$($env:SystemRoot)\logs\dosvc" "$LogDir\DO" *.log *.etl /S | Out-Null
        & "$($env:SystemRoot)\system32\robocopy.exe" "$($env:SystemRoot)\SoftwareDistribution\DeliveryOptimization\SavedLogs" "$LogDir\DO" *.log *.etl /S | Out-Null
        & "$($env:SystemRoot)\system32\reg.exe" "export" "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" "$LogDir\DO\registry_DO.txt" /y | Out-Null

        StopOrStartService -ServiceName "wuauserv" -Start
        StopOrStartService -ServiceName "usosvc" -Start
        StopOrStartService -ServiceName "dosvc" -Start

        "Copy Update Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & Copy-Item "$($env:SystemRoot)\windowsupdate.log" "$LogDir" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:SystemRoot)\SoftwareDistribution\ReportingEvents.log" "$LogDir" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:LocalAppData)\microsoft\windows\windowsupdate.log" "$LogDir\WindowsUpdatePerUser.log" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:SystemRoot)\windowsupdate (1).log" "$LogDir\Old.WindowsUpdate.log" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:SystemRoot)\SoftwareDistribution\Plugins\7D5F3CBA-03DB-4BE5-B4B36DBED19A6833\TokenRetrieval.log" "$LogDir" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:SystemRoot)\winsxs\poqexec.log" "$LogDir" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:SystemRoot)\winsxs\pending.xml" "$LogDir" -ErrorAction SilentlyContinue
        & Copy-Item "$($env:SystemRoot)\servicing\sessions\sessions.xml" "$LogDir" -ErrorAction SilentlyContinue

        "Copy UUP Logs and action list xmls" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:SystemRoot)\SoftwareDistribution\Download" "$LogDir\UUP" *.log *.xml | Out-Null

        "Copy App XML" | LogSectionHeader | Tee-Object -Append $LogFile
        mkdir "$LogDir\AppxProvisioning" | Out-Null
        $XmlPath = "$($env:SystemDrive)\ProgramData\Microsoft\Windows\AppxProvisioning.xml" 
        if (Test-Path $XmlPath) {
            Copy-Item $XmlPath "$LogDir\AppxProvisioning"
        }

        "Battery Report" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\powercfg.exe" /batteryreport /duration 14 /output "$LogDir\batteryreport.html"

        "Sleep Study" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\powercfg.exe" /sleepstudy /duration 14 /output "$LogDir\sleepstudy.html"

        "Sleep Study Diagnostics" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\powercfg.exe" /systemsleepdiagnostics /output "$LogDir\system-sleep-diagnostics.html"

        "Copy SleepStudy ETL Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\robocopy.exe" /mir "$($env:SystemRoot)\system32\SleepStudy" "$LogDir\SleepStudy" /if *.etl | Out-Null

        "Power srumutil" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\powercfg.exe" /srumutil /output "$LogDir\srumutil.csv"

        "Power Plan" | LogSectionHeader | Tee-Object -Append $LogFile
        mkdir "$LogDir\PowerPlan" | Out-Null
        & "$($env:SystemRoot)\system32\powercfg.exe" /q > "$LogDir\PowerPlan\PowerPlan.txt" 2>&1
        & "$($env:SystemRoot)\system32\powercfg.exe" /qh > "$LogDir\PowerPlan\PowerPlan_H.txt" 2>&1
        & "$($env:SystemRoot)\system32\powercfg.exe" /export "$LogDir\PowerPlan\PowerPlan.pow" SCHEME_CURRENT

        "Maintenance Scheduled Tasks" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-ScheduledTask | Where-Object { $_.Settings.MaintenanceSettings } | ForEach-Object { 
            [PSCustomObject]@{TaskName = $_.TaskName;TaskPath = $_.TaskPath;State = $_.State; Deadline = $_.Settings.MaintenanceSettings.Deadline }
        } | Format-Table * | Out-File -Append $LogFile

        "BCD" | LogSectionHeader | Tee-Object -Append $LogFile
        mkdir "$LogDir\BCD" | Out-Null
        & "$($env:windir)\system32\bcdedit.exe" /enum all > "$LogDir\BCD\BCD.txt" 2>&1
        $testsigningstatus = (Get-Content "$LogDir\BCD\BCD.txt" | Select-String -SimpleMatch "testsigning" -ErrorAction Ignore)
        $testsigningstatus = ($testsigningstatus | Select-String -SimpleMatch "Yes" -ErrorAction Ignore)
        if ($testsigningstatus) {
            "Testsigning: Enabled" | Tee-Object -Append $LogFile
        } else {
            "Testsigning: Disabled" | Tee-Object -Append $LogFile
        }

        "Disk Drives" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-WmiObject win32_diskdrive | format-list * | Out-File -Append $LogFile

        "Volumes" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-WmiObject win32_volume | format-list * | Out-File -Append $LogFile

        "Partitions" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-WmiObject win32_diskpartition | format-list * | Out-File -Append $LogFile

        "Device Manager State" | LogSectionHeader | Tee-Object -Append $LogFile
        $AllDevices = Get-WmiObject Win32_PNPEntity
        $AllDevices | Format-List * | Out-File -Encoding ASCII -FilePath "$LogDir\DeviceManager.txt"
        $BangedDevices = @($AllDevices | Where-Object {$_.ConfigManagerErrorcode -ne 0})
        foreach ($Device in $BangedDevices) {
            Write-Output "" | Out-File -Append $LogFile
            Write-Output "Found error device Name: $($Device.Name)" | Out-File -Append $LogFile
            Write-Output "             HardwareId: $($Device.HardwareId)"  | Out-File -Append $LogFile
            Write-Output "                  Error: $($Device.ConfigManagerErrorCode)"  | Out-File -Append $LogFile
        }

        "Driver State (Active Only)" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-ActiveDrivers | Format-Table -AutoSize -Property INF, Version, DeviceID | Out-File -Append $Logfile

        "MOBB Status" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\netsh.exe" m s i | Out-File -Append $LogFile

        "Secure Boot" | LogSectionHeader | Tee-Object -Append $LogFile
        try {
            if (Confirm-SecureBootUEFI) {
                "Secure Boot Enabled" | Tee-Object -Append $LogFile

                mkdir "$LogDir\SecureBoot" | Out-Null

                foreach ($SecureBootVar in @("PK","KEK","DB","DBX")) {
                    Get-SecureBootUEFI -Name $SecureBootVar -OutputFilePath "$LogDir\SecureBoot\$SecureBootVar`.bin" 
                    "$LogDir\SecureBoot\$SecureBootVar`.bin" | Out-File -Append $LogFile
                }

                # this dumps out the line that has the "PK" in it.  
                Get-Content "$LogDir\SecureBoot\PK.bin" | Select-String "PK" | Out-File -Append $LogFile
            } else {
                "Secure Boot Disabled" | Tee-Object -Append $LogFile
            }
        } catch {
            Write-Output "Unhandled Exception: $_.Exception.GetType().Name" |  Out-File -Append $LogFile
            Write-Output $_.Exception | Out-File -Append $LogFile
            $_ | Format-List -Force | Out-File -Append $LogFile
        }

        "TPM" | LogSectionHeader | Tee-Object -Append $LogFile
        try {
            get-TPM | Format-Table -AutoSize -Property TPMPresent, TPMReady, AutoProvisioning | Out-File -Append $LogFile
        } catch {
            Write-Output "Unhandled Exception: $_.Exception.GetType().Name" |  Out-File -Append $LogFile
            Write-Output $_.Exception | Out-File -Append $LogFile
            $_ | Format-List -Force | Out-File -Append $LogFile
        }

        "Display Information" | LogSectionHeader | Tee-Object -Append $LogFile
        try {
            $MonitorInfo = Get-WmiObject -Namespace root\wmi -Class WMIMonitorID | Format-List *
            $MonitorInfo | Out-File -Append $LogFile
            mkdir "$LogDir\Display" | Out-Null
            $MonitorInfo | Out-File -Encoding ASCII -FilePath "$LogDir\Display\MonitorIDs.txt" 
            "Detailed monitor info in Display\MonitorModes.txt" | Tee-Object -Append $LogFile
            Get-WmiObject -namespace root\wmi WmiMonitorListedSupportedSourceModes | ForEach-Object {
                $_ | Format-List * | Out-File -Append -Encoding ASCII -FilePath "$LogDir\Display\MonitorModes.txt"
                $_.MonitorSourceModes |ForEach-Object { 
                     $_ | Format-List * | Out-File -Encoding ASCII -Append -FilePath "$LogDir\Display\MonitorModes.txt"
                }
            }
        } catch {
            Write-Output "Unhandled Exception: $_.Exception.GetType().Name" |  Out-File -Append $LogFile
            Write-Output $_.Exception | Out-File -Append $LogFile
            $_ | Format-List -Force | Out-File -Append $LogFile
        }

        "OS Updates" | LogSectionHeader | Tee-Object -Append $LogFile
        Get-WindowsPackage -Online | 
        ForEach-Object { 
            $line = $_.PackageName
            if ($line.StartsWith("Package_for_KB")) {
                $line | Out-File -Append $LogFile
            }
        }

        "RAM" | LogSectionHeader | Tee-Object -Append $LogFile
        $capacity = 0
        $manufacturer = "unknown"
        $partNumber = "unknown"
        
        Get-CimInstance -class "cim_physicalmemory" | ForEach-Object { 
            $capacity += $_.Capacity
            $manufacturer = $_.Manufacturer
            $partNumber = $_.PartNumber
        }

        "PhysicalMemory:  $("{0:N0}" -f ($capacity)) - $("{0:N0}" -f ($capacity/1MB)) MB" | Out-File -Append $LogFile
        $usable = $(Get-WmiObject win32_computersystem).TotalPhysicalMemory
        "UsableMemory:    $("{0:N0}" -f ($usable)) - $("{0:N0}" -f ($usable/1MB)) MB" | Out-File -Append $LogFile
        $reserved = $capacity - $usable
        "ReservedMemory:  $("{0:N0}" -f ($reserved)) - $("{0:N0}" -f ($reserved/1MB)) MB"  | Out-File -Append $LogFile
        "Manufacturer:    $manufacturer" | Out-File -Append $LogFile
        "PartNumber:      $partNumber" | Out-File -Append $LogFile

        "Boot Disk" | LogSectionHeader | Out-File -Append $LogFile
        $disks = @(Get-Disk | Where-Object { $_.IsBoot })
        $disks | ForEach-Object {
            $FriendlyName = $_.FriendlyName
            $Model = $_.Model
            $FirmwareVersion = $_.FirmwareVersion
            $Size =  $("{0:N0}" -f ($_.Size/1GB))
            [int]$freeGB = (Get-WmiObject Win32_logicaldisk | `
            Where-Object -FilterScript {$_.DeviceID -ilike 'C:'} | `
            Select-Object -Property FreeSpace).FreeSpace / 1GB

            "FriendlyName:  $FriendlyName" | Out-File -Append $LogFile
            "Model:         $Model" | Out-File -Append $LogFile
            "Firmware:      $FirmwareVersion" | Out-File -Append $LogFile
            "Size:          $Size GB" | Out-File -Append $LogFile
            "FreeSpace:     $freeGB GB" | Out-File -Append $LogFile
        }

        "Bitlocker" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\manage-bde.exe" -status 2>&1 | Out-File -Append $LogFile

        "dxdiag" | LogSectionHeader | Tee-Object -Append $LogFile
        Push-Location $LogDir
        $process = Start-Process -FilePath "$($env:SystemRoot)\system32\dxdiag.exe" -Wait -PassThru -ArgumentList @("/t","dxdiag.txt")
        Pop-Location
        Write-Output "Exit: $($process.ExitCode)" | Out-File -Append $LogFile

        "ddodiag" | LogSectionHeader | Tee-Object -Append $LogFile
        Push-Location $LogDir
        $process = Start-Process -FilePath "$($env:SystemRoot)\system32\ddodiag.exe" -Wait -PassThru -ArgumentList @("-o","ddodiag.txt")
        Pop-Location
        Write-Output "Exit: $($process.ExitCode)" | Out-File -Append $LogFile

        "systeminfo" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\systeminfo.exe" 2>&1 > $LogDir\systeminfo.txt

        "msinfo32" | LogSectionHeader | Tee-Object -Append $LogFile
        $process = Start-Process -FilePath "$($env:SystemRoot)\system32\msinfo32.exe" -Wait -PassThru -ArgumentList @("/nfo","$LogDir\msinfo32.nfo")
        Write-Output "Exit: $($process.ExitCode)" | Out-File -Append $LogFile

        "IMEI" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\netsh.exe" mbn show interface > "$LogDir\IMEI.txt"

        "Windows Store Logs" | LogSectionHeader | Tee-Object -Append $LogFile
        & "$($env:SystemRoot)\system32\\WSCollect.exe"
        $Desktop = [Environment]::GetFolderPath("Desktop")
        Move-Item -force "$Desktop\StoreLogs_*.cab" $LogDir

        & Copy-Item "$($env:temp)\winstore.log" "$LogDir\winstore-Broker.log" -Force -ErrorAction SilentlyContinue
        & Copy-Item "$($env:userprofile)\AppData\Local\Packages\WinStore_cw5n1h2txyewy\AC\Temp\winstore.log" "$LogDir" -Force -ErrorAction SilentlyContinue

        "Group Policy Report" | LogSectionHeader | Tee-Object -Append $LogFile
        & "gpresult" /f /x $LogDir\groupolicy_report.xml
    }

    end {
        return
        }
    }
    