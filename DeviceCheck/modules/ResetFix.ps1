<#
.SYNOPSIS
    Used to attempt fixing Windows Update issues.
#>

<#
    Gets Is UpdatesPaused
#>
function Get-IsUpdatesPaused {
    [CmdletBinding()]
    param()
    
    
    $keys = Get-ItemProperty "HKLM:\Software\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
    if ($null -ne $keys -and $keys.PSObject.Properties.Match('PausedFeatureStatus').Count) {
        if ($keys.PausedFeatureStatus -ne 0) {
            Write-Message "Paused Feature Status is enabled."  -ForegroundColor "Yellow"
            return $true
        }
    }

    if ($null -ne $keys -and $keys.PSObject.Properties.Match('PausedQualityStatus').Count) {
        if ($keys.PausedQualityStatus -ne 0)
        {
            Write-Message "Paused Quality Status is enabled."  -ForegroundColor "Yellow"
            return $true
        }
    }

    return $false
}

<#
    Turns off Updates Paused
#>
function Set-UpdatesPausedOff {
    [CmdletBinding()]
    param()
    
    New-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UpdatePolicy\Settings" -Name "PausedFeatureStatus" -Value 0 -Force | Out-Null
    New-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UpdatePolicy\Settings" -Name "PausedQualityStatus" -Value 0 -Force | Out-Null
	
	Write-Message "FIXED: Re-enabled feature and quality updates to resume installation." -ForegroundColor "Green"
}

<#
    Gets Is Features Updates Defered
#>
function Get-IsFeatureUpdatesDefered {
    [CmdletBinding()]
    param()
    
    $keys = Get-ItemProperty "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings"
    if ($null -ne $keys -and $keys.PSObject.Properties.Match('DeferUpgrade').Count) {
        if ($keys.DeferUpgrade -ne 0) {
            Write-Message "Defer is enabled." -ForegroundColor "Yellow"
            return $true
        }
    }

    return $false
}

<#
   Turns off Updates Defered
#>
function Set-FeatureUpdatesDeferedOff {
    [CmdletBinding()]
    param()
    
    New-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferUpgrade" -Value 0 -Force | Out-Null
	
	Write-Message "FIXED: Re-enabled feature updates to resume installation." -ForegroundColor "Green"
}

<#
   Restore System Apps
#>
function RestoreSystemApps {
    [CmdletBinding()]
    param()

    Write-Output "We are now preparing to repair system apps. The computer will be slow to respond during this process. Launching other processes or using the machine will make the process take longer." -ForegroundColor Cyan
    taskkill /f /im explorer.exe

    Get-AppxPackage -packageType bundle | ForEach-Object {Add-AppxPackage -register -disabledevelopmentmode ($_.installlocation + "\appxmetadata\appxbundlemanifest.xml")}
    
    $bundlefamilies = (Get-AppxPackage -packagetype Bundle).packagefamilyname
    
    Get-AppxPackage -packagetype main | Where-Object {-not ($bundlefamilies -contains $_.packagefamilyname)} | ForEach-Object {
        Add-AppxPackage -register -disabledevelopmentmode ($_.installlocation + "\appxmanifest.xml")
    }

    explorer.exe
}

<#
   Clear the Store Cache
#>
function ClearStoreCache {
    [CmdletBinding()]
    param()
    
    taskkill /f /im winstore.app.exe
    & wsreset.exe
}

<#
   Run the  Update Apps Task
#>
function RunUpdateAppsTask {
    [CmdletBinding()]
    param()
    
    & schtasks /run /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update"
}

<#
   Register System Files
#>
function RegisterFiles {
    [CmdletBinding()]
    param ()

    StopWindowsUpdateComponents
    # Reregister the BITS files and the Windows Update files
    Set-Location "$env:WINDIR\system32"
    & regsvr32.exe /s atl.dll
    & regsvr32.exe /s urlmon.dll
    & regsvr32.exe /s mshtml.dll
    & regsvr32.exe /s shdocvw.dll
    & regsvr32.exe /s browseui.dll
    & regsvr32.exe /s jscript.dll
    & regsvr32.exe /s vbscript.dll
    & regsvr32.exe /s scrrun.dll
    & regsvr32.exe /s msxml.dll
    & regsvr32.exe /s msxml3.dll
    & regsvr32.exe /s msxml6.dll
    & regsvr32.exe /s actxprxy.dll
    & regsvr32.exe /s softpub.dll
    & regsvr32.exe /s wintrust.dll
    & regsvr32.exe /s dssenh.dll
    & regsvr32.exe /s rsaenh.dll
    & regsvr32.exe /s gpkcsp.dll
    & regsvr32.exe /s sccbase.dll
    & regsvr32.exe /s slbcsp.dll
    & regsvr32.exe /s cryptdlg.dll
    & regsvr32.exe /s oleaut32.dll
    & regsvr32.exe /s ole32.dll
    & regsvr32.exe /s shell32.dll
    & regsvr32.exe /s initpki.dll
    & regsvr32.exe /s wuapi.dll
    & regsvr32.exe /s wuaueng.dll
    & regsvr32.exe /s wuaueng1.dll
    & regsvr32.exe /s wucltui.dll
    & regsvr32.exe /s wups.dll
    & regsvr32.exe /s wups2.dll
    & regsvr32.exe /s wuweb.dll
    & regsvr32.exe /s qmgr.dll
    & regsvr32.exe /s qmgrprxy.dll
    & regsvr32.exe /s wucltux.dll
    & regsvr32.exe /s muweb.dll
    & regsvr32.exe /s wuwebv.dll
	
	Write-Message "FIXED: Reregistered Windows Update and BITS system files." -ForegroundColor "Green"
}

<#
   Stop Windows Update Components
#>
function StopWindowsUpdateComponents {
    [CmdletBinding()]
    param()
    
    Stop-Service -Force BITS -ErrorAction SilentlyContinue | Out-Null
    Stop-Service -Force wuauserv -ErrorAction SilentlyContinue |Out-Null
    Stop-Service -Force appidsvc -ErrorAction SilentlyContinue |Out-Null
    Stop-Service -Force CryptSvc -ErrorAction SilentlyContinue |Out-Null
}

<#
   Start Windows Update Components
#>
function StartWindowsUpdateComponents {
    [CmdletBinding()]    
    param()
    
    Start-Service -Force BITS -ErrorAction SilentlyContinue | Out-Null
    Start-Service -Force wuauserv -ErrorAction SilentlyContinue |Out-Null
    Start-Service -Force appidsvc -ErrorAction SilentlyContinue |Out-Null
    Start-Service -Force CryptSvc -ErrorAction SilentlyContinue |Out-Null
}

<#
   Cleanup Windows Updates
#>
function CleanupWindowsUpdate {
    [CmdletBinding()]
    param()
    
    StopWindowsUpdateComponents
    # Removing SoftwareDistribution
    Remove-Item -Recurse "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\*"

    if (Test-Path "$env:SystemRoot\winsxs\pending.xml")
    {
        Remove-Item -recurse "$env:SystemRoot\winsxs\pending.xml"
    }

    CMD /C "rd /s /q $env:SystemRoot\SoftwareDistribution"
    CMD /C "rd /s /q $env:SYSTEMRoot\system32\Catroot2"

    if (Test-Path "$env:SYSTEMROOT\WindowsUpdate.log")
    {
        Remove-Item -recurse "$env:SYSTEMROOT\WindowsUpdate.log"
    }
}

<#
   Reset WinSock
#>
function ResetWinSock {
    [CmdletBinding()]
    param()
    
    # Resetting Winsock
    Set-Location "$env:WINDIR\system32"
    & netsh winsock reset
    #& netsh advfirewall reset
    & ipconfig /flushdns
    & netsh winhttp reset proxy
}

<#
   Scan/Repair System
#>
function ScanRepairSystem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch] $All,
        [Parameter(Mandatory=$false)]
        [switch] $dism,
        [Parameter(Mandatory=$false)]
        [switch] $windowsimage,
        [Parameter(Mandatory=$false)]
        [switch] $sfc
    )
    
    if ($All)
    {
        $dism = $true
        $windowsimage = $true
        $sfc = $true
    }

    if ($dism)
    {
        Write-Output "Running dism /online /cleanup-image /startcomponentcleanup /resetbase"
        cmd /c dism /online /cleanup-image /startcomponentcleanup /resetbase	
    }

    if ($windowsimage)
    {
        Write-Output "Running Repair-WindowsImage -Online -RestoreHealth"
        Repair-WindowsImage -Online -RestoreHealth 
    }
    
    if ($sfc)
    {
        Write-Output "Running SFC -scannow"
        SFC -scannow
    }    
}

<#
   Restore Default Power Scheme
#>
function RestoreDefaultPowerScheme {
    [CmdletBinding()]
    param()
    
    Write-Output "Running powercfg -restoredefaultschemes"
    & powercfg -restoredefaultschemes
}