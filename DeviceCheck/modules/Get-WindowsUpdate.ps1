<#
    .SYNOPSIS
        Powershell Script to Install Updates Based on the Type of update    
    .DESCRIPTION
        Using the WIndows Update API, Each update has a specific Root category. By selecting with Type of Update you want, you can avoid installing unwanted updates
    .PARAMETER Path
        The full path AND name where the script is located.
    .PARAMETER Reboot
        If a reboot is required for an update, the system will restart.
    .PARAMETER InstallUpdates
        Default = false.
        If false, just scans to see if there are updates.  If set to true will attempt to download and install any updates found.
    .PARAMETER ProxyAddress
        Instead of using the default windows update API, use another endpoint for updates. 
    .PARAMETER UpdateTypes
        RootCategories that are associated with windows updates. Choose the types you wish to filter for. 
        "Critical","Definition", "Drivers", "FeaturePacks", "Security", "ServicePacks", "Tools", "UpdateRollups", "Updates", "Microsoft", "ALL"
    .PARAMETER UpdateID
        Finds updates of a specific UUID (or sets of UUIDs) 
    .PARAMETER Verbose
    .EXAMPLE
            & '.\Get-WindowsUpdate.ps1' -Reboot -UpdateTypes Definition, Critical, Security -Path '.\Get-WindowsUpdate.ps1'
#>
function Get-WindowsUpdate {
[CmdletBinding()]
param(
[switch]$Reboot, 
[switch]$InstallUpdates = $false, 
[string]$ProxyAddress,
[String[]][ValidateSet("Critical","Definition", "Drivers", "FeaturePacks", "Security", "ServicePacks", "Tools", "UpdateRollups", "Updates", "Microsoft", "ALL")]$UpdateTypes,
[string[]]$UpdateID
)
    $AvailableUpdates = @()
    $UpdateTypeIds = @()
    $UpdateTypes
    
    if ($null -eq $UpdateTypes) {
        $UpdateTypes = 'ALL'
    }

    if ($Reboot) {
        Write-Output "The computer will reboot if needed after installation is complete."
        Write-Output ""
    }

    if ($InstallUpdates -eq $false) {
        Write-Output "Running in scan only mode."
    }

    $Session = New-Object -com "Microsoft.Update.Session"

    if ($null -ne $ProxyAddress) {
    Write-Verbose "Setting Proxy"
        $Session.WebProxy.Address = $ProxyAddress
        $Session.WebProxy.AutoDetect = $FALSE
        $Session.WebProxy.BypassProxyOnLocal = $TRUE
    }

    Write-Verbose "Creating Update Type Array"
    foreach ($UpdateType in $UpdateTypes) {
        switch ($UpdateType)
        {
            "Critical" {$UpdateTypeId = 0}
            "Definition"{$UpdateTypeId = 1}
            "Drivers"{$UpdateTypeId = 2}
            "FeaturePacks"{$UpdateTypeId = 3}
            "Security"{$UpdateTypeId = 4}
            "ServicePacks"{$UpdateTypeId = 5}
            "Tools"{$UpdateTypeId = 6}
            "UpdateRollups"{$UpdateTypeId = 7}
            "Updates"{$UpdateTypeId = 8}
            "Microsoft"{$UpdateTypeId = 9}
            default {$UpdateTypeId = 99}
        }
        
        $UpdateTypeIds += $UpdateTypeId
    }
    
    Write-Output "Searching for updates..."
    $Search = $Session.CreateUpdateSearcher()
    $searchCriteria = "IsInstalled=0 and IsHidden=0"
    
    if ($UpdateID) {
        Write-Message "Searching for UpdateID = '$([string]::join(", ", $UpdateID))'"
        $tmp = $searchCriteria
        $searchCriteria = ""
        $LoopCount=0
        foreach($ID in $UpdateID) {        
            if ($LoopCount -gt 0)
            {
                $searchCriteria += " or "
            }
            
            $searchCriteria += "($tmp and UpdateID = '$ID')"
            $LoopCount++
        }        
    }
    
    $SearchResults = $Search.Search($searchCriteria)
    Write-Message ("Searching: " + $SearchCriteria)
    $msg = ("There are " + $SearchResults.Updates.Count + " TOTAL updates available.")

    if ($SearchResults.Updates.Count -gt 0) {
        Write-Message $msg -ForegroundColor "Yellow"
    }
    else {
        Write-Message $msg -ForegroundColor "Green"
        return
    }    

    if ($UpdateTypeIds -eq 99) {
        $AvailableUpdates = $SearchResults.Updates
    }
    else {        
        foreach ($UpdateTypeId in $UpdateTypeIds) {
            $AvailableUpdates += $SearchResults.RootCategories.Item($UpdateTypeId).Updates
        }
    }

    Write-Output "Updates selected for installation"
    $AvailableUpdates | ForEach-Object {    
        if (($_.InstallationBehavior.CanRequestUserInput) -or ($_.EulaAccepted -eq $FALSE)) {
            Write-Message ($_.Title + " *** Requires user input and will not be installed.") -ForegroundColor "Yellow"
            Write-Message ("*** InstallationBehavior.CanRequestUserInput " + $_.InstallationBehavior.CanRequestUserInput) -ForegroundColor "Yellow"
            Write-Message ("*** EulaAccepted " + $_.EulaAccepted) -ForegroundColor "Yellow"
        }
        else {
            Write-Message $_.Title -ForegroundColor "Green"
        }
        
        $_.Identity.PSObject.Properties | Foreach-Object { Write-Message "$($_.Name) = $($_.Value)" }
    }
    
    # Exit script if no updates are available
    if ($InstallUpdates -eq $false) {
        Write-Output "Exiting...";
        return
    }
    
    if ($AvailableUpdates.count -lt 1) {
        Write-Output "No results meet your criteria. Exiting";
        return
    }
    
    Write-Verbose "Creating Download Selection"
    $DownloadCollection = New-Object -com "Microsoft.Update.UpdateColl"

    $AvailableUpdates | ForEach-Object {
        if ($_.InstallationBehavior.CanRequestUserInput -ne $TRUE) {
                $DownloadCollection.Add($_) | Out-Null
            }
        }

    if ($DownloadCollection.count -lt 1) {
        Write-Output "No download results meet your criteria. Exiting";
        return
    }

    Write-Output "Download Updates..."

    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $DownloadCollection
    $Downloader.Download()

    Write-Output "Download complete."

    Write-Verbose "Creating Installation Object"
    $InstallCollection = New-Object -com "Microsoft.Update.UpdateColl"
    $AvailableUpdates | ForEach-Object {
        if ($_.IsDownloaded) {
            $InstallCollection.Add($_) | Out-Null
        }
    }

    Write-Output "Installing updates..."
    $Installer = $Session.CreateUpdateInstaller()
    $Installer.Updates = $InstallCollection
    $Results = $Installer.Install()
    Write-Output "Installation complete."
    Write-Output ""

    # Reboot if needed
    if ($Results.RebootRequired) {
        if ($Reboot) {
            Write-Output "Rebooting..."
            Restart-Computer ## add computername here
        }
        else {
            Write-Output "Please reboot."
        }
    }
    else {
        Write-Output "No reboot required."
    }    
}

<#
    .SYNOPSIS
        Get Hidden Updates 
#>
function Get-HiddenUpdates {
	[CmdletBinding()] 
	param()
    Write-Output "Searching for hidden updates..."
    $Session = New-Object -com "Microsoft.Update.Session"
    $Search = $Session.CreateUpdateSearcher()
    $SearchResults = $Search.Search("IsInstalled=0 and IsHidden=1")
    
    $msg = ("There are " + $SearchResults.Updates.Count + " TOTAL hidden updates available.")
    if ($SearchResults.Updates.Count -gt 0) {    
        Write-Message ($msg) -ForegroundColor "Yellow"
    }
    else {
        Write-Message ($msg) -ForegroundColor "Green"
    }

    if ($SearchResults.Updates.Count -gt 0) {
        Write-Output "Hidden updates found"
        $AvailableUpdates = $SearchResults.Updates
        $AvailableUpdates | ForEach-Object {    
            Write-Message ($_.Title + " *** has been marked as hidden, this will prevent it from being installed.") -ForegroundColor "Yellow"
        }
    }

    return $SearchResults.Updates
}

<#
    .SYNOPSIS
        Un Hide Hidden Updates
#>
function UnHideUpdates {
	[CmdletBinding()]
	param()
    Write-Output "Searching for hidden updates..."
    $Session = New-Object -com "Microsoft.Update.Session"
    $Search = $Session.CreateUpdateSearcher()
    $SearchResults = $Search.Search("IsInstalled=0 and IsHidden=1")
    
    $msg = ("There are " + $SearchResults.Updates.Count + " TOTAL hidden updates available.")
    if ($SearchResults.Updates.Count -gt 0) {    
        Write-Message ($msg) -ForegroundColor "Yellow"
    }
    else {
        Write-Message ($msg) -ForegroundColor "Green"
    }
   
    if ($SearchResults.Updates.Count -gt 0) {    
        Write-Output "Hidden updates selected for unhiding."
        $AvailableUpdates = $SearchResults.Updates
        $AvailableUpdates | ForEach-Object {    
            Write-Message ($_.Title + " *** has been marked as unhidden.") -ForegroundColor "Yellow"
            $_.IsHidden = $false
        }
		
		Write-Message ("FIXED:" + $SearchResults.Updates.Count + "were unhidden.")
    }
}