<#
.SYNOPSIS
Update all 2015 - 2022 versions of Visual Studio

Assumes Visual Studio is installed in Default Location.

Command line arguments for Visual Studio Installation can be found here: 
    https://docs.microsoft.com/en-us/visualstudio/install/use-command-line-parameters-to-install-visual-studio?view=vs-2022
#>

Write-Output ("Updating Visual Studio... on " + $env:COMPUTERNAME)

# Hash Table for Internal Version Numbers of Visual Studio
$VSRelease = @{"2015" = "14"; "2017" = "15"; "2019" = "16"; "2022" = "17" }

# Hash Table for Visual Studio Editions
$VSEditions = @("Enterprise", "Professional", "Community")

# Path to save web page with download links from visualstudio.microsoft.com
$VSURLPath = "C:\Temp\"

if (!(Test-Path $VSURLPath))
{
    New-Item -ItemType Directory -Force -Path $VSURLPath > $null
}

foreach ($Release in $VSRelease.Keys)
{
    Write-Output "Searching for Release $Release"

    if ($Release -ge 2022) {
        $VSInstallRootPath = "C:\Program Files\Microsoft Visual Studio"
    }
    else {
        $VSInstallRootPath = "C:\Program Files (x86)\Microsoft Visual Studio"
    }

    foreach ($Edition in $VSEditions)
    {
        $VSInstallPath = "$VSInstallRootPath\$Release\$Edition"
        Write-Output "VSInstallPath: $VSInstallPath"

        $VS_Edition_TXT = "VS_" + $Edition + "_" + $Release + ".txt"

        if (Test-Path $VSInstallPath) {
            Write-Output ("Found Visual Studio $Edition $Release in $VSInstallPath")
            $ReleaseNumber = $VSRelease[$Release]
            $VS_Edition_EXE = "VS_$Edition" + "_$Release.exe"
            
            # Ensuring an older file doesn't exist
            if (Test-Path "$VSURLPath$VS_Edition_TXT") {
                Write-Output "Removing $VSURLPath$VS_Edition_TXT"
                Remove-Item "$VSURLPath$VS_Edition_TXT"
            }
            
            # This helps with download speed by not displaying the Progress.
            $ProgressPreference = 'SilentlyContinue'
            Write-Output "Getting Download URL for Visual Studio $Edition $Release. Saving to .....$VSURLPath$VS_Edition_TXT"
            Invoke-WebRequest -uri "https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=$Edition&rel=$ReleaseNumber" -OutFile "$VSURLPath$VS_Edition_TXT"

            Write-Output "Extracting Download URL from the $VSURLPath$VS_Edition_TXT"
            $FindUrl = Select-String "$VSURLPath$VS_Edition_TXT" -Pattern "downloadVS.aspx" -SimpleMatch
            $DownloadUrl = $FindUrl.Line -split ":",2
            $VS_Edition_URL = $DownloadUrl.Item(1)
            $VS_Edition_URLFINAL = $VS_Edition_URL.Replace("'","")

            Write-Output "Downloading $VS_Edition_EXE to $VSURLPath from $VS_Edition_URLFINAL"
            Write-Output "Update Visual Studio Installer"
           
            $VSSetupPath = "$VSURLPath$VS_Edition_EXE";
            # Ensuring an older file doesn't exist
            if (Test-Path "$VSSetupPath") {
                Write-Output "Removing $VSSetupPath"
                Remove-Item "$VSSetupPath"
            }

            Invoke-WebRequest -uri $VS_Edition_URLFINAL -Method GET -UseBasicParsing -OutFile "$VSURLPath$VS_Edition_EXE"
            # Reset Progress
            $ProgressPreference = 'Continue'

            # Update the VS Installer first
            Write-Output "Launching $VSSetupPath to update the VS Installer"
            $InstallerUpdateProcess = Start-Process -FilePath $VSSetupPath -Wait -PassThru -ArgumentList @("--update","--quiet");
            $InstallerUpdateProcess.WaitForExit();

            Write-Output "$VS_Edition_EXE exited with code: $($InstallerUpdateProcess.ExitCode)"
            Write-Output "Update Visual Studio $Edition $Release"

            $VSInstallPathEscaped = """$VSInstallRootPath\$Release\$Edition"""
            Write-Output "VSInstallPathEscaped: $VSInstallPathEscaped"
            Write-Output "VSInstallRootPath: $VSInstallRootPath"

            # Start process to update Visual Studio
            Write-Output "--installpath '$VSInstallPath'"
            $VSUpdateProcess = Start-Process -FilePath "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vs_installer.exe" -Wait -PassThru -ArgumentList @("update","--norestart","--quiet","--force","--channelUri https://aka.ms/vs/$ReleaseNumber/release/channel","--installpath $VSInstallPathEscaped");
            $VSUpdateProcess.WaitForExit();

            Write-Output "vs_installer.exe exited with code: $($VSUpdateProcess.ExitCode)"

            # Cleanup            
            Write-Output "Cleanup..."
            if (Test-Path "$VSSetupPath") {
                Write-Output "Removing $VSSetupPath"
                Remove-Item "$VSSetupPath"
            }
            
            if (Test-Path "$VSURLPath$VS_Edition_TXT") {
                Write-Output "Removing $VSURLPath$VS_Edition_TXT"
                Remove-Item "$VSURLPath$VS_Edition_TXT"
            }

            if ($VSUpdateProcess.ExitCode -ne 0)
            {
                # This is read by the calling script to know if the job failed so it's reported correctly.
                Write-Error -Message "Installation failed with $($VSUpdateProcess.ExitCode)"
            }
        }
        else {
            Write-Output ("Visual Studio $Edition $Release not found.")
        }
    }
}