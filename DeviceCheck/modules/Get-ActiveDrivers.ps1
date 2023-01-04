<#
.SYNOPSIS
    Get Active Drivers
#>

function Get-ActiveDrivers {
    [CmdletBinding()]
    param(
    )

    begin {
    }

    process {
        $ActiveDrivers = @()

        $DriverList = Get-WindowsDriver -Online
        $PNPSignedDriverList = Get-WmiObject win32_pnpsigneddriver

        $DriverList | ForEach-Object {
            $MyDriver = $_.Driver
            $OrigINF = Split-Path -Leaf $_.OriginalFileName 
            $PNPSignedDrivers = @($PNPSignedDriverList | Where-Object { $($_.InfName) -eq $MyDriver })
            $PNPSignedDrivers | ForEach-Object {
                $PNPVerObject = New-Object System.Version
                [System.Version]::TryParse($_.DriverVersion,[ref] $PNPVerObject) | Out-Null

                $DeviceID = $_.DeviceID
                $BangedDevices = @(Get-WmiObject Win32_PNPEntity | Where-Object {$_.DeviceID -eq $DeviceID})
                if ($BangedDevices.Count -ne 0) {      
                    $ActiveDriver = New-Object System.Object
                    $ActiveDriver | Add-Member -Type NoteProperty -Name INF -Value $OrigINF
                    $ActiveDriver | Add-Member -Type NoteProperty -Name Version -Value $PNPVerObject
                    $ActiveDriver | Add-Member -Type NoteProperty -Name DeviceID -Value $DeviceID
                    $ActiveDrivers += $ActiveDriver
                }
            }
        }
    }

    end {
        return $ActiveDrivers
    }
}
