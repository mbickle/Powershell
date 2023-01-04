<#
.SYNOPSIS
    Get Capsule Firmware
#>

function Get-CapsuleFirmware {
    [CmdletBinding()]
    param(
    )

    begin {
    }

    process {
        #Make an empty array to hold things
        $firmware = @()

        #This just out a global with the contents of win32_pnpsigneddriver
        #Load-Win32_PNPSignedDriver
        $Win32_PNPSignedDriver = Get-WmiObject win32_pnpsigneddriver

        #For each Firmware capsule node
        if (Test-Path HKLM:\HARDWARE\UEFI\ESRT) {
            Get-ChildItem -Path HKLM:\HARDWARE\UEFI\ESRT -ErrorAction Continue | ForEach-Object { 
                $esrt = $_
                #Parse out the firmware GUID
                $fwGuid = $esrt.Name.Split('{')[1].TrimEnd('}') | Where-Object {$_.Length -eq 36}
                #Capture firmwaredriverinfo from PNP for each node
                $fwDriverInfo = $Win32_PNPSignedDriver | Where-Object -FilterScript {$_.HardwareID -like "*$fwGuid*"} 

                #Added GUID result value to the object so we can filter appropriately
                $fw = New-Object System.Object
                $fw | Add-Member -Type NoteProperty -Name Name -Value $fwDriverInfo.Description
                $fw | Add-Member -Type NoteProperty -Name PnPVersion -Value $fwDriverInfo.DriverVersion
                #$fw | Add-Member -Type NoteProperty -Name other -Value ($fwDriverInfo.name)
                $fw | Add-Member -Type NoteProperty -Name ESRT -Value $fwguid

                #Parse out version data for each value, filling out the table
                $esrt.GetValueNames() | ForEach-Object {
                    $val = $esrt.GetValue($_)
                    if($_.Contains('Version')){$val = "{0:x}" -f $val}
                    if(-not ($_.Contains('Type'))) {
                        $fw | Add-Member -type NoteProperty -name $_ -value $val 
                    }
                }

                $firmware += $fw
            } 
        }
        else
        {
            $fw = New-Object System.Object
            $fw | Add-Member -Type NoteProperty -Name Name -Value "Unknown"
            
            $firmware += $fw
        }
    }

    end {
        return $firmware
    }
}
