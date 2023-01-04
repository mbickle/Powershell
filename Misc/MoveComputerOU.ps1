<#
.SYNOPSIS
Move the computer to TargetOU

.PARAMETER ComputerName
Name of the computer to move OU.

.PARAMETER TargetOU
The TargetOU to move computer.


In Oct 2018 of Win10 you can just go to "Manage optional features" in settings and click on "Add a feature" search for "RSAT: Active Directory Domain Services and Lightweight Directory Services Tools" to install. This is only for Win10 Client.
#>

[cmdletbinding()]            

Param (
    [Parameter(Mandatory=$true, HelpMessage="The computer to get OU.")]
    [string]$ComputerName,    
    [Parameter(mandatory=$true)]
    $TargetOU
)            

Import-Module ActiveDirectory
$Domain = [ADSI]""
$DN=$Domain.DistinguishedName
$Computer = Get-ADComputer $ComputerName
if(!$Computer) {
 Write-Host "No Computer are found in default container"
 return
}

if(!(Move-ADObject $Computer -TargetPath $TargetOU)) {
    $Status = "SUCCESS"
} else {
    $Status = "FAILED"
}
 
$OutputObj = New-Object -TypeName PSobject
$OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.Name.tostring()
$OutputObj | Add-Member -MemberType NoteProperty -Name DestinationPath -Value $TargetOU
$OutputObj | Add-Member -MemberType NoteProperty -Name Status -Value $Status
$OutputObj
