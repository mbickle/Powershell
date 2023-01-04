<#
.SYNOPSIS
    Enables MSDTC on local computer.
#>

# Import the module
Import-Module -Name MsDtc

# Set the DTC config
$dtcNetworkSetting = @{
    DtcName                           = 'Local'
    AuthenticationLevel               = 'NoAuth'
    InboundTransactionsEnabled        = $true
    OutboundTransactionsEnabled       = $true
    RemoteClientAccessEnabled         = $true
    RemoteAdministrationAccessEnabled = $true
    XATransactionsEnabled             = $false
    LUTransactionsEnabled             = $true
}
$dtcJob = Set-DtcNetworkSetting @dtcNetworkSetting -AsJob
$firewallJob = Enable-NetFirewallRule -DisplayGroup "Distributed Transaction Coordinator" -AsJob
$dtcJob
$firewallJob

Write-Host "Waiting..."
Wait-Job -ID $dtcJob.Id
Wait-Job -ID $firewallJob.Id

Write-Host "Job Results"
Receive-Job -Job $dtcJob
Receive-Job -Job $firewallJob

Get-DtcNetworkSetting -DtcName "Local"

# Restart the MsDtc service
Get-Service -Name MsDtc | Restart-Service