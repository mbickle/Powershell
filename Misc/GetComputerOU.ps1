<#
.SYNOPSIS
Get the OU of the Computer

.PARAMETER ComputerName
Name of computer to get OU 
Default: local computer name
#>

Param (
    [Parameter(Mandatory=$false, HelpMessage="The computer to get OU.")]
    [string]$ComputerName = $env:computername
)

Function Get-OSCComputerOU
{
    Param (
        [Parameter(Mandatory=$false, HelpMessage="The computer to get OU.")]
        [string]$ComputerName = $env:computername
    )
    
    $Filter = "(&(objectCategory=Computer)(Name=$ComputerName))"

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher
    $DirectorySearcher.Filter = $Filter
    $SearcherPath = $DirectorySearcher.FindOne()
    $DistinguishedName = $SearcherPath.GetDirectoryEntry().DistinguishedName

    $OUName = ($DistinguishedName.Split(","))[1]
    $OUMainName = $OUName.SubString($OUName.IndexOf("=")+1)
    
    $Obj = New-Object -TypeName PSObject -Property @{"ComputerName" = $ComputerName
                                                     "BelongsToOU" = $OUMainName
                                                     "FullOU" = $DistinguishedName }
    $Obj
}

Get-OSCComputerOU -ComputerName $ComputerName