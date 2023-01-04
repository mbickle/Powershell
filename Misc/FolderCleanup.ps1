<#    
.SYNOPSIS
Script to clean up folders/files that are over X days old

.PARAMETER Path
Specifies the target Path.

.PARAMETER Age
Specifies the target Age in days, e.g. Last write time of the item.

.PARAMETER Force
Switch parameter that allows for hidden and read-only files to also be removed.

.PARAMETER Empty Folder
Switch parameter to use empty folder remove function.

.EXAMPLE
FolderCleanup.ps1 -Path 'C:\foo' -Age 7 #Remove Files In The Target Path That Are Older Than The Specified Age (in days), Recursively.

Remove-AgedItems -Path 'C:\foo' -Age 7 -Force #Remove Files In The Target Path That Are Older Than The Specified Age (in days), Recursively. Force will include hidden and read-only files.

Remove-AgedItems -Path 'C:\foo' -Age 0 -EmptyFolder #Remove All Empty Folders In Target Path.

Remove-AgedItems -Path 'C:\foo' -Age 7 -EmptyFolder #Remove All Empty Folders In Target Path That Are Older Than Specified Age (in days).

.NOTES
The -EmptyFolders switch branches the function so that it will only perform its empty folder cleanup operation, it will not affect aged files with this switch.
It is recommended to first perform a cleanup of the aged files in the target path and them perform a cleanup of the empty folders.
#>
param (
	[String][Parameter(Mandatory = $true)]
	$Path,
	[int][Parameter(Mandatory = $true)]
	$Age,
	[switch]$Force,
	[switch]$EmptyFolder
)

function Format-FileSize([int64] $size) 
{
    if ($size -lt 1024)
    {
        return $size
    }
    if ($size -lt 1Mb)
    {
        return "{0:0.0} Kb" -f ($size/1Kb)
    }
    if ($size -lt 1Gb)
    {
        return "{0:0.0} Mb" -f ($size/1Mb)
    }
    return "{0:0.0} Gb" -f ($size/1Gb)
}

function Get-DiskUsage
{
	param(
		[string]$Path = ".",
		[switch]$SortBySize,
		[switch]$Summary
	)

	Write-Host "DiskUsage: $Path"
	$directory = (Get-Item $Path).FullName
            
	    if ($Summary)
        {
            $summaryResults = Get-ChildItem -Recurse -Path $Path -Force | Measure-Object -Sum Length
        
            $results = New-Object psobject -Property @{
			    Directory=$directory;
			    Size=Format-FileSize($summaryResults.Sum);
			    Bytes=$summaryResults.Sum;
                Files=$summaryResults.Count;
            }
        }
        else
        {
        	$groupedList = Get-ChildItem -Recurse -Path $Path -Force |
        		Group-Object directoryName |
		        	Select-Object name, @{name='length'; expression={($_.group | Measure-Object -sum length).sum}}

	        $results = ($groupedList | ForEach-Object {
		        $dn = $_
                $files = Get-ChildItem -File $dn.name -Force
		        $size = ($groupedList | Where-Object { $_.name -like "$($dn.name)*" } | Measure-Object -Sum length).sum

                New-Object psobject -Property @{
			        Directory=$dn.name;
			        Size=Format-FileSize($size);
			        Bytes=$size;
                    Files=$files.Count
		        }
	        })
    }
	
	if ($SortBySize)
	{
		$results = $results | Sort-Object -property Bytes
	}

    $results | Format-Table -AutoSize -Property Files, Bytes, Size, Directory

    if (-not $Summary)
    {
        $summaryResults = Get-ChildItem -Recurse -Path $Path -Force | Measure-Object -Sum Length
        
        $results = New-Object psobject -Property @{
            Directory=$directory;
            Size=Format-FileSize($summaryResults.Sum);
            Bytes=$summaryResults.Sum;
            Files=$summaryResults.Count;
        }

        $results | Format-Table -AutoSize -Property Files, Bytes, Size, Directory
    }
}

function Remove-AgedItems
{
    param (
		[String][Parameter(Mandatory = $true)]
        $Path,
        [int][Parameter(Mandatory = $true)]
        $Age,
        [switch]$Force,
        [switch]$EmptyFolder
	)
    
    $CurrDate = (Get-Date)
    
    Write-Host $Path

    if (Test-Path -Path $Path)
    {        
        $Items = (Get-ChildItem -Path $Path -Recurse -Force -File)        
        Write-Host ($Items).Length

        $AgedItems = ($Items | Where-object { $_.LastWriteTime -lt $CurrDate.AddDays(- $Age) })
        
        if ($EmptyFolder.IsPresent)
        {   
            $Folders = @()
            ForEach ($Folder in (Get-ChildItem -Path $Path -Recurse | Where-Object { ($_.PSisContainer) -and ($_.LastWriteTime -lt $CurrDate.AddDays(- $Age)) }))
            {
                $Folders += New-Object PSObject -Property @{
                    Object = $Folder
                    Depth = ($Folder.FullName.Split("\")).Count
                }
            }
			
            $Folders = $Folders | Sort-Object Depth -Descending
            
            ForEach ($Folder in $Folders)
            {
                If ($Folder.Object.GetFileSystemInfos().Count -eq 0)
                {                    
                    Remove-Item -Path $Folder.Object.FullName -Force                    
                    Start-Sleep -Seconds 0.2                    
                }
            }            
        }        
        else
        {   
            if ($AgedItems.Count -gt 0)
            {
                if ($Force.IsPresent)
                {                
                    $AgedItems | Remove-Item -Recurse -Force                
                }            
                else
                {   
                    Write-Host "Removing $AgedItems"             
                    $AgedItems | Remove-Item -Recurse
                }     
            }
            else
            {
                Write-Host "Nothing to remove..."
            }       
        }        
    }    
    else
    {        
        Write-Error "Target path '$Path' was not found."
		throw "Target path '$Path' was not found."
    }    
}

$command = ${function:Remove-AgedItems}
$folders = (Get-ChildItem -Path $Path -Directory) 
Get-DiskUsage $Path 

foreach ($folder in $folders)
{
    $arguments = "$Path\$folder", "$Age"
    Start-Job -ScriptBlock $command -ArgumentList $arguments
}

$MaxWait = 60
$Wait = 0
while ($CompletedJobs = Get-Job | Where-Object {$_.State -eq "Running"})
{
    if ($Wait -gt $MaxWait)
    {
		write-host "Hit MaxWait time waiting for jobs to complete. " -ForegroundColor Yellow
        break
    }

    write-host "    " (Get-Job | Where-Object {$_.State -eq "Running"} | Measure-Object).count "...Jobs are still running" -ForegroundColor Yellow

    $CompletedJobs = Get-Job | Where-Object {$_.State -eq "Completed"} | Remove-Job

    start-sleep 5
    $Wait += 1
}

$CompletedJobs = Get-Job | Where-Object {$_.State -eq "Completed"} | Remove-Job

$FailedJobs = @(Get-Job)

if ($FailedJobs.Count -gt 0)
{
    $FailedJobsErrors = @()    
    Foreach ($FailedJob in $FailedJobs)
    {
        $ChildJobsErrors = @()
        Foreach ($ChildJob in $FailedJob.ChildJobs)
        {
            $ChildJobsErrors += $ChildJob.JobStateInfo.Reason
        }

        $FailedJobsErrors += $FailedJob.Location +" " + $ChildJobsErrors + " - Job failed.`n" 
    }

    Write-Host $FailedJobsErrors -ForegroundColor Red
    # | Out-File $jobErrors -Append
}

Get-Job | Remove-Job -Force
Get-DiskUsage $Path -Summary | Format-Table
Write-Host "`n  Cleanup has been completed.`n" -ForegroundColor Green 
