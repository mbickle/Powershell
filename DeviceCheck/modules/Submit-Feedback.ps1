<#
.SYNOPSIS
    Submit Feedback via Feedback Hub
#>


function Submit-FeedbackHub {
    [CmdletBinding()]
    param(
        [string] $referrer = 'deviceCheck',
        [int] $contextId = 158,
        [string] $title,
        [string] $tag
    )

    Write-Output "Launching Feedback Hub from $referrer"

    $DeviceModel = (Get-WmiObject win32_computersystem).Model
    $title = "$DeviceModel - $title"

    Start-Process "feedback-hub:?referrer=$referrer&tabID=2&newFeedback=true&feedbackType=2&ContextId=$contextId&searchString=$title&tag=$tag"  
}

