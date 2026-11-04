#Requires -Version 7.4
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [Parameter(Mandatory)][int]$ParentProcessId,
    [Parameter(Mandatory)][long]$ParentStartTicks,
    [ValidateRange(1,900)][int]$TimeoutSeconds=480,
    [string]$LabConfirmation,
    [switch]$AllowMutation
)
. (Join-Path $PSScriptRoot 'Lab.Common.ps1')
if (-not (Test-NetworkLabConfirmation -GateOpen ([bool]$AllowMutation) -Phrase $LabConfirmation)) {
    [ordered]@{status='BLOCKED';reason='Watchdog mutation gate is closed.';networkChanges=$false} |
        ConvertTo-Json -Depth 4
    return
}
try {
    $run = Assert-LabRunDirectoryBoundary `
        -RunDirectory $RunDirectory `
        -SkillRoot (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
} catch {
    [ordered]@{status='BLOCKED';reason=$_.Exception.Message;networkChanges=$false} |
        ConvertTo-Json -Depth 4
    return
}
Set-LabMutationAuthorization
Write-LabJson (Join-Path $run 'watch-ready.json') @{parentProcessId=$ParentProcessId;parentStartTicks=$ParentStartTicks;time=[DateTimeOffset]::UtcNow.ToString('o')}
$deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
try{
    while([DateTime]::UtcNow -lt $deadline){
        if(Test-Path -LiteralPath (Join-Path $run 'done.json')){
            $done=Get-Content -LiteralPath (Join-Path $run 'done.json') -Raw|ConvertFrom-Json
            if($done.status -eq 'MANUAL_RECOVERY_REQUIRED'){exit 1}
            if($done.cleanupVerified){
                if(Test-Path -LiteralPath (Join-Path $run 'control.json')){
                    if(Test-LabCleanupRecord -RunDirectory $run){exit 0}
                }elseif(Test-Path -LiteralPath (Join-Path $run 'cleanup-created.json')){
                    $clean=Get-Content -LiteralPath (Join-Path $run 'cleanup-created.json') -Raw|ConvertFrom-Json
                    $created=Get-Content -LiteralPath (Join-Path $run 'created-switch.json') -Raw|ConvertFrom-Json
                    if($clean.status -eq 'PASS' -and $clean.switchId -ceq $created.switchId -and $clean.switchName -ceq $created.switchName){exit 0}
                }
            }
        }
        $parent=Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue
        if(-not $parent -or $parent.StartTime.ToUniversalTime().Ticks -ne $ParentStartTicks){break}
        Start-Sleep -Milliseconds 500
    }
    $created=$null
    if(Test-Path -LiteralPath (Join-Path $run 'created-switch.json')){
        $record=Get-Content -LiteralPath (Join-Path $run 'created-switch.json') -Raw|ConvertFrom-Json
        $created=[pscustomobject]@{Id=[guid]$record.switchId;Name=[string]$record.switchName}
    }
    $cleanup=Invoke-LabCleanup -RunDirectory $run -Created $created -Control $null
    $status=if($cleanup.cleanupVerified){'FAIL'}else{'MANUAL_RECOVERY_REQUIRED'}
    $failure=if($cleanup.failure){$cleanup.failure}else{'Supervisor interrupted or timed out; owned resources removed, validation chain incomplete.'}
    Write-LabTerminalRecords -RunDirectory $run -Status $status -Failure $failure -CleanupVerified ([bool]$cleanup.cleanupVerified)
}catch{
    $failure='MANUAL_RECOVERY_REQUIRED: '+$_.Exception.Message
    Write-LabJson (Join-Path $run 'watchdog-error.json') @{status='MANUAL_RECOVERY_REQUIRED';error=$failure}
    Write-LabTerminalRecords -RunDirectory $run -Status 'MANUAL_RECOVERY_REQUIRED' -Failure $failure -CleanupVerified $false
}
