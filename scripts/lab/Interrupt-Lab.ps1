#Requires -Version 7.4
param(
    [Parameter(Mandatory)][string]$RunDirectory,
    [string]$LabConfirmation,
    [switch]$AllowMutation
)
. (Join-Path $PSScriptRoot 'Lab.Common.ps1')
if (-not (Test-NetworkLabConfirmation -GateOpen ([bool]$AllowMutation) -Phrase $LabConfirmation)) {
    [ordered]@{status='BLOCKED';reason='Interruption worker mutation gate is closed.';networkChanges=$false} |
        ConvertTo-Json -Depth 4
    return
}
$run = Assert-LabRunDirectoryBoundary `
    -RunDirectory $RunDirectory `
    -SkillRoot (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
Set-LabMutationAuthorization
$script:LabMutationCount=0
$x=Get-LabIdentity $run
Write-LabJson (Join-Path $run 'interrupted-journal.json') @{changeId=$x.control.runId+'-interruption';state='APPLYING';intent='remove-owned-test-ipv4';address=$x.control.ipv4;time=[DateTimeOffset]::Now.ToString('o')}
Remove-LabAddress $run $x.control.ipv4
[Environment]::Exit(77)
