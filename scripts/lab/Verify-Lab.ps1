#Requires -Version 7.4
param(
    [Parameter(Mandatory)][string]$Address,
    [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
    [Parameter(Mandatory)][ValidateRange(-1,2147483647)][int]$InterfaceIndex,
    [Parameter(Mandatory)][ValidateLength(1,256)][string]$Nonce,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'validation/Socket.psm1') `
    -Force `
    -DisableNameChecking
$result = Invoke-NetworkSocketProbe `
    -Address $Address `
    -Port $Port `
    -InterfaceIndex $InterfaceIndex `
    -Nonce $Nonce
[IO.File]::WriteAllText(
    $OutputPath,
    ($result | ConvertTo-Json -Depth 10),
    [Text.UTF8Encoding]::new($false)
)
$result
if ($result.status -ne 'PASS') {
    exit 7
}
