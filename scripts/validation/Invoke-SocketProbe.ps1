#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Address,
    [Parameter(Mandatory)][ValidateRange(1,65535)][int]$Port,
    [ValidateRange(-1,2147483647)][int]$InterfaceIndex = -1,
    [Parameter(Mandatory)][ValidateLength(1,256)][string]$Nonce,
    [ValidateRange(250,30000)][int]$TimeoutMilliseconds = 3000,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Socket.psm1') -Force -DisableNameChecking
$result = Invoke-NetworkSocketProbe `
    -Address $Address `
    -Port $Port `
    -InterfaceIndex $InterfaceIndex `
    -Nonce $Nonce `
    -TimeoutMilliseconds $TimeoutMilliseconds
if ($OutputPath) {
    $full = [IO.Path]::GetFullPath($OutputPath)
    $directory = [IO.Path]::GetDirectoryName($full)
    if ($directory -and -not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw 'Socket result directory does not exist.'
    }
    [IO.File]::WriteAllText(
        $full,
        ($result | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )
}
$result
if ($result.status -ne 'PASS') {
    exit 7
}
