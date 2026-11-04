#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Destination=(Join-Path $env:USERPROFILE '.codex\skills\windows-network-fixer'),
    [string]$BackupRoot=(Join-Path $env:LOCALAPPDATA 'CodexSkillBackups')
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $source 'scripts/common/Core.psm1') -Force -Global -DisableNameChecking
Import-Module (Join-Path $source 'scripts/state/State.psm1') -Force -Global -DisableNameChecking
$destinationFull=Assert-NetworkSafePath $Destination
$backupFull=Assert-NetworkSafePath $BackupRoot
if([IO.Path]::GetFileName($destinationFull) -cne 'windows-network-fixer'){throw 'Destination must name windows-network-fixer.'}
foreach($left in @($source,$destinationFull)){
    if($backupFull.StartsWith($left.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $left.StartsWith($backupFull.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase) -or
        $left.Equals($backupFull,[StringComparison]::OrdinalIgnoreCase)){throw 'Backup directory must be disjoint from source and installation.'}
}
if($source.Equals($destinationFull,[StringComparison]::OrdinalIgnoreCase)){throw 'Run installation from a separate source package.'}
$manifest=Get-Content -LiteralPath (Join-Path $source 'manifests/compatibility.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if($manifest.version -ne '1.0.1'){throw 'Unexpected source version.'}
$releasePaths=@('CHANGELOG.md','SKILL.md','agents','manifests','references','schemas','scripts','tests')
$files=@(foreach($relative in $releasePaths){
    $path=Assert-NetworkSafePath (Join-Path $source $relative)
    $item=Get-Item -LiteralPath $path -ErrorAction Stop
    if($item.PSIsContainer){
        foreach($child in @(Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction Stop)){
            if($child.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Release package contains a reparse point.'}
            if(-not $child.PSIsContainer){$child}
        }
    }else{$item}
})
if(-not $PSCmdlet.ShouldProcess($destinationFull,"Install v$($manifest.version) and back up current files to $backupFull")){
    [pscustomobject]@{status='NOT_RUN';destination=$destinationFull;files=$files.Count}
    return
}
$backup=Join-Path $backupFull ("windows-network-fixer-$([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid())")
if(Test-Path -LiteralPath $destinationFull -PathType Container){
    [IO.Directory]::CreateDirectory($backup)|Out-Null
    foreach($item in @(Get-ChildItem -LiteralPath $destinationFull -Force)){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Installed skill contains a reparse point.'}
        Copy-Item -LiteralPath $item.FullName -Destination (Join-Path $backup $item.Name) -Recurse -ErrorAction Stop
    }
}
[IO.Directory]::CreateDirectory($destinationFull)|Out-Null
$receipt=[Collections.Generic.List[object]]::new()
foreach($file in $files){
    $relative=[IO.Path]::GetRelativePath($source,$file.FullName)
    $target=Assert-NetworkSafePath (Join-Path $destinationFull $relative)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))|Out-Null
    $expected=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    [IO.File]::Copy($file.FullName,$target,$true)
    $actual=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if($actual -cne $expected){throw "Installed byte verification failed: $relative. Backup: $backup"}
    $receipt.Add(@{file=$relative;sha256=$actual})
}
$result=@{status='PASS';version=$manifest.version;source=$source;destination=$destinationFull;backup=$backup;files=@($receipt);networkChanges=$false}
if(-not(Test-Path -LiteralPath $backup)){[IO.Directory]::CreateDirectory($backup)|Out-Null}
Write-NetworkJson -Path (Join-Path $backup 'installation-receipt.json') -Object $result
[pscustomobject]@{status='PASS';version=$manifest.version;destination=$destinationFull;backup=$backup;files=$receipt.Count;networkChanges=$false}
