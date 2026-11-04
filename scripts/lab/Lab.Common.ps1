#Requires -Version 7.4
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'common/Core.psm1') `
    -Force `
    -DisableNameChecking

$script:LabMutationAuthorized = $false

function Set-LabMutationAuthorization {
    $script:LabMutationAuthorized = $true
}

function Assert-LabMutationAuthorized {
    if ($script:LabMutationAuthorized -ne $true) {
        throw 'Lab mutation authorization was not established in this process.'
    }
}

function Assert-LabRunDirectoryBoundary {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$SkillRoot
    )
    # Syntax validation must precede filesystem access or directory creation.
    Test-NetworkSafePathSyntax $RunDirectory | Out-Null
    Test-NetworkSafePathSyntax $SkillRoot | Out-Null
    $run = [IO.Path]::GetFullPath($RunDirectory).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $skill = [IO.Path]::GetFullPath($SkillRoot).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $separator = [IO.Path]::DirectorySeparatorChar
    if (
        $run.Equals($skill, [StringComparison]::OrdinalIgnoreCase) -or
        $run.StartsWith($skill + $separator, [StringComparison]::OrdinalIgnoreCase) -or
        $skill.StartsWith($run + $separator, [StringComparison]::OrdinalIgnoreCase)
    ) {
        throw 'Lab run directory and skill source must be disjoint.'
    }
    $current = $run
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Reparse-point lab state paths are forbidden.'
            }
            if (Test-Path -LiteralPath (Join-Path $current '.git')) {
                throw 'Lab run directory must be outside Git worktrees.'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if (-not $parent -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
    $run
}

function Get-LabTerminalStatus {
    param(
        [AllowNull()][object]$Failure,
        [bool]$Preview
    )
    if ($Preview) {
        return 'NOT_RUN'
    }
    if ($null -eq $Failure -or [string]::IsNullOrWhiteSpace([string]$Failure)) {
        return 'PASS'
    }
    if ([string]$Failure -like 'MANUAL_RECOVERY_REQUIRED:*') {
        return 'MANUAL_RECOVERY_REQUIRED'
    }
    'FAIL'
}

function Write-LabJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Value
    )
    $full = [IO.Path]::GetFullPath($Path)
    $directory = [IO.Path]::GetDirectoryName($full)
    if (-not $directory -or -not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw 'Lab output directory does not exist.'
    }
    [IO.File]::WriteAllText(
        $full,
        ($Value | ConvertTo-Json -Depth 18),
        [Text.UTF8Encoding]::new($false)
    )
}

function New-LabControl {
    param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][object]$SwitchId,
        [Parameter(Mandatory)][object]$AdapterGuid)
    # NetAdapter.InterfaceGuid can be a braced string, not a System.Guid.
    $control=@{
        runId=$RunId
        switchName='CodexLab-'+$RunId.Substring(0,12)
        switchId=[guid]::Parse([string]$SwitchId).ToString('D')
        adapterGuid=[guid]::Parse([string]$AdapterGuid).ToString('D')
        ipv4='192.0.2.241'
        ipv6='fd42:6364:786c::241'
    }
    Test-LabControl $control | Out-Null
    $control
}

function New-LabAddressSnapshot {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Control,
        [Parameter(Mandatory)][object[]]$Addresses)
    Test-LabControl $Control | Out-Null
    @{
        kind='DisposableLabAddressSnapshot'
        runId=[string]$Control.runId
        switchId=[guid]::Parse([string]$Control.switchId).ToString('D')
        adapterGuid=[guid]::Parse([string]$Control.adapterGuid).ToString('D')
        addresses=@($Addresses)
    }
}

function Test-LabControl {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Control)
    if ([string]$Control.runId -notmatch '^[0-9a-f]{32}$') {
        throw 'Invalid lab run identity.'
    }
    if ([string]$Control.switchName -ne 'CodexLab-' + ([string]$Control.runId).Substring(0,12)) {
        throw 'Lab switch name does not match the run identity.'
    }
    $switchId = [guid]::Empty
    $adapterGuid = [guid]::Empty
    if (
        -not [guid]::TryParse([string]$Control.switchId, [ref]$switchId) -or
        -not [guid]::TryParse([string]$Control.adapterGuid, [ref]$adapterGuid)
    ) {
        throw 'Lab control identities must be GUIDs.'
    }
    if ([string]$Control.ipv4 -ne '192.0.2.241' -or [string]$Control.ipv6 -ne 'fd42:6364:786c::241') {
        throw 'Lab control address scope changed.'
    }
    $true
}

function Test-LabCleanupRecord {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [System.Collections.IDictionary]$Control
    )
    if ($null -eq $Control) {
        $Control = Get-LabControl $RunDirectory
    }
    $path = Join-Path $RunDirectory 'cleanup.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return $false
    }
    $file = Get-Item -LiteralPath $path -Force
    if (
        $file.Length -gt 65536 -or
        $file.Attributes -band [IO.FileAttributes]::ReparsePoint
    ) {
        return $false
    }
    try {
        $record = ConvertFrom-NetworkJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
        return (
            [string]$record.status -eq 'PASS' -and
            [string]$record.runId -eq [string]$Control.runId -and
            [string]$record.switchId -eq [string]$Control.switchId -and
            [guid]::Parse([string]$record.adapterGuid).ToString('D') -eq [guid]::Parse([string]$Control.adapterGuid).ToString('D') -and
            [bool]$record.addressesAbsent
        )
    } catch {
        return $false
    }
}

function Get-LabControl {
    param([Parameter(Mandatory)][string]$RunDirectory)
    $run = Assert-LabRunDirectoryBoundary `
        -RunDirectory $RunDirectory `
        -SkillRoot (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
    $path = Join-Path $run 'control.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'Lab control record is missing.'
    }
    $control = ConvertFrom-NetworkJson (Get-Content -LiteralPath $path -Raw -Encoding UTF8)
    Test-LabControl $control | Out-Null
    $control
}

function Get-LabIdentity {
    param([Parameter(Mandatory)][string]$RunDirectory)
    $control = Get-LabControl $RunDirectory
    $switch = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
        $_.Id.ToString() -eq $control.switchId
    })
    if (
        $switch.Count -ne 1 -or
        $switch[0].Name -ne $control.switchName -or
        $switch[0].SwitchType.ToString() -ne 'Internal'
    ) {
        throw 'Lab switch identity drift.'
    }
    $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
        [guid]::Parse([string]$_.InterfaceGuid).ToString('D') -eq [guid]::Parse([string]$control.adapterGuid).ToString('D')
    })
    if ($adapter.Count -ne 1) {
        throw 'Lab adapter identity drift.'
    }
    $managed = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop | Where-Object {
        $_.SwitchId.ToString() -eq $control.switchId
    })
    if (
        $managed.Count -ne 1 -or
        $managed[0].MacAddress -ne $adapter[0].MacAddress.Replace('-','')
    ) {
        throw 'Lab ownership relationship changed.'
    }
    [pscustomobject]@{
        control = $control
        adapter = $adapter[0]
        switch = $switch[0]
    }
}

function Wait-LabAddress {
    param([int]$InterfaceIndex,[string]$Address)
    for ($i = 0; $i -lt 50; $i++) {
        $found = @(Get-NetIPAddress -InterfaceIndex $InterfaceIndex -ErrorAction Stop |
            Where-Object { $_.IPAddress -eq $Address })
        if ($found.Count -eq 1 -and $found[0].AddressState.ToString() -eq 'Preferred') {
            return
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'Lab address did not become Preferred.'
}

function Get-LabConfig {
    param([Parameter(Mandatory)][string]$RunDirectory)
    $identity = Get-LabIdentity $RunDirectory
    @(
        Get-NetIPAddress `
            -InterfaceIndex $identity.adapter.ifIndex `
            -PolicyStore ActiveStore `
            -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -in @($identity.control.ipv4, $identity.control.ipv6)
            } |
            Sort-Object IPAddress |
            ForEach-Object {
                [ordered]@{
                    IPAddress = $_.IPAddress
                    PrefixLength = $_.PrefixLength
                    SkipAsSource = [bool]$_.SkipAsSource
                    PolicyStore = 'ActiveStore'
                }
            }
    )
}

function Remove-LabAddress {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$Address
    )
    Assert-LabMutationAuthorized
    $identity = Get-LabIdentity $RunDirectory
    if ($Address -notin @($identity.control.ipv4, $identity.control.ipv6)) {
        throw 'Address is outside the disposable lab scope.'
    }
    $item = @(Get-NetIPAddress `
        -InterfaceIndex $identity.adapter.ifIndex `
        -PolicyStore ActiveStore `
        -ErrorAction Stop |
        Where-Object { $_.IPAddress -eq $Address })
    if ($item.Count -ne 1) {
        throw 'Expected exactly one owned lab address.'
    }
    $script:LabMutationCount++
    $item[0] | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
}

function Restore-LabSnapshot {
    param(
        [Parameter(Mandatory)][string]$RunDirectory,
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$TrustedHash
    )
    Assert-LabMutationAuthorized
    $skillRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $run = Assert-LabRunDirectoryBoundary `
        -RunDirectory $RunDirectory `
        -SkillRoot $skillRoot
    Test-NetworkSafePathSyntax $SnapshotPath | Out-Null
    $snapshotFull = [IO.Path]::GetFullPath($SnapshotPath)
    if (
        [IO.Path]::GetDirectoryName($snapshotFull) -ne $run -or
        [IO.Path]::GetFileName($snapshotFull) -notmatch '^lab-address-snapshot(?:-[a-z0-9]+)?\.json$'
    ) {
        throw 'Lab snapshot path is outside its fixed run scope.'
    }
    $snapshotFile = Get-Item -LiteralPath $snapshotFull -ErrorAction Stop
    if (
        $snapshotFile.Length -gt 1048576 -or
        $snapshotFile.Attributes -band [IO.FileAttributes]::ReparsePoint
    ) {
        throw 'Lab snapshot is a reparse point or exceeds the size limit.'
    }
    $actualHash = (Get-FileHash -LiteralPath $snapshotFull -Algorithm SHA256).Hash
    if ($actualHash -ne $TrustedHash) {
        throw 'Lab snapshot hash mismatch; no mutation permitted.'
    }
    $json = Get-Content -LiteralPath $snapshotFull -Raw -Encoding UTF8
    $schema = Join-Path $skillRoot 'schemas/LabAddressSnapshot.schema.json'
    if (-not (Test-Json -Json $json -SchemaFile $schema -ErrorAction SilentlyContinue)) {
        throw 'Lab snapshot schema validation failed; no mutation permitted.'
    }
    $snapshot = ConvertFrom-NetworkJson $json
    $identity = Get-LabIdentity $Run
    if (
        [string]$snapshot.kind -ne 'DisposableLabAddressSnapshot' -or
        [string]$snapshot.runId -ne [string]$identity.control.runId -or
        [string]$snapshot.switchId -ne [string]$identity.control.switchId -or
        [guid]::Parse([string]$snapshot.adapterGuid).ToString('D') -ne [guid]::Parse([string]$identity.control.adapterGuid).ToString('D')
    ) {
        throw 'Lab snapshot resource identity mismatch.'
    }
    $expected = @(
        [ordered]@{
            IPAddress = [string]$identity.control.ipv4
            PrefixLength = 32
            SkipAsSource = $true
            PolicyStore = 'ActiveStore'
        },
        [ordered]@{
            IPAddress = [string]$identity.control.ipv6
            PrefixLength = 128
            SkipAsSource = $true
            PolicyStore = 'ActiveStore'
        }
    )
    $snapshotAddresses = @($snapshot.addresses | Sort-Object IPAddress)
    $expectedAddresses = @($expected | Sort-Object IPAddress)
    if (
        ($snapshotAddresses | ConvertTo-Json -Depth 5 -Compress) -cne
        ($expectedAddresses | ConvertTo-Json -Depth 5 -Compress)
    ) {
        throw 'Lab snapshot address scope violation.'
    }
    $readAddressState = {
        param($Item)
        $owned = Get-LabIdentity $Run
        if (
            [string]$owned.control.runId -ne [string]$snapshot.runId -or
            [string]$owned.control.switchId -ne [string]$snapshot.switchId -or
            [guid]::Parse([string]$owned.control.adapterGuid).ToString('D') -ne
                [guid]::Parse([string]$snapshot.adapterGuid).ToString('D')
        ) {
            throw 'Lab snapshot resource identity changed during restore.'
        }
        $allCurrent = @(Get-NetIPAddress `
            -InterfaceIndex $owned.adapter.ifIndex `
            -PolicyStore ActiveStore `
            -ErrorAction Stop)
        foreach ($address in $allCurrent) {
            if ([string]$address.IPAddress -in @($expected.IPAddress)) { continue }
            $ip = [Net.IPAddress]::Parse([string]$address.IPAddress)
            $bytes = $ip.GetAddressBytes()
            # OS link-local addresses are outside the two managed Lab addresses.
            if ($ip.IsIPv6LinkLocal -or (
                $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
                $bytes[0] -eq 169 -and $bytes[1] -eq 254
            )) { continue }
            throw 'Unexpected lab address outside snapshot scope.'
        }
        $current = @($allCurrent | Where-Object { $_.IPAddress -eq $Item.IPAddress })
        $policyStore = if ($current.Count -eq 1) {
            $current[0].PSObject.Properties['PolicyStore']
        } else {
            $null
        }
        if (
            $current.Count -gt 1 -or
            ($current.Count -eq 1 -and (
                [string]$current[0].IPAddress -cne [string]$Item.IPAddress -or
                $current[0].PrefixLength -ne $Item.PrefixLength -or
                $current[0].SkipAsSource -isnot [bool] -or
                $current[0].SkipAsSource -ne $true -or
                ($null -ne $policyStore -and
                    [string]$policyStore.Value -cne 'ActiveStore')
            ))
        ) {
            throw 'Existing lab address drift; refusing overwrite.'
        }
        [pscustomobject]@{item=$Item;identity=$owned;current=$current}
    }
    # Complete the read-only checks for both owned addresses before the first write.
    $preflight = @($snapshotAddresses | ForEach-Object { & $readAddressState $_ })
    $added = [Collections.Generic.List[object]]::new()
    try {
        foreach ($state in $preflight) {
            if ($state.current.Count -ne 0) { continue }
            $item = $state.item
            $fresh = & $readAddressState $item
            if ($fresh.current.Count -ne 0) {
                throw 'Lab address changed after preflight; refusing overwrite.'
            }
            $script:LabMutationCount++
            New-NetIPAddress `
                -InterfaceIndex $fresh.identity.adapter.ifIndex `
                -IPAddress $item.IPAddress `
                -PrefixLength $item.PrefixLength `
                -SkipAsSource $true `
                -PolicyStore ActiveStore `
                -ErrorAction Stop | Out-Null
            $added.Add($item)
            Wait-LabAddress $fresh.identity.adapter.ifIndex $item.IPAddress
        }
    } catch {
        $restoreFailure = $_.Exception.Message
        $cleanupFailures = [Collections.Generic.List[string]]::new()
        for ($i = $added.Count - 1; $i -ge 0; $i--) {
            try {
                # Compensate only this call's successful additions, still exactly owned and unchanged.
                $fresh = & $readAddressState $added[$i]
                if ($fresh.current.Count -eq 1) {
                    $script:LabMutationCount++
                    $fresh.current[0] | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                }
            } catch {
                $cleanupFailures.Add($_.Exception.Message)
            }
        }
        if ($cleanupFailures.Count -gt 0) {
            throw "MANUAL_RECOVERY_REQUIRED: $restoreFailure; restore compensation failed: $($cleanupFailures -join '; ')"
        }
        throw $restoreFailure
    }
}

function Remove-ExactLabSwitch {
    param([Parameter(Mandatory)][string]$RunDirectory)
    Assert-LabMutationAuthorized
    $run = Assert-LabRunDirectoryBoundary `
        -RunDirectory $RunDirectory `
        -SkillRoot (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
    $lock = $null
    try {
        $lock = [IO.File]::Open(
            (Join-Path $run 'cleanup.lock'),
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        $control = Get-LabControl $run
        if (Test-Path -LiteralPath (Join-Path $run 'cleanup.json')) {
            if (-not (Test-LabCleanupRecord -RunDirectory $run -Control $control)) {
                throw 'Existing lab cleanup record is invalid.'
            }
            return
        }
        $switch = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
            $_.Id.ToString() -eq $control.switchId
        })
        if ($switch.Count -eq 0) {
            $residualAdapter = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
                Where-Object { [guid]::Parse([string]$_.InterfaceGuid).ToString('D') -eq [guid]::Parse([string]$control.adapterGuid).ToString('D') })
            $residualAddress = @(Get-NetIPAddress -ErrorAction Stop |
                Where-Object { $_.IPAddress -in @($control.ipv4, $control.ipv6) })
            if ($residualAdapter.Count -or $residualAddress.Count) {
                throw 'Switch absent but owned adapter or addresses remain.'
            }
            Write-LabJson (Join-Path $run 'cleanup.json') @{
                status = 'PASS'
                switchAlreadyAbsent = $true
                runId = $control.runId
                switchId = $control.switchId
                adapterGuid = [guid]::Parse([string]$control.adapterGuid).ToString('D')
                addressesAbsent = $true
                time = [DateTimeOffset]::Now.ToString('o')
            }
            return
        }
        $identity = Get-LabIdentity $run
        $attached = @(
            Get-VM -ErrorAction Stop |
                Get-VMNetworkAdapter -ErrorAction Stop |
                Where-Object { $_.SwitchId.ToString() -eq $control.switchId }
        )
        if ($attached.Count) {
            throw 'Unexpected VM attachment; refuse cleanup.'
        }
        $identity.switch | Remove-VMSwitch -Force -Confirm:$false -ErrorAction Stop
        $absent = $false
        for ($i = 0; $i -lt 20; $i++) {
            $switchExists = @(Get-VMSwitch -ErrorAction Stop | Where-Object {
                $_.Id.ToString() -eq $control.switchId
            }).Count
            $adapterExists = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
                [guid]::Parse([string]$_.InterfaceGuid).ToString('D') -eq [guid]::Parse([string]$control.adapterGuid).ToString('D')
            }).Count
            $addressExists = @(Get-NetIPAddress -ErrorAction Stop | Where-Object {
                $_.IPAddress -in @($control.ipv4, $control.ipv6)
            }).Count
            if (-not $switchExists -and -not $adapterExists -and -not $addressExists) {
                $absent = $true
                break
            }
            Start-Sleep -Milliseconds 250
        }
        if (-not $absent) {
            throw 'Lab cleanup incomplete.'
        }
        Write-LabJson (Join-Path $run 'cleanup.json') @{
            status = 'PASS'
            runId = $control.runId
            switchId = $control.switchId
            adapterGuid = [guid]::Parse([string]$control.adapterGuid).ToString('D')
            addressesAbsent = $true
            time = [DateTimeOffset]::Now.ToString('o')
        }
    } finally {
        if ($lock) {
            $lock.Dispose()
        }
    }
}


function Test-LabSocketAcceptance {
    param([Parameter(Mandatory)][object]$Result,[bool]$ExpectedSuccess,[bool]$AddressAbsent=$false)
    $names=@($Result.PSObject.Properties.Name)
    if ('status' -notin $names) { return $false }
    if ($ExpectedSuccess) { return [string]$Result.status -ceq 'PASS' }
    return (
        $AddressAbsent -and [string]$Result.status -ceq 'FAIL' -and
        'connectAttempted' -in $names -and -not [bool]$Result.connectAttempted -and
        'failedStage' -in $names -and [string]$Result.failedStage -ceq 'bind' -and
        'nativeError' -in $names -and [int]$Result.nativeError -eq 10049
    )
}

function Write-LabTerminalRecords {
    param([Parameter(Mandatory)][string]$RunDirectory,[Parameter(Mandatory)][string]$Status,
        [AllowNull()][object]$Failure,[bool]$CleanupVerified,[object[]]$Tests=@())
    $time=[DateTimeOffset]::UtcNow.ToString('o')
    Write-LabJson (Join-Path $RunDirectory 'done.json') @{time=$time;status=$Status;cleanupVerified=$CleanupVerified}
    Write-LabJson (Join-Path $RunDirectory 'result.json') @{status=$Status;error=$Failure;cleanupVerified=$CleanupVerified;tests=@($Tests);runDirectory=$RunDirectory;networkScope='Disposable own internal adapter addresses only';installedSkillMutationEnabled=$false;time=$time}
}

function Invoke-LabCleanup {
    param([Parameter(Mandatory)][string]$RunDirectory,[AllowNull()][object]$Created,
        [AllowNull()][System.Collections.IDictionary]$Control)
    try {
        Assert-LabMutationAuthorized
        if ($null -ne $Control -or (Test-Path -LiteralPath (Join-Path $RunDirectory 'control.json'))) {
            Remove-ExactLabSwitch $RunDirectory
            if (-not (Test-LabCleanupRecord -RunDirectory $RunDirectory)) { throw 'Cleanup record did not verify.' }
        } elseif ($null -ne $Created) {
            $switchId=[guid]$Created.Id
            $switchName=[string]$Created.Name
            if ($switchId -eq [guid]::Empty -or $switchName -notmatch '^CodexLab-[0-9a-f]{12}$') { throw 'Pre-control switch identity is invalid.' }
            $owned=@(Get-VMSwitch -ErrorAction Stop | Where-Object {$_.Id -eq $switchId})
            $attached=@(Get-VM -ErrorAction Stop | Get-VMNetworkAdapter -ErrorAction Stop | Where-Object {$_.SwitchId -eq $switchId})
            if($attached.Count){throw 'Unexpected VM attachment before control persistence.'}
            if($owned.Count -gt 1){throw 'Ambiguous pre-control switch identity.'}
            if($owned.Count -eq 1){
                if($owned[0].Name -cne $switchName -or $owned[0].SwitchType.ToString() -cne 'Internal'){throw 'Pre-control switch identity changed.'}
                $owned[0]|Remove-VMSwitch -Force -Confirm:$false -ErrorAction Stop
            }
            if(@(Get-VMSwitch -ErrorAction Stop | Where-Object {$_.Id -eq $switchId}).Count -or
                @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop | Where-Object {$_.SwitchId -eq $switchId}).Count){throw 'Pre-control switch cleanup incomplete.'}
            # No address mutation is allowed until control.json exists.
            Write-LabJson (Join-Path $RunDirectory 'cleanup-created.json') @{status='PASS';switchId=$switchId.ToString();switchName=$switchName;controlNeverCreated=$true;time=[DateTimeOffset]::UtcNow.ToString('o')}
        } elseif (Test-Path -LiteralPath (Join-Path $RunDirectory 'creation-intent.json')) {
            throw 'Creation intent exists without a durable exact switch identity; inspect manually, never delete by name.'
        }
        return @{cleanupVerified=$true;failure=$null}
    } catch {
        $failure='MANUAL_RECOVERY_REQUIRED: '+$_.Exception.Message
        Write-LabJson (Join-Path $RunDirectory 'cleanup-error.json') @{status='MANUAL_RECOVERY_REQUIRED';error=$failure;time=[DateTimeOffset]::UtcNow.ToString('o')}
        return @{cleanupVerified=$false;failure=$failure}
    }
}
