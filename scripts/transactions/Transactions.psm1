#Requires -Version 7.4
Set-StrictMode -Version Latest

function ConvertTo-NetworkCanonicalValue {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $canonical = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -CaseSensitive)) {
            $canonical[$key] = ConvertTo-NetworkCanonicalValue $Value[$key]
        }
        return $canonical
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = [Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            $items.Add((ConvertTo-NetworkCanonicalValue $item))
        }
        return ,$items.ToArray()
    }
    $Value
}

function ConvertTo-NetworkCanonicalJson {
    param([AllowNull()][object]$Object)
    $canonical = ConvertTo-NetworkCanonicalValue $Object
    ConvertTo-Json -InputObject $canonical -Depth 50 -Compress
}

function Copy-NetworkTransactionObject {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Object)
    ConvertFrom-NetworkJson (ConvertTo-Json -InputObject $Object -Depth 50 -Compress)
}

function Get-TransactionTransitionHash {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Transition)
    $event = [ordered]@{
        sequence = [int]$Transition.sequence
        state = [string]$Transition.state
        at = [string]$Transition.at
        reason = [string]$Transition.reason
        journalDataHash = [string]$Transition.journalDataHash
        previousEventHash = if ($null -eq $Transition.previousEventHash) {
            $null
        } else {
            [string]$Transition.previousEventHash
        }
    }
    Get-NetworkHash (ConvertTo-NetworkCanonicalJson $event)
}

function Get-TransactionJournalDataHash {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Journal)
    $data = [ordered]@{}
    foreach ($key in @('hostRef','changeSetId','changeSetHash','owner','targetStableId','beforeStateHash','desiredAfterHash','fencing','validationIds','unrestoredResourceIds','failureReason')) {
        $data[$key] = $Journal[$key]
    }
    Get-NetworkHash (ConvertTo-NetworkCanonicalJson $data)
}

function New-TransactionTransition {
    param(
        [Parameter(Mandatory)][int]$Sequence,
        [Parameter(Mandatory)][string]$State,
        [Parameter(Mandatory)][DateTimeOffset]$At,
        [Parameter(Mandatory)][string]$Reason,
        [AllowNull()][object]$PreviousEventHash,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal
    )
    $transition = [ordered]@{
        sequence = $Sequence
        state = $State
        at = $At.ToUniversalTime().ToString('o')
        reason = $Reason
        journalDataHash = Get-TransactionJournalDataHash $Journal
        previousEventHash = if ($null -eq $PreviousEventHash) {
            $null
        } else {
            [string]$PreviousEventHash
        }
    }
    $transition.eventHash = Get-TransactionTransitionHash $transition
    $transition
}

function Get-NetworkTargetStableId {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$ChangeSet)
    $operations = @($ChangeSet.operations)
    if ($operations.Count -eq 0) {
        throw 'A transaction requires at least one change operation.'
    }
    $ids = @($operations | ForEach-Object { [string]$_.resource.stableId } | Where-Object { $_ } | Sort-Object -Unique)
    if ($ids.Count -eq 0) {
        throw 'Every transaction operation requires a stable resource identity.'
    }
    $ids -join '|'
}

function Assert-NetworkChangeSetOwner {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ChangeSet,
        [Parameter(Mandatory)][string]$Owner
    )
    if ($Owner -notin @('windows','flclash')) {
        throw 'Transaction owner must be a supported known owner.'
    }
    foreach ($operation in @($ChangeSet.operations)) {
        if ([string]$operation.resource.owner -ne $Owner) {
            throw 'ChangeSet resource owner does not match the transaction owner.'
        }
    }
}

function Get-NetworkTransactionBindingHash {
    param(
        [Parameter(Mandatory)][string]$ChangeSetId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$ChangeSetHash,
        [Parameter(Mandatory)][string]$DesiredAfterHash,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Fencing,
        [Parameter(Mandatory)][string]$TargetStableId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$BeforeStateHash,
        [Parameter(Mandatory)][ValidateSet('windows','flclash')][string]$Owner,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][string]$AuthorizationScope,
        [Parameter(Mandatory)][DateTimeOffset]$ApprovedAt,
        [Parameter(Mandatory)][DateTimeOffset]$ExpiresAt
    )
    $binding = [ordered]@{
        changeSetId = $ChangeSetId
        changeSetHash = $ChangeSetHash
        desiredAfterHash = $DesiredAfterHash
        fencing = $Fencing
        targetStableId = $TargetStableId
        beforeStateHash = $BeforeStateHash
        owner = $Owner
        principal = $Principal
        authorizationScope = $AuthorizationScope
        approvedAt = $ApprovedAt.ToUniversalTime().ToString('o')
        expiresAt = $ExpiresAt.ToUniversalTime().ToString('o')
    }
    Get-NetworkHash (ConvertTo-NetworkCanonicalJson $binding)
}

function New-NetworkTransactionJournal {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$ChangeSet,
        [Parameter(Mandatory)][ValidateSet('windows','flclash')][string]$Owner,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow,
        [DateTimeOffset]$FencingExpiresAt,
        [ValidatePattern('^[0-9a-f]{32,64}$')][string]$FencingToken
    )
    Assert-NetworkChangeSetOwner -ChangeSet $ChangeSet -Owner $Owner
    if ([string]$ChangeSet.expectedBeforeHash -notmatch '^[0-9a-f]{64}$') {
        throw 'ChangeSet expectedBeforeHash must be a lowercase SHA-256 digest.'
    }
    if ($FencingExpiresAt -eq [DateTimeOffset]::MinValue) {
        $FencingExpiresAt = $Now.AddMinutes(30)
    }
    if ($FencingExpiresAt -le $Now) {
        throw 'Fencing lease must expire after issuance.'
    }
    if (-not $FencingToken) {
        $FencingToken = [Convert]::ToHexString(
            [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
        ).ToLowerInvariant()
    }
    $targetStableId = Get-NetworkTargetStableId $ChangeSet
    $context = @{
        hostRef = [string]$ChangeSet.hostRef
        principalRef = $Owner
        synthetic = $false
    }
    $journal = New-NetworkObject -Type TransactionJournal -Context $context -EvidenceIds @($ChangeSet.evidenceIds)
    $journal.changeSetId = [string]$ChangeSet.id
    $journal.changeSetHash = Get-NetworkHash (ConvertTo-NetworkCanonicalJson $ChangeSet)
    $journal.owner = $Owner
    $journal.targetStableId = $targetStableId
    $journal.beforeStateHash = [string]$ChangeSet.expectedBeforeHash
    $journal.desiredAfterHash = Get-NetworkHash (ConvertTo-NetworkCanonicalJson $ChangeSet.desiredAfter)
    $journal.state = 'PLANNED'
    $journal.approval = $null
    $journal.fencing = [ordered]@{
        token = $FencingToken
        issuedAt = $Now.ToUniversalTime().ToString('o')
        expiresAt = $FencingExpiresAt.ToUniversalTime().ToString('o')
    }
    $journal.validationIds = @()
    $journal.unrestoredResourceIds = @()
    $journal.failureReason = $null
    $journal.updatedAt = $Now.ToUniversalTime().ToString('o')
    $journal.transitions = @(
        New-TransactionTransition `
            -Sequence 1 `
            -State 'PLANNED' `
            -At $Now `
            -Reason 'Journal created; no network mutation authorized.' `
            -PreviousEventHash $null `
            -Journal $journal
    )
    $journal.updatedAt = [string]$journal.transitions[0].at
    $journal
}

function Assert-NetworkTransactionApproval {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal,
        [System.Collections.IDictionary]$ChangeSet,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow,
        [switch]$RequireActive
    )
    if ($null -eq $Journal.approval) {
        throw 'Transaction journal has no approval binding.'
    }
    if ($Journal.owner -notin @('windows','flclash')) {
        throw 'Transaction approval owner is unknown.'
    }
    if ($ChangeSet) {
        Assert-NetworkChangeSetOwner -ChangeSet $ChangeSet -Owner ([string]$Journal.owner)
        $targetStableId = Get-NetworkTargetStableId $ChangeSet
        if ([string]$ChangeSet.id -ne [string]$Journal.changeSetId) {
            throw 'ChangeSet identity changed after approval.'
        }
        if ([string]$ChangeSet.hostRef -ne [string]$Journal.hostRef) {
            throw 'ChangeSet host identity changed after approval.'
        }
        if ($targetStableId -ne [string]$Journal.targetStableId) {
            throw 'ChangeSet target changed after approval.'
        }
        if ([string]$ChangeSet.expectedBeforeHash -ne [string]$Journal.beforeStateHash) {
            throw 'ChangeSet before-state hash changed after approval.'
        }
        if ((Get-NetworkHash (ConvertTo-NetworkCanonicalJson $ChangeSet.desiredAfter)) -cne [string]$Journal.desiredAfterHash) {
            throw 'ChangeSet desired-state hash changed after approval.'
        }
        $changeSetHash = Get-NetworkHash (ConvertTo-NetworkCanonicalJson $ChangeSet)
        if ($changeSetHash -ne [string]$Journal.changeSetHash) {
            throw 'ChangeSet content changed after approval.'
        }
    }
    $expectedHash = Get-NetworkTransactionBindingHash `
        -ChangeSetId ([string]$Journal.changeSetId) `
        -ChangeSetHash ([string]$Journal.changeSetHash) `
        -DesiredAfterHash ([string]$Journal.desiredAfterHash) `
        -Fencing $Journal.fencing `
        -TargetStableId ([string]$Journal.targetStableId) `
        -BeforeStateHash ([string]$Journal.beforeStateHash) `
        -Owner ([string]$Journal.owner) `
        -Principal ([string]$Journal.approval.principal) `
        -AuthorizationScope ([string]$Journal.approval.scope) `
        -ApprovedAt ([DateTimeOffset]::Parse([string]$Journal.approval.approvedAt)) `
        -ExpiresAt ([DateTimeOffset]::Parse([string]$Journal.approval.expiresAt))
    if ($expectedHash -ne [string]$Journal.approval.bindingHash) {
        throw 'Transaction approval binding no longer matches the journal.'
    }
    $approvedAt = [DateTimeOffset]::Parse([string]$Journal.approval.approvedAt)
    $expiresAt = [DateTimeOffset]::Parse([string]$Journal.approval.expiresAt)
    if ($approvedAt -ge $expiresAt) {
        throw 'Transaction approval validity interval is invalid.'
    }
    if ($approvedAt -lt [DateTimeOffset]::Parse([string]$Journal.fencing.issuedAt)) {
        throw 'Transaction approval predates its fencing lease.'
    }
    if ($expiresAt -gt [DateTimeOffset]::Parse([string]$Journal.fencing.expiresAt)) {
        throw 'Transaction approval outlives its fencing lease.'
    }
    if ($RequireActive) {
        if ($Now -ge $expiresAt) {
            throw 'Transaction approval has expired.'
        }
        if ($Now -ge [DateTimeOffset]::Parse([string]$Journal.fencing.expiresAt)) {
            throw 'Transaction fencing lease has expired.'
        }
    }
}

function Approve-NetworkTransactionJournal {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal,
        [Parameter(Mandatory)][System.Collections.IDictionary]$ChangeSet,
        [Parameter(Mandatory)][string]$AuthorizationScope,
        [Parameter(Mandatory)][string]$Principal,
        [Parameter(Mandatory)][DateTimeOffset]$ExpiresAt,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow
    )
    Assert-NetworkTransactionJournalIntegrity -Journal $Journal | Out-Null
    if ([string]$Journal.state -ne 'PLANNED') {
        throw 'Only a PLANNED journal can receive initial approval.'
    }
    if ($null -ne $Journal.approval) {
        throw 'Transaction approval cannot be reused or replaced.'
    }
    if ([string]::IsNullOrWhiteSpace($AuthorizationScope) -or [string]::IsNullOrWhiteSpace($Principal)) {
        throw 'Authorization scope and principal are required.'
    }
    if ($ExpiresAt -le $Now) {
        throw 'Approval expiry must be in the future.'
    }
    if ($ExpiresAt -gt [DateTimeOffset]::Parse([string]$Journal.fencing.expiresAt)) {
        throw 'Approval cannot outlive the fencing lease.'
    }
    $copy = Copy-NetworkTransactionObject $Journal
    $copy.approval = [ordered]@{
        scope = $AuthorizationScope
        principal = $Principal
        approvedAt = $Now.ToUniversalTime().ToString('o')
        expiresAt = $ExpiresAt.ToUniversalTime().ToString('o')
        bindingHash = Get-NetworkTransactionBindingHash `
            -ChangeSetId ([string]$copy.changeSetId) `
            -ChangeSetHash ([string]$copy.changeSetHash) `
            -DesiredAfterHash ([string]$copy.desiredAfterHash) `
            -Fencing $copy.fencing `
            -TargetStableId ([string]$copy.targetStableId) `
            -BeforeStateHash ([string]$copy.beforeStateHash) `
            -Owner ([string]$copy.owner) `
            -Principal $Principal `
            -AuthorizationScope $AuthorizationScope `
            -ApprovedAt $Now `
            -ExpiresAt $ExpiresAt
    }
    Assert-NetworkTransactionApproval -Journal $copy -ChangeSet $ChangeSet -Now $Now -RequireActive
    Move-NetworkTransactionJournal -Journal $copy -NextState 'APPROVED' -Now $Now -Reason 'Exact ChangeSet, target, before-state, scope and expiry were approved.'
}

function Assert-NetworkTransactionJournalIntegrity {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal,
        [System.Collections.IDictionary]$ChangeSet
    )
    if ($Journal.owner -notin @('windows','flclash')) {
        throw 'Transaction journal owner is unknown.'
    }
    if ([string]$Journal.changeSetHash -notmatch '^[0-9a-f]{64}$') {
        throw 'Transaction journal ChangeSet hash is invalid.'
    }
    $allowed = @{
        PLANNED = @('APPROVED')
        APPROVED = @('APPLYING')
        APPLYING = @('VALIDATING','ROLLING_BACK','MANUAL_RECOVERY_REQUIRED')
        VALIDATING = @('COMMITTED','FAILED_VALIDATION','MANUAL_RECOVERY_REQUIRED')
        FAILED_VALIDATION = @('ROLLING_BACK','MANUAL_RECOVERY_REQUIRED')
        ROLLING_BACK = @('ROLLED_BACK','ROLLBACK_FAILED','MANUAL_RECOVERY_REQUIRED')
        COMMITTED = @()
        ROLLED_BACK = @()
        ROLLBACK_FAILED = @()
        MANUAL_RECOVERY_REQUIRED = @()
    }
    $transitions = @($Journal.transitions)
    if ($transitions.Count -eq 0 -or [string]$transitions[0].state -ne 'PLANNED') {
        throw 'Transaction journal must start with PLANNED.'
    }
    $previousTime = [DateTimeOffset]::MinValue
    for ($index = 0; $index -lt $transitions.Count; $index++) {
        $transition = $transitions[$index]
        if ([int]$transition.sequence -ne $index + 1) {
            throw 'Transaction journal transition sequence is not contiguous.'
        }
        $time = [DateTimeOffset]::Parse([string]$transition.at)
        if ($time -lt $previousTime) {
            throw 'Transaction journal transition time moved backwards.'
        }
        $previousTime = $time
        if ($index -gt 0) {
            $from = [string]$transitions[$index - 1].state
            $to = [string]$transition.state
            if (-not $allowed.ContainsKey($from) -or $to -notin @($allowed[$from])) {
                throw "Illegal journal history transition: $from -> $to."
            }
        }
        $expectedPreviousHash = if ($index -eq 0) {
            $null
        } else {
            [string]$transitions[$index - 1].eventHash
        }
        if (
            ($null -eq $expectedPreviousHash -and $null -ne $transition.previousEventHash) -or
            ($null -ne $expectedPreviousHash -and
                [string]$transition.previousEventHash -cne $expectedPreviousHash)
        ) {
            throw 'Transaction journal transition hash chain is broken.'
        }
        if (
            [string]$transition.previousEventHash -and
            [string]$transition.previousEventHash -notmatch '^[0-9a-f]{64}$'
        ) {
            throw 'Transaction journal previous event hash is invalid.'
        }
        if ([string]$transition.eventHash -notmatch '^[0-9a-f]{64}$') {
            throw 'Transaction journal event hash is invalid.'
        }
        if ((Get-TransactionTransitionHash $transition) -cne [string]$transition.eventHash) {
            throw 'Transaction journal transition content changed.'
        }
    }
    $last = $transitions[$transitions.Count - 1]
    if ((Get-TransactionJournalDataHash $Journal) -cne [string]$last.journalDataHash) {
        throw 'Transaction journal decision data changed after its final transition.'
    }
    if ([string]$last.state -ne [string]$Journal.state) {
        throw 'Transaction journal state does not match its final transition.'
    }
    if ([DateTimeOffset]::Parse([string]$Journal.updatedAt) -ne [DateTimeOffset]::Parse([string]$last.at)) {
        throw 'Transaction journal updatedAt does not match its final transition.'
    }
    if ([string]$Journal.state -eq 'PLANNED') {
        if ($null -ne $Journal.approval -or $transitions.Count -ne 1) {
            throw 'PLANNED journal cannot contain approval or later transitions.'
        }
    } else {
        if ($null -eq $Journal.approval -or $transitions.Count -lt 2 -or [string]$transitions[1].state -ne 'APPROVED') {
            throw 'Non-planned journal lacks initial approval transition.'
        }
        Assert-NetworkTransactionApproval -Journal $Journal -ChangeSet $ChangeSet
    }
    if ([string]$Journal.state -eq 'COMMITTED' -and (@($Journal.validationIds).Count -eq 0 -or @($Journal.unrestoredResourceIds).Count -ne 0)) {
        throw 'COMMITTED journal requires validation evidence.'
    }
    if ([string]$Journal.state -eq 'ROLLED_BACK') {
        if (@($Journal.validationIds).Count -eq 0 -or @($Journal.unrestoredResourceIds).Count -ne 0) {
            throw 'ROLLED_BACK journal lacks clean validation evidence.'
        }
    }
    if ([string]$Journal.state -eq 'ROLLBACK_FAILED' -and @($Journal.unrestoredResourceIds).Count -eq 0) {
        throw 'ROLLBACK_FAILED journal lacks unrestored resources.'
    }
    $true
}

function Move-NetworkTransactionJournal {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal,
        [Parameter(Mandatory)][ValidateSet('APPROVED','APPLYING','VALIDATING','COMMITTED','FAILED_VALIDATION','ROLLING_BACK','ROLLED_BACK','ROLLBACK_FAILED','MANUAL_RECOVERY_REQUIRED')][string]$NextState,
        [DateTimeOffset]$Now = [DateTimeOffset]::UtcNow,
        [string]$Reason,
        [string[]]$ValidationIds = @(),
        [string[]]$UnrestoredResourceIds = @()
    )
    $allowed = @{
        PLANNED = @('APPROVED')
        APPROVED = @('APPLYING')
        APPLYING = @('VALIDATING','ROLLING_BACK','MANUAL_RECOVERY_REQUIRED')
        VALIDATING = @('COMMITTED','FAILED_VALIDATION','MANUAL_RECOVERY_REQUIRED')
        FAILED_VALIDATION = @('ROLLING_BACK','MANUAL_RECOVERY_REQUIRED')
        ROLLING_BACK = @('ROLLED_BACK','ROLLBACK_FAILED','MANUAL_RECOVERY_REQUIRED')
        COMMITTED = @()
        ROLLED_BACK = @()
        ROLLBACK_FAILED = @()
        MANUAL_RECOVERY_REQUIRED = @()
    }
    $lastAt = [DateTimeOffset]::Parse([string]$Journal.transitions[-1].at)
    if ($Now -lt $lastAt) { throw 'Transaction transition time cannot move backwards.' }
    $current = [string]$Journal.state
    if (-not $allowed.ContainsKey($current) -or $NextState -notin @($allowed[$current])) {
        throw "Illegal transaction transition: $current -> $NextState."
    }
    if ($current -eq 'PLANNED') {
        if ($NextState -eq 'APPROVED') {
            if ($null -eq $Journal.approval) {
                throw 'APPROVED transition requires an approval binding.'
            }
            Assert-NetworkTransactionApproval -Journal $Journal -Now $Now
        }
    } else {
        Assert-NetworkTransactionJournalIntegrity -Journal $Journal | Out-Null
    }
    if ($NextState -eq 'APPLYING') {
        Assert-NetworkTransactionApproval -Journal $Journal -Now $Now -RequireActive
    } elseif ($current -ne 'PLANNED') {
        Assert-NetworkTransactionApproval -Journal $Journal -Now $Now
    }
    $copy = Copy-NetworkTransactionObject $Journal
    $copy.validationIds = @(@($copy.validationIds) + @($ValidationIds) | Where-Object { $_ } | Sort-Object -Unique)
    $copy.unrestoredResourceIds = @(
        @($copy.unrestoredResourceIds) + @($UnrestoredResourceIds) |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
    if ($NextState -eq 'COMMITTED' -and ($copy.validationIds.Count -eq 0 -or $copy.unrestoredResourceIds.Count -ne 0)) {
        throw 'COMMITTED requires at least one validation ID.'
    }
    if ($NextState -eq 'ROLLED_BACK') {
        if ($copy.validationIds.Count -eq 0) {
            throw 'ROLLED_BACK requires at least one post-restore validation ID.'
        }
        if ($copy.unrestoredResourceIds.Count -ne 0) {
            throw 'ROLLED_BACK cannot retain unrestored resources.'
        }
    }
    if ($NextState -eq 'ROLLBACK_FAILED' -and $copy.unrestoredResourceIds.Count -eq 0) {
        throw 'ROLLBACK_FAILED requires at least one unrestored resource.'
    }
    $copy.state = $NextState
    $copy.updatedAt = $Now.ToUniversalTime().ToString('o')
    $copy.failureReason = if ([string]::IsNullOrWhiteSpace($Reason) -and $NextState -in @(
        'FAILED_VALIDATION','ROLLBACK_FAILED','MANUAL_RECOVERY_REQUIRED'
    )) {
        'Manual review required; no success was inferred.'
    } elseif ($NextState -in @('FAILED_VALIDATION','ROLLBACK_FAILED','MANUAL_RECOVERY_REQUIRED')) {
        $Reason
    } else {
        $null
    }
    $existingTransitions = @($copy.transitions)
    $previousEventHash = if ($existingTransitions.Count -eq 0) {
        $null
    } else {
        [string]$existingTransitions[$existingTransitions.Count - 1].eventHash
    }
    $copy.transitions = @(
        $existingTransitions +
        @(
            New-TransactionTransition `
                -Sequence ($existingTransitions.Count + 1) `
                -State $NextState `
                -At $Now `
                -Reason $(if ([string]::IsNullOrWhiteSpace($Reason)) {
                    "Transition to $NextState."
                } else {
                    $Reason
                }) `
                -PreviousEventHash $previousEventHash `
                -Journal $copy
        )
    )
    $copy
}

function Get-NetworkRecoveryDecision {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{64}$')][string]$CurrentStateHash,
        [ValidatePattern('^[0-9a-f]{64}$')][string]$DesiredStateHash
    )
    Assert-NetworkTransactionJournalIntegrity -Journal $Journal | Out-Null
    if ($DesiredStateHash -and $DesiredStateHash -cne [string]$Journal.desiredAfterHash) { throw 'Recovery desired hash must match the journal binding.' }
    $state = [string]$Journal.state
    $beforeMatch = $CurrentStateHash -eq [string]$Journal.beforeStateHash
    $effectiveDesiredHash = if ($DesiredStateHash) { $DesiredStateHash } else { [string]$Journal.desiredAfterHash }
    $desiredMatch = $CurrentStateHash -eq $effectiveDesiredHash
    $decision = switch ($state) {
        'PLANNED' {
            if ($beforeMatch) { 'NOT_STARTED_NO_MUTATION' } else { 'PRESTART_DRIFT_REPLAN' }
        }
        'APPROVED' {
            if ($beforeMatch) { 'APPROVED_NOT_STARTED' } else { 'PREAPPLY_DRIFT_REPLAN' }
        }
        'APPLYING' {
            if ($desiredMatch) {
                'APPLIED_AWAITING_INDEPENDENT_VALIDATION'
            } elseif ($beforeMatch) {
                'APPLY_NOT_OBSERVED_REOBSERVE'
            } else {
                'PARTIAL_OR_DRIFT_MANUAL_REVIEW'
            }
        }
        'VALIDATING' {
            if ($desiredMatch) { 'VALIDATION_INTERRUPTED_REOBSERVE' } else { 'POST_APPLY_DRIFT_OR_PARTIAL' }
        }
        'COMMITTED' {
            if ($desiredMatch) { 'COMPLETE_NO_WRITE' } else { 'POST_COMMIT_DRIFT' }
        }
        'FAILED_VALIDATION' { 'ROLLBACK_ELIGIBLE_AFTER_INDEPENDENT_READ' }
        'ROLLING_BACK' { 'ROLLBACK_INTERRUPTED_REOBSERVE' }
        'ROLLED_BACK' {
            if ($beforeMatch) { 'ROLLBACK_OBSERVED' } else { 'POST_ROLLBACK_DRIFT' }
        }
        default { 'MANUAL_RECOVERY_REQUIRED' }
    }
    [ordered]@{
        schemaVersion = '1.0.0'
        journalId = [string]$Journal.id
        state = $state
        currentStateHash = $CurrentStateHash
        beforeStateHash = [string]$Journal.beforeStateHash
        desiredStateHash = $effectiveDesiredHash
        beforeMatch = $beforeMatch
        desiredMatch = [bool]$desiredMatch
        decision = $decision
        safeToReplay = $false
        automaticWriteAllowed = $false
        requiresIndependentRead = $true
        requiresManualReview = $decision -match 'DRIFT|PARTIAL|MANUAL|REOBSERVE|INTERRUPTED'
    }
}

function New-NetworkRollbackResult {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Journal,
        [Parameter(Mandatory)][string]$SnapshotId,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Feasibility,
        [string[]]$AttemptedOperations = @(),
        [object[]]$RestoredResources = @(),
        [object[]]$UnrestoredResources = @(),
        [string[]]$ValidationIds = @(),
        [Parameter(Mandatory)][ValidateSet('ROLLED_BACK','ROLLBACK_FAILED','MANUAL_RECOVERY_REQUIRED')][string]$FinalState,
        [string[]]$ManualSteps = @(),
        [string[]]$EvidenceIds = @()
    )
    if ($FinalState -eq 'ROLLED_BACK' -and $ValidationIds.Count -eq 0) {
        throw 'ROLLED_BACK requires a post-restore validation ID.'
    }
    if ($FinalState -eq 'ROLLED_BACK' -and $UnrestoredResources.Count -ne 0) {
        throw 'ROLLED_BACK cannot retain unrestored resources.'
    }
    if ($FinalState -eq 'ROLLBACK_FAILED' -and $UnrestoredResources.Count -eq 0) {
        throw 'ROLLBACK_FAILED requires explicit unrestored resources.'
    }
    if ($FinalState -eq 'MANUAL_RECOVERY_REQUIRED' -and @($ManualSteps | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -eq 0) {
        throw 'MANUAL_RECOVERY_REQUIRED requires actionable manual steps.'
    }
    $context = @{
        hostRef = [string]$Journal.hostRef
        principalRef = [string]$Journal.owner
        synthetic = $false
    }
    $result = New-NetworkObject -Type RollbackResult -Context $context -EvidenceIds $EvidenceIds
    $result.changeId = [string]$Journal.changeSetId
    $result.snapshotId = $SnapshotId
    $result.feasibility = $Feasibility
    $result.attemptedOperations = @($AttemptedOperations)
    $result.restoredResources = @($RestoredResources)
    $result.unrestoredResources = @($UnrestoredResources)
    $result.validationIds = @($ValidationIds)
    $result.finalState = $FinalState
    $result.manualSteps = @($ManualSteps)
    if (-not (Test-Json -Json (ConvertTo-Json -InputObject $result -Depth 50 -Compress) `
        -SchemaFile (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'schemas/RollbackResult.schema.json') `
        -ErrorAction SilentlyContinue)) {
        throw 'Invalid RollbackResult contract.'
    }
    $result
}

Export-ModuleMember -Function @(
    'Approve-NetworkTransactionJournal',
    'Assert-NetworkTransactionApproval',
    'Assert-NetworkTransactionJournalIntegrity',
    'ConvertTo-NetworkCanonicalJson',
    'Get-NetworkRecoveryDecision',
    'Move-NetworkTransactionJournal',
    'New-NetworkRollbackResult',
    'New-NetworkTransactionJournal'
)
