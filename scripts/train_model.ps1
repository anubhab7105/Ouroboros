<#
.SYNOPSIS
    Train a model on a generated dataset and print its evaluation.

.DESCRIPTION
    Generates a dataset with labels, trains, evaluates, and prints the metric
    set together with what the metrics do not mean.

    Read that last part. The generator plants the typologies the rules look
    for, so a score from this pipeline measures agreement between the generator
    and the model. It is a real check that training works end to end and no
    evidence at all about detection quality on a real portfolio.
    docs/model-card.md is blunter about it.

.EXAMPLE
    ./scripts/train_model.ps1
    ./scripts/train_model.ps1 -Accounts 2000 -Split temporal
#>
[CmdletBinding()]
param(
    [int]$Accounts = 1000,
    [ValidateSet('grouped', 'temporal', 'random')][string]$Split = 'grouped',
    [int]$Seed = 42,
    [string]$Out = ''
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if ($Split -eq 'random') {
    Write-Warning 'A random split puts four accounts of a five-account ring in training and the fifth in test. The score it reports is how well the model memorised that ring.'
    Write-Host ''
}

if (-not $Out) { $Out = "data/generated/train-seed$Seed" }

Write-Host 'generating a labelled dataset'
python scripts/generate_data.py `
    --accounts $Accounts `
    --transactions ($Accounts * 40) `
    --complaints ([int]($Accounts / 4)) `
    --seed $Seed `
    --with-labels `
    --out $Out
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host ''
Write-Host "training and evaluating ($Split split)"
python scripts/evaluate_model.py --dataset $Out --split $Split --seed $Seed
$evaluated = $LASTEXITCODE

Write-Host ''
Write-Host "dataset kept at $Out. It is reproducible from -Seed $Seed, so delete"
Write-Host 'it rather than committing it.'

exit $evaluated
