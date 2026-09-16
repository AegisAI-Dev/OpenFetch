<#
.SYNOPSIS
Creates the OpenFetch activation manifest for a separately installed PO Token
helper package.

.DESCRIPTION
OpenFetch never bundles the PO Token provider. A user installs the helper
package in a directory of their choice and activates it with a manifest at

    %LOCALAPPDATA%\OpenFetch\optional-po-provider\active.json

This tool records every file in the package (path, size, SHA-256) plus the
aggregate package hash, in exactly the format that
src/openfetch/core/pot_provider.py verifies before every helper launch. Any
later change to the package - an added, removed or modified file - makes
OpenFetch refuse to start the helper until the manifest is generated again.

This tool does NOT establish publisher authenticity: it hashes whatever is on
disk. Obtain the helper package from a source you trust and inspect it before
activating it.

The helper identifiers written below are a fixed protocol contract with the
helper package. They intentionally keep their Neural Extractor-era values; the
test suite asserts they stay identical to the values OpenFetch enforces.

.PARAMETER PackageRoot
Directory containing node.exe and helper.mjs. It must be outside the OpenFetch
application directory (OpenFetch rejects a helper inside its own install).

.PARAMETER OutputPath
Manifest to write. Defaults to the location OpenFetch reads.

.PARAMETER Force
Replace an existing manifest.

.EXAMPLE
powershell -NoProfile -ExecutionPolicy Bypass -File New-OpenFetchPoHelperActivation.ps1 -PackageRoot "D:\Tools\OpenFetch PO Helper 1.3.1"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,

    [string]$OutputPath,

    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Protocol contract, pinned to src/openfetch/core/pot_provider.py.
$SchemaVersion = 1
$HelperId = 'org.neuralshield.neural-extractor.po-helper'
$HelperVersion = '1.0.0'
$ProviderVersion = '1.3.1'
$ProtocolVersion = 1
$Entrypoint = 'node.exe'
$EntryModule = 'helper.mjs'
$MaxPackageFiles = 20000
$MaxPackageEntries = 40000
$MaxPackageBytes = 4GB
$VolatileDirectoryNames = @('__pycache__', '.ruff_cache', '.pytest_cache', '.mypy_cache')

# --- Package root ------------------------------------------------------------
if (-not (Test-Path -LiteralPath $PackageRoot -PathType Container)) {
    throw "Package root is not an existing directory: $PackageRoot"
}
$rootItem = Get-Item -LiteralPath $PackageRoot -Force
if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'The package root cannot be a reparse point.'
}
$resolvedRoot = $rootItem.FullName.TrimEnd('\')
if ([IO.Path]::GetPathRoot($rootItem.FullName).TrimEnd('\') -eq $resolvedRoot) {
    throw 'The package root cannot be a drive root.'
}

foreach ($required in @($Entrypoint, $EntryModule)) {
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedRoot $required) -PathType Leaf)) {
        throw "The package root does not contain $required. Point -PackageRoot at the helper package directory."
    }
}

# Refuse to activate a package whose helper does not implement this contract.
$helperSource = [IO.File]::ReadAllText((Join-Path $resolvedRoot $EntryModule))
$expectedDeclarations = @(
    ('const HELPER_ID = "{0}";' -f $HelperId),
    ('const HELPER_VERSION = "{0}";' -f $HelperVersion),
    ('const PROVIDER_VERSION = "{0}";' -f $ProviderVersion),
    ('const PROTOCOL_VERSION = {0};' -f $ProtocolVersion)
)
foreach ($declaration in $expectedDeclarations) {
    $pattern = '(?m)^' + [regex]::Escape($declaration) + '\r?$'
    if (-not [regex]::IsMatch($helperSource, $pattern)) {
        throw "$EntryModule does not declare the supported helper contract: $declaration"
    }
}

# --- Output path -------------------------------------------------------------
if (-not $OutputPath) {
    if (-not $env:LOCALAPPDATA) {
        throw 'LOCALAPPDATA is not set; pass -OutputPath explicitly.'
    }
    $OutputPath = Join-Path $env:LOCALAPPDATA 'OpenFetch\optional-po-provider\active.json'
}
$outputFull = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ($outputFull.StartsWith($resolvedRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The activation manifest must be written outside the package root.'
}
if (Test-Path -LiteralPath $outputFull) {
    $existing = Get-Item -LiteralPath $outputFull -Force
    if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "The output path is not a regular file: $outputFull"
    }
    if (-not $Force) {
        throw "An activation manifest already exists: $outputFull (use -Force to replace it)"
    }
}

# --- Enumerate and hash ------------------------------------------------------
$items = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -Force)
if ($items.Count -gt $MaxPackageEntries) {
    throw 'Package entry-count limit violated.'
}
foreach ($item in $items) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Reparse point rejected: $($item.FullName)"
    }
}
$files = @($items | Where-Object { -not $_.PSIsContainer })
if ($files.Count -eq 0 -or $files.Count -gt $MaxPackageFiles) {
    throw 'Package file-count limit violated.'
}

$records = [Collections.Generic.List[object]]::new()
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$volatile = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[Int64]$totalBytes = 0
foreach ($file in $files) {
    $relative = $file.FullName.Substring($resolvedRoot.Length + 1).Replace('\', '/')
    if ($relative.Length -eq 0 -or $relative.Length -gt 4096) {
        throw 'Invalid relative package path.'
    }
    foreach ($character in $relative.ToCharArray()) {
        if ([int]$character -lt 0x20 -or [int]$character -gt 0x7e) {
            throw "Only ASCII package paths are supported: $relative"
        }
    }
    if (-not $seen.Add($relative)) {
        throw "Case-folded path collision: $relative"
    }
    $parts = $relative.Split('/')
    for ($index = 0; $index -lt $parts.Length - 1; $index++) {
        if ($VolatileDirectoryNames -contains $parts[$index]) {
            [void]$volatile.Add(($parts[0..$index] -join '/'))
        }
    }
    $totalBytes += $file.Length
    if ($totalBytes -gt $MaxPackageBytes) {
        throw 'Package byte-size limit violated.'
    }
    $records.Add([ordered]@{
        path = $relative
        size = [Int64]$file.Length
        sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}

# Same order and digest framing as the OpenFetch verifier:
# sorted case-insensitively; UTF8(path) NUL ASCII(size) NUL ASCII(sha256) LF.
$records.Sort([Comparison[object]]{
    param($left, $right)
    [StringComparer]::Ordinal.Compare(
        ([string]$left.path).ToLowerInvariant(),
        ([string]$right.path).ToLowerInvariant()
    )
})
$digest = [Security.Cryptography.IncrementalHash]::CreateHash(
    [Security.Cryptography.HashAlgorithmName]::SHA256
)
$utf8 = [Text.UTF8Encoding]::new($false)
$ascii = [Text.Encoding]::ASCII
foreach ($record in $records) {
    $digest.AppendData($utf8.GetBytes([string]$record.path))
    $digest.AppendData([byte[]](0))
    $digest.AppendData($ascii.GetBytes([string]$record.size))
    $digest.AppendData([byte[]](0))
    $digest.AppendData($ascii.GetBytes([string]$record.sha256))
    $digest.AppendData([byte[]](10))
}
$packageSha256 = [BitConverter]::ToString($digest.GetHashAndReset()).Replace('-', '').ToLowerInvariant()
$digest.Dispose()

$manifest = [ordered]@{
    schema_version = $SchemaVersion
    helper_id = $HelperId
    helper_version = $HelperVersion
    provider_version = $ProviderVersion
    protocol_version = $ProtocolVersion
    package_root = $resolvedRoot
    entrypoint = $Entrypoint
    arguments = @($EntryModule)
    package_sha256 = $packageSha256
    files = $records
}
$json = ($manifest | ConvertTo-Json -Depth 6 -Compress) + "`n"

# --- Write atomically --------------------------------------------------------
$outputDirectory = Split-Path -Parent $outputFull
[void](New-Item -ItemType Directory -Path $outputDirectory -Force)
$temporary = Join-Path $outputDirectory ('.active-' + [Guid]::NewGuid().ToString('N') + '.tmp')
try {
    [IO.File]::WriteAllText($temporary, $json, $utf8)
    if (Test-Path -LiteralPath $outputFull) {
        [IO.File]::Replace($temporary, $outputFull, [NullString]::Value)
    } else {
        [IO.File]::Move($temporary, $outputFull)
    }
} finally {
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force
    }
}

foreach ($directory in $volatile) {
    Write-Warning "The package contains a regenerable cache directory ($directory). If it changes, OpenFetch will refuse the helper until this tool is run again."
}

[ordered]@{
    output = $outputFull
    package_root = $resolvedRoot
    files = $records.Count
    bytes = $totalBytes
    package_sha256 = $packageSha256
} | ConvertTo-Json -Compress
