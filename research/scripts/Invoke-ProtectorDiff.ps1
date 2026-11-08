<#
.SYNOPSIS
Collects reproducible, non-destructive static and runtime measurements for a
baseline PE and one or more protected variants.

.DESCRIPTION
The input artifacts are never executed in place. Each runtime sample is made
from a fresh copy under an owned temporary directory. The script verifies the
original SHA-256 values again before it exits.

Outputs:
  report.json
  artifacts.csv
  pe_sections.csv
  pe_directories.csv
  string_hits.csv
  runtime_runs.csv

.EXAMPLE
pwsh -File .\Invoke-ProtectorDiff.ps1 `
  -Baseline ..\inputs\helloO2.exe `
  -Artifact ..\outputs\vmp-mixed.exe `
  -StringNeedle hello `
  -Iterations 31 -Warmup 5 `
  -OutputDirectory ..\evidence\hello-comparison

.EXAMPLE
# Fast smoke test.
pwsh -File .\Invoke-ProtectorDiff.ps1 `
  -Baseline ..\inputs\helloO2.exe `
  -Artifact ..\outputs\novapack-hello.exe `
  -StringNeedle hello `
  -Iterations 2 -Warmup 1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$Baseline,

    [Parameter(Mandatory = $true)]
    [Alias('Artifacts')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string[]]$Artifact,

    [string[]]$StringNeedle = @(),

    [ValidateRange(1, 10000)]
    [int]$Iterations = 31,

    [ValidateRange(0, 1000)]
    [int]$Warmup = 5,

    [ValidateRange(100, 600000)]
    [int]$TimeoutMs = 10000,

    [string[]]$RunArgument = @(),

    [string[]]$RuntimeDependency = @(),

    [ValidateSet('Exact', 'ExitCode', 'Disabled')]
    [string]$SemanticMode = 'Exact',

    [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\evidence\protector-diff'),

    [switch]$SkipRuntime,

    [switch]$KeepRunDirectories
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:DirectoryNames = @(
    'EXPORT', 'IMPORT', 'RESOURCE', 'EXCEPTION', 'SECURITY', 'BASERELOC',
    'DEBUG', 'ARCHITECTURE', 'GLOBALPTR', 'TLS', 'LOADCFG', 'BOUNDIMPORT',
    'IAT', 'DELAYIMPORT', 'CLR', 'RESERVED'
)
$script:Pe64OrdinalMask = [uint64]::Parse('8000000000000000', [System.Globalization.NumberStyles]::HexNumber)

function Get-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path)
}

function Get-Sha256HexFromBytes {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-Sha256HexFromRange {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][long]$Length
    )
    if ($Length -eq 0) {
        return Get-Sha256HexFromBytes -Bytes ([byte[]]@())
    }
    $stream = [System.IO.MemoryStream]::new($Bytes, [int]$Offset, [int]$Length, $false, $true)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-ByteRange {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][long]$Offset,
        [Parameter(Mandatory = $true)][long]$Length,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ($Offset -lt 0 -or $Length -lt 0 -or $Offset -gt $Bytes.LongLength -or $Length -gt ($Bytes.LongLength - $Offset)) {
        throw "$Label is outside the file (offset=$Offset length=$Length file=$($Bytes.LongLength))."
    }
}

function Read-U16 {
    param([byte[]]$Bytes, [long]$Offset, [string]$Label = 'UInt16')
    Assert-ByteRange -Bytes $Bytes -Offset $Offset -Length 2 -Label $Label
    return [System.BitConverter]::ToUInt16($Bytes, [int]$Offset)
}

function Read-U32 {
    param([byte[]]$Bytes, [long]$Offset, [string]$Label = 'UInt32')
    Assert-ByteRange -Bytes $Bytes -Offset $Offset -Length 4 -Label $Label
    return [System.BitConverter]::ToUInt32($Bytes, [int]$Offset)
}

function Read-U64 {
    param([byte[]]$Bytes, [long]$Offset, [string]$Label = 'UInt64')
    Assert-ByteRange -Bytes $Bytes -Offset $Offset -Length 8 -Label $Label
    return [System.BitConverter]::ToUInt64($Bytes, [int]$Offset)
}

function Read-AsciiZ {
    param(
        [byte[]]$Bytes,
        [long]$Offset,
        [int]$MaximumLength = 4096
    )
    if ($Offset -lt 0 -or $Offset -ge $Bytes.LongLength) {
        return $null
    }
    $end = $Offset
    $limit = [Math]::Min($Bytes.LongLength, $Offset + $MaximumLength)
    while ($end -lt $limit -and $Bytes[$end] -ne 0) {
        $end++
    }
    return [System.Text.Encoding]::ASCII.GetString($Bytes, [int]$Offset, [int]($end - $Offset))
}

function Get-Entropy {
    param(
        [byte[]]$Bytes,
        [long]$Offset,
        [long]$Length
    )
    if ($Length -le 0) {
        return $null
    }
    Assert-ByteRange -Bytes $Bytes -Offset $Offset -Length $Length -Label 'entropy range'
    $counts = [int[]]::new(256)
    $nonzero = 0L
    $end = $Offset + $Length
    for ($index = $Offset; $index -lt $end; $index++) {
        $value = $Bytes[$index]
        $counts[$value]++
        if ($value -ne 0) {
            $nonzero++
        }
    }
    $entropy = 0.0
    foreach ($count in $counts) {
        if ($count -eq 0) {
            continue
        }
        $probability = [double]$count / [double]$Length
        $entropy -= $probability * [Math]::Log($probability, 2)
    }
    return [pscustomobject]@{
        entropy      = [Math]::Round($entropy, 6)
        nonzero      = $nonzero
        nonzero_ratio = [Math]::Round(([double]$nonzero / [double]$Length), 6)
    }
}

function Convert-RvaToFileOffset {
    param(
        [uint64]$Rva,
        [uint64]$SizeOfHeaders,
        [object[]]$Sections,
        [long]$FileLength
    )
    if ($Rva -lt $SizeOfHeaders -and $Rva -lt [uint64]$FileLength) {
        return [long]$Rva
    }
    foreach ($section in $Sections) {
        $span = [Math]::Max([uint64]$section.virtual_size, [uint64]$section.raw_size)
        if ($Rva -lt [uint64]$section.rva -or $Rva -ge ([uint64]$section.rva + $span)) {
            continue
        }
        $delta = $Rva - [uint64]$section.rva
        if ($delta -ge [uint64]$section.raw_size) {
            return $null
        }
        $offset = [uint64]$section.raw_offset + $delta
        if ($offset -ge [uint64]$FileLength) {
            return $null
        }
        return [long]$offset
    }
    return $null
}

function Get-PeMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ArtifactId
    )

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.LongLength -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw 'Not a DOS MZ image.'
    }
    $peOffset = [long](Read-U32 $bytes 0x3C 'e_lfanew')
    Assert-ByteRange -Bytes $bytes -Offset $peOffset -Length 24 -Label 'PE header'
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw 'Invalid PE signature.'
    }

    $coff = $peOffset + 4
    $machine = Read-U16 $bytes $coff 'Machine'
    $sectionCount = Read-U16 $bytes ($coff + 2) 'NumberOfSections'
    $timestamp = Read-U32 $bytes ($coff + 4) 'TimeDateStamp'
    $optionalSize = Read-U16 $bytes ($coff + 16) 'SizeOfOptionalHeader'
    $characteristics = Read-U16 $bytes ($coff + 18) 'Characteristics'
    $optional = $coff + 20
    Assert-ByteRange -Bytes $bytes -Offset $optional -Length $optionalSize -Label 'optional header'
    $magic = Read-U16 $bytes $optional 'OptionalHeader.Magic'
    if ($magic -ne 0x10B -and $magic -ne 0x20B) {
        throw ('Unsupported optional-header magic 0x{0:X}.' -f $magic)
    }
    $is64 = $magic -eq 0x20B
    $entryRva = Read-U32 $bytes ($optional + 16) 'AddressOfEntryPoint'
    $imageBase = if ($is64) { Read-U64 $bytes ($optional + 24) 'ImageBase' } else { [uint64](Read-U32 $bytes ($optional + 28) 'ImageBase') }
    $sectionAlignment = Read-U32 $bytes ($optional + 32) 'SectionAlignment'
    $fileAlignment = Read-U32 $bytes ($optional + 36) 'FileAlignment'
    $sizeOfImage = Read-U32 $bytes ($optional + 56) 'SizeOfImage'
    $sizeOfHeaders = Read-U32 $bytes ($optional + 60) 'SizeOfHeaders'
    $checksum = Read-U32 $bytes ($optional + 64) 'CheckSum'
    $subsystem = Read-U16 $bytes ($optional + 68) 'Subsystem'
    $dllCharacteristics = Read-U16 $bytes ($optional + 70) 'DllCharacteristics'
    $directoryCountOffset = if ($is64) { $optional + 108 } else { $optional + 92 }
    $directoryOffset = if ($is64) { $optional + 112 } else { $optional + 96 }
    $declaredDirectoryCount = Read-U32 $bytes $directoryCountOffset 'NumberOfRvaAndSizes'
    $availableDirectoryBytes = [Math]::Max(0, ($optional + $optionalSize) - $directoryOffset)
    $directoryCount = [Math]::Min(16, [Math]::Min([int]$declaredDirectoryCount, [int]($availableDirectoryBytes / 8)))

    $sectionTable = $optional + $optionalSize
    Assert-ByteRange -Bytes $bytes -Offset $sectionTable -Length ([long]$sectionCount * 40) -Label 'section table'
    $sections = @()
    $rawEnd = [uint64]$sizeOfHeaders
    for ($index = 0; $index -lt $sectionCount; $index++) {
        $offset = $sectionTable + ($index * 40)
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, [int]$offset, 8).Trim([char]0)
        $virtualSize = Read-U32 $bytes ($offset + 8) 'section.VirtualSize'
        $rva = Read-U32 $bytes ($offset + 12) 'section.VirtualAddress'
        $rawSize = Read-U32 $bytes ($offset + 16) 'section.SizeOfRawData'
        $rawOffset = Read-U32 $bytes ($offset + 20) 'section.PointerToRawData'
        $sectionCharacteristics = Read-U32 $bytes ($offset + 36) 'section.Characteristics'
        $validRawSize = 0L
        if ($rawSize -gt 0 -and $rawOffset -lt $bytes.LongLength) {
            $validRawSize = [Math]::Min([long]$rawSize, $bytes.LongLength - [long]$rawOffset)
        }
        $rawMetrics = if ($validRawSize -gt 0) { Get-Entropy -Bytes $bytes -Offset $rawOffset -Length $validRawSize } else { $null }
        $rawHash = if ($validRawSize -gt 0) { Get-Sha256HexFromRange -Bytes $bytes -Offset $rawOffset -Length $validRawSize } else { $null }
        $candidateEnd = [uint64]$rawOffset + [uint64]$rawSize
        if ($candidateEnd -gt $rawEnd) {
            $rawEnd = $candidateEnd
        }
        $sections += [pscustomobject]@{
            artifact_id  = $ArtifactId
            index        = $index
            name         = $name
            rva          = [uint64]$rva
            virtual_size = [uint64]$virtualSize
            raw_offset   = [uint64]$rawOffset
            raw_size     = [uint64]$rawSize
            valid_raw_size = $validRawSize
            characteristics = ('0x{0:X8}' -f $sectionCharacteristics)
            entropy      = if ($null -ne $rawMetrics) { $rawMetrics.entropy } else { $null }
            nonzero_ratio = if ($null -ne $rawMetrics) { $rawMetrics.nonzero_ratio } else { $null }
            raw_sha256   = $rawHash
        }
    }

    $directories = @()
    for ($index = 0; $index -lt 16; $index++) {
        if ($index -lt $directoryCount) {
            $rva = Read-U32 $bytes ($directoryOffset + ($index * 8)) "directory[$index].rva"
            $size = Read-U32 $bytes ($directoryOffset + ($index * 8) + 4) "directory[$index].size"
        }
        else {
            $rva = 0
            $size = 0
        }
        $directories += [pscustomobject]@{
            artifact_id = $ArtifactId
            index       = $index
            name        = $script:DirectoryNames[$index]
            rva_or_offset = [uint64]$rva
            size        = [uint64]$size
            present     = ($rva -ne 0 -and $size -ne 0)
            address_kind = if ($index -eq 4) { 'file-offset' } else { 'rva' }
        }
    }

    $entryOffset = Convert-RvaToFileOffset -Rva $entryRva -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
    $entryBytes = [byte[]]@()
    if ($null -ne $entryOffset) {
        $entryLength = [Math]::Min(64, $bytes.LongLength - $entryOffset)
        if ($entryLength -gt 0) {
            $entryBytes = [byte[]]$bytes[$entryOffset..($entryOffset + $entryLength - 1)]
        }
    }

    $imports = @()
    $importDirectory = $directories[1]
    if ($importDirectory.present) {
        $descriptorOffset = Convert-RvaToFileOffset -Rva $importDirectory.rva_or_offset -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
        if ($null -ne $descriptorOffset) {
            for ($descriptorIndex = 0; $descriptorIndex -lt 4096; $descriptorIndex++) {
                $current = $descriptorOffset + ($descriptorIndex * 20)
                if ($current + 20 -gt $bytes.LongLength) { break }
                $originalThunk = Read-U32 $bytes $current 'import.OriginalFirstThunk'
                $timeDate = Read-U32 $bytes ($current + 4) 'import.TimeDateStamp'
                $forwarder = Read-U32 $bytes ($current + 8) 'import.ForwarderChain'
                $nameRva = Read-U32 $bytes ($current + 12) 'import.Name'
                $firstThunk = Read-U32 $bytes ($current + 16) 'import.FirstThunk'
                if (($originalThunk -bor $timeDate -bor $forwarder -bor $nameRva -bor $firstThunk) -eq 0) { break }
                $nameOffset = Convert-RvaToFileOffset -Rva $nameRva -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
                $dllName = if ($null -ne $nameOffset) { Read-AsciiZ -Bytes $bytes -Offset $nameOffset } else { $null }
                $thunkRva = if ($originalThunk -ne 0) { $originalThunk } else { $firstThunk }
                $thunkOffset = Convert-RvaToFileOffset -Rva $thunkRva -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
                $symbols = @()
                if ($null -ne $thunkOffset) {
                    $pointerSize = if ($is64) { 8 } else { 4 }
                    for ($thunkIndex = 0; $thunkIndex -lt 65536; $thunkIndex++) {
                        $slot = $thunkOffset + ($thunkIndex * $pointerSize)
                        if ($slot + $pointerSize -gt $bytes.LongLength) { break }
                        $value = if ($is64) { Read-U64 $bytes $slot 'import thunk' } else { [uint64](Read-U32 $bytes $slot 'import thunk') }
                        if ($value -eq 0) { break }
                        $isOrdinal = if ($is64) { $value -ge $script:Pe64OrdinalMask } else { $value -ge [uint64]0x80000000 }
                        if ($isOrdinal) {
                            $symbols += ('#{0}' -f ($value -band 0xFFFF))
                        }
                        else {
                            $hintNameOffset = Convert-RvaToFileOffset -Rva $value -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
                            if ($null -ne $hintNameOffset -and $hintNameOffset + 2 -lt $bytes.LongLength) {
                                $symbols += (Read-AsciiZ -Bytes $bytes -Offset ($hintNameOffset + 2))
                            }
                            else {
                                $symbols += ('rva:0x{0:X}' -f $value)
                            }
                        }
                    }
                }
                $imports += [pscustomobject]@{
                    dll     = $dllName
                    symbols = $symbols
                    count   = $symbols.Count
                }
            }
        }
    }

    $exportFunctionCount = 0
    $exportNameCount = 0
    $exportModuleName = $null
    $exportDirectory = $directories[0]
    if ($exportDirectory.present) {
        $exportOffset = Convert-RvaToFileOffset -Rva $exportDirectory.rva_or_offset -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
        if ($null -ne $exportOffset -and $exportOffset + 40 -le $bytes.LongLength) {
            $moduleNameRva = Read-U32 $bytes ($exportOffset + 12) 'export.Name'
            $exportFunctionCount = Read-U32 $bytes ($exportOffset + 20) 'export.NumberOfFunctions'
            $exportNameCount = Read-U32 $bytes ($exportOffset + 24) 'export.NumberOfNames'
            $moduleNameOffset = Convert-RvaToFileOffset -Rva $moduleNameRva -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
            if ($null -ne $moduleNameOffset) {
                $exportModuleName = Read-AsciiZ -Bytes $bytes -Offset $moduleNameOffset
            }
        }
    }

    $resourceRootEntries = 0
    $resourceDirectory = $directories[2]
    if ($resourceDirectory.present) {
        $resourceOffset = Convert-RvaToFileOffset -Rva $resourceDirectory.rva_or_offset -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
        if ($null -ne $resourceOffset -and $resourceOffset + 16 -le $bytes.LongLength) {
            $resourceRootEntries = (Read-U16 $bytes ($resourceOffset + 12) 'resource.NumberOfNamedEntries') + (Read-U16 $bytes ($resourceOffset + 14) 'resource.NumberOfIdEntries')
        }
    }

    $tlsCallbacks = @()
    $tlsDirectory = $directories[9]
    if ($tlsDirectory.present) {
        $tlsOffset = Convert-RvaToFileOffset -Rva $tlsDirectory.rva_or_offset -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
        $minimumTlsSize = if ($is64) { 40 } else { 24 }
        if ($null -ne $tlsOffset -and $tlsOffset + $minimumTlsSize -le $bytes.LongLength) {
            $callbackVa = if ($is64) { Read-U64 $bytes ($tlsOffset + 24) 'TLS.AddressOfCallbacks' } else { [uint64](Read-U32 $bytes ($tlsOffset + 12) 'TLS.AddressOfCallbacks') }
            if ($callbackVa -ge $imageBase) {
                $callbackRva = $callbackVa - $imageBase
                $callbackOffset = Convert-RvaToFileOffset -Rva $callbackRva -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
                if ($null -ne $callbackOffset) {
                    $pointerSize = if ($is64) { 8 } else { 4 }
                    for ($index = 0; $index -lt 256; $index++) {
                        $slot = $callbackOffset + ($index * $pointerSize)
                        if ($slot + $pointerSize -gt $bytes.LongLength) { break }
                        $callback = if ($is64) { Read-U64 $bytes $slot 'TLS callback' } else { [uint64](Read-U32 $bytes $slot 'TLS callback') }
                        if ($callback -eq 0) { break }
                        $tlsCallbacks += [pscustomobject]@{
                            va  = ('0x{0:X}' -f $callback)
                            rva = if ($callback -ge $imageBase) { ('0x{0:X}' -f ($callback - $imageBase)) } else { $null }
                        }
                    }
                }
            }
        }
    }

    $relocationBlocks = 0
    $relocationEntries = 0
    $relocationNonAbsoluteEntries = 0
    $relocationDirectory = $directories[5]
    if ($relocationDirectory.present) {
        $relocationOffset = Convert-RvaToFileOffset -Rva $relocationDirectory.rva_or_offset -SizeOfHeaders $sizeOfHeaders -Sections $sections -FileLength $bytes.LongLength
        if ($null -ne $relocationOffset) {
            $cursor = $relocationOffset
            $limit = [Math]::Min($bytes.LongLength, $relocationOffset + [long]$relocationDirectory.size)
            while ($cursor + 8 -le $limit) {
                $blockSize = Read-U32 $bytes ($cursor + 4) 'relocation.SizeOfBlock'
                if ($blockSize -lt 8 -or $cursor + $blockSize -gt $limit) { break }
                $entryCount = [int](($blockSize - 8) / 2)
                $relocationBlocks++
                $relocationEntries += $entryCount
                for ($index = 0; $index -lt $entryCount; $index++) {
                    $encoded = Read-U16 $bytes ($cursor + 8 + ($index * 2)) 'relocation entry'
                    if (($encoded -shr 12) -ne 0) {
                        $relocationNonAbsoluteEntries++
                    }
                }
                $cursor += $blockSize
            }
        }
    }

    $securityDirectory = $directories[4]
    $overlayStart = [Math]::Min([uint64]$bytes.LongLength, $rawEnd)
    $overlaySize = [uint64]$bytes.LongLength - $overlayStart

    $flatImportSymbols = @($imports | ForEach-Object { $_.symbols })
    return [pscustomobject]@{
        metadata = [pscustomobject]@{
            format             = if ($is64) { 'PE32+' } else { 'PE32' }
            machine            = ('0x{0:X4}' -f $machine)
            timestamp          = [uint64]$timestamp
            characteristics    = ('0x{0:X4}' -f $characteristics)
            image_base         = ('0x{0:X}' -f $imageBase)
            entry_rva          = ('0x{0:X}' -f $entryRva)
            entry_file_offset  = if ($null -ne $entryOffset) { ('0x{0:X}' -f $entryOffset) } else { $null }
            entry_bytes_hex    = if ($entryBytes.Count -gt 0) { ([System.BitConverter]::ToString($entryBytes)).Replace('-', '') } else { '' }
            entry_bytes_sha256 = if ($entryBytes.Count -gt 0) { Get-Sha256HexFromBytes -Bytes $entryBytes } else { $null }
            section_alignment  = [uint64]$sectionAlignment
            file_alignment     = [uint64]$fileAlignment
            size_of_image      = [uint64]$sizeOfImage
            size_of_headers    = [uint64]$sizeOfHeaders
            checksum           = ('0x{0:X8}' -f $checksum)
            subsystem          = ('0x{0:X4}' -f $subsystem)
            dll_characteristics = ('0x{0:X4}' -f $dllCharacteristics)
            section_count      = [int]$sectionCount
            data_directory_count = [int]$declaredDirectoryCount
            import_dll_count   = $imports.Count
            import_symbol_count = $flatImportSymbols.Count
            export_function_count = [uint64]$exportFunctionCount
            export_name_count  = [uint64]$exportNameCount
            export_module_name = $exportModuleName
            resource_root_entries = [int]$resourceRootEntries
            tls_callback_count = $tlsCallbacks.Count
            tls_callbacks      = $tlsCallbacks
            exception_entry_estimate = if ($directories[3].present -and $is64) { [Math]::Floor([double]$directories[3].size / 12.0) } else { $null }
            relocation_blocks  = $relocationBlocks
            relocation_entries = $relocationEntries
            relocation_nonabsolute_entries = $relocationNonAbsoluteEntries
            overlay_offset     = [uint64]$overlayStart
            overlay_size       = [uint64]$overlaySize
            certificate_offset = if ($securityDirectory.present) { [uint64]$securityDirectory.rva_or_offset } else { $null }
            certificate_size   = if ($securityDirectory.present) { [uint64]$securityDirectory.size } else { 0 }
        }
        sections    = $sections
        directories = $directories
        imports     = $imports
    }
}

function Find-BytePattern {
    param(
        [byte[]]$Bytes,
        [byte[]]$Pattern,
        [int]$MaximumMatches = 128
    )
    $matches = @()
    if ($Pattern.Count -eq 0 -or $Pattern.Count -gt $Bytes.Count) {
        return $matches
    }
    $lastStart = $Bytes.Count - $Pattern.Count
    for ($offset = 0; $offset -le $lastStart; $offset++) {
        if ($Bytes[$offset] -ne $Pattern[0]) {
            continue
        }
        $matched = $true
        for ($index = 1; $index -lt $Pattern.Count; $index++) {
            if ($Bytes[$offset + $index] -ne $Pattern[$index]) {
                $matched = $false
                break
            }
        }
        if ($matched) {
            $matches += $offset
            if ($matches.Count -ge $MaximumMatches) {
                break
            }
            $offset += $Pattern.Count - 1
        }
    }
    return $matches
}

function Get-StringHits {
    param(
        [string]$Path,
        [string]$ArtifactId,
        [string[]]$Needles
    )
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $results = @()
    foreach ($needle in $Needles) {
        foreach ($encodingName in @('utf8', 'utf16le')) {
            $encoding = if ($encodingName -eq 'utf8') { [System.Text.UTF8Encoding]::new($false) } else { [System.Text.UnicodeEncoding]::new($false, $false) }
            $pattern = $encoding.GetBytes($needle)
            $offsets = @(Find-BytePattern -Bytes $bytes -Pattern $pattern)
            $results += [pscustomobject]@{
                artifact_id = $ArtifactId
                needle      = $needle
                encoding    = $encodingName
                found       = $offsets.Count -gt 0
                count_capped = $offsets.Count
                offsets_hex = (($offsets | ForEach-Object { '0x{0:X}' -f $_ }) -join ';')
                capped_at   = 128
            }
        }
    }
    return $results
}

function ConvertTo-WindowsCommandLineArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $slashCount++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($slashCount * 2) + 1)))
            [void]$builder.Append('"')
            $slashCount = 0
            continue
        }
        if ($slashCount -gt 0) {
            [void]$builder.Append(('\' * $slashCount))
            $slashCount = 0
        }
        [void]$builder.Append($character)
    }
    if ($slashCount -gt 0) {
        [void]$builder.Append(('\' * ($slashCount * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-CapturedProcess {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [int]$ProcessTimeoutMs
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $argumentListProperty = $startInfo.PSObject.Properties['ArgumentList']
    if ($null -ne $argumentListProperty) {
        foreach ($argument in $Arguments) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
    }
    else {
        $startInfo.Arguments = (($Arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument $_ }) -join ' ')
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = [System.IO.MemoryStream]::new()
    $stderr = [System.IO.MemoryStream]::new()
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    $exitCode = $null
    $cpuMs = $null
    $peakWorkingSet = $null
    try {
        if (-not $process.Start()) {
            throw 'Process.Start returned false.'
        }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if (-not $process.WaitForExit($ProcessTimeoutMs)) {
            $timedOut = $true
            try {
                $killWithTree = $process.PSObject.Methods['Kill'] | Where-Object { $_.OverloadDefinitions -match 'Boolean' } | Select-Object -First 1
                if ($null -ne $killWithTree) {
                    $process.Kill($true)
                }
                else {
                    $process.Kill()
                }
            }
            catch {
                # Preserve the timeout result even if the process raced with termination.
            }
            [void]$process.WaitForExit(2000)
        }
        else {
            $process.WaitForExit()
        }
        [void][System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 2000)
        $stopwatch.Stop()
        if (-not $timedOut -and $process.HasExited) {
            $exitCode = $process.ExitCode
        }
        try { $cpuMs = [Math]::Round($process.TotalProcessorTime.TotalMilliseconds, 4) } catch {}
        try { $peakWorkingSet = [int64]$process.PeakWorkingSet64 } catch {}
        $stdoutBytes = $stdout.ToArray()
        $stderrBytes = $stderr.ToArray()
        return [pscustomobject]@{
            wall_ms       = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 4)
            cpu_ms        = $cpuMs
            peak_ws_bytes = $peakWorkingSet
            timed_out     = $timedOut
            exit_code     = $exitCode
            stdout_bytes  = $stdoutBytes
            stderr_bytes  = $stderrBytes
            stdout_sha256 = Get-Sha256HexFromBytes -Bytes $stdoutBytes
            stderr_sha256 = Get-Sha256HexFromBytes -Bytes $stderrBytes
            stdout_length = $stdoutBytes.LongLength
            stderr_length = $stderrBytes.LongLength
        }
    }
    finally {
        $stopwatch.Stop()
        $process.Dispose()
        $stdout.Dispose()
        $stderr.Dispose()
    }
}

function Get-Median {
    param([double[]]$Values)
    if ($Values.Count -eq 0) { return $null }
    $ordered = @($Values | Sort-Object)
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if (($ordered.Count % 2) -eq 1) { return [double]$ordered[$middle] }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}

function Get-P90 {
    param([double[]]$Values)
    if ($Values.Count -eq 0) { return $null }
    $ordered = @($Values | Sort-Object)
    $index = [Math]::Max(0, [Math]::Ceiling(0.9 * $ordered.Count) - 1)
    return [double]$ordered[$index]
}

function Get-Mad {
    param([double[]]$Values)
    if ($Values.Count -eq 0) { return $null }
    $median = Get-Median $Values
    $deviations = @($Values | ForEach-Object { [Math]::Abs([double]$_ - [double]$median) })
    return Get-Median $deviations
}

function New-SafeArtifactId {
    param([string]$Path, [string]$Sha256)
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path) -replace '[^A-Za-z0-9._-]', '_'
    return ('{0}-{1}' -f $base, $Sha256.Substring(0, 12).ToLowerInvariant())
}

function Test-PathIsChild {
    param([string]$Child, [string]$Parent)
    $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    return $childFull.StartsWith($parentFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)
}

$baselinePath = Get-FullPath $Baseline
$artifactPaths = @($Artifact | ForEach-Object { Get-FullPath $_ })
$dependencyPaths = @($RuntimeDependency | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Runtime dependency not found: $_" }
    Get-FullPath $_
})
$allPaths = @($baselinePath) + $artifactPaths
$seen = @{}
$subjects = @()
foreach ($path in $allPaths) {
    $key = $path.ToLowerInvariant()
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $item = Get-Item -LiteralPath $path
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $subjects += [pscustomobject]@{
        path          = $path
        is_baseline   = $path -eq $baselinePath
        sha256_before = $hash
        size_before   = [int64]$item.Length
        last_write_utc_before = $item.LastWriteTimeUtc.ToString('o')
        artifact_id   = New-SafeArtifactId -Path $path -Sha256 $hash
    }
}

$outputFull = [System.IO.Path]::GetFullPath($OutputDirectory)
[void][System.IO.Directory]::CreateDirectory($outputFull)
$campaignId = [Guid]::NewGuid().ToString('N')
$runtimeRoot = Join-Path $outputFull (Join-Path '_runtime' $campaignId)
if (-not $SkipRuntime) {
    [void][System.IO.Directory]::CreateDirectory($runtimeRoot)
}

$artifactResults = @()
$sectionRows = @()
$directoryRows = @()
$stringRows = @()
$runtimeRows = @()
$runtimeDetails = @()
$baselineReference = $null
$baselineStable = $true

try {
    foreach ($subject in $subjects) {
        Write-Host ("[static] {0}" -f $subject.path)
        $pe = $null
        $analysisError = $null
        try {
            $pe = Get-PeMetadata -Path $subject.path -ArtifactId $subject.artifact_id
            $sectionRows += $pe.sections
            $directoryRows += $pe.directories
        }
        catch {
            $analysisError = $_.Exception.Message
        }
        $hits = @(Get-StringHits -Path $subject.path -ArtifactId $subject.artifact_id -Needles $StringNeedle)
        $stringRows += $hits

        $measuredRuns = @()
        if (-not $SkipRuntime) {
            $totalRuns = $Warmup + $Iterations
            for ($ordinal = 0; $ordinal -lt $totalRuns; $ordinal++) {
                $isWarmup = $ordinal -lt $Warmup
                $iteration = if ($isWarmup) { $ordinal + 1 } else { ($ordinal - $Warmup) + 1 }
                $kind = if ($isWarmup) { 'warmup' } else { 'measured' }
                $runDirectory = Join-Path $runtimeRoot (Join-Path $subject.artifact_id ('{0}-{1:D4}' -f $kind, $iteration))
                [void][System.IO.Directory]::CreateDirectory($runDirectory)
                $runExecutable = Join-Path $runDirectory ([System.IO.Path]::GetFileName($subject.path))
                Copy-Item -LiteralPath $subject.path -Destination $runExecutable -Force
                foreach ($dependency in $dependencyPaths) {
                    $dependencyDestination = Join-Path $runDirectory ([System.IO.Path]::GetFileName($dependency))
                    if (Test-Path -LiteralPath $dependencyDestination) {
                        $existingHash = (Get-FileHash -LiteralPath $dependencyDestination -Algorithm SHA256).Hash
                        $incomingHash = (Get-FileHash -LiteralPath $dependency -Algorithm SHA256).Hash
                        if ($existingHash -ne $incomingHash) {
                            throw "Runtime dependency name collision: $dependencyDestination"
                        }
                    }
                    else {
                        Copy-Item -LiteralPath $dependency -Destination $dependencyDestination
                    }
                }
                Write-Host ("[run] {0} {1}/{2}" -f $subject.artifact_id, ($ordinal + 1), $totalRuns)
                $captured = Invoke-CapturedProcess -Executable $runExecutable -Arguments $RunArgument -WorkingDirectory $runDirectory -ProcessTimeoutMs $TimeoutMs
                if (-not $isWarmup) {
                    if ($subject.is_baseline -and $null -eq $baselineReference) {
                        $baselineReference = [pscustomobject]@{
                            exit_code     = $captured.exit_code
                            timed_out     = $captured.timed_out
                            stdout_sha256 = $captured.stdout_sha256
                            stderr_sha256 = $captured.stderr_sha256
                        }
                    }
                    $semanticMatch = $null
                    if ($SemanticMode -eq 'Disabled') {
                        $semanticMatch = $null
                    }
                    elseif ($null -ne $baselineReference) {
                        $semanticMatch = (-not $captured.timed_out) -and (-not $baselineReference.timed_out) -and ($captured.exit_code -eq $baselineReference.exit_code)
                        if ($SemanticMode -eq 'Exact') {
                            $semanticMatch = $semanticMatch -and ($captured.stdout_sha256 -eq $baselineReference.stdout_sha256) -and ($captured.stderr_sha256 -eq $baselineReference.stderr_sha256)
                        }
                    }
                    if ($subject.is_baseline -and $semanticMatch -eq $false) {
                        $baselineStable = $false
                    }
                    $row = [pscustomobject]@{
                        run_id          = ('{0}-run-{1:D4}' -f $subject.artifact_id, $iteration)
                        artifact_id     = $subject.artifact_id
                        is_baseline     = $subject.is_baseline
                        iteration       = $iteration
                        wall_ms         = $captured.wall_ms
                        cpu_ms          = $captured.cpu_ms
                        peak_ws_bytes   = $captured.peak_ws_bytes
                        timed_out       = $captured.timed_out
                        exit_code       = $captured.exit_code
                        stdout_sha256   = $captured.stdout_sha256
                        stderr_sha256   = $captured.stderr_sha256
                        stdout_length   = $captured.stdout_length
                        stderr_length   = $captured.stderr_length
                        semantic_mode   = $SemanticMode
                        semantic_match  = $semanticMatch
                    }
                    $runtimeRows += $row
                    $measuredRuns += $row
                    $runtimeDetails += [pscustomobject]@{
                        run_id        = $row.run_id
                        stdout_base64 = [Convert]::ToBase64String($captured.stdout_bytes)
                        stderr_base64 = [Convert]::ToBase64String($captured.stderr_bytes)
                    }
                }
                if (-not $KeepRunDirectories) {
                    if (-not (Test-PathIsChild -Child $runDirectory -Parent $runtimeRoot)) {
                        throw "Refusing to remove a run directory outside the owned runtime root: $runDirectory"
                    }
                    Remove-Item -LiteralPath $runDirectory -Recurse -Force
                }
            }
        }

        $wallValues = @($measuredRuns | ForEach-Object { [double]$_.wall_ms })
        $median = Get-Median $wallValues
        $p90 = Get-P90 $wallValues
        $mad = Get-Mad $wallValues
        $semanticValues = @($measuredRuns | Where-Object { $null -ne $_.semantic_match } | ForEach-Object { [bool]$_.semantic_match })
        $semanticPass = if ($SkipRuntime -or $SemanticMode -eq 'Disabled') { $null } elseif ($semanticValues.Count -eq 0) { $null } else { -not ($semanticValues -contains $false) }
        $peMetadata = if ($null -ne $pe) { $pe.metadata } else { $null }
        $artifactResults += [pscustomobject]@{
            artifact_id       = $subject.artifact_id
            path              = $subject.path
            is_baseline       = $subject.is_baseline
            sha256            = $subject.sha256_before
            size_bytes        = $subject.size_before
            analysis_error    = $analysisError
            pe                = $peMetadata
            imports           = if ($null -ne $pe) { $pe.imports } else { @() }
            string_hits       = $hits
            runtime_summary   = [pscustomobject]@{
                measured_runs = $measuredRuns.Count
                median_ms     = if ($null -ne $median) { [Math]::Round($median, 4) } else { $null }
                p90_ms        = if ($null -ne $p90) { [Math]::Round($p90, 4) } else { $null }
                mad_ms        = if ($null -ne $mad) { [Math]::Round($mad, 4) } else { $null }
                semantic_pass = $semanticPass
                unique_exit_codes = @($measuredRuns | ForEach-Object { $_.exit_code } | Sort-Object -Unique)
                unique_stdout_sha256 = @($measuredRuns | ForEach-Object { $_.stdout_sha256 } | Sort-Object -Unique)
                unique_stderr_sha256 = @($measuredRuns | ForEach-Object { $_.stderr_sha256 } | Sort-Object -Unique)
                timeout_count = @($measuredRuns | Where-Object timed_out).Count
            }
        }
    }

    $baselineResult = $artifactResults | Where-Object is_baseline | Select-Object -First 1
    $baselineMedian = $baselineResult.runtime_summary.median_ms
    foreach ($result in $artifactResults) {
        $overhead = $null
        if ($null -ne $baselineMedian -and [double]$baselineMedian -gt 0 -and $null -ne $result.runtime_summary.median_ms) {
            $overhead = (([double]$result.runtime_summary.median_ms / [double]$baselineMedian) - 1.0) * 100.0
        }
        Add-Member -InputObject $result.runtime_summary -NotePropertyName median_overhead_pct -NotePropertyValue $(if ($null -ne $overhead) { [Math]::Round($overhead, 4) } else { $null })
    }

    foreach ($subject in $subjects) {
        $afterItem = Get-Item -LiteralPath $subject.path
        $afterHash = (Get-FileHash -LiteralPath $subject.path -Algorithm SHA256).Hash
        if ($afterHash -ne $subject.sha256_before -or $afterItem.Length -ne $subject.size_before) {
            throw "Input artifact changed during collection: $($subject.path)"
        }
    }

    $environment = [pscustomobject]@{
        machine_name     = [Environment]::MachineName
        os_description   = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        os_architecture  = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        process_architecture = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        powershell_version = $PSVersionTable.PSVersion.ToString()
        processor_count  = [Environment]::ProcessorCount
    }

    $report = [pscustomobject]@{
        schema_version = 'protector-diff-v1'
        campaign_id    = $campaignId
        generated_utc  = [DateTime]::UtcNow.ToString('o')
        parameters     = [pscustomobject]@{
            baseline       = $baselinePath
            artifacts      = $artifactPaths
            string_needles = $StringNeedle
            iterations     = $Iterations
            warmup          = $Warmup
            timeout_ms      = $TimeoutMs
            run_arguments   = $RunArgument
            runtime_dependencies = $dependencyPaths
            semantic_mode  = $SemanticMode
            skip_runtime   = [bool]$SkipRuntime
        }
        environment    = $environment
        baseline_stable = if ($SkipRuntime -or $SemanticMode -eq 'Disabled') { $null } else { $baselineStable }
        baseline_reference = $baselineReference
        artifacts      = $artifactResults
        runtime_runs   = $runtimeRows
        runtime_streams = $runtimeDetails
    }

    $reportPath = Join-Path $outputFull 'report.json'
    [System.IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 20), [System.Text.UTF8Encoding]::new($false))

    $flatArtifactRows = foreach ($result in $artifactResults) {
        $peSummary = $result.pe
        [pscustomobject]@{
            artifact_id       = $result.artifact_id
            path              = $result.path
            is_baseline       = $result.is_baseline
            sha256            = $result.sha256
            size_bytes        = $result.size_bytes
            pe_format         = if ($null -ne $peSummary) { $peSummary.format } else { $null }
            machine           = if ($null -ne $peSummary) { $peSummary.machine } else { $null }
            entry_rva         = if ($null -ne $peSummary) { $peSummary.entry_rva } else { $null }
            entry_file_offset = if ($null -ne $peSummary) { $peSummary.entry_file_offset } else { $null }
            entry_bytes_sha256 = if ($null -ne $peSummary) { $peSummary.entry_bytes_sha256 } else { $null }
            section_count     = if ($null -ne $peSummary) { $peSummary.section_count } else { $null }
            import_dll_count  = if ($null -ne $peSummary) { $peSummary.import_dll_count } else { $null }
            import_symbol_count = if ($null -ne $peSummary) { $peSummary.import_symbol_count } else { $null }
            export_name_count = if ($null -ne $peSummary) { $peSummary.export_name_count } else { $null }
            resource_root_entries = if ($null -ne $peSummary) { $peSummary.resource_root_entries } else { $null }
            tls_callback_count = if ($null -ne $peSummary) { $peSummary.tls_callback_count } else { $null }
            relocation_entries = if ($null -ne $peSummary) { $peSummary.relocation_entries } else { $null }
            overlay_size      = if ($null -ne $peSummary) { $peSummary.overlay_size } else { $null }
            analysis_error    = $result.analysis_error
            measured_runs     = $result.runtime_summary.measured_runs
            median_ms         = $result.runtime_summary.median_ms
            p90_ms            = $result.runtime_summary.p90_ms
            mad_ms            = $result.runtime_summary.mad_ms
            median_overhead_pct = $result.runtime_summary.median_overhead_pct
            semantic_pass     = $result.runtime_summary.semantic_pass
            timeout_count     = $result.runtime_summary.timeout_count
        }
    }

    @($flatArtifactRows) | Export-Csv -LiteralPath (Join-Path $outputFull 'artifacts.csv') -NoTypeInformation -Encoding utf8
    @($sectionRows) | Export-Csv -LiteralPath (Join-Path $outputFull 'pe_sections.csv') -NoTypeInformation -Encoding utf8
    @($directoryRows) | Export-Csv -LiteralPath (Join-Path $outputFull 'pe_directories.csv') -NoTypeInformation -Encoding utf8
    @($stringRows) | Export-Csv -LiteralPath (Join-Path $outputFull 'string_hits.csv') -NoTypeInformation -Encoding utf8
    @($runtimeRows) | Export-Csv -LiteralPath (Join-Path $outputFull 'runtime_runs.csv') -NoTypeInformation -Encoding utf8

    Write-Host "Report: $reportPath"
    Write-Host "Inputs verified unchanged: $($subjects.Count)"
}
finally {
    if (-not $KeepRunDirectories -and (Test-Path -LiteralPath $runtimeRoot)) {
        $ownedRuntimeParent = Join-Path $outputFull '_runtime'
        if (-not (Test-PathIsChild -Child $runtimeRoot -Parent $ownedRuntimeParent)) {
            throw "Refusing to remove a runtime directory outside the owned output tree: $runtimeRoot"
        }
        Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
        if ((Test-Path -LiteralPath $ownedRuntimeParent) -and -not (Get-ChildItem -LiteralPath $ownedRuntimeParent -Force | Select-Object -First 1)) {
            Remove-Item -LiteralPath $ownedRuntimeParent -Force
        }
    }
}
