<#
.SYNOPSIS
Extracts archives with NanaZip, picking the ZIP file name code page automatically.

.DESCRIPTION
Legacy ZIP entries store their names in the creator's code page without saying which one. This
reads the raw names from the central directory, scores UTF-8, Shift-JIS (932) and CP949 (949),
and passes the best one to NanaZip as -mcp. Archives are extracted one after another.

Smart mode puts a single top-level folder or file next to the archive and anything else in a
new folder named after the archive. Folder mode always uses that new folder.

.EXAMPLE
.\Expand-ArchiveAuto.ps1 a.zip b.7z
.\Expand-ArchiveAuto.ps1 -Mode Folder -OutDir D:\out a.zip
.\Expand-ArchiveAuto.ps1 -DetectOnly a.zip
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)][string[]]$Path,
    [ValidateSet('Smart', 'Folder')][string]$Mode = 'Smart',
    # Put the results here instead of next to each archive
    [string]$OutDir,
    # Force a code page instead of detecting it; 0 means detect
    [ValidateScript({ $_ -eq 0 -or [Text.Encoding]::GetEncoding($_) })][int]$CodePage = 0,
    # Print "<code page or default><TAB><archive>" per archive and extract nothing
    [switch]$DetectOnly,
    # Use the console extractor (NanaZipC) and report errors on the console; for tests
    [switch]$Console
)

$ErrorActionPreference = 'Stop'

function Read-Exact([IO.Stream]$Stream, [long]$Offset, [int]$Count) {
    $buf = New-Object byte[] $Count
    [void]$Stream.Seek($Offset, 'Begin')
    $done = 0
    while ($done -lt $Count) {
        $n = $Stream.Read($buf, $done, $Count - $done)
        if ($n -le 0) { throw "Unexpected end of file at offset $($Offset + $done)" }
        $done += $n
    }
    return , $buf
}

function Get-Crc32([byte[]]$Bytes) {
    if (-not $script:Crc32Table) {
        $script:Crc32Table = New-Object uint32[] 256
        for ($n = 0; $n -lt 256; $n++) {
            $c = [uint32]$n
            for ($k = 0; $k -lt 8; $k++) {
                $c = if ($c -band 1) { [uint32](3988292384 -bxor ($c -shr 1)) } else { $c -shr 1 }   # 0xEDB88320
            }
            $script:Crc32Table[$n] = $c
        }
    }
    $crc = [uint32]4294967295
    foreach ($b in $Bytes) { $crc = [uint32]($script:Crc32Table[($crc -bxor $b) -band 0xFF] -bxor ($crc -shr 8)) }
    return [uint32]($crc -bxor 4294967295)
}

# NanaZip uses an Info-ZIP Unicode Path field only when its CRC matches the stored name
function Test-UnicodePathField([byte[]]$Cd, [int]$Start, [int]$Length, [byte[]]$Name) {
    $x = $Start
    $end = $Start + $Length
    while ($x + 4 -le $end) {
        $id = [BitConverter]::ToUInt16($Cd, $x)
        $size = [BitConverter]::ToUInt16($Cd, $x + 2)
        if ($x + 4 + $size -gt $end) { return $false }
        if ($id -eq 0x7075 -and $size -ge 5 -and $Cd[$x + 4] -eq 1 -and
            [BitConverter]::ToUInt32($Cd, $x + 5) -eq (Get-Crc32 $Name)) { return $true }
        $x += 4 + $size
    }
    return $false
}

# Raw names of the entries NanaZip decodes with a code page: no UTF-8 flag, no valid Unicode Path
# field, some non-ASCII byte. $null when no central directory can be found.
function Get-LegacyZipNames([string]$ZipPath) {
    $fs = [IO.File]::OpenRead($ZipPath)
    try {
        $tailLen = [int][Math]::Min($fs.Length, 65557)
        $tailStart = $fs.Length - $tailLen
        $tail = Read-Exact $fs $tailStart $tailLen
        # The real end record is the last one whose comment ends exactly at the end of the file
        $eocd = -1
        for ($i = $tailLen - 22; $i -ge 0; $i--) {
            if ([BitConverter]::ToUInt32($tail, $i) -eq 0x06054b50 -and
                $i + 22 + [BitConverter]::ToUInt16($tail, $i + 20) -eq $tailLen) { $eocd = $i; break }
        }
        if ($eocd -lt 0) { return $null }
        # Measure the central directory back from its end, so a prepended SFX stub does not matter
        $cdEnd = $tailStart + $eocd
        $cdSize = [long][BitConverter]::ToUInt32($tail, $eocd + 12)
        $locator = $eocd - 20
        if ($locator -ge 0 -and [BitConverter]::ToUInt32($tail, $locator) -eq 0x07064b50) {
            # ZIP64: the 56-byte end record sits right before its locator
            $recordPos = $tailStart + $locator - 56
            if ($recordPos -lt 0) { return $null }
            $record = Read-Exact $fs $recordPos 56
            if ([BitConverter]::ToUInt32($record, 0) -ne 0x06064b50) { return $null }
            $cdEnd = $recordPos
            $cdSize = [BitConverter]::ToInt64($record, 40)
        }
        if ($cdSize -lt 0 -or $cdSize -gt $cdEnd -or $cdSize -gt 512MB) { return $null }
        $cd = Read-Exact $fs ($cdEnd - $cdSize) ([int]$cdSize)
    }
    finally { $fs.Dispose() }

    $legacy = New-Object System.Collections.Generic.List[byte[]]
    $p = 0
    while ($p + 46 -le $cd.Length -and [BitConverter]::ToUInt32($cd, $p) -eq 0x02014b50) {
        $flags = [BitConverter]::ToUInt16($cd, $p + 8)
        $nLen = [BitConverter]::ToUInt16($cd, $p + 28)
        $xLen = [BitConverter]::ToUInt16($cd, $p + 30)
        $next = $p + 46 + $nLen + $xLen + [BitConverter]::ToUInt16($cd, $p + 32)
        if ($next -gt $cd.Length) { break }
        $name = New-Object byte[] $nLen
        [Array]::Copy($cd, $p + 46, $name, 0, $nLen)
        $nonAscii = $false
        foreach ($b in $name) { if ($b -ge 0x80) { $nonAscii = $true; break } }
        if ($nonAscii -and -not ($flags -band 0x800) -and -not (Test-UnicodePathField $cd ($p + 46 + $nLen) $xLen $name)) {
            $legacy.Add($name)
        }
        $p = $next
    }
    return , $legacy
}

# How much the decoded names look like real file names. Each wrong guess has a typical look:
# Shift-JIS read as CP949 gives rare UHC-extension Hangul, CP949 read as Shift-JIS gives half-width
# katakana, and legacy bytes read as UTF-8 give invalid sequences or stray Latin letters.
function Get-CodePageScore([int]$CodePage, $Names) {
    $decoder = [Text.Encoding]::GetEncoding($CodePage, [Text.EncoderFallback]::ReplacementFallback,
        (New-Object Text.DecoderReplacementFallback ([string][char]0xFFFD)))
    $score = 0
    foreach ($bytes in $Names) {
        if ($CodePage -eq 932) {
            # .NET rejects NEC and IBM extension characters that Windows (and so NanaZip) decodes
            $bytes = [byte[]]$bytes.Clone()
            for ($i = 0; $i + 1 -lt $bytes.Length; $i++) {
                if ($bytes[$i] -in 0x87, 0xED, 0xEE) { $bytes[$i] = 0x81; $bytes[$i + 1] = 0x40; $i++ }
                elseif ($bytes[$i] -ge 0x81 -and $bytes[$i] -le 0x9F -or $bytes[$i] -ge 0xE0 -and $bytes[$i] -le 0xFC) { $i++ }
            }
        }
        foreach ($ch in $decoder.GetString($bytes).ToCharArray()) {
            $c = [int]$ch
            if ($c -lt 0x80) { continue }
            if ($c -eq 0xFFFD) { $score -= 5 }
            elseif ($c -ge 0x3040 -and $c -le 0x30FF) { $score += 2 }          # kana
            elseif ($c -ge 0xAC00 -and $c -le 0xD7A3) {
                # Names use the 2350 KS X 1001 syllables (both CP949 bytes >= 0xA1)
                $b = $script:Cp949.GetBytes([string]$ch)
                if ($b[0] -ge 0xA1 -and $b[1] -ge 0xA1) { $score += 2 } else { $score -= 2 }
            }
            elseif ($c -ge 0x4E00 -and $c -le 0x9FFF) { $score += 1 }          # CJK ideographs
            elseif ($c -ge 0xC0 -and $c -le 0xFF -and $c -ne 0xD7 -and $c -ne 0xF7) { $score += 2 }   # accented letters
            elseif ($c -ge 0x300 -and $c -le 0x36F) { $score += 2 }            # combining accents (macOS)
            elseif ($c -ge 0xFF61 -and $c -le 0xFF9F) { $score -= 3 }          # half-width katakana
            elseif ($c -ge 0xFF01 -and $c -le 0xFF5E -or $c -ge 0x3000 -and $c -le 0x303F) { }   # full-width forms
            else { $score -= 1 }
        }
    }
    return $score
}

# The code page to pass as -mcp, or $null to keep NanaZip's default
function Get-ZipCodePage([string]$ZipPath) {
    if ([IO.Path]::GetExtension($ZipPath) -ne '.zip') { return $null }
    try { $names = Get-LegacyZipNames $ZipPath } catch { return $null }
    if ($null -eq $names -or $names.Count -eq 0) { return $null }
    $best = $null
    $bestScore = 0
    foreach ($cp in 949, 932, 65001) {   # ties go to the earlier one
        $score = Get-CodePageScore $cp $names
        if ($score -gt $bestScore) { $best = $cp; $bestScore = $score }
    }
    return $best
}

# NanaZip parses its command line like CommandLineToArgvW: a backslash before a quote escapes it
function ConvertTo-Argument([string]$Value) { '"' + ($Value -replace '(\\+)$', '$1$1') + '"' }

# Explorer can hand us a PATH without the Store app alias folder, so look there too
function Find-NanaZip([string]$Exe) {
    $cmd = Get-Command $Exe -CommandType Application -TotalCount 1 -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $alias = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) "Microsoft\WindowsApps\$Exe"
    if (Test-Path -LiteralPath $alias) { return $alias }
    throw "$Exe was not found. Install NanaZip from the Microsoft Store or with: winget install M2Team.NanaZip"
}

function Invoke-NanaZip([string]$Archive, [string]$Destination, $Cp) {
    $exe = if ($Console) { 'NanaZipC.exe' } else { 'NanaZipG.exe' }
    $psi = New-Object Diagnostics.ProcessStartInfo (Find-NanaZip $exe)
    $argList = @('x', $Archive, "-o$Destination") + @(if ($Cp) { "-mcp=$Cp" })
    $psi.Arguments = ($argList | ForEach-Object { ConvertTo-Argument $_ }) -join ' '
    $psi.UseShellExecute = $false
    $proc = [Diagnostics.Process]::Start($psi)
    $proc.WaitForExit()
    return $proc.ExitCode
}

# x.tar.gz and friends hold a single .tar that NanaZip leaves unpacked
$CompoundArchive = '\.(tar\.(gz|bz2|xz|zst|lzma)|tgz|tbz2?|txz)$'

function Get-BaseName([string]$Archive) {
    $name = [IO.Path]::GetFileName($Archive)
    $base = if ($name -match '^(.*)\.tar\.[^.]+$') { $Matches[1] } else { [IO.Path]::GetFileNameWithoutExtension($name) }
    if ($base) { $base } else { 'archive' }
}

# Moves $Source to "$Parent\$Name", or "$Name (2)" and so on when taken
function Move-ToFreeName([string]$Source, [string]$Parent, [string]$Name) {
    for ($n = 1; ; $n++) {
        $dest = Join-Path $Parent $(if ($n -eq 1) { $Name } else { "$Name ($n)" })
        try { [IO.Directory]::Move($Source, $dest); return }
        catch [IO.IOException] { if (-not (Test-Path -LiteralPath $dest)) { throw } }   # the name is taken
    }
}

# Extracts into a hidden staging folder first, so concurrent runs and existing files never collide
function Expand-OneArchive([string]$Archive, [string]$TargetDir) {
    $cp = if ($CodePage) { $CodePage } else { Get-ZipCodePage $Archive }
    $stage = Join-Path $TargetDir ('.nanazip-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($stage)
    try {
        $exit = Invoke-NanaZip $Archive $stage $cp
        $items = @(Get-ChildItem -LiteralPath $stage -Force)
        if ($exit -le 1 -and $items.Count -eq 1 -and $items[0].Extension -eq '.tar' -and $Archive -match $CompoundArchive) {
            $exit = Invoke-NanaZip $items[0].FullName $stage $null
            Remove-Item -LiteralPath $items[0].FullName
            $items = @(Get-ChildItem -LiteralPath $stage -Force)
        }
        # 1 means warnings; NanaZipG has already shown its own dialog for errors and a cancel
        if ($exit -gt 1 -and $Console) { throw "NanaZipC exited with code $exit" }
        if ($exit -eq 255 -or $items.Count -eq 0) { return }   # cancelled, or nothing to place
        if ($Mode -eq 'Smart' -and $items.Count -eq 1) {
            $target = Join-Path $TargetDir $items[0].Name
            try {
                if ($items[0].PSIsContainer) { [IO.Directory]::Move($items[0].FullName, $target) }
                else { [IO.File]::Move($items[0].FullName, $target) }
                return
            }
            catch [IO.IOException] { }   # the name is taken: use a folder named after the archive
        }
        Move-ToFreeName $stage $TargetDir (Get-BaseName $Archive)
    }
    finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    }
}

if ($Console -or $DetectOnly) {
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { }
}
$failures = New-Object System.Collections.Generic.List[string]
try {
    $script:Cp949 = [Text.Encoding]::GetEncoding(949)
    $archives = foreach ($p in $Path) { (Resolve-Path -LiteralPath $p).ProviderPath }
    if ($DetectOnly) {
        foreach ($a in $archives) {
            $cp = Get-ZipCodePage $a
            "{0}`t{1}" -f $(if ($null -eq $cp) { 'default' } else { $cp }), $a
        }
        return
    }
    $outRoot = if ($OutDir) { (Resolve-Path -LiteralPath $OutDir).ProviderPath }
    foreach ($a in $archives) {
        try { Expand-OneArchive $a $(if ($outRoot) { $outRoot } else { Split-Path -Parent $a }) }
        catch { $failures.Add("$a`n$($_.Exception.Message)") }
    }
}
catch { $failures.Add($_.Exception.Message) }

if ($failures.Count) {
    $message = $failures -join "`n`n"
    if ($Console -or $DetectOnly) { Write-Host "ERROR: $message" -ForegroundColor Red }
    else {
        # Started hidden from Explorer, so report in a dialog that comes to the front
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($message, 'NanaZip auto encoding', 'OK', 'Error', 'Button1', 'DefaultDesktopOnly')
    }
    exit 1
}
