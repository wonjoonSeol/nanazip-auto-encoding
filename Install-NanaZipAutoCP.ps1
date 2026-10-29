<#
.SYNOPSIS
Installs or removes the NanaZip auto encoding menu items for the current user.

.DESCRIPTION
Copies Expand-ArchiveAuto.ps1 and NanaZipAutoCP.dll to %LOCALAPPDATA%\NanaZipAutoCP and registers,
in HKCU only (no admin rights):
  - two right-click items for .zip files and two right-drag items for archives:
    Extract Here (Smart) and Extract to Folder, both picking the ZIP file name encoding
  - a "NanaZip (blue icon)" app for every archive type NanaZip opens, listed in Open with and in
    Settings > Default apps, which opens the files in NanaZip and shows NanaZip's app icon
Requires 64-bit Windows on x64 and NanaZip (Microsoft Store or "winget install M2Team.NanaZip").

.EXAMPLE
.\Install-NanaZipAutoCP.ps1                  # menu language follows the Windows display language
.\Install-NanaZipAutoCP.ps1 -Language en     # English menu
.\Install-NanaZipAutoCP.ps1 -Uninstall
#>
param(
    [ValidateSet('auto', 'en', 'ko')][string]$Language = 'auto',
    [switch]$Uninstall,
    # Report on the console only, without the closing message box
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$InstallDir = Join-Path $env:LOCALAPPDATA 'NanaZipAutoCP'
$Dll = 'NanaZipAutoCP.dll'
$Classes = 'HKCU:\Software\Classes'
$SettingsKey = 'HKCU:\Software\NanaZipAutoCP'
$DragClsid = '{F395F013-BB22-4061-B844-BF5C79EBBE58}'
$ContextMenuClsid = '{DA650B86-9BE4-4187-9870-9179AE35AC68}'
# Known folders such as Downloads only load Folder drag handlers; a folder that matches several of
# these classes still gets the handler once
$HandlerKeys = @{
    "$Classes\SystemFileAssociations\.zip\shellex\ContextMenuHandlers\NanaZipAutoCP" = $ContextMenuClsid
    "$Classes\Directory\shellex\DragDropHandlers\NanaZipAutoCP"                     = $DragClsid
    "$Classes\Drive\shellex\DragDropHandlers\NanaZipAutoCP"                         = $DragClsid
    "$Classes\Folder\shellex\DragDropHandlers\NanaZipAutoCP"                        = $DragClsid
}
$ArchiveExtensions = '.zip;.7z;.rar;.tar;.gz;.tgz;.bz2;.tbz;.tbz2;.xz;.txz;.zst;.lzh;.lha;.cab;.iso;.wim;.arj;.lzma;.001'
# Every type NanaZip opens (the file associations in its AppxManifest.xml); each gets the blue icon
# ProgId NanaZipAutoCP<extension>
$IconExtensions = ('.001;.7z;.apfs;.arj;.asar;.b64;.br;.bz2;.bzip2;.cab;.cb7;.cbr;.cbz;.cpio;.deb;.dmg;.esd;.fat;.gz;.gzip;' +
    '.hfs;.hfsx;.iso;.lha;.liz;.lz;.lz4;.lz5;.lzh;.lzma;.lzma2;.ntfs;.nupkg;.rar;.rpm;.squashfs;.swm;.tar;.taz;.tbz;' +
    '.tbz2;.tgz;.tlz;.tlz4;.tlz5;.tpz;.txz;.tz;.tzst;.tzstd;.vdi;.vhd;.vhdx;.vmdk;.wim;.xar;.xz;.z;.zip;.zipx;.zst;.zstd') -split ';'
$RegisteredAppsKey = 'Software\RegisteredApplications'
$RunOnceKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$Text = @{
    en = @{
        Smart = 'Extract Here (Smart) with NanaZip (auto encoding)'
        Folder = 'Extract to Folder with NanaZip (auto encoding)'
        App = 'NanaZip (blue icon)'
        AppDescription = "Opens archives in NanaZip and shows NanaZip's blue app icon"
        Type = '{0} archive'
        Done = "Installed. Right-click a .zip file or right-drag archives onto a folder.`n`nFor the blue icon: Settings > Apps > Default apps > NanaZip (blue icon), then pick it under each type you want. Or right-click an archive > Open with > Choose another app > NanaZip (blue icon) > Always."
    }
    ko = @{
        Smart = 'NanaZip으로 여기에 압축 풀기 (스마트, 인코딩 자동)'
        Folder = 'NanaZip으로 폴더에 압축 풀기 (인코딩 자동)'
        App = 'NanaZip (파란 아이콘)'
        AppDescription = '압축 파일을 NanaZip으로 열고 NanaZip의 파란 앱 아이콘으로 보여 줍니다'
        Type = '{0} 압축 파일'
        Done = "설치했습니다. .zip 파일을 우클릭하거나 압축 파일을 폴더로 오른쪽 드래그하세요.`n`n파란 아이콘: 설정 > 앱 > 기본 앱 > NanaZip (파란 아이콘)에서 원하는 형식마다 고르세요. 압축 파일 우클릭 > 연결 프로그램 > 다른 앱 선택 > NanaZip (파란 아이콘) > 항상으로 골라도 됩니다."
    }
}

# Rebuilds the first RT_GROUP_ICON of a PE file as a standalone multi-size .ico
function Export-PeIcon([string]$PePath, [string]$OutPath) {
    $d = [IO.File]::ReadAllBytes($PePath)
    if ([BitConverter]::ToUInt16($d, 0) -ne 0x5A4D) { throw "$PePath is not a PE file" }
    $lfanew = [BitConverter]::ToInt32($d, 0x3C)
    $nSec = [BitConverter]::ToUInt16($d, $lfanew + 6)
    $optSize = [BitConverter]::ToUInt16($d, $lfanew + 20)
    $opt = $lfanew + 24
    $dataDirs = $opt + $(if ([BitConverter]::ToUInt16($d, $opt) -eq 0x20B) { 112 } else { 96 })
    $sections = @(for ($i = 0; $i -lt $nSec; $i++) {
        $s = $opt + $optSize + $i * 40
        [pscustomobject]@{
            Size = [Math]::Max([BitConverter]::ToUInt32($d, $s + 8), [BitConverter]::ToUInt32($d, $s + 16))
            Va   = [long][BitConverter]::ToUInt32($d, $s + 12)
            Raw  = [long][BitConverter]::ToUInt32($d, $s + 20)
        }
    })
    $toOffset = {
        param([long]$Rva)
        foreach ($s in $sections) { if ($Rva -ge $s.Va -and $Rva -lt $s.Va + $s.Size) { return $Rva - $s.Va + $s.Raw } }
        throw "RVA $Rva is outside every section"
    }
    $res = & $toOffset ([BitConverter]::ToUInt32($d, $dataDirs + 2 * 8))
    $subdirBit = [uint32]2147483648
    $entries = {
        param([long]$DirOffset)
        $n = [BitConverter]::ToUInt16($d, $DirOffset + 12) + [BitConverter]::ToUInt16($d, $DirOffset + 14)
        for ($i = 0; $i -lt $n; $i++) {
            [pscustomobject]@{
                Id     = [BitConverter]::ToUInt32($d, $DirOffset + 16 + $i * 8)
                Target = [BitConverter]::ToUInt32($d, $DirOffset + 20 + $i * 8)
            }
        }
    }
    $leaf = {
        param([uint32]$Target)
        # Follow the name and language subdirectories down to the first data entry
        while ($Target -band $subdirBit) { $Target = @(& $entries ($res + ($Target -bxor $subdirBit)))[0].Target }
        $o = & $toOffset ([BitConverter]::ToUInt32($d, $res + $Target))
        $bytes = New-Object byte[] ([BitConverter]::ToUInt32($d, $res + $Target + 4))
        [Array]::Copy($d, $o, $bytes, 0, $bytes.Length)
        , $bytes
    }
    $types = @(& $entries $res)
    $iconDir = ($types | Where-Object Id -EQ 3).Target -bxor $subdirBit     # RT_ICON
    $groupDir = ($types | Where-Object Id -EQ 14).Target -bxor $subdirBit   # RT_GROUP_ICON
    $icons = @{}
    foreach ($e in & $entries ($res + $iconDir)) { $icons[[int]$e.Id] = & $leaf $e.Target }
    $group = & $leaf @(& $entries ($res + $groupDir))[0].Target

    $count = [BitConverter]::ToUInt16($group, 4)
    $ms = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter $ms
    $w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$count)
    $pos = 6 + 16 * $count
    $images = New-Object System.Collections.Generic.List[byte[]]
    for ($i = 0; $i -lt $count; $i++) {
        $g = 6 + $i * 14
        $img = $icons[[int][BitConverter]::ToUInt16($group, $g + 12)]
        $w.Write($group, $g, 8)               # width, height, colors, reserved, planes, bit count
        $w.Write([uint32]$img.Length)
        $w.Write([uint32]$pos)
        $pos += $img.Length
        $images.Add($img)
    }
    foreach ($img in $images) { $w.Write($img) }
    $w.Flush()
    [IO.File]::WriteAllBytes($OutPath, $ms.ToArray())
    $w.Dispose()
}

# Tells Explorer that file associations changed, so it redraws file icons
function Update-ShellAssociations {
    if (-not ('NanaZipAutoCP.Shell' -as [type])) {
        Add-Type -Namespace NanaZipAutoCP -Name Shell -MemberDefinition '[DllImport("shell32.dll")] public static extern void SHChangeNotify(int eventId, uint flags, IntPtr item1, IntPtr item2);'
    }
    [NanaZipAutoCP.Shell]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)   # SHCNE_ASSOCCHANGED
}

function Show-Result([string]$Message, [string]$Icon = 'Information') {
    Write-Host $Message
    if (-not $Quiet) {
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($Message, 'NanaZip auto encoding', 'OK', $Icon)
    }
}

function Remove-Registration {
    # Static verbs written by earlier versions of this installer
    $oldVerbs = 'NanaZipAutoCP', 'NanaZipShiftJIS', 'NanaZipAuto1Here', 'NanaZipAuto1Smart', 'NanaZipAuto2Folder', 'NanaZipAuto3ShiftJIS' |
        ForEach-Object { "$Classes\SystemFileAssociations\.zip\shell\$_" }
    $progIds = @($IconExtensions | ForEach-Object { "$Classes\NanaZipAutoCP$_" })
    $keys = @($HandlerKeys.Keys) + $oldVerbs + "$Classes\CLSID\$DragClsid" + "$Classes\CLSID\$ContextMenuClsid" + $SettingsKey + $progIds
    foreach ($k in $keys) { if (Test-Path -LiteralPath $k) { Remove-Item -LiteralPath $k -Recurse } }
    foreach ($ext in $IconExtensions) { Remove-UserValue "Software\Classes\$ext\OpenWithProgids" "NanaZipAutoCP$ext" }
    Remove-UserValue $RegisteredAppsKey 'NanaZipAutoCP'
}

# Keeps the key's other values, which matters where other apps list themselves too (New-Item -Force
# would wipe them), and creates a Classes key in milliseconds where New-Item takes half a second
function Set-UserValue([string]$SubKey, [string]$Name, [string]$Value) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($SubKey)
    $key.SetValue($Name, $Value)
    $key.Dispose()
}

function Remove-UserValue([string]$SubKey, [string]$Name) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($SubKey, $true)
    if ($key) { $key.DeleteValue($Name, $false); $key.Dispose() }
}

function Copy-Payload([string]$Name) {
    $src = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Name))
    $dst = [IO.Path]::GetFullPath((Join-Path $InstallDir $Name))
    if ($src -ne $dst) {
        if ($Name -eq $Dll) {
            # Explorer keeps the DLL loaded: it can be renamed but not overwritten. Old renamed copies
            # are removed once Explorer has let go of them.
            Get-ChildItem -LiteralPath $InstallDir -Filter "$Dll.old*" | Remove-Item -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $dst) {
                try { Remove-Item -LiteralPath $dst }
                catch { Rename-Item -LiteralPath $dst -NewName "$Dll.old$([DateTime]::Now.Ticks)" }
            }
        }
        Copy-Item -LiteralPath $src -Destination $dst -Force
    }
    # Files from a downloaded zip carry the internet zone mark
    Unblock-File -LiteralPath $dst
}

try {
    if ($Uninstall) {
        Remove-Registration
        Update-ShellAssociations
        if (Test-Path -LiteralPath $InstallDir) {
            try { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
            catch {
                # Explorer still has the DLL loaded; delete the folder at the next sign-in
                Set-ItemProperty -LiteralPath $RunOnceKey -Name 'NanaZipAutoCPCleanup' -Value "cmd.exe /c rmdir /s /q `"$InstallDir`""
            }
        }
        Show-Result 'Removed the NanaZip auto encoding menu items and the "NanaZip (blue icon)" app. If you picked it as the default app for some types, pick another one for them.'
        return
    }

    # Everything that can fail runs before the registry is touched
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
        throw 'The menu items need 64-bit Windows on x64; NanaZipAutoCP.dll is not built for this PC.'
    }
    $alias = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WindowsApps\NanaZipG.exe'
    if (-not (Get-Command NanaZipG.exe -CommandType Application -ErrorAction SilentlyContinue) -and -not (Test-Path -LiteralPath $alias)) {
        throw 'NanaZip is not installed. Install it from the Microsoft Store or with: winget install M2Team.NanaZip'
    }
    foreach ($f in 'Expand-ArchiveAuto.ps1', $Dll) {
        if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $f))) { throw "$f must be next to the installer." }
    }
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) {
        Write-Warning 'Running as administrator: the menu items are installed for the account running this script.'
    }
    if ($Language -eq 'auto') {
        $Language = if ((Get-UICulture).TwoLetterISOLanguageName -eq 'ko') { 'ko' } else { 'en' }
    }
    $t = $Text[$Language]

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    foreach ($f in 'Expand-ArchiveAuto.ps1', 'Install-NanaZipAutoCP.ps1', $Dll) { Copy-Payload $f }
    $icon = Join-Path $InstallDir 'NanaZip.ico'
    try {
        $pkg = Get-AppxPackage -Name '*NanaZip*' |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.InstallLocation 'NanaZip.Modern.FileManager.exe') } |
            Sort-Object { [version]$_.Version } -Descending | Select-Object -First 1
        Export-PeIcon (Join-Path $pkg.InstallLocation 'NanaZip.Modern.FileManager.exe') $icon
    }
    catch { Write-Warning "Could not read NanaZip's icon: $($_.Exception.Message)" }
    if (-not (Test-Path -LiteralPath $icon)) { $icon = $null }

    Remove-Registration
    if (Test-Path -LiteralPath $RunOnceKey) { Remove-ItemProperty -LiteralPath $RunOnceKey -Name 'NanaZipAutoCPCleanup' -ErrorAction SilentlyContinue }
    New-Item -Path $SettingsKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $SettingsKey -Name Script -Value (Join-Path $InstallDir 'Expand-ArchiveAuto.ps1')
    Set-ItemProperty -LiteralPath $SettingsKey -Name Extensions -Value $ArchiveExtensions
    Set-ItemProperty -LiteralPath $SettingsKey -Name LabelSmart -Value $t.Smart
    Set-ItemProperty -LiteralPath $SettingsKey -Name LabelFolder -Value $t.Folder
    if ($icon) { Set-ItemProperty -LiteralPath $SettingsKey -Name Icon -Value $icon }
    foreach ($clsid in $DragClsid, $ContextMenuClsid) {
        $k = "$Classes\CLSID\$clsid"
        New-Item -Path "$k\InprocServer32" -Force | Out-Null
        Set-ItemProperty -LiteralPath $k -Name '(default)' -Value 'NanaZip auto encoding menu'
        Set-ItemProperty -LiteralPath "$k\InprocServer32" -Name '(default)' -Value (Join-Path $InstallDir $Dll)
        Set-ItemProperty -LiteralPath "$k\InprocServer32" -Name ThreadingModel -Value 'Apartment'
    }
    foreach ($k in $HandlerKeys.Keys) {
        New-Item -Path $k -Force | Out-Null
        Set-ItemProperty -LiteralPath $k -Name '(default)' -Value $HandlerKeys[$k]
    }

    # -open, as NanaZip registers itself, so NanaZip's "Extract on open" setting applies
    $nanazip = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\NanaZip.exe'
    # Settings > Apps > Default apps lists the app with all its types on one page
    $capabilities = 'Software\NanaZipAutoCP\Capabilities'
    Set-UserValue $capabilities ApplicationName $t.App
    Set-UserValue $capabilities ApplicationDescription $t.AppDescription
    if ($icon) { Set-UserValue $capabilities ApplicationIcon $icon }
    foreach ($ext in $IconExtensions) {
        $progId = "NanaZipAutoCP$ext"
        $progKey = "Software\Classes\$progId"
        Set-UserValue $progKey '' ($t.Type -f $ext.TrimStart('.').ToUpperInvariant())
        Set-UserValue "$progKey\Application" ApplicationName $t.App
        if ($icon) {
            Set-UserValue "$progKey\DefaultIcon" '' $icon
            Set-UserValue "$progKey\Application" ApplicationIcon $icon
        }
        Set-UserValue "$progKey\shell\open\command" '' "`"$nanazip`" `"%1`" -open"
        Set-UserValue "Software\Classes\$ext\OpenWithProgids" $progId ''
        Set-UserValue "$capabilities\FileAssociations" $ext $progId
    }
    Set-UserValue $RegisteredAppsKey 'NanaZipAutoCP' $capabilities
    Update-ShellAssociations
    Show-Result $t.Done
}
catch {
    Show-Result "NanaZip auto encoding: $($_.Exception.Message)" 'Error'
    exit 1
}
