# build_ios.ps1 - local cross-compile of an iOS arm64 IPA (no CI, no macOS)
# NOTE: keep this file pure ASCII - PowerShell 5.1 parses .ps1 as GBK and non-ASCII breaks it.
# Usage:
#   .\build_ios.ps1 -Name iogpu_probe -Src E:\IOS18.7.2\poc\iogpu_probe.m -Plist E:\IOS18.7.2\poc\Info_iogpu.plist
param(
  [Parameter(Mandatory=$true)][string]$Name,
  [Parameter(Mandatory=$true)][string]$Src,
  [Parameter(Mandatory=$true)][string]$Plist,
  [string[]]$Frameworks = @('IOKit','CoreFoundation','UIKit','Foundation'),
  [string]$OutDir = 'E:\IOS18.7.2\poc\localbuild'
)

$ErrorActionPreference = 'Stop'
$LLVM = 'D:\ReverseKit\llvm233\clang+llvm-23.1.6-x86_64-pc-windows-msvc\bin'
$SDK  = 'D:\ReverseKit\sdks-repo\iPhoneOS16.5.sdk'

if (-not (Test-Path "$LLVM\clang.exe"))    { throw "clang.exe missing at $LLVM" }
if (-not (Test-Path "$LLVM\ld64.lld.exe")) { throw "ld64.lld.exe missing at $LLVM" }
if (-not (Test-Path "$SDK\usr\lib\libSystem.tbd")) { throw "SDK incomplete (no libSystem.tbd)" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
# clean Payload so a previous build's .app does not leak into this IPA
$payloadRoot = Join-Path $OutDir 'Payload'
if (Test-Path $payloadRoot) { Remove-Item $payloadRoot -Recurse -Force }
$app = Join-Path $OutDir ('Payload\' + $Name + '.app')
New-Item -ItemType Directory -Force -Path $app | Out-Null

$obj = Join-Path $OutDir ($Name + '.o')
$bin = Join-Path $app $Name

Write-Host "==> compile $Src"
& "$LLVM\clang.exe" -target arm64-apple-ios16.0 -isysroot $SDK -F"$SDK/System/Library/Frameworks" `
    -Os -fobjc-arc -fno-stack-protector -c $Src -o $obj
if ($LASTEXITCODE -ne 0) { throw "compile failed ($LASTEXITCODE)" }

Write-Host "==> link"
$fwArgs = @()
foreach ($f in $Frameworks) { $fwArgs += @('-framework', $f) }
& "$LLVM\ld64.lld.exe" -arch arm64 -platform_version ios 16.0 16.0 `
    -syslibroot $SDK -L"$SDK/usr/lib" `
    -o $bin $obj @fwArgs -lSystem
if ($LASTEXITCODE -ne 0) { throw "link failed ($LASTEXITCODE)" }

Write-Host "==> package"
Copy-Item $Plist (Join-Path $app 'Info.plist') -Force
$plistTxt = Get-Content (Join-Path $app 'Info.plist') -Raw
if ($plistTxt -notmatch ('<string>' + [regex]::Escape($Name) + '</string>')) {
    Write-Warning "Info.plist CFBundleExecutable may not be '$Name' (install/sign will fail)"
}

$ipa = Join-Path $OutDir ($Name + '.ipa')
# Pack with an explicit entry order (Info.plist BEFORE the binary) because i4Tools
# rejects IPAs whose binary comes first, and 7-Zip always sorts alphabetically.
$packer = Join-Path $PSScriptRoot 'pack_ipa.py'
& python $packer $ipa $app $Name
if ($LASTEXITCODE -ne 0) { throw "pack_ipa.py failed ($LASTEXITCODE)" }

$binLen = (Get-Item $bin).Length
$magic  = [System.BitConverter]::ToString([System.IO.File]::ReadAllBytes($bin)[0..3])
Write-Host ""
Write-Host "OK: $ipa"
Write-Host ("    binary = " + $bin + "  (" + $binLen + " bytes, magic=" + $magic + ")")
Write-Host "    expect magic = FE-ED-FA-CF (MH_MAGIC_64)"