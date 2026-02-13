param(
    [string]$SourceApk = "",
    [string]$KeystorePath = "$env:USERPROFILE\.android\debug.keystore",
    [string]$KeystoreAlias = "androiddebugkey",
    [string]$StorePass = "android",
    [string]$KeyPass = "android"
)

$ErrorActionPreference = "Stop"

function Find-ToolPath {
    param(
        [string]$ToolName,
        [string[]]$FallbackGlobs
    )

    $fromPath = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($fromPath) {
        return $fromPath.Source
    }

    foreach ($glob in $FallbackGlobs) {
        $candidates = Get-ChildItem -Path $glob -File -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending
        if ($candidates) {
            return $candidates[0].FullName
        }
    }

    return $null
}

function Find-NewestUnsignedApk {
    $downloads = Join-Path $env:USERPROFILE "Downloads"
    if (-not (Test-Path $downloads)) {
        throw "Downloads folder not found at $downloads"
    }

    $apk = Get-ChildItem $downloads -Recurse -File -Filter "*unsigned.apk" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $apk) {
        throw "No *unsigned.apk found in Downloads. Build/download an APK first."
    }

    return $apk.FullName
}

if ([string]::IsNullOrWhiteSpace($SourceApk)) {
    $SourceApk = Find-NewestUnsignedApk
}

if (-not (Test-Path $SourceApk)) {
    throw "Source APK not found: $SourceApk"
}

if (-not (Test-Path $KeystorePath)) {
    throw "Keystore not found: $KeystorePath"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$downloadsDir = Join-Path $repoRoot "static\downloads"
if (-not (Test-Path $downloadsDir)) {
    throw "Target folder not found: $downloadsDir"
}

$apksigner = Find-ToolPath -ToolName "apksigner.bat" -FallbackGlobs @(
    "C:\android-sdk\build-tools\*\apksigner.bat",
    "$env:LOCALAPPDATA\Android\Sdk\build-tools\*\apksigner.bat"
)
$zipalign = Find-ToolPath -ToolName "zipalign.exe" -FallbackGlobs @(
    "C:\android-sdk\build-tools\*\zipalign.exe",
    "$env:LOCALAPPDATA\Android\Sdk\build-tools\*\zipalign.exe"
)

if (-not $apksigner -or -not $zipalign) {
    throw "apksigner/zipalign not found. Install Android build-tools (e.g. 34.0.0) first."
}

$tmpDir = [System.IO.Path]::GetTempPath()
$tempAligned = Join-Path $tmpDir ("SafeScan-aligned-" + (Get-Date -Format "yyyyMMddHHmmss") + ".apk")
$tempSigned = Join-Path $tmpDir ("SafeScan-signed-" + (Get-Date -Format "yyyyMMddHHmmss") + ".apk")

& $zipalign -p -f 4 $SourceApk $tempAligned
if ($LASTEXITCODE -ne 0) {
    throw "zipalign failed."
}

& $apksigner sign `
    --ks $KeystorePath `
    --ks-key-alias $KeystoreAlias `
    --ks-pass ("pass:" + $StorePass) `
    --key-pass ("pass:" + $KeyPass) `
    --out $tempSigned `
    $tempAligned

if ($LASTEXITCODE -ne 0) {
    throw "apksigner sign failed."
}

& $apksigner verify --verbose $tempSigned | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "APK signature verification failed."
}

$apkMain = Join-Path $downloadsDir "SafeScan.apk"
$apkCompat = Join-Path $downloadsDir "SafeScanOffline.apk"

Copy-Item $tempSigned $apkMain -Force
Copy-Item $tempSigned $apkCompat -Force

$mainHash = (Get-FileHash $apkMain -Algorithm SHA256).Hash

Write-Host "APK updated successfully."
Write-Host "Source: $SourceApk"
Write-Host "Target: $apkMain"
Write-Host "SHA256: $mainHash"
Write-Host "Also updated: $apkCompat"
