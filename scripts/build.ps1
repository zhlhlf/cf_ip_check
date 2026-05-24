param(
    [string]$Version = "dev",
    [switch]$SkipAndroid
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

function Invoke-GoBuild {
    param(
        [string]$GOOS,
        [string]$GOARCH,
        [string]$Ext,
        [string]$CGO = "0",
        [string]$CC = ""
    )

    $name = "cfip-$GOOS-$GOARCH$Ext"
    $out = Join-Path $dist $name
    Write-Host "Building $name"
    $env:CGO_ENABLED = $CGO
    $env:GOOS = $GOOS
    $env:GOARCH = $GOARCH
    if ($CC) {
        $env:CC = $CC
    } else {
        Remove-Item Env:CC -ErrorAction SilentlyContinue
    }

    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $out .
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed for $GOOS/$GOARCH"
    }
}

Invoke-GoBuild -GOOS windows -GOARCH amd64 -Ext ".exe"
Invoke-GoBuild -GOOS linux -GOARCH amd64 -Ext ""
Invoke-GoBuild -GOOS darwin -GOARCH amd64 -Ext ""

if (-not $SkipAndroid) {
    $androidCC = $env:ANDROID_CC
    if (-not $androidCC -and $env:ANDROID_NDK_HOME) {
        $hostTag = if ($IsLinux) { "linux-x86_64" } elseif ($IsMacOS) { "darwin-x86_64" } else { "windows-x86_64" }
        $clangName = if ($IsWindows -or $env:OS -eq "Windows_NT") { "x86_64-linux-android21-clang.cmd" } else { "x86_64-linux-android21-clang" }
        $candidate = Join-Path $env:ANDROID_NDK_HOME "toolchains\llvm\prebuilt\$hostTag\bin\$clangName"
        if (Test-Path $candidate) {
            $androidCC = $candidate
        }
    }

    if (-not $androidCC) {
        throw "android/amd64 requires Android NDK. Set ANDROID_NDK_HOME or ANDROID_CC, or pass -SkipAndroid."
    }

    Invoke-GoBuild -GOOS android -GOARCH amd64 -Ext "" -CGO "1" -CC $androidCC
}

Compress-Archive -Path (Join-Path $dist "cfip-*") -DestinationPath (Join-Path $dist "cfip-$Version-all.zip") -Force
Write-Host "Done: $dist"
