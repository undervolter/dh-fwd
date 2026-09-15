param(
    [string]$Version  = "v2.3.1",
    [string]$OutDir   = "builds"
)

$ErrorActionPreference = "Stop"

# Targets
$Targets = @(
    @{ GOOS = "windows"; GOARCH = "amd64"; Name = "dh-fwd_win_x64.exe"   }
    @{ GOOS = "windows"; GOARCH = "arm64"; Name = "dh-fwd_win_arm64.exe" }
    @{ GOOS = "linux";   GOARCH = "amd64"; Name = "dh-fwd_linux_x64"     }
    @{ GOOS = "linux";   GOARCH = "arm64"; Name = "dh-fwd_linux_arm64"   }
)

# Prep
$Root = $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }

New-Item -ItemType Directory -Force -Path "$Root\$OutDir" | Out-Null

$LdFlags = "-s -w -X main.Version=$Version"
$ok  = 0
$err = 0

Write-Host ""
Write-Host "  dh-fwd cross-build  |  version: $Version" -ForegroundColor Cyan
Write-Host "  output: $OutDir\" -ForegroundColor Cyan
Write-Host ("  " + ("-" * 52)) -ForegroundColor DarkGray
Write-Host ""

# Build loop
foreach ($t in $Targets) {
    $out   = "$Root\$OutDir\$($t.Name)"
    $label = "$($t.GOOS)/$($t.GOARCH)".PadRight(18)

    $env:GOOS        = $t.GOOS
    $env:GOARCH      = $t.GOARCH
    $env:CGO_ENABLED = "0"

    Write-Host -NoNewline "  building $label  ->  $($t.Name)  "

    $sw     = [System.Diagnostics.Stopwatch]::StartNew()
    $result = & go build -trimpath -ldflags $LdFlags -o $out . 2>&1
    $sw.Stop()

    if ($LASTEXITCODE -eq 0) {
        $size    = (Get-Item $out).Length
        $sizeStr = if ($size -ge 1MB) { "{0:F1} MB" -f ($size / 1MB) }
                   else               { "{0} KB"    -f [int]($size / 1KB) }
        Write-Host ("[ OK  {0,6}  {1,3}ms ]" -f $sizeStr, $sw.ElapsedMilliseconds) -ForegroundColor Green
        $ok++
    } else {
        Write-Host "[ FAIL ]" -ForegroundColor Red
        Write-Host "    $result" -ForegroundColor DarkRed
        $err++
    }
}

# Cleanup env
Remove-Item Env:\GOOS        -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH      -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue

# Summary
Write-Host ""
Write-Host ("  " + ("-" * 52)) -ForegroundColor DarkGray
if ($err -eq 0) {
    Write-Host "  All $ok builds succeeded." -ForegroundColor Green
} else {
    Write-Host "  $ok succeeded, $err failed." -ForegroundColor Yellow
}
Write-Host ""
