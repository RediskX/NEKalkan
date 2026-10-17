# Packs NEKalkan.dll into a 1C external component ZIP (MANIFEST.XML + DLL): out\NEKalkan_win64.zip
param([string]$Dll = 'out\NEKalkan.dll', [string]$Out = 'out\NEKalkan_win64.zip')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (-not (Test-Path $Dll)) { throw "Missing $Dll - run tools\build.ps1 first" }
    $stage = Join-Path $root 'build\package'
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item $Dll (Join-Path $stage 'NEKalkan.dll')
    $manifest = @'
<?xml version="1.0" encoding="UTF-8"?>
<bundle xmlns="http://v8.1c.ru/8.2/addin/bundle">
  <component os="Windows" path="NEKalkan.dll" type="native" arch="x86_64"/>
</bundle>
'@
    [System.IO.File]::WriteAllText((Join-Path $stage 'MANIFEST.XML'), $manifest, (New-Object System.Text.UTF8Encoding($false)))
    Remove-Item $Out -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $Out -CompressionLevel Optimal
    $hash = (Get-FileHash $Out -Algorithm SHA256).Hash
    Write-Host "OK: $Out ($((Get-Item $Out).Length) bytes) SHA256=$hash"
} finally { Pop-Location }
