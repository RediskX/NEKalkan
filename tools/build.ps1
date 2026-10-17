# NEKalkan build (Windows x64): LLVM only, no CRT, no Windows SDK.
#   .\tools\build.ps1            - out\NEKalkan.dll (production) + out\NEKalkan_test.dll (same engine + test C API)
#   .\tools\build.ps1 -Debug     - no optimization, debug info
#   .\tools\build.ps1 -Guard     - also out\NEKalkan_guard_test.dll: test DLL with a guard-page heap (catches overruns / use-after-free)
param([string]$LlvmBin = 'C:\Program Files\LLVM\bin', [switch]$Debug, [switch]$Guard, [string]$Out = 'out\NEKalkan.dll')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    New-Item -ItemType Directory -Path build, out -Force | Out-Null
    $cc = Join-Path $LlvmBin 'clang++.exe'
    $link = Join-Path $LlvmBin 'lld-link.exe'
    foreach ($lib in @('kernel32', 'advapi32')) {
        & $link /lib /machine:x64 "/def:tools/$lib.def" "/out:build/$lib.lib"
        if ($LASTEXITCODE) { throw "Import library failed: $lib" }
    }
    $opt = if ($Debug) { @('-O0', '-g') } else { @('-O2') }
    $flags = @('--target=x86_64-pc-windows-msvc', '-std=c++17', '-fms-extensions', '-fno-rtti', '-fno-exceptions',
        '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-ffreestanding', '-nostdlib', '-mno-stack-arg-probe',
        '-Wall', '-Wextra', '-Wno-unused-parameter', '-Werror', '-Isrc') + $opt
    $libs = @('build/kernel32.lib', 'build/advapi32.lib')

    # Compiles every source into $dir and returns @{common; native; testapi}
    function Compile-All([string]$dir, [string[]]$extra) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $r = @{ common = @(); native = @(); testapi = @() }
        foreach ($src in Get-ChildItem src -Filter *.cpp | Where-Object { $_.Name -notmatch '_linux\.cpp$' }) {
            $obj = "$dir/$($src.BaseName).obj"
            & $cc @flags @extra -c $src.FullName -o $obj
            if ($LASTEXITCODE) { throw "Compilation failed: $($src.Name)" }
            if ($src.Name -eq 'native1c.cpp') { $r.native += $obj } elseif ($src.Name -eq 'capi.cpp') { $r.testapi += $obj } else { $r.common += $obj }
        }
        return $r
    }
    function Link-Dll([string]$dll, [string]$implib, [string[]]$objs) {
        & $link /dll /timestamp:0 /nodefaultlib /machine:x64 /entry:DllMain "/out:$dll" "/implib:$implib" @objs @libs
        if ($LASTEXITCODE) { throw "Link failed: $dll" }
    }

    $outDir = Split-Path -Parent $Out
    $testOut = Join-Path $outDir 'NEKalkan_test.dll'
    $o = Compile-All 'build' @()
    Link-Dll $Out 'build/NEKalkan.lib' ($o.common + $o.native)
    Link-Dll $testOut 'build/NEKalkan_test.lib' ($o.common + $o.testapi)
    Write-Host "OK: $Out ($((Get-Item $Out).Length) bytes), $testOut ($((Get-Item $testOut).Length) bytes)"

    if ($Guard) {
        $g = Compile-All 'build/guard' @('-DNEK_GUARD_HEAP')
        $guardOut = Join-Path $outDir 'NEKalkan_guard_test.dll'
        Link-Dll $guardOut 'build/NEKalkan_guard_test.lib' ($g.common + $g.testapi)
        Write-Host "OK: $guardOut ($((Get-Item $guardOut).Length) bytes)"
    }
} finally { Pop-Location }
