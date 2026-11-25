$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src/ds2net/proxy.cpp'
$outDir = Join-Path $root 'build'
$dll = Join-Path $outDir 'steam_api64.dll'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

& g++ -std=c++17 -O2 -shared -static-libgcc -static-libstdc++ -o $dll $src -lws2_32 -Wl,--no-insert-timestamp
if ($LASTEXITCODE -ne 0) { throw "g++ failed with exit code $LASTEXITCODE" }

Get-Item $dll | Select-Object FullName, Length, LastWriteTime
