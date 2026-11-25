$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$mod = Join-Path $root 'mod'
$build = Join-Path $root 'build/mod'

cmake -S $mod -B $build -G "Visual Studio 17 2022" -A x64
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }

cmake --build $build --config Release --target ds2_seamless_coop
if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

Get-ChildItem -LiteralPath $build -Recurse -File -Filter 'dinput8.dll' | Select-Object FullName, Length
