[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Executable
)

$ErrorActionPreference = 'Stop'

$exePath = (Resolve-Path -LiteralPath $Executable).Path
$vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswherePath)) {
    throw "vswhere.exe not found: $vswherePath"
}

$vsInstallPath = & $vswherePath -latest -products '*' -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($vsInstallPath)) {
    throw 'Visual Studio installation was not found; cannot inspect PE imports.'
}

$msvcToolsPath = Join-Path $vsInstallPath 'VC/Tools/MSVC'
$dumpbin = Get-ChildItem -Path $msvcToolsPath -Filter dumpbin.exe -Recurse |
    Where-Object { $_.FullName -match '\\Hostx64\\x64\\dumpbin\.exe$' } |
    Select-Object -First 1
if (-not $dumpbin) {
    throw 'x64 dumpbin.exe was not found in the Visual Studio installation.'
}

$dependencyOutput = & $dumpbin.FullName /DEPENDENTS $exePath 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "dumpbin /DEPENDENTS failed:`n$($dependencyOutput -join "`n")"
}
$dependencyText = $dependencyOutput -join "`n"
Write-Host $dependencyText

if ($dependencyText -match '(?im)^\s*sqlite3\.dll\s*$') {
    throw 'The executable imports sqlite3.dll. Use the x64-windows-static vcpkg triplet.'
}

Write-Host 'Static SQLite import check passed: sqlite3.dll is not a PE dependency.'
