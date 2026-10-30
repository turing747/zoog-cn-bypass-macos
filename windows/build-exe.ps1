# Optional: build a single-file zoog-cn-bypass.exe with PyInstaller (no Python needed at runtime).
#   powershell -ExecutionPolicy Bypass -File .\build-exe.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
python -m pip install --user -r requirements-build.txt
$data = Join-Path $PSScriptRoot '..\data'
python -m PyInstaller --noconfirm --onefile --name zoog-cn-bypass `
    --add-data "$data;data" `
    --distpath .\dist --workpath .\build `
    --paths . zoog_cn_bypass\__main__.py
Write-Host "Built: $PSScriptRoot\dist\zoog-cn-bypass.exe"
Write-Host "Copy it next to zoog-cn-bypass.cmd or run it directly (install/status/...)."
