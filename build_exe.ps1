$ErrorActionPreference = "Stop"

if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    python -m pip install --upgrade pyinstaller
}

python -m PyInstaller `
    --noconfirm `
    --onefile `
    --windowed `
    --name "PhishingURLDetector" `
    --clean `
    main.py

Write-Host ""
Write-Host "EXE created at: $PWD\dist\PhishingURLDetector.exe"
