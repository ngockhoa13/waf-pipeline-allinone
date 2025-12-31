# PowerShell cleanup script for Windows
# Run this before committing to GitHub

Write-Host "🧹 Cleaning up unnecessary files..." -ForegroundColor Cyan

# Remove empty marker files
if (Test-Path "[automation]") { Remove-Item "[automation]"; Write-Host "✓ Removed [automation]" }
if (Test-Path "[modsec]") { Remove-Item "[modsec]"; Write-Host "✓ Removed [modsec]" }

# Remove debug scripts
if (Test-Path "deep_diagnostic.sh") { Remove-Item "deep_diagnostic.sh"; Write-Host "✓ Removed deep_diagnostic.sh" }

# Remove backup files
Get-ChildItem -Filter "*.backup*" | Remove-Item -Force
Get-ChildItem -Filter "*.bak" | Remove-Item -Force
Write-Host "✓ Removed backup files" -ForegroundColor Green

# Remove mysterious files
@("exporting", "naming", "transferring", "writing", "=") | ForEach-Object {
    if (Test-Path $_) { Remove-Item $_; Write-Host "✓ Removed $_" }
}

Write-Host "`n✅ Cleanup complete!" -ForegroundColor Green
Write-Host "`n📋 Git status:" -ForegroundColor Yellow
git status --short
