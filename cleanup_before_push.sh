#!/bin/bash
# Cleanup script before pushing to GitHub
# Usage: ./cleanup_before_push.sh

echo "🧹 Cleaning up unnecessary files..."

# Backup files
echo "Removing backup files..."
rm -f *.backup
rm -f *.backup.*
rm -f *.bak
rm -f default.conf.template.backup*
rm -f Dockerfile.modsec.backup*
rm -f docker-compose.yml.bak
rm -f modsecurity*.backup*
rm -f phase2_replay.py.backup

# Temporary/debug scripts
echo "Removing temporary scripts..."
rm -f fix_*.sh
rm -f test_*.sh
rm -f debug_*.sh
rm -f apply_config_fix.sh
rm -f ultimate_fix.sh
rm -f analyze_verification.py

# Mysterious temp files
echo "Removing mysterious files..."
rm -f exporting naming transferring writing =

# Optional: DVWA files (uncomment if not using DVWA)
# echo "Removing DVWA setup..."
# rm -f docker-compose.dvwa.yml
# rm -f setup_dvwa.sh

# Clean output/results (keep structure)
echo "Cleaning output directories..."
rm -rf output/*
rm -rf results/*
mkdir -p output
mkdir -p results
touch output/.gitkeep
touch results/.gitkeep

# Clean empty logs
rm -rf logs/*
mkdir -p logs
touch logs/.gitkeep

echo "✅ Cleanup complete!"
echo ""
echo "📋 Files to commit:"
git status --short

echo ""
echo "⚠️  Review the changes above before committing"
echo "💡 To commit: git add . && git commit -m 'Clean up temporary files'"
