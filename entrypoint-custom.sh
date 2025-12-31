#!/bin/sh
set -e

echo "=== Custom ModSecurity Setup ==="

# Show what we have
echo "Config files:"
ls -lh /etc/modsecurity.d/modsec-main.conf 2>/dev/null || echo "modsec-main.conf not found"
ls -lh /etc/modsecurity.d/modsecurity.conf 2>/dev/null || echo "modsecurity.conf not found"
ls -lh /etc/modsecurity.d/modsecurity-override.conf 2>/dev/null || echo "modsecurity-override.conf not found"

# Verify audit setting
echo ""
echo "Audit log settings:"
grep "SecAuditLogRelevantStatus" /etc/modsecurity.d/*.conf 2>/dev/null || echo "No SecAuditLogRelevantStatus found"

echo ""
echo "=== Setup Complete ==="
echo ""

# Continue with original entrypoint
exec /docker-entrypoint.sh "$@"
