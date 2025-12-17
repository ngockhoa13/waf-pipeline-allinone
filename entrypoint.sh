#!/bin/sh
set -e

echo "════════════════════════════════════════════════════"
echo " 🚀 WAF TESTING PIPELINE - NGINX + MODSECURITY"
echo "════════════════════════════════════════════════════"
echo " Target Domain: $TARGET_DOMAIN"
echo " Output Directory: $OUTPUT_DIR"
echo "════════════════════════════════════════════════════"

mkdir -p /output /var/log/nginx /var/log/modsecurity/audit

# Replace TARGET_DOMAIN in nginx config
sed -i "s/\${TARGET_DOMAIN}/$TARGET_DOMAIN/g" /etc/nginx/conf.d/default.conf

# Start Nginx
echo "🔧 Starting Nginx + ModSecurity WAF..."
nginx -t
nginx &

# Wait for port 8080
echo "⏳ Waiting for Nginx to listen on 8080..."
for i in $(seq 1 30); do
    if nc -z localhost 8080 2>/dev/null; then
        echo "✅ Nginx + ModSecurity ready on :8080"
        break
    fi
    sleep 1
done

echo "🔧 Starting OWASP ZAP daemon..."
/opt/zap/zap.sh -daemon -host 0.0.0.0 -port 8081 \
    -config api.disablekey=true \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true \
    -config start.checkForUpdates=false \
    -addoninstallall > /var/log/zap.log 2>&1 &

ZAP_PID=$!

# Wait for ZAP to be REALLY ready - check for valid JSON response
echo "⏳ Waiting for ZAP API to return valid JSON responses..."
WAIT_COUNT=0
MAX_WAIT=180  # 3 minutes

while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
    # Try to get a JSON response from ZAP
    if RESPONSE=$(curl -s http://localhost:8081/JSON/core/view/version/ 2>&1); then
        # Check if it's valid JSON by looking for expected fields
        if echo "$RESPONSE" | grep -q '"version"'; then
            echo "✅ ZAP API is fully ready and returning JSON!"
            # Give it a few more seconds to stabilize
            sleep 5
            break
        fi
    fi
    
    sleep 2
    WAIT_COUNT=$((WAIT_COUNT + 2))
    
    if [ $((WAIT_COUNT % 10)) -eq 0 ]; then
        echo "   Still waiting... ${WAIT_COUNT}s elapsed (ZAP initializing)"
    fi
done

if [ $WAIT_COUNT -ge $MAX_WAIT ]; then
    echo "❌ ZAP timeout after ${MAX_WAIT} seconds"
    echo "Last 50 lines of ZAP log:"
    tail -50 /var/log/zap.log
    exit 1
fi

# Verify ZAP is truly ready with multiple API calls
echo "🔍 Verifying ZAP API endpoints..."
for endpoint in "core/view/version" "core/view/mode" "core/view/homeDirectory"; do
    if ! curl -f -s "http://localhost:8081/JSON/${endpoint}/" > /dev/null 2>&1; then
        echo "⚠️  Warning: ZAP endpoint /${endpoint} not responding"
    fi
done

echo "✅ ZAP verification complete!"

# Phase 1: Capture baseline traffic
echo ""
echo "🎯 Phase 1: Capturing baseline traffic..."
export TARGET_URL="http://$TARGET_DOMAIN"
export ZAP_ADDR="127.0.0.1"
export ZAP_PORT="8081"
export WAF_PORT="8080"
export PHASE1_CSV="/output/phase1_baseline.csv"

python3 /opt/phase1_capture.py

if [ ! -f "$PHASE1_CSV" ]; then
    echo "❌ Phase 1 failed - no CSV generated"
    echo "Last 100 lines of ZAP log:"
    tail -100 /var/log/zap.log
    exit 1
fi

# Phase 2: Replay through WAF
echo ""
echo "🛡️  Phase 2: Replaying through ModSecurity WAF..."
export PHASE2_CSV="/output/phase2_waf_results.csv"
export PHASE2_JSON="/output/phase2_waf_results.json"

python3 /opt/phase2_replay.py \
    -i "$PHASE1_CSV" \
    -o "$PHASE2_CSV" \
    -j "$PHASE2_JSON" \
    -p 8080

# Summary
if [ -f "$PHASE2_CSV" ]; then
    TOTAL=$(wc -l < "$PHASE2_CSV" | tr -d ' ')
    ATTACK=$(grep -c ',attack,' "$PHASE2_CSV" 2>/dev/null || echo 0)
    BENIGN=$(grep -c ',benign,' "$PHASE2_CSV" 2>/dev/null || echo 0)

    echo "════════════════════════════════════════════════════"
    echo " ✅ PIPELINE COMPLETED SUCCESSFULLY!"
    echo " Total Requests: $TOTAL"
    echo " Attack Requests: $ATTACK"
    echo " Benign Requests: $BENIGN"
    echo "════════════════════════════════════════════════════"
else
    echo "❌ Phase 2 failed - no results file"
    exit 1
fi
