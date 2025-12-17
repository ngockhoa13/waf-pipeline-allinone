#!/bin/bash
set -e

echo "════════════════════════════════════════════════════"
echo " 🤖 AUTOMATION CONTROLLER"
echo "════════════════════════════════════════════════════"
echo " Target: $TARGET_DOMAIN"
echo " ZAP: $ZAP_HOST:$ZAP_PORT"
echo " WAF: $MODSEC_HOST:$MODSEC_PORT"
echo "════════════════════════════════════════════════════"

# Wait for services
echo "⏳ Waiting for ZAP service..."
for i in $(seq 1 60); do
    if curl -f -s "http://${ZAP_HOST}:${ZAP_PORT}/JSON/core/view/version/" > /dev/null 2>&1; then
        echo "✅ ZAP is ready!"
        break
    fi
    sleep 2
done

echo "⏳ Waiting for ModSecurity WAF..."
for i in $(seq 1 30); do
    if nc -z ${MODSEC_HOST} ${MODSEC_PORT} 2>/dev/null; then
        echo "✅ WAF is ready!"
        break
    fi
    sleep 1
done

echo "⏳ Waiting 10 seconds for services to stabilize..."
sleep 10

# Phase 1: ZAP Scan
echo ""
echo "════════════════════════════════════════════════════"
echo " 📡 PHASE 1: ZAP Attack Generation"
echo "════════════════════════════════════════════════════"

export TARGET_URL="http://${TARGET_DOMAIN}"
export PHASE1_CSV="/output/phase1_baseline.csv"

python3 /opt/phase1_capture.py

if [ ! -f "$PHASE1_CSV" ]; then
    echo "❌ Phase 1 failed!"
    exit 1
fi

PHASE1_LINES=$(wc -l < "$PHASE1_CSV")
echo "✅ Phase 1 complete: $PHASE1_LINES lines generated"

# Phase 2: WAF Testing
echo ""
echo "════════════════════════════════════════════════════"
echo " 🛡️  PHASE 2: WAF Classification"
echo "════════════════════════════════════════════════════"

export PHASE2_CSV="/output/phase2_waf_results.csv"
export PHASE2_JSON="/output/phase2_waf_results.json"
export MODSEC_LOG="/tmp/modsec_audit.log"

if [ -f "$MODSEC_LOG" ]; then
    echo "✅ Audit log found: $MODSEC_LOG"
else
    echo "⚠️  WARNING: Audit log not found at $MODSEC_LOG"
fi

python3 /opt/phase2_replay.py \
    -i "$PHASE1_CSV" \
    -o "$PHASE2_CSV" \
    -j "$PHASE2_JSON" \
    --host ${MODSEC_HOST} \
    -p ${MODSEC_PORT} \
    -l "$MODSEC_LOG" \
    -w 6

if [ ! -f "$PHASE2_CSV" ]; then
    echo "❌ Phase 2 failed!"
    exit 1
fi

# Summary - FIX: Use column 13 (label) instead of column 8
TOTAL=$(tail -n +2 "$PHASE2_CSV" | wc -l | tr -d ' ')
ATTACK=$(tail -n +2 "$PHASE2_CSV" | cut -d',' -f13 | grep -c "attack" 2>/dev/null || echo 0)
BENIGN=$(tail -n +2 "$PHASE2_CSV" | cut -d',' -f13 | grep -c "benign" 2>/dev/null || echo 0)

# Technique breakdown
echo ""
echo "════════════════════════════════════════════════════"
echo " ✅ PIPELINE COMPLETED!"
echo "════════════════════════════════════════════════════"
echo " Total Requests: $TOTAL"
echo " Detected as Attack: $ATTACK"
echo " Detected as Benign: $BENIGN"
echo ""
echo " 📊 Attack Techniques Breakdown:"
tail -n +2 "$PHASE2_CSV" | grep ',attack,' | cut -d',' -f14 | sort | uniq -c | sort -rn | head -10 | while read count tech; do
    echo "    - $tech: $count"
done
echo "════════════════════════════════════════════════════"
echo ""
echo "📁 Results saved to /output/"
echo "   - Phase 1: $PHASE1_CSV"
echo "   - Phase 2: $PHASE2_CSV"
echo "   - Phase 2: $PHASE2_JSON"
echo ""
