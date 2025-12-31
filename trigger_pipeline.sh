#!/bin/bash
#
# WAF PIPELINE TRIGGER
# ====================
# Chạy pipeline cho domain mới mà KHÔNG CẦN rebuild containers
#
# Usage:
#   ./trigger_pipeline.sh <target_url> [output_dir] [cookie]
#
# Examples:
#   ./trigger_pipeline.sh https://testaspnet.vulnweb.com
#   ./trigger_pipeline.sh https://example.com ./results/example
#   ./trigger_pipeline.sh https://example.com ./results/example "session=abc123; auth=xyz"
#
# Note:
#   - target_url có thể là full URL (https://example.com) hoặc domain (example.com)
#   - cookie là optional, dùng để crawl các trang cần đăng nhập
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ====================== PARSE ARGUMENTS ======================
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: Target URL required${NC}"
    echo ""
    echo "Usage: $0 <target_url> [output_dir] [cookie]"
    echo ""
    echo "Examples:"
    echo "  $0 https://testaspnet.vulnweb.com"
    echo "  $0 https://example.com ./results/example"
    echo "  $0 https://example.com ./results/example \"session=abc123; auth=xyz\""
    echo ""
    echo "Notes:"
    echo "  - target_url: full URL (https://example.com) or domain (example.com)"
    echo "  - cookie: optional, for authenticated crawling"
    exit 1
fi

TARGET_INPUT="$1"
OUTPUT_BASE="${2:-./output}"
COOKIE="${3:-}"

# Parse target URL - extract domain for directory naming
if [[ "$TARGET_INPUT" =~ ^https?:// ]]; then
    # Full URL provided (https://example.com)
    TARGET_URL="$TARGET_INPUT"
    TARGET_DOMAIN=$(echo "$TARGET_INPUT" | sed -E 's|^https?://||' | sed -E 's|/.*||')
else
    # Only domain provided (example.com)
    TARGET_URL="http://$TARGET_INPUT"
    TARGET_DOMAIN="$TARGET_INPUT"
fi

# Create unique output directory for this run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${OUTPUT_BASE}/${TARGET_DOMAIN}_${TIMESTAMP}"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           WAF PIPELINE TRIGGER                             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Target URL:${NC}     ${TARGET_URL}"
echo -e "${GREEN}Target Domain:${NC}  ${TARGET_DOMAIN}"
echo -e "${GREEN}Output Dir:${NC}     ${OUTPUT_DIR}"
if [ -n "$COOKIE" ]; then
    COOKIE_PREVIEW=$(echo "$COOKIE" | cut -c1-30)
    echo -e "${GREEN}Cookie:${NC}         ${COOKIE_PREVIEW}... (authenticated mode)"
else
    echo -e "${GREEN}Cookie:${NC}         None (anonymous mode)"
fi
echo ""

# ====================== CHECK CONTAINERS ======================
echo -e "${YELLOW}[1/5] Checking containers...${NC}"

if ! docker ps | grep -q "waf-zap"; then
    echo -e "${RED}❌ ZAP container not running!${NC}"
    echo "Start with: docker-compose up -d zap"
    exit 1
fi

if ! docker ps | grep -q "waf-modsec"; then
    echo -e "${RED}❌ ModSec container not running!${NC}"
    echo "Start with: docker-compose up -d modsec"
    exit 1
fi

if ! docker ps | grep -q "waf-automation"; then
    echo -e "${RED}❌ Automation container not running!${NC}"
    echo "Start with: docker-compose up -d automation"
    exit 1
fi

echo -e "${GREEN}✓ All containers running${NC}"

# ====================== CREATE OUTPUT DIR ======================
echo -e "\n${YELLOW}[2/5] Creating output directory...${NC}"

mkdir -p "${OUTPUT_DIR}"

echo -e "${GREEN}✓ Output directory created: ${OUTPUT_DIR}${NC}"

# ====================== CLEAR PREVIOUS STATE ======================
echo -e "\n${YELLOW}[3/5] Clearing previous state...${NC}"

# Clear ZAP session
docker exec waf-zap curl -s "http://localhost:8080/JSON/core/action/newSession/?zapapiformat=JSON" > /dev/null 2>&1 || true

# Clear ModSec logs
docker exec waf-modsec sh -c "truncate -s 0 /tmp/modsec_audit.log" 2>/dev/null || true
docker exec waf-modsec sh -c "truncate -s 0 /tmp/modsec_debug.log" 2>/dev/null || true

# Clear automation completion flag
docker exec waf-automation rm -f /output/.pipeline_completed 2>/dev/null || true

echo -e "${GREEN}✓ State cleared${NC}"

# ====================== CONFIGURE PIPELINE ======================
echo -e "\n${YELLOW}[4/5] Configuring pipeline...${NC}"

# Create trigger script directly in automation container
docker exec waf-automation sh -c "cat > /opt/pipeline_trigger.sh <<'TRIGGER_EOF'
#!/bin/bash
set -e

# Configuration
export TARGET_DOMAIN='${TARGET_DOMAIN}'
export TARGET_URL='${TARGET_URL}'
export COOKIE='${COOKIE}'
export OUTPUT_DIR='/output'
export PHASE1_CSV='/output/phase1_baseline.csv'
export PHASE2_CSV='/output/phase2_waf_results.csv'
export PHASE2_JSON='/output/phase2_waf_results.json'
export ZAP_HOST='zap'
export ZAP_PORT='8080'
export MODSEC_HOST='modsec'
export MODSEC_PORT='8080'

# Ensure output directory exists
mkdir -p \$OUTPUT_DIR

# Run pipeline
/opt/run_pipeline.sh

# List results
echo ''
echo 'Results in /output/:'
ls -lh /output/*.csv /output/*.json /output/*.txt 2>/dev/null || echo 'No result files'
TRIGGER_EOF
"

docker exec waf-automation chmod +x /opt/pipeline_trigger.sh

echo -e "${GREEN}✓ Configuration complete${NC}"

# ====================== RUN PIPELINE ======================
echo -e "\n${YELLOW}[5/5] Executing pipeline...${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Run pipeline in automation container
docker exec waf-automation /opt/pipeline_trigger.sh

# ====================== COLLECT RESULTS ======================
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "\n${YELLOW}Collecting results...${NC}"

# Wait for files to be written
sleep 3

# List what's in the container
echo -e "${BLUE}Files in container:${NC}"
docker exec waf-automation ls -lh /output/current_run/ 2>/dev/null || echo "No files in current_run"
docker exec waf-automation ls -lh /output/ 2>/dev/null | head -10

# Copy from container's /output/ (where phase1 & phase2 actually write)
# NOT from /output/current_run/
echo -e "${BLUE}Copying from container /output/ to host...${NC}"

# Copy phase1_baseline.csv
if docker exec waf-automation test -f /output/phase1_baseline.csv; then
    docker cp waf-automation:/output/phase1_baseline.csv "${OUTPUT_DIR}/" 2>/dev/null
    echo -e "${GREEN}✓ Copied phase1_baseline.csv${NC}"
fi

# Copy phase2_waf_results.csv
if docker exec waf-automation test -f /output/phase2_waf_results.csv; then
    docker cp waf-automation:/output/phase2_waf_results.csv "${OUTPUT_DIR}/" 2>/dev/null
    echo -e "${GREEN}✓ Copied phase2_waf_results.csv${NC}"
fi

# Copy phase2_waf_results.json
if docker exec waf-automation test -f /output/phase2_waf_results.json; then
    docker cp waf-automation:/output/phase2_waf_results.json "${OUTPUT_DIR}/" 2>/dev/null
    echo -e "${GREEN}✓ Copied phase2_waf_results.json${NC}"
fi

# Copy additional files if they exist
if docker exec waf-automation test -f /output/crawled_urls.txt; then
    docker cp waf-automation:/output/crawled_urls.txt "${OUTPUT_DIR}/" 2>/dev/null
    echo -e "${GREEN}✓ Copied crawled_urls.txt${NC}"
fi

if docker exec waf-automation test -f /output/param_urls.txt; then
    docker cp waf-automation:/output/param_urls.txt "${OUTPUT_DIR}/" 2>/dev/null
    echo -e "${GREEN}✓ Copied param_urls.txt${NC}"
fi

# Verify results
if [ -f "${OUTPUT_DIR}/phase1_baseline.csv" ]; then
    PHASE1_LINES=$(wc -l < "${OUTPUT_DIR}/phase1_baseline.csv")
    echo -e "${GREEN}✓ Phase 1: ${PHASE1_LINES} lines${NC}"
else
    echo -e "${YELLOW}⚠ Phase 1 output not found${NC}"
fi

if [ -f "${OUTPUT_DIR}/phase2_waf_results.csv" ]; then
    PHASE2_LINES=$(wc -l < "${OUTPUT_DIR}/phase2_waf_results.csv")
    echo -e "${GREEN}✓ Phase 2: ${PHASE2_LINES} lines${NC}"
else
    echo -e "${YELLOW}⚠ Phase 2 output not found${NC}"
fi

# ====================== SUMMARY ======================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  PIPELINE COMPLETE!                        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📁 Results saved to:${NC}"
echo -e "   ${OUTPUT_DIR}/"
echo ""

if [ -f "${OUTPUT_DIR}/phase2_waf_results.csv" ]; then
    echo -e "${BLUE}📊 Quick Stats:${NC}"
    TOTAL=$(tail -n +2 "${OUTPUT_DIR}/phase2_waf_results.csv" | wc -l | tr -d ' ')
    ATTACK=$(tail -n +2 "${OUTPUT_DIR}/phase2_waf_results.csv" | cut -d',' -f13 | grep -c "attack" 2>/dev/null || echo 0)
    BENIGN=$(tail -n +2 "${OUTPUT_DIR}/phase2_waf_results.csv" | cut -d',' -f13 | grep -c "benign" 2>/dev/null || echo 0)
    
    echo -e "   Total:  ${TOTAL}"
    echo -e "   Attack: ${ATTACK}"
    echo -e "   Benign: ${BENIGN}"
fi

echo ""
echo -e "${GREEN}✅ Ready for next domain!${NC}"
echo -e "${BLUE}Run:${NC} $0 <new-domain>"
echo ""
