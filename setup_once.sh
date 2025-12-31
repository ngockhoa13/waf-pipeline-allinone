#!/bin/bash
#
# SETUP SCRIPT - RUN ONCE
# =======================
# Build và start tất cả containers lần đầu tiên
#
# Usage:
#   ./setup_once.sh
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        WAF PIPELINE - ONE-TIME SETUP                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if docker-compose exists
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ docker-compose not found!${NC}"
    exit 1
fi

# ====================== STOP OLD CONTAINERS ======================
echo -e "${YELLOW}[1/5] Stopping old containers...${NC}"
docker-compose down 2>/dev/null || true
echo -e "${GREEN}✓ Old containers stopped${NC}"

# ====================== BUILD CONTAINERS ======================
echo -e "\n${YELLOW}[2/5] Building containers...${NC}"
echo -e "${BLUE}This may take 5-10 minutes on first run...${NC}"

docker-compose build --no-cache

echo -e "${GREEN}✓ Containers built${NC}"

# ====================== START CONTAINERS ======================
echo -e "\n${YELLOW}[3/5] Starting containers...${NC}"

docker-compose up -d

echo -e "${GREEN}✓ Containers started${NC}"

# ====================== WAIT FOR HEALTHY ======================
echo -e "\n${YELLOW}[4/5] Waiting for containers to be healthy...${NC}"

echo -e "${BLUE}Waiting for ZAP...${NC}"
for i in {1..60}; do
    if docker exec waf-zap curl -f -s "http://localhost:8080/JSON/core/view/version/" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ ZAP is healthy${NC}"
        break
    fi
    sleep 2
    if [ $i -eq 60 ]; then
        echo -e "${RED}❌ ZAP failed to start${NC}"
        exit 1
    fi
done

echo -e "${BLUE}Waiting for ModSecurity...${NC}"
for i in {1..30}; do
    if docker exec waf-modsec curl -f -s "http://localhost:8080/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ ModSecurity is healthy${NC}"
        break
    fi
    sleep 2
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ ModSecurity failed to start${NC}"
        exit 1
    fi
done

echo -e "${BLUE}Checking automation...${NC}"
if docker ps | grep -q "waf-automation"; then
    echo -e "${GREEN}✓ Automation container is running${NC}"
else
    echo -e "${RED}❌ Automation container not running${NC}"
    exit 1
fi

# ====================== CREATE OUTPUT DIRECTORIES ======================
echo -e "\n${YELLOW}[5/5] Creating output directories...${NC}"

mkdir -p ./output
mkdir -p ./logs

echo -e "${GREEN}✓ Directories created${NC}"

# ====================== SUMMARY ======================
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              SETUP COMPLETE!                               ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📦 Running Containers:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep waf

echo ""
echo -e "${GREEN}✅ Ready to run pipeline!${NC}"
echo ""
echo -e "${BLUE}Usage:${NC}"
echo -e "  ./trigger_pipeline.sh <domain> [output_dir]"
echo ""
echo -e "${BLUE}Examples:${NC}"
echo -e "  ./trigger_pipeline.sh testaspnet.vulnweb.com"
echo -e "  ./trigger_pipeline.sh example.com ./results/example"
echo ""
echo -e "${YELLOW}💡 Tip:${NC} Containers will keep running. You can trigger"
echo -e "   multiple domains without rebuilding!"
echo ""
