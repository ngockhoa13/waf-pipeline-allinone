#!/bin/bash
#
# DVWA Setup & Test Script
# =========================
# Script để khởi động DVWA và hướng dẫn lấy cookie
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           DVWA - Test Environment Setup                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if DVWA is running
if docker ps | grep -q "dvwa-test"; then
    echo -e "${GREEN}✓ DVWA is already running${NC}"
else
    echo -e "${YELLOW}[1/2] Starting DVWA...${NC}"
    docker-compose -f docker-compose.dvwa.yml up -d
    
    echo -e "${YELLOW}[2/2] Waiting for DVWA to be ready...${NC}"
    for i in $(seq 1 30); do
        if curl -s http://localhost:4280 > /dev/null 2>&1; then
            echo -e "${GREEN}✓ DVWA is ready!${NC}"
            break
        fi
        echo -n "."
        sleep 2
    done
    echo ""
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    DVWA IS READY!                          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}📍 DVWA URL:${NC} http://localhost:4280"
echo -e "${CYAN}👤 Login:${NC}    admin"
echo -e "${CYAN}🔑 Password:${NC} password"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}                    HƯỚNG DẪN LẤY COOKIE${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}Bước 1:${NC} Mở trình duyệt và truy cập: ${GREEN}http://localhost:4280${NC}"
echo ""
echo -e "${BLUE}Bước 2:${NC} Đăng nhập với: ${GREEN}admin / password${NC}"
echo ""
echo -e "${BLUE}Bước 3:${NC} Click 'Create / Reset Database' nếu lần đầu"
echo ""
echo -e "${BLUE}Bước 4:${NC} Lấy cookie:"
echo "   - Mở DevTools (F12) → Tab Application → Cookies"
echo "   - Copy giá trị của: ${GREEN}PHPSESSID${NC} và ${GREEN}security${NC}"
echo ""
echo -e "${BLUE}Bước 5:${NC} Chạy pipeline với cookie:"
echo ""
echo -e "${CYAN}./trigger_pipeline.sh http://localhost:4280 ./output \"PHPSESSID=xxx; security=low\"${NC}"
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${GREEN}💡 Tip:${NC} Security levels: low, medium, high, impossible"
echo ""

# Optional: Auto-login and get cookie
echo -e "${YELLOW}Bạn có muốn tự động lấy cookie không? (y/n)${NC}"
read -r answer

if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
    echo ""
    echo -e "${BLUE}Đang tự động đăng nhập và lấy cookie...${NC}"
    
    # First, get the initial session and CSRF token
    RESPONSE=$(curl -s -c /tmp/dvwa_cookies.txt -b /tmp/dvwa_cookies.txt \
        "http://localhost:4280/login.php" 2>/dev/null)
    
    # Extract CSRF token
    CSRF_TOKEN=$(echo "$RESPONSE" | grep -oP "user_token' value='\K[^']+")
    
    if [ -z "$CSRF_TOKEN" ]; then
        echo -e "${RED}Không thể lấy CSRF token. Hãy lấy cookie thủ công.${NC}"
        exit 1
    fi
    
    # Login
    curl -s -c /tmp/dvwa_cookies.txt -b /tmp/dvwa_cookies.txt \
        -X POST "http://localhost:4280/login.php" \
        -d "username=admin&password=password&Login=Login&user_token=$CSRF_TOKEN" \
        -L > /dev/null 2>&1
    
    # Extract cookies
    PHPSESSID=$(grep PHPSESSID /tmp/dvwa_cookies.txt | awk '{print $NF}')
    SECURITY=$(grep security /tmp/dvwa_cookies.txt | awk '{print $NF}')
    
    if [ -z "$SECURITY" ]; then
        SECURITY="low"
    fi
    
    if [ -n "$PHPSESSID" ]; then
        COOKIE_STRING="PHPSESSID=$PHPSESSID; security=$SECURITY"
        
        echo ""
        echo -e "${GREEN}✓ Cookie lấy thành công!${NC}"
        echo ""
        echo -e "${CYAN}Cookie:${NC} $COOKIE_STRING"
        echo ""
        echo -e "${YELLOW}Chạy lệnh sau để test:${NC}"
        echo ""
        echo -e "${GREEN}./trigger_pipeline.sh http://localhost:4280 ./output/dvwa \"$COOKIE_STRING\"${NC}"
        echo ""
        
        # Save to file for convenience
        echo "$COOKIE_STRING" > /tmp/dvwa_cookie_string.txt
        echo -e "${BLUE}Cookie đã được lưu vào: /tmp/dvwa_cookie_string.txt${NC}"
    else
        echo -e "${RED}Không thể lấy cookie. Hãy thử lấy thủ công.${NC}"
    fi
fi

echo ""
