#!/usr/bin/env python3
"""
PHASE 1: ZAP PROXY + ATTACK TOOLS - COMPLETE VERSION (FIXED URL ENCODING)
==========================================================================
✅ MỖI TOOL CHỈ ATTACK 1 LẦN (tránh duplicate)
✅ ĐẢM BẢO TRAFFIC ĐI QUA ZAP PROXY
✅ THU THẬP DATASET ĐẦY ĐỦ TỪ ATTACK TOOLS
✅ VALIDATE PROXY CONNECTION TRƯỚC KHI ATTACK
✅ ENHANCED DEBUGGING CHO TRAFFIC FLOW
✅ FIX: Decode URL-encoded body before saving to CSV

Key Features:
- Each tool runs ONCE per selected URL
- Verify proxy is working before attacks
- Better traffic capture validation
- Improved error handling
- Clear logging of captured payloads
- FIXED: No double URL encoding issue
"""
import os
import csv
import time
import subprocess
import urllib.parse
import requests
import hashlib
import shutil
from datetime import datetime
import sys
import warnings

# Tắt SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

try:
    from zapv2 import ZAPv2
except ImportError:
    print("❌ Cần cài: pip install python-owasp-zap-v2.4")
    sys.exit(1)

# ====================== CONFIG ======================
TARGET = os.getenv('TARGET_URL', 'http://testaspnet.vulnweb.com')
ZAP_HOST = os.getenv('ZAP_HOST', 'zap')
ZAP_PORT = os.getenv('ZAP_PORT', '8080')
PROXY = f"http://{ZAP_HOST}:{ZAP_PORT}"

OUTPUT_DIR = os.getenv('OUTPUT_DIR', '/output')
FINAL_CSV = os.path.join(OUTPUT_DIR, "phase1_baseline.csv")
URL_FILE = os.path.join(OUTPUT_DIR, "crawled_urls.txt")
PARAM_URL_FILE = os.path.join(OUTPUT_DIR, "param_urls.txt")

MAX_URLS_AJAX = int(os.getenv('MAX_URLS_AJAX', '8'))
MAX_URLS_ATTACK = int(os.getenv('MAX_URLS_ATTACK', '5'))
ATTACK_TIMEOUT = int(os.getenv('ATTACK_TIMEOUT', '90'))

# Global state
seen_signatures = set()
total_exported = 0
attack_stats = {}

# ====================== UTILS ======================
def log(msg, level="INFO"):
    """Logging với màu sắc"""
    colors = {
        "INFO": "\033[94m",
        "OK": "\033[92m", 
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "DEBUG": "\033[95m"
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"{color}[{timestamp}] [{level}] {msg}{reset}", flush=True)

def clean_multiline(text):
    """Clean text cho CSV - bảo toàn payload"""
    if not text:
        return ""
    return str(text).replace("\n", " ").replace("\r", "").strip()

def decode_body_if_needed(body):
    """
    ✅ CRITICAL FIX: Decode URL-encoded body before saving
    ZAP may return URL-encoded body, we need to decode it
    to avoid double-encoding in Phase 2
    """
    if not body or not isinstance(body, str):
        return body
    
    # Check if body contains URL encoding (has %)
    if '%' in body:
        try:
            # Try to decode
            decoded = urllib.parse.unquote_plus(body)
            
            # Only use decoded if it actually changed something
            # and doesn't start with % (indicating it was encoded)
            if decoded != body and not decoded.startswith('%'):
                # log(f"  [DECODE] Body decoded: {len(body)} → {len(decoded)} bytes", "DEBUG")
                return decoded
        except Exception as e:
            # If decode fails, keep original
            pass
    
    return body

def has_param(url):
    """Kiểm tra URL có parameter"""
    return urllib.parse.urlparse(url).query != ""

def get_sig(req_body, url, tech):
    """
    Tạo signature để deduplicate
    ✅ Attack traffic: KHÔNG deduplicate
    ✅ Benign traffic: Deduplicate bình thường
    """
    if tech in ["SQLI", "XSS", "RCE", "DIR", "COMMIX", "FFUF"]:
        import random
        return hashlib.md5(f"{tech}|{time.time()}|{random.random()}".encode()).hexdigest()
    
    payload = (req_body or "").lower()
    path = urllib.parse.urlparse(url).path.lower()
    return hashlib.md5(f"{tech}|{payload[:100]}|{path}".encode()).hexdigest()

def url_priority(url):
    """Tính priority của URL cho attack"""
    score = 0
    path = urllib.parse.urlparse(url).path.lower()
    
    if any(k in path for k in ["search", "login", "contact", "register", "api"]): 
        score += 10
    if any(k in path for k in ["blog", "post", "comment"]): 
        score += 5
    if has_param(url): 
        score += 20
    
    return score

# ====================== ZAP CONNECTION ======================
def get_zap():
    """Kết nối ZAP API"""
    log(f"Connecting to ZAP at {PROXY}...")
    
    for attempt in range(1, 41):
        try:
            zap = ZAPv2(
                apikey='',
                proxies={'http': PROXY, 'https': PROXY}
            )
            version = zap.core.version
            log(f"✅ Connected to ZAP v{version}", "OK")
            time.sleep(2)
            return zap
        except Exception as e:
            if attempt % 5 == 0:
                log(f"Attempt {attempt}/40 - Waiting for ZAP...", "WARNING")
            time.sleep(3)
    
    log("❌ Cannot connect to ZAP!", "ERROR")
    sys.exit(1)

def verify_proxy_working():
    """
    ✅ CRITICAL: Verify ZAP proxy is capturing traffic
    """
    log("\n" + "="*80, "INFO")
    log("VERIFYING ZAP PROXY CONNECTION", "OK")
    log("="*80, "INFO")
    
    test_url = f"{TARGET}/test-proxy-{int(time.time())}"
    
    try:
        # Test request through proxy
        response = requests.get(
            test_url,
            proxies={'http': PROXY, 'https': PROXY},
            verify=False,
            timeout=10
        )
        
        log(f"  ✓ Proxy request sent: {test_url}", "OK")
        
        # Verify ZAP captured it
        time.sleep(2)
        zap = get_zap()
        msgs = zap.core.messages(start=0, count=10)
        
        captured = False
        for msg in msgs:
            if test_url in str(msg.get('requestHeader', '')):
                captured = True
                break
        
        if captured:
            log("  ✅ ZAP PROXY IS CAPTURING TRAFFIC!", "OK")
            return True
        else:
            log("  ⚠️  ZAP not capturing - check proxy settings", "WARNING")
            return False
            
    except Exception as e:
        log(f"  ✗ Proxy verification failed: {e}", "ERROR")
        return False

# ====================== EXPORT ======================
def parse_request_header(req_header):
    """Parse request headers thành dict"""
    method = "GET"
    url = ""
    first_line = ""
    headers_dict = {}
    
    if not req_header:
        return method, url, headers_dict, first_line
    
    lines = req_header.split("\n")
    
    if lines:
        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)
        
        if len(parts) >= 2:
            method = parts[0]
            url_part = parts[1]
            url = url_part if url_part.startswith("http") else url_part
    
    for line in lines[1:]:
        line = line.strip()
        if not line or line.startswith("HTTP/"):
            continue
        
        if ':' in line:
            k, v = line.split(':', 1)
            k = k.strip()
            v = v.strip()
            if k and v:
                headers_dict[k] = v
    
    if url and not url.startswith("http"):
        host = headers_dict.get('Host', urllib.parse.urlparse(TARGET).netloc)
        scheme = "https" if "https" in TARGET else "http"
        url = f"{scheme}://{host}{url}"
    
    return method, url, headers_dict, first_line

def headers_to_pipe_format(headers_dict):
    """Convert headers dict sang pipe-separated format"""
    if not headers_dict:
        return ""
    
    ordered_keys = []
    if 'Host' in headers_dict:
        ordered_keys.append('Host')
    
    for k in sorted(headers_dict.keys()):
        if k != 'Host':
            ordered_keys.append(k)
    
    parts = []
    for k in ordered_keys:
        v = headers_dict[k]
        v_escaped = str(v).replace('|', '&#124;')
        parts.append(f"{k}: {v_escaped}")
    
    return "|".join(parts)

def export_and_save(tech, zap=None):
    """
    Export messages từ ZAP
    ✅ FIX: Decode URL-encoded body before saving
    """
    global seen_signatures, total_exported
    
    if zap is None:
        zap = get_zap()
    
    if not zap:
        log("  [SKIP export: ZAP not available]", "WARNING")
        return 0

    domain = urllib.parse.urlparse(TARGET).netloc
    new_rows = []

    try:
        msgs = zap.core.messages(start=0, count=5000)
        log(f"  Processing {len(msgs)} messages from ZAP...", "DEBUG")
        
        for m in msgs:
            if not isinstance(m, dict):
                continue
            
            req_header = m.get("requestHeader", "")
            req_body = m.get("requestBody", "")
            resp_header = m.get("responseHeader", "")
            resp_body = m.get("responseBody", "")
            
            method, url, headers_dict, first_line = parse_request_header(req_header)
            
            if not url or domain not in url:
                continue
            
            if 'Host' not in headers_dict and url:
                parsed = urllib.parse.urlparse(url)
                if parsed.netloc:
                    headers_dict['Host'] = parsed.netloc
            
            req_header_formatted = headers_to_pipe_format(headers_dict)
            
            # ✅ CRITICAL FIX: Decode URL-encoded body before saving
            req_body_decoded = decode_body_if_needed(req_body)
            
            sig = get_sig(req_body_decoded, url, tech)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)
            
            clean_req_body = clean_multiline(req_body_decoded)
            clean_resp_body = clean_multiline(resp_body)[:15000]
            
            if tech in ["SQLI", "XSS", "RCE", "COMMIX"] and (req_body_decoded or "'" in url or "<" in url):
                log(f"  📝 {tech} payload captured: {url[:60]}... body={len(req_body_decoded)} bytes", "DEBUG")
            
            new_rows.append([
                m.get("timestamp", ""),
                tech,
                method,
                url,
                req_header_formatted,
                clean_req_body,
                clean_multiline(resp_header),
                clean_resp_body,
                first_line if first_line else f"{method} / HTTP/1.1"
            ])

        if new_rows:
            os.makedirs(OUTPUT_DIR, exist_ok=True)
            
            mode = 'a' if os.path.exists(FINAL_CSV) else 'w'
            with open(FINAL_CSV, mode, newline="", encoding="utf-8") as f:
                w = csv.writer(f, quoting=csv.QUOTE_ALL, escapechar='\\')
                
                if mode == 'w':
                    w.writerow([
                        "timestamp", "tool", "method", "url", "req_header", 
                        "req_body", "resp_header", "resp_body", "full_request"
                    ])
                w.writerows(new_rows)
            
            total_exported += len(new_rows)
            log(f"  ✓ Exported {len(new_rows)} requests → Total: {total_exported}", "OK")
        else:
            log(f"  ⚠ 0 new requests for {tech}", "WARNING")
        
        return len(new_rows)
        
    except Exception as e:
        log(f"  Export error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return 0

# ====================== CRAWL PHASES ======================
def spider_crawl(zap):
    """BƯỚC 1: Spider Crawl"""
    log("="*80)
    log("BƯỚC 1: SPIDER CRAWL", "OK")
    log("="*80)

    try:
        scan_id = zap.spider.scan(url=TARGET)
        
        for _ in range(24):
            status = zap.spider.status(scan_id)
            log(f"  Spider progress: {status}%")
            if status == "100": 
                break
            time.sleep(5)
        
        zap.spider.stop(scan_id)
        time.sleep(3)

        urls = zap.core.urls()
        domain_urls = [u for u in urls if urllib.parse.urlparse(TARGET).netloc in u]
        log(f"SPIDER: {len(domain_urls)} URLs found", "OK")
        
        with open(URL_FILE, "w") as f:
            for u in domain_urls: 
                f.write(u + "\n")
        
        export_and_save("SPIDER", zap)
        return domain_urls
        
    except Exception as e:
        log(f"Spider error: {e}", "ERROR")
        return []

def ajax_crawl(zap, urls):
    """BƯỚC 2: Ajax Crawl"""
    log("="*80)
    log(f"BƯỚC 2: AJAX CRAWL ({MAX_URLS_AJAX} URLs)", "OK")
    log("="*80)

    sorted_urls = sorted(urls, key=url_priority, reverse=True)[:MAX_URLS_AJAX]
    
    for i, url in enumerate(sorted_urls, 1):
        log(f"  AJAX [{i}/{len(sorted_urls)}] → {url[:70]}...")
        
        try:
            zap.ajaxSpider.scan(url=url, inscope=True)
            
            for _ in range(5):
                time.sleep(5)
                if zap.ajaxSpider.status == "stopped":
                    break
            
            zap.ajaxSpider.stop()
            time.sleep(1)
            
        except Exception as e:
            log(f"  AJAX error: {e}", "WARNING")

    final_urls = zap.core.urls()
    final_domain_urls = [u for u in final_urls if urllib.parse.urlparse(TARGET).netloc in u]
    log(f"AJAX COMPLETE: {len(final_domain_urls)} URLs total", "OK")
    
    export_and_save("AJAX", zap)
    return final_domain_urls

def quick_scan(zap, urls):
    """BƯỚC 3: Quick Scan"""
    log("="*80)
    log("BƯỚC 3: QUICK SCAN", "OK")
    log("="*80)

    form_urls = [u for u in urls if any(k in u.lower() for k in ["login", "search", "contact"])][:3]
    
    for url in form_urls:
        try:
            log(f"  Scanning: {url[:70]}...")
            scan_id = zap.ascan.scan(url=url, recurse=False, scanpolicyname="Light")
            time.sleep(10)
            zap.ascan.stop(scan_id)
        except:
            pass

    time.sleep(5)
    
    all_urls = zap.core.urls()
    domain_urls = [u for u in all_urls if urllib.parse.urlparse(TARGET).netloc in u]
    param_urls = [u for u in domain_urls if has_param(u)]

    with open(PARAM_URL_FILE, "w") as f:
        for u in param_urls: 
            f.write(u + "\n")

    log(f"SCAN COMPLETE: {len(param_urls)} param URLs found", "OK")
    export_and_save("SCAN", zap)
    
    return param_urls, domain_urls

def benign_browsing(zap, all_urls):
    """BƯỚC 3.5: Benign Browsing"""
    log("="*80)
    log("BƯỚC 3.5: BENIGN BROWSING", "OK")
    log("="*80)
    
    benign_urls = sorted(all_urls, key=url_priority, reverse=True)[:15]
    
    for i, url in enumerate(benign_urls, 1):
        log(f"  [{i}/{len(benign_urls)}] Visiting: {url[:70]}...")
        try:
            zap.core.access_url(url=url, followredirects=True)
            time.sleep(1)
        except:
            pass
    
    export_and_save("BENIGN", zap)
    log("BENIGN BROWSING COMPLETE", "OK")

# ====================== ATTACK TOOLS ======================
def run_single_attack(zap, url, cmd, tech):
    """
    ✅ MỖI TOOL CHỈ ATTACK 1 LẦN VÀO URL NÀY
    ✅ ĐẢM BẢO TRAFFIC ĐI QUA ZAP PROXY
    """
    tool_name = cmd[0]
    
    if not shutil.which(tool_name): 
        log(f"  ⚠️  {tool_name} NOT INSTALLED", "WARNING")
        return 0
    
    log(f"\n🎯 {tech} ATTACK on: {url[:65]}...", "INFO")
    log(f"  Tool: {tool_name}", "DEBUG")
    
    # Setup proxy environment
    env = {
        **os.environ, 
        "http_proxy": PROXY, 
        "https_proxy": PROXY,
        "HTTP_PROXY": PROXY,
        "HTTPS_PROXY": PROXY
    }
    
    cmd_exec = [arg.replace("TARGET", url) for arg in cmd]
    log(f"  CMD: {' '.join(cmd_exec[:5])}...", "DEBUG")
    
    # Count messages before attack
    try:
        msgs_before = len(zap.core.messages(start=0, count=10000))
    except:
        msgs_before = 0
    
    try:
        proc = subprocess.Popen(
            cmd_exec, 
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        stdout, stderr = proc.communicate(timeout=ATTACK_TIMEOUT)
        
        if stdout:
            output = stdout.decode('utf-8', errors='ignore')[:400]
            if output.strip():
                log(f"  STDOUT: {output[:200]}", "DEBUG")
        
        if stderr:
            error = stderr.decode('utf-8', errors='ignore')[:200]
            if error.strip() and "warning" not in error.lower():
                log(f"  STDERR: {error[:100]}", "DEBUG")
            
    except subprocess.TimeoutExpired:
        proc.kill()
        log(f"  ⏱ Timeout after {ATTACK_TIMEOUT}s", "WARNING")
    except Exception as e:
        log(f"  ✗ Error: {e}", "ERROR")
        return 0
    
    # Wait for traffic to be captured
    time.sleep(8)
    
    # Count messages after attack
    try:
        msgs_after = len(zap.core.messages(start=0, count=10000))
        new_msgs = msgs_after - msgs_before
        
        if new_msgs > 0:
            log(f"  📊 ZAP captured {new_msgs} new requests", "OK")
        else:
            log(f"  ⚠️  ZAP captured 0 new requests!", "WARNING")
    except:
        new_msgs = 0
    
    # Export captured traffic
    count = export_and_save(tech, zap)
    
    if count > 0:
        log(f"  ✅ {tech} COMPLETE - {count} requests exported", "OK")
    else:
        log(f"  ⚠️  {tech} COMPLETE - NO requests exported", "WARNING")
    
    return count

def attack_phase_optimized(zap, param_urls, all_urls):
    """
    ✅ MỖI TOOL CHỈ CHẠY 1 LẦN
    ✅ CHỌN URL TỐT NHẤT CHO MỖI TOOL
    """
    log("\n" + "="*80)
    log(f"BƯỚC 4: ATTACK PHASE (OPTIMIZED - 1 RUN PER TOOL)", "OK")
    log("="*80)
    
    # Chọn URL tốt nhất
    attack_urls = param_urls[:MAX_URLS_ATTACK]
    if not attack_urls:
        log("No param URLs, using top URLs", "WARNING")
        attack_urls = sorted(all_urls, key=url_priority, reverse=True)[:MAX_URLS_ATTACK]
    
    if not attack_urls:
        log("❌ No URLs available for attack!", "ERROR")
        return
    
    log(f"Selected {len(attack_urls)} URLs for attacks", "INFO")
    for i, u in enumerate(attack_urls[:3], 1):
        log(f"  {i}. {u[:70]}...", "INFO")
    
    global attack_stats
    attack_stats = {}
    
    # SQLMAP - 1 URL
    log("\n" + "-"*80, "INFO")
    log("TOOL 1/4: SQLMAP", "OK")
    log("-"*80, "INFO")
    
    best_url = attack_urls[0]
    count = run_single_attack(
        zap, best_url,
        ["sqlmap", "-u", "TARGET", "--batch", "--level=2", "--risk=2", 
         "--threads=2", "--technique=BEUST", "--forms", "--random-agent",
         "--timeout=30", "--retries=1"],
        "SQLI"
    )
    attack_stats["SQLI"] = count
    time.sleep(5)
    
    # XSSTRIKE - 1 URL
    log("\n" + "-"*80, "INFO")
    log("TOOL 2/4: XSSTRIKE", "OK")
    log("-"*80, "INFO")
    
    xss_url = attack_urls[1] if len(attack_urls) > 1 else attack_urls[0]
    count = run_single_attack(
        zap, xss_url,
        ["xsstrike", "-u", "TARGET", "--skip-dom", "--timeout=40", "--crawl"],
        "XSS"
    )
    attack_stats["XSS"] = count
    time.sleep(5)
    
    # COMMIX - 1 URL
    if shutil.which("commix"):
        log("\n" + "-"*80, "INFO")
        log("TOOL 3/4: COMMIX", "OK")
        log("-"*80, "INFO")
        
        rce_url = attack_urls[2] if len(attack_urls) > 2 else attack_urls[0]
        count = run_single_attack(
            zap, rce_url,
            ["commix", "--url", "TARGET", "--level=2", "--timeout=40", 
             "--batch", "--skip-waf"],
            "RCE"
        )
        attack_stats["RCE"] = count
        time.sleep(5)
    
    # FFUF - 1 URL
    if shutil.which("ffuf"):
        log("\n" + "-"*80, "INFO")
        log("TOOL 4/4: FFUF", "OK")
        log("-"*80, "INFO")
        
        noparam = [u for u in all_urls if not has_param(u)]
        if noparam:
            dir_url = noparam[0]
            count = run_single_attack(
                zap, dir_url,
                ["ffuf", "-u", "TARGET/FUZZ", 
                 "-w", "/usr/share/wordlists/dirb/common.txt",
                 "-mc", "200,301,302,403", "-t", "3", "-timeout", "20",
                 "-se"],
                "DIR"
            )
            attack_stats["DIR"] = count
    
    # SUMMARY
    log("\n" + "="*80, "INFO")
    log("ATTACK PHASE COMPLETE", "OK")
    log("="*80, "INFO")
    
    total_captured = sum(attack_stats.values())
    log(f"Total requests captured: {total_captured}", "OK")
    
    for tool, count in attack_stats.items():
        log(f"  {tool}: {count} requests", "INFO")

# ====================== MAIN ======================
def main():
    print("="*80)
    print(" PHASE 1: OPTIMIZED VERSION (FIXED URL ENCODING)")
    print(" - Each tool runs ONCE")
    print(" - Guaranteed ZAP proxy capture")
    print(" - Enhanced traffic validation")
    print(" - FIX: No double URL encoding")
    print("="*80)
    print(f" Target: {TARGET}")
    print(f" ZAP: {PROXY}")
    print(f" Output: {OUTPUT_DIR}")
    print(f" Attack URLs: {MAX_URLS_ATTACK}")
    print(f" Attack Timeout: {ATTACK_TIMEOUT}s")
    
    # Check tools
    log("\n" + "="*80, "INFO")
    log("CHECKING ATTACK TOOLS", "INFO")
    log("="*80, "INFO")
    
    tools_found = []
    tools_missing = []
    
    for tool in ["sqlmap", "xsstrike", "commix", "ffuf"]:
        if shutil.which(tool):
            tools_found.append(tool)
            log(f"  ✓ {tool}: {shutil.which(tool)}", "OK")
        else:
            tools_missing.append(tool)
            log(f"  ✗ {tool}: NOT FOUND", "WARNING")
    
    if not tools_found:
        log("\n❌ NO ATTACK TOOLS FOUND!", "ERROR")
        sys.exit(1)
    else:
        log(f"\n✅ Found {len(tools_found)}/{len(tools_found)+len(tools_missing)} tools", "OK")

    # Connect to ZAP
    zap = get_zap()
    if not zap:
        sys.exit(1)
    
    # Verify proxy
    if not verify_proxy_working():
        log("\n⚠️  Proxy may not be working correctly!", "WARNING")
        log("Continuing anyway...", "WARNING")

    # Set proxy environment
    os.environ["http_proxy"] = PROXY
    os.environ["https_proxy"] = PROXY
    os.environ["HTTP_PROXY"] = PROXY
    os.environ["HTTPS_PROXY"] = PROXY

    # MAIN WORKFLOW
    log("\n" + "="*80, "INFO")
    log("STARTING PIPELINE", "OK")
    log("="*80 + "\n", "INFO")
    
    # Step 1: Spider
    spider_urls = spider_crawl(zap)
    if not spider_urls:
        log("Spider failed!", "ERROR")
        sys.exit(1)
    
    # Step 2: AJAX
    all_urls = ajax_crawl(zap, spider_urls)
    
    # Step 3: Quick Scan
    param_urls, all_urls = quick_scan(zap, all_urls)
    
    # Step 3.5: Benign Browsing
    benign_browsing(zap, all_urls)
    
    # Step 4: Attack Phase
    if tools_found:
        attack_phase_optimized(zap, param_urls, all_urls)
    else:
        log("\n⚠️  SKIPPING ATTACK PHASE", "WARNING")

    # Final Export
    log("\n" + "="*80)
    log("FINAL EXPORT", "OK")
    log("="*80)
    export_and_save("FINAL", zap)

    # STATISTICS
    log(f"\n{'='*80}")
    log(f"✅ PHASE 1 COMPLETED!", "OK")
    log(f"{'='*80}")
    log(f"Total Requests Exported: {total_exported}", "OK")
    
    if os.path.exists(FINAL_CSV):
        with open(FINAL_CSV, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            by_tool = {}
            for row in rows:
                tool = row.get('tool', 'UNKNOWN')
                by_tool[tool] = by_tool.get(tool, 0) + 1
            
            log("\nBreakdown by Tool:", "INFO")
            for tool, count in sorted(by_tool.items()):
                log(f"  {tool}: {count} requests", "INFO")
    
    print("\n" + "="*80)
    print(f"📁 Output Files:")
    print(f"   CSV: {FINAL_CSV}")
    print(f"   URLs: {URL_FILE}")
    print(f"   Param URLs: {PARAM_URL_FILE}")
    print("="*80 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n[!] Stopped by user", "WARNING")
        sys.exit(0)
    except Exception as e:
        log(f"\n[!] Fatal error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)
