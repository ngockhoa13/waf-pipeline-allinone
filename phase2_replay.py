#!/usr/bin/env python3
"""
PHASE 2: WAF REPLAY & LABELING - TAG-BASED CLASSIFICATION
==========================================================
✅ PRIMARY: Tag-based classification (attack-sqli, attack-xss, etc.)
✅ FALLBACK: Rule ID mapping (backup only)
✅ PRIORITY: High-confidence rules for better accuracy
✅ IMPROVED: Handle multiple attack types with priority system

Key Improvements:
- Tags are MORE accurate than rule IDs
- Automatic adaptation to new CRS rules
- Better handling of overlapping attack types
- Confidence scoring based on high-confidence rules
"""
import argparse
import csv
import json
import os
import threading
import time
import uuid
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ===================== CONFIG =====================
DEFAULT_LOG = "/tmp/modsec_audit.log"
DEFAULT_PORT = 8080
MAX_WORKERS = 3
REQUEST_TIMEOUT = 10
LOG_WAIT_TIMEOUT = 5
CHUNK_SIZE = 131072
RETRY_COUNT = 2

LOG_OFFSET_FILE = "/tmp/modsec_replay_offset.lock"
OFFSET_LOCK = threading.Lock()

verification_stats = {
    "verified": 0,
    "failed": 0,
    "total": 0,
    "lock": threading.Lock()
}

def verify_payload_in_log(log_entry: dict, original_body: str) -> dict:
    """Verify payload in log"""
    result = {"verified": False, "reason": "no_log"}
    
    if not log_entry:
        return result
    
    transaction = log_entry.get("transaction", {})
    request_body = transaction.get("request", {}).get("body", "")
    
    if request_body and original_body:
        if original_body in request_body:
            result = {"verified": True, "reason": "body_match"}
        else:
            result = {"verified": False, "reason": "body_mismatch"}
    elif original_body:
        result = {"verified": False, "reason": "body_missing_in_log"}
    else:
        result = {"verified": True, "reason": "no_body"}
    
    messages = log_entry.get("transaction", {}).get("messages", [])
    if not messages:
        messages = log_entry.get("audit_data", {}).get("messages", [])
    
    for msg in messages:
        if isinstance(msg, dict):
            data = msg.get("details", {}).get("data", "")
            if data and original_body:
                if any(chunk in data for chunk in original_body.split()[:5] if len(chunk) > 3):
                    result = {"verified": True, "reason": "payload_in_matched_data"}
                    break
    
    return result

def update_verification_stats(verified: bool):
    with verification_stats["lock"]:
        verification_stats["total"] += 1
        if verified:
            verification_stats["verified"] += 1
        else:
            verification_stats["failed"] += 1

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Connection": "keep-alive"
})

# ===================== TAG-BASED CLASSIFICATION =====================
class TagBasedClassifier:
    """
    ✅ PRIMARY: Classify based on attack tags from ModSecurity
    Tags are more reliable than rule IDs for multi-rule scenarios
    """
    
    # High-confidence rules for confidence scoring
    HIGH_CONFIDENCE_RULES = {
        "942100",  # SQLi via libinjection
        "941100",  # XSS via libinjection
        "932160",  # Command injection
        "933160",  # PHP injection
        "930120",  # OS file access (LFI)
    }
    
    # Attack type priorities (higher = more specific)
    ATTACK_PRIORITIES = {
        "sqli": 100,
        "xss": 95,
        "lfi": 90,
        "rfi": 85,
        "cmdi": 80,
        "rce": 70,
        "php_injection": 75,
        "java_injection": 75,
        "session_fixation": 65,
        "protocol_violation": 50,
        "scanner_noise": 10,
    }
    
    # Tag normalization mapping
    TAG_NORMALIZATIONS = {
        "injection-generic": "cmdi",
        "injection-php": "php_injection",
        "injection-java": "java_injection",
        "fixation": "session_fixation",
        "protocol": "protocol_violation",
    }
    
    @classmethod
    def extract_attack_types_from_tags(cls, tags: list) -> list:
        """
        Extract attack types from CRS tags
        Returns: [(attack_type, priority), ...]
        """
        attack_types = []
        
        for tag in tags:
            if not isinstance(tag, str):
                continue
            
            # Extract attack-xxx pattern
            if tag.startswith("attack-"):
                attack_type = tag.replace("attack-", "")
                
                # Normalize
                for old, new in cls.TAG_NORMALIZATIONS.items():
                    if old in attack_type:
                        attack_type = new
                        break
                
                # Get priority
                priority = cls.ATTACK_PRIORITIES.get(attack_type, 50)
                
                if (attack_type, priority) not in attack_types:
                    attack_types.append((attack_type, priority))
        
        # Sort by priority (highest first)
        attack_types.sort(key=lambda x: x[1], reverse=True)
        
        return attack_types
    
    @classmethod
    def has_high_confidence_rule(cls, rule_ids: list) -> bool:
        """Check if any high-confidence rule triggered"""
        return any(rid in cls.HIGH_CONFIDENCE_RULES for rid in rule_ids)
    
    @classmethod
    def classify(cls, log_entry: dict, status_code: int, method: str, body: str = "") -> dict:
        """
        ✅ TAG-BASED CLASSIFICATION with fallback
        """
        result = {
            "label": "benign",
            "technique": "benign",
            "confidence": "low",
            "evidence": "",
            "payload": "",
            "location": "",
            "rule_ids": [],
            "tags": [],
            "msgs": [],
            "data_list": [],
            "severity": "",
            "source": "FALLBACK"
        }
        
        # Get messages
        messages = log_entry.get("transaction", {}).get("messages", [])
        if not messages:
            messages = log_entry.get("audit_data", {}).get("messages", [])
        
        if not messages:
            if status_code == 403:
                result.update({
                    "label": "attack",
                    "technique": "waf_blocked",
                    "confidence": "medium",
                    "evidence": "http_403_no_rules",
                    "source": "HTTP_403"
                })
            elif status_code == 200:
                result.update({
                    "label": "benign",
                    "technique": "benign",
                    "confidence": "high",
                    "source": "HTTP_200"
                })
            return result
        
        # Parse messages
        all_rule_ids = []
        all_tags = []
        all_msgs = []
        all_data = []
        
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            
            # Extract from message dict
            message_text = msg.get("message", "")
            if message_text and message_text not in all_msgs:
                all_msgs.append(message_text)
            
            details = msg.get("details", {})
            
            # Rule ID
            rule_id = str(details.get("ruleId", ""))
            if rule_id and rule_id not in all_rule_ids:
                all_rule_ids.append(rule_id)
            
            # Tags
            tags = details.get("tags", [])
            if isinstance(tags, list):
                for tag in tags:
                    if tag not in all_tags:
                        all_tags.append(tag)
            
            # Data
            data = details.get("data", "")
            if data and data not in all_data:
                all_data.append(data)
                
                # Extract payload/location
                if "Matched Data:" in data:
                    payload = data.split("Matched Data:")[-1].strip()
                    if "found within" in payload:
                        result["payload"] = payload.split("found within")[0].strip()
                        result["location"] = payload.split("found within")[-1].strip()
                    else:
                        result["payload"] = payload[:100]
            
            # Severity
            if not result["severity"] and details.get("severity"):
                result["severity"] = str(details["severity"])
        
        # ✅ STEP 1: Extract attack types from TAGS (PRIMARY)
        attack_types_from_tags = cls.extract_attack_types_from_tags(all_tags)
        
        # ✅ STEP 2: Check for scanner rules
        scanner_rules = {"913100", "913101", "913102", "913110", "913120", "990002"}
        is_scanner = any(rid in scanner_rules for rid in all_rule_ids)
        
        # ✅ STEP 3: Determine confidence
        has_high_conf = cls.has_high_confidence_rule(all_rule_ids)
        
        # ✅ STEP 4: Classification logic
        if is_scanner and not attack_types_from_tags:
            # Scanner noise only
            result.update({
                "label": "benign",
                "technique": "scanner_noise",
                "confidence": "high",
                "source": "SCANNER_RULE"
            })
        
        elif attack_types_from_tags:
            # Attack detected from tags
            primary_attack = attack_types_from_tags[0][0]  # Highest priority
            
            # Determine confidence
            if has_high_conf:
                confidence = "high"
            elif len(attack_types_from_tags) >= 2:
                confidence = "high"  # Multiple attack types = high confidence
            else:
                confidence = "medium"
            
            result.update({
                "label": "attack",
                "technique": primary_attack,
                "confidence": confidence,
                "source": "TAG_BASED"
            })
            
        elif status_code == 403:
            # Blocked but no attack tags
            result.update({
                "label": "attack",
                "technique": "waf_blocked",
                "confidence": "medium",
                "source": "HTTP_403"
            })
        
        else:
            # No attack detected
            result.update({
                "label": "benign",
                "technique": "benign",
                "confidence": "high",
                "source": "NO_RULES"
            })
        
        # Build evidence
        evidence_parts = []
        if all_rule_ids:
            evidence_parts.append(f"rules:{','.join(all_rule_ids[:5])}")
        if attack_types_from_tags:
            attack_list = [a[0] for a in attack_types_from_tags[:3]]
            evidence_parts.append(f"attack_tags:{','.join(attack_list)}")
        if all_tags:
            evidence_parts.append(f"total_tags:{len(all_tags)}")
        if status_code == 403:
            evidence_parts.append("http_403")
        if has_high_conf:
            evidence_parts.append("high_conf_rule")
        
        result["evidence"] = ";".join(evidence_parts) if evidence_parts else "no_evidence"
        result["rule_ids"] = ";".join(all_rule_ids)
        result["tags"] = ";".join(all_tags[:15])
        result["msgs"] = ";".join([m[:100] for m in all_msgs[:5]])
        result["data_list"] = ";".join([d[:100] for d in all_data[:5]])
        
        return result

# ===================== LOG TAILER =====================
class LogTailer:
    """Log tailer with replay ID matching"""
    
    def __init__(self, path: str):
        self.path = path
        self.offset = 0
        self.last_entries_cache = []
        
        if os.path.exists(LOG_OFFSET_FILE):
            try:
                os.remove(LOG_OFFSET_FILE)
            except:
                pass
        
        if os.path.exists(path):
            self.offset = os.path.getsize(path)
        
        print(f"[LOG] Monitoring: {path} (offset: {self.offset})")

    def _save_offset(self, offset):
        with OFFSET_LOCK:
            try:
                with open(LOG_OFFSET_FILE, 'w') as f:
                    f.write(str(offset))
            except:
                pass

    def wait_for_entry(self, url: str, method: str, timestamp_start: float, replay_id: str = None) -> dict:
        """Wait for log entry matching request"""
        parsed = urlparse(url)
        path = parsed.path or "/"
        query = parsed.query
        full_path = f"{path}?{query}" if query else path
        
        timestamp_min = timestamp_start - 2
        timestamp_max = timestamp_start + LOG_WAIT_TIMEOUT + 2
        
        end_time = time.time() + LOG_WAIT_TIMEOUT
        candidates = []
        
        # Tail from offset
        while time.time() < end_time:
            try:
                if not os.path.exists(self.path):
                    time.sleep(0.1)
                    continue
                
                with open(self.path, 'rb') as f:
                    f.seek(self.offset)
                    chunk = f.read(CHUNK_SIZE)
                    
                    if not chunk:
                        time.sleep(0.1)
                        continue
                    
                    text = chunk.decode('utf-8', errors='ignore')
                    self.offset = f.tell()
                    self._save_offset(self.offset)
                    
                    for line in text.splitlines():
                        if not line.strip():
                            continue
                        
                        try:
                            entry = json.loads(line)
                            
                            self.last_entries_cache.append(entry)
                            if len(self.last_entries_cache) > 100:
                                self.last_entries_cache.pop(0)
                            
                            tx = entry.get("transaction", {})
                            req = tx.get("request", {})
                            
                            # Match by replay ID
                            if replay_id:
                                req_headers = req.get("headers", {})
                                log_replay_id = (
                                    req_headers.get("X-Replay-ID") or 
                                    req_headers.get("X-Replay-Id") or 
                                    req_headers.get("x-replay-id")
                                )
                                
                                if log_replay_id == replay_id:
                                    print(f"  [LOG✓] Found by Replay-ID")
                                    return entry
                            
                            # Match by URL + method
                            req_method = req.get("method", "")
                            req_uri = req.get("uri", "")
                            
                            if req_method != method:
                                continue
                            
                            if not (path == req_uri or path in req_uri or req_uri in full_path):
                                continue
                            
                            # Timestamp check
                            unique_id = tx.get("unique_id", "")
                            if unique_id:
                                try:
                                    log_timestamp = float(unique_id.split('.')[0])
                                    if timestamp_min <= log_timestamp <= timestamp_max:
                                        candidates.append((entry, log_timestamp))
                                except:
                                    candidates.append((entry, timestamp_start))
                            else:
                                candidates.append((entry, timestamp_start))
                                
                        except:
                            continue
                            
            except:
                time.sleep(0.1)
        
        # Choose best candidate
        if candidates:
            candidates.sort(key=lambda x: abs(x[1] - timestamp_start))
            print(f"  [LOG✓] Found by URL+time")
            return candidates[0][0]
        
        # Search cache
        if self.last_entries_cache:
            for entry in reversed(self.last_entries_cache):
                try:
                    tx = entry.get("transaction", {})
                    req = tx.get("request", {})
                    
                    if replay_id:
                        req_headers = req.get("headers", {})
                        log_replay_id = (
                            req_headers.get("X-Replay-ID") or 
                            req_headers.get("X-Replay-Id") or 
                            req_headers.get("x-replay-id")
                        )
                        if log_replay_id == replay_id:
                            print(f"  [CACHE✓] Found!")
                            return entry
                    
                    if req.get("method") == method and path in req.get("uri", ""):
                        print(f"  [CACHE✓] Found!")
                        return entry
                except:
                    continue
        
        print(f"  [WARN] No log entry found")
        return {}

# ===================== REPLAYER =====================
def replay_request(req: dict, rid: str, host: str, port: int, tailer: LogTailer, 
                   idx: int, total: int) -> dict:
    """Replay single request"""
    
    url = req.get('url', '')
    method = req.get('method', 'GET').upper()
    headers = dict(req.get('headers', {}))
    body = req.get('body', '') or req.get('req_body', '')
    tool = req.get('tool', 'UNKNOWN')
    
    if not url:
        return {
            "index": idx,
            "replay_id": rid,
            "url": "",
            "status_code": "ERR",
            "label": "error",
            "technique": "missing_url",
            "confidence": "low",
            "source": "ERROR"
        }
    
    url = re.sub(r"^https?://[^/]+", f"http://{host}:{port}", url)
    
    headers['X-Replay-ID'] = rid
    headers['User-Agent'] = headers.get('User-Agent', session.headers['User-Agent'])
    
    payload_sent = False
    body_size = 0
    
    if method in ['POST', 'PUT', 'PATCH'] and body:
        if isinstance(body, str):
            body_bytes = body.encode('utf-8', errors='ignore')
        else:
            body_bytes = body
        
        body_size = len(body_bytes)
        headers['Content-Length'] = str(body_size)
        
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        payload_sent = True
    else:
        body_bytes = None
    
    status = "ERR"
    elapsed = 0
    timestamp_start = time.time()
    
    for attempt in range(RETRY_COUNT + 1):
        try:
            start = time.time()
            
            resp = session.request(
                method=method,
                url=url,
                headers=headers,
                data=body_bytes,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=False
            )
            
            status = resp.status_code
            elapsed = time.time() - start
            timestamp_start = start
            break
            
        except requests.exceptions.Timeout:
            status = "TIMEOUT"
            if attempt == RETRY_COUNT:
                elapsed = REQUEST_TIMEOUT
        except:
            if attempt == RETRY_COUNT:
                status = "ERR"
                elapsed = 0
        
        if attempt < RETRY_COUNT:
            time.sleep(0.3)
    
    log_entry = tailer.wait_for_entry(url, method, timestamp_start, replay_id=rid)
    
    verification = verify_payload_in_log(log_entry, body)
    
    if method == 'POST':
        update_verification_stats(verification["verified"])
    
    # ✅ USE TAG-BASED CLASSIFIER
    classification = TagBasedClassifier.classify(log_entry, status, method, body)
    
    short_rid = rid.split('-')[1][:8] if '-' in rid else rid[:8]
    
    status_symbol = {
        200: "✓", 403: "⊗", 404: "?", 500: "⚠", 502: "⚠",
        "ERR": "✗", "TIMEOUT": "⏱"
    }.get(status, "?")
    
    label_color = "\033[91m" if classification["label"] == "attack" else "\033[92m"
    label_display = f"{label_color}{classification['label'].upper():<8}\033[0m"
    
    print(f"[{idx:05d}/{total:05d}] [{short_rid}] {status_symbol} {status:>3} | {method:4}")
    print(f"  → {label_display} [{classification['source']:>15}] {classification['technique']:<20} ({classification['confidence']})")
    
    if classification["rule_ids"]:
        print(f"     Rules: {classification['rule_ids'][:80]}")
    
    if classification["payload"]:
        print(f"     Payload: {classification['payload'][:60]}")
    
    if method == 'POST' and payload_sent:
        verify_icon = "✓" if verification["verified"] else "⚠"
        print(f"     Body: {body_size}B {verify_icon} ({verification['reason']})")
    
    return {
        "index": idx,
        "replay_id": rid,
        "url": req.get('url', ''),
        "sent_url": url,
        "method": method,
        "tool": tool,
        "status_code": str(status),
        "response_time": f"{elapsed:.3f}",
        "body_size": body_size,
        "payload_sent": "yes" if payload_sent else "no",
        "payload_verified": "yes" if verification["verified"] else "no",
        "verify_reason": verification["reason"],
        **{k: v for k, v in classification.items() if k not in ['rule_ids', 'tags', 'msgs', 'data_list']},
        "rule_ids": classification["rule_ids"],
        "tags": classification["tags"],
        "msgs": classification["msgs"],
        "data_list": classification["data_list"]
    }

# ===================== MAIN =====================
def main():
    parser = argparse.ArgumentParser(description="Phase 2: TAG-BASED Classification")
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-j", "--json", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("-n", "--limit", type=int)
    parser.add_argument("-w", "--workers", type=int, default=MAX_WORKERS)
    parser.add_argument("-l", "--log", default=DEFAULT_LOG)
    args = parser.parse_args()

    print("\n" + "="*80)
    print(" 🔄 PHASE 2: TAG-BASED CLASSIFICATION")
    print("="*80)
    print(f" Input:       {args.input}")
    print(f" Output CSV:  {args.output}")
    print(f" Output JSON: {args.json}")
    print(f" Target:      {args.host}:{args.port}")
    print(f" Workers:     {args.workers}")
    print("="*80 + "\n")

    with open(args.input, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        requests_list = []
        
        for r in reader:
            req = {
                "method": r.get('method', 'GET'),
                "url": r.get('url', ''),
                "headers": {},
                "body": r.get('req_body', '') or r.get('body', ''),
                "tool": r.get('tool', 'UNKNOWN')
            }
            
            req_header = r.get('req_header', '')
            if req_header:
                for line in req_header.split('|'):
                    if ':' in line:
                        k, v = line.split(':', 1)
                        req["headers"][k.strip()] = v.strip()
            
            requests_list.append(req)
    
    if not requests_list:
        print("[!] No requests!")
        return
    
    if args.limit:
        requests_list = requests_list[:args.limit] if args.limit > 0 else requests_list
        print(f"[LIMIT] Processing {len(requests_list)} requests")
    
    total = len(requests_list)
    post_count = sum(1 for r in requests_list if r['method'] == 'POST')
    
    print(f"[+] Total: {total} | POST: {post_count}\n")
    
    tailer = LogTailer(args.log)
    
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
    
    fieldnames = [
        "index", "replay_id", "url", "sent_url", "method", "tool",
        "status_code", "response_time", 
        "body_size", "payload_sent", "payload_verified", "verify_reason",
        "label", "technique", "confidence", "source", "evidence",
        "payload", "location",
        "rule_ids", "tags", "msgs", "data_list", "severity"
    ]
    
    with open(args.output, 'w', newline='', encoding='utf-8') as csvf, \
         open(args.json, 'w', encoding='utf-8') as jsonf:
        
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {}
            
            for i, req in enumerate(requests_list, 1):
                rid = f"replay-{i:06d}-{uuid.uuid4().hex[:6]}"
                
                future = executor.submit(
                    replay_request,
                    req, rid, args.host, args.port, tailer, i, total
                )
                futures[future] = i
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    writer.writerow(result)
                    csvf.flush()
                    jsonf.write(json.dumps(result) + "\n")
                    jsonf.flush()
                except Exception as e:
                    print(f"[!] Error: {e}")
    
    print(f"\n{'='*80}")
    print(f"✅ COMPLETE!")
    print(f"{'='*80}")
    
    with verification_stats["lock"]:
        total_verified = verification_stats["verified"]
        total_failed = verification_stats["failed"]
        total_post = verification_stats["total"]
    
    if total_post > 0:
        print(f"\n📊 PAYLOAD VERIFICATION:")
        print(f"   POST: {total_post}")
        print(f"   ✓ Verified: {total_verified} ({total_verified/total_post*100:.1f}%)")
        print(f"   ✗ Failed: {total_failed} ({total_failed/total_post*100:.1f}%)")
    
    print(f"\n📁 OUTPUT:")
    print(f" CSV:  {args.output}")
    print(f" JSON: {args.json}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
