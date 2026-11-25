import os
import json
import requests
from bs4 import BeautifulSoup
import urllib3
import re
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_URL = os.environ.get('TARGET_URL', 'http://testphp.vulnweb.com/').rstrip('/')
findings = []
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
})

print(f"[*] Starting scan on: {TARGET_URL}")

# 1. فحص المسارات الحساسة
SENSITIVE_PATHS = [".env", ".git/config", "admin/", "phpinfo.php", "server-status", "backup.zip", "config.php.bak"]
print("[*] Checking sensitive paths...")

def check_path(path):
    try:
        url = f"{TARGET_URL}/{path}"
        res = session.get(url, timeout=5, verify=False)
        if res.status_code == 200 and "404" not in res.text[:200]:
            return {"severity": "high", "title": f"مسار مفتوح: /{path}", "evidence": url}
    except:
        pass
    return None

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(check_path, SENSITIVE_PATHS))
    for r in results:
        if r: findings.append(r)

# 2. فحص ثغرات XSS
print("[*] Testing forms for XSS...")
try:
    res = session.get(TARGET_URL, timeout=10, verify=False)
    soup = BeautifulSoup(res.text, 'html.parser')
    forms = soup.find_all('form')
    
    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        form_url = TARGET_URL + action if not action.startswith('http') else action
        
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name and input_tag.get('type') in ['text', 'search']:
                payload = '<script>alert("XSS")</script>'
                if method == 'post':
                    req = session.post(form_url, data={input_name: payload}, timeout=5, verify=False)
                else:
                    req = session.get(form_url, params={input_name: payload}, timeout=5, verify=False)
                
                if payload in req.text:
                    findings.append({
                        "severity": "high", 
                        "title": "ثغرة XSS منعكسة", 
                        "evidence": f"Payload: {payload} in {input_name} at {form_url}"
                    })
except Exception as e:
    print(f"XSS Scan error: {e}")

# حفظ التقرير
with open('scan_report.json', 'w', encoding='utf-8') as f:
    json.dump({"target": TARGET_URL, "findings": findings}, f, ensure_ascii=False, indent=4)

print(f"[+] Scan complete. Found {len(findings)} issues. Saved to scan_report.json")
