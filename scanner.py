import os
import json
import asyncio
from playwright.async_api import async_playwright
from bs4 import BeautifulSoup
import re
import concurrent.futures

TARGET_URL = os.environ.get('TARGET_URL', 'https://unico.io').rstrip('/')
findings = []

async def fetch_page(url):
    async with async_playwright() as p:
        # تشغيل متصفح كروم بوضع التخفي
        browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
        context = await browser.new_context(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            viewport={'width': 1920, 'height': 1080}
        )
        page = await context.new_page()
        
        print(f"[*] Navigating to {url}...")
        try:
            # الانتظار حتى تحميل الشبكة
            await page.goto(url, wait_until='networkidle', timeout=30000)
            html = await page.content()
            print(f"[+] Page loaded successfully. Length: {len(html)}")
            return html
        except Exception as e:
            print(f"[!] Navigation error: {e}")
            return None
        finally:
            await browser.close()

def check_sensitive_paths(base_url):
    print("[*] Checking sensitive paths...")
    paths = ["admin/", "login", "phpinfo.php", "server-status", ".env", ".git/config"]
    
    # دالة مساعدة للفحص
    def check_sync(path):
        try:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            res = requests.get(f"{base_url}/{path}", timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            if res.status_code == 200 and "404" not in res.text[:200]:
                return {"severity": "high", "title": f"مسار مفتوح: /{path}", "evidence": f"{base_url}/{path}"}
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(check_sync, paths))
        return [r for r in results if r]

async def main():
    global findings
    
    # 1. جلب الصفحة بالمتصفح الوهمي
    html = await fetch_page(TARGET_URL)
    
    if not html:
        findings.append({"severity": "crit", "title": "فشل الاتصال بالموقع", "evidence": "Browser failed to load the page. Maybe it's completely down."})
    else:
        # 2. تحليل كود الصفحة
        print("[*] Analyzing HTML...")
        soup = BeautifulSoup(html, 'html.parser')
        
        # فحص ثغرات XSS في النماذج
        forms = soup.find_all('form')
        for form in forms:
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                if input_name and input_tag.get('type') in ['text', 'search']:
                    findings.append({
                        "severity": "info", 
                        "title": "نموذج إدخال مكتشف", 
                        "evidence": f"Input name: {input_name}"
                    })
        
        # فحص التعليقات المسربة
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        for c in comments:
            if re.search(r'(password|secret|api_key|db_pass)', c, re.IGNORECASE):
                findings.append({"severity": "high", "title": "بيانات مسربة في تعليقات HTML", "evidence": c[:100]})
        
        # 3. فحص المسارات الحساسة (بالتوازي)
        path_findings = check_sensitive_paths(TARGET_URL)
        findings.extend(path_findings)

    # حفظ التقرير
    with open('scan_report.json', 'w', encoding='utf-8') as f:
        json.dump({"target": TARGET_URL, "findings": findings}, f, ensure_ascii=False, indent=4)
    
    print(f"[+] Scan complete. Found {len(findings)} issues.")

if __name__ == '__main__':
    asyncio.run(main())