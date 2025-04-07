import os
import requests
from colorama import init, Fore, Style
import nmap
from scapy.all import sniff
from bs4 import BeautifulSoup
import paramiko
from pyfiglet import Figlet

version = "v1.0"
author = "Pharmyx"
divider = "========================================"

init()

def draven():
    f = Figlet(font='slant')
    print(Fore.CYAN + f.renderText("Draven") + Style.RESET_ALL)
    print(Fore.YELLOW + "Draven is a tool made by Pharmyx for testing and securing your own devices.")
    print("It’s meant to be used responsibly. Using it to harm others or break into systems")
    print("you don’t own is illegal. If you get caught misusing it, you could face serious")
    print("consequences, like arrest." + Style.RESET_ALL)

def track_ip():
    ip = input(Fore.WHITE + "Enter the IP address you want to track: " + Style.RESET_ALL)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data["status"] == "success":
            print(Fore.GREEN + "\nIP Tracking Results:" + Style.RESET_ALL)
            print(f"IP Address: {data['query']}")
            print(f"Country: {data['country']} ({data['countryCode']})")
            print(f"Region: {data['regionName']}")
            print(f"City: {data['city']}")
            print(f"ZIP Code: {data['zip']}")
            print(f"Latitude: {data['lat']}")
            print(f"Longitude: {data['lon']}")
            print(f"ISP: {data['isp']}")
        else:
            print(Fore.RED + "Error: Invalid or private IP." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def nmap_scan():
    try:
        nm = nmap.PortScanner()
        ip = input(Fore.WHITE + "Enter the IP address to scan: " + Style.RESET_ALL)
        print(Fore.YELLOW + f"Scanning {ip} (this may take a moment)..." + Style.RESET_ALL)
        nm.scan(ip, '1-1024')
        for host in nm.all_hosts():
            print(Fore.GREEN + f"\nHost: {host} ({nm[host].hostname()})" + Style.RESET_ALL)
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")
    except nmap.PortScannerError as e:
        print(Fore.RED + f"Nmap not found or failed: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + "Please ensure Nmap is installed and added to your PATH." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Scan failed: {e}" + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def packet_sniffer():
    print(Fore.YELLOW + "Sniffing packets (Ctrl+C to stop)..." + Style.RESET_ALL)
    try:
        sniff(prn=lambda pkt: print(Fore.GREEN + pkt.summary() + Style.RESET_ALL), count=10)
    except Exception as e:
        print(Fore.RED + f"Sniffing failed: {e}" + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def scrape_website():
    url = input(Fore.WHITE + "Enter the website URL to scrape (e.g., http://example.com): " + Style.RESET_ALL)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        print(Fore.GREEN + "\nScraped Data:" + Style.RESET_ALL)
        print("Title:", soup.title.string if soup.title else "No title found")
        links = [a['href'] for a in soup.find_all('a', href=True)]
        print(f"Found {len(links)} links:")
        for link in links[:5]:
            print(link)
    except Exception as e:
        print(Fore.RED + f"Scraping failed: {e}" + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def ssh_connect():
    hostname = input(Fore.WHITE + "Enter SSH hostname: " + Style.RESET_ALL)
    username = input(Fore.WHITE + "Enter SSH username: " + Style.RESET_ALL)
    password = input(Fore.WHITE + "Enter SSH password: " + Style.RESET_ALL)
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password)
        print(Fore.GREEN + "Connected successfully!" + Style.RESET_ALL)
        stdin, stdout, stderr = ssh.exec_command("ls" if os.name != 'nt' else "dir")
        print(stdout.read().decode())
        ssh.close()
    except Exception as e:
        print(Fore.RED + f"SSH connection failed: {e}" + Style.RESET_ALL)
    input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main_menu():
    while True:
        clear_screen()
        draven()
        print(Fore.WHITE + divider + Style.RESET_ALL)
        print(Fore.CYAN + "\nMain Menu:" + Style.RESET_ALL)
        print("1. INFO")
        print("2. WEBSITE")
        print("3. Exit")
        print(Fore.CYAN + "\nOSINT-Tools:" + Style.RESET_ALL)
        print("4. IP Logger")
        print("5. IP Tracker")
        print("6. Nmap Scanner")
        print("7. Packet Sniffer")
        print("8. Website Scraper")
        print("9. SSH Connect")
        choice = input(Fore.WHITE + "\nEnter your choice (1-9): " + Style.RESET_ALL)
        if choice == "1":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            print(Fore.GREEN + f"Draven {version} by {author} - A tool for ethical hacking and testing." + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        elif choice == "2":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            print(Fore.YELLOW + "Website feature not implemented yet." + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        elif choice == "3":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            print(Fore.RED + "Exiting Draven." + Style.RESET_ALL)
            break
        elif choice == "4":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            print(Fore.YELLOW + "IP Logger feature not implemented yet." + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)
        elif choice == "5":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            track_ip()
        elif choice == "6":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            nmap_scan()
        elif choice == "7":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            packet_sniffer()
        elif choice == "8":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            scrape_website()
        elif choice == "9":
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            ssh_connect()
        else:
            clear_screen()
            draven()
            print(Fore.WHITE + divider + Style.RESET_ALL)
            print(Fore.RED + "Invalid choice. Please enter a number between 1 and 9." + Style.RESET_ALL)
            input(Fore.WHITE + "\nPress Enter to return..." + Style.RESET_ALL)

if __name__ == "__main__":
    main_menu()