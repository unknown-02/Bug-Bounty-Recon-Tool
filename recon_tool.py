import socket
import requests
import os
import json
from dns import resolver
from urllib.parse import urljoin

# Replace with your APIs
SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "Unable to resolve IP"

def find_subdomains(domain):
    print("[*] Finding subdomains...")
    subdomains = []
    wordlist_path = "wordlist/subdomains.txt"
    try:
        with open(wordlist_path, "r") as file:
            for sub in file:
                subdomain = f"{sub.strip()}.{domain}"
                try:
                    socket.gethostbyname(subdomain)
                    subdomains.append(subdomain)
                except socket.gaierror:
                    pass
    except FileNotFoundError:
        print("[!] Subdomain wordlist not found.")
    return subdomains

def find_directory_listing(domain):
    print("[*] Finding directories...")
    directories = []
    wordlist_path = "wordlist/directories.txt"
    try:
        with open(wordlist_path, "r") as file:
            for word in file:
                url = urljoin(f"http://{domain}/", word.strip())
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        directories.append(url)
                except requests.RequestException:
                    pass
    except FileNotFoundError:
        print("[!] Directory wordlist not found.")
    return directories

def shodan_lookup(ip):
    print("[*] Looking up IP on Shodan...")
    if not SHODAN_API_KEY:
        return "Shodan API Key not configured."
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        return response.json()
    except requests.RequestException:
        return "Error querying Shodan."

def virustotal_lookup(domain):
    print("[*] Looking up domain on VirusTotal...")
    if not VIRUSTOTAL_API_KEY:
        return "VirusTotal API Key not configured."
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers)
        return response.json()
    except requests.RequestException:
        return "Error querying VirusTotal."

def run_tool(domain):
    print(f"[*] Running reconnaissance for {domain}")
    ip = get_ip(domain)
    print(f"[+] IP Address: {ip}")

    subdomains = find_subdomains(domain)
    print(f"[+] Found Subdomains: {subdomains}")

    directories = find_directory_listing(domain)
    print(f"[+] Found Directories: {directories}")

    shodan_data = shodan_lookup(ip)
    print(f"[+] Shodan Data: {json.dumps(shodan_data, indent=2)}")

    vt_data = virustotal_lookup(domain)
    print(f"[+] VirusTotal Data: {json.dumps(vt_data, indent=2)}")

if __name__ == "__main__":
    target = input("Enter the target domain: ")
    run_tool(target)
