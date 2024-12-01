import os
import json
import aiohttp
import asyncio
from aiohttp import ClientSession
from time import time

# Function to load API keys from config.json
def load_api_keys():
    if os.path.exists('config.json'):
        with open('config.json', 'r') as config_file:
            return json.load(config_file)
    else:
        return {"shodan_key": "", "virustotal_key": ""}

# Function to save API keys to config.json
def save_api_keys(keys):
    with open('config.json', 'w') as config_file:
        json.dump(keys, config_file)

# Function to get user input for API keys
def get_api_keys():
    keys = {}
    keys['shodan_key'] = input("Enter your Shodan API key: ")
    keys['virustotal_key'] = input("Enter your VirusTotal API key: ")
    save_api_keys(keys)

# Asynchronous function to scan subdomains
async def subdomain_scan(domain, wordlist_path, session):
    print("Starting Subdomain Scan...")
    found_subdomains = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                subdomain = line.strip()
                if not subdomain or subdomain.startswith('.') or subdomain.endswith('.'):
                    continue
                full_subdomain = f'{subdomain}.{domain}'
                try:
                    async with session.get(f'http://{full_subdomain}', timeout=2) as response:
                        if response.status == 200:
                            found_subdomains.append(full_subdomain)
                            print(f"Found subdomain: {full_subdomain}")
                except Exception:
                    continue
    except FileNotFoundError:
        print(f"Wordlist not found: {wordlist_path}")
    return found_subdomains

# Asynchronous function to scan directories
async def directory_scan(domain, wordlist_path, session):
    print("Starting Directory Scan...")
    found_directories = []
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                directory = line.strip()
                url = f'http://{domain}/{directory}'
                try:
                    async with session.get(url, timeout=2) as response:
                        if response.status == 200:
                            found_directories.append(url)
                            print(f"Found directory: {url}")
                except Exception:
                    continue
    except FileNotFoundError:
        print(f"Wordlist not found: {wordlist_path}")
    return found_directories

# Asynchronous function to perform Shodan scan
async def shodan_scan(domain, shodan_key, session):
    print("Starting Shodan Scan...")
    try:
        async with session.get(f'https://dns.google/resolve?name={domain}&type=A', timeout=2) as ip_response:
            if ip_response.status == 200:
                ip_data = await ip_response.json()
                ip_addresses = [answer['data'] for answer in ip_data.get('Answer', [])]
                if ip_addresses:
                    ip_address = ip_addresses[0]
                    print(f"Performing Shodan scan for IP: {ip_address}")

                    shodan_url = f'https://api.shodan.io/shodan/host/{ip_address}?key={shodan_key}'
                    async with session.get(shodan_url, timeout=5) as shodan_response:
                        if shodan_response.status == 200:
                            data = await shodan_response.json()
                            print(f"Shodan data for {domain}:")
                            print(f"   - IP: {data.get('ip_str', 'No IP data')}")
                            print(f"   - Organization: {data.get('org', 'No organization data')}")
                            print(f"   - Country: {data.get('country_name', 'No country data')}")
                        else:
                            print(f"Shodan API error: {shodan_response.status}")
                else:
                    print(f"No IP address found for {domain}.")
            else:
                print(f"Failed to resolve domain: {domain}.")
    except Exception as e:
        print(f"Error during Shodan scan: {e}")

# Asynchronous function to perform VirusTotal scan
async def virustotal_scan(domain, virustotal_key, session):
    print("Starting VirusTotal Scan...")
    try:
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        headers = {'x-apikey': virustotal_key}
        async with session.get(url, headers=headers, timeout=5) as response:
            if response.status == 200:
                data = await response.json()
                scan_reports = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                print(f"VirusTotal data for {domain}:")
                print(f"   - Malicious Reports: {scan_reports.get('malicious', 0)}")
            else:
                print(f"VirusTotal API error: {response.status}")
    except Exception as e:
        print(f"Error during VirusTotal scan: {e}")

# Asynchronous function to enumerate IP addresses for a domain
async def enumerate_ips(domain, session):
    print("Starting IP Enumeration...")
    try:
        ip_addresses = []
        async with session.get(f'https://dns.google/resolve?name={domain}&type=A', timeout=2) as response:
            if response.status == 200:
                result = await response.json()
                if 'Answer' in result:
                    ip_addresses = [answer['data'] for answer in result['Answer']]
                    print(f"IP addresses for {domain}: {ip_addresses}")
            else:
                print(f"Failed to retrieve IP addresses for {domain}.")
    except Exception as e:
        print(f"Error during IP enumeration: {e}")

# Main asynchronous function to run tasks sequentially
async def main():
    keys = load_api_keys()
    if not keys['shodan_key'] or not keys['virustotal_key']:
        get_api_keys()
        keys = load_api_keys()

    domain_to_check = input("Enter the domain to scan (e.g., dell.com): ")

    async with ClientSession() as session:
        await enumerate_ips(domain_to_check, session)
        await subdomain_scan(domain_to_check, "wordlists/subdomain_wordlist.txt", session)
        await directory_scan(domain_to_check, "wordlists/directory_wordlist.txt", session)
        await shodan_scan(domain_to_check, keys['shodan_key'], session)
        await virustotal_scan(domain_to_check, keys['virustotal_key'], session)

if __name__ == "__main__":
    try:
        start_time = time()
        asyncio.run(main())
        print(f"Finished in {time() - start_time:.2f} seconds.")
    except KeyboardInterrupt:
        print("\nProcess interrupted. Exiting...")
