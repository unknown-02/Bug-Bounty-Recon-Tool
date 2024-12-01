# ReconTool: Automated Reconnaissance Tool

ReconTool is a Python-based automated reconnaissance tool for cybersecurity professionals and bug bounty hunters. It identifies IP addresses, subdomains, sub-subdomains, directory listings, and endpoints using dorks and APIs.

## Features
- Resolve IP addresses for a given domain.
- Subdomain enumeration using Sublist3r and APIs.
- Directory brute-forcing using a custom wordlist.
- Shodan and VirusTotal integration for enriched data.
- Generate organized output for reporting.

## Installation
1. Clone this repository:
```bash
git clone https://github.com/your-username/ReconTool.git
cd ReconTool
```
2. Install dependencies:
```bash
pip install -r requirements.txt
Configure API keys:
```

3. Add your API keys for Shodan and VirusTotal in the recon_tool.py file:
```python
SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
```

## Usage
Run the tool by providing a target domain:

```bash
python recon_tool.py
```

Follow the prompts to input the target domain and view the results.


## Configuration File
API keys are stored in a config.json file in the following format:

```json
{
    "shodan_api_key": "your_shodan_api_key",
    "virustotal_api_key": "your_virustotal_api_key"
}
```

To manually edit this file, open it in a text editor and replace the placeholder values with your API keys.

## Wordlists
Default wordlist for directory enumeration.
```
wordlist/directories.txt
```

Default wordlist for subdomain enumeration.
```
wordlist/subdomains.txt
```