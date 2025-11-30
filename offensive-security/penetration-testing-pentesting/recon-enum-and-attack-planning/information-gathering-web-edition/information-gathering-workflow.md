# Information Gathering Workflow

### Nmap

{% code overflow="wrap" %}
```bash
sudo nmap --script http-auth --script-args http-auth.path=/login -p 80,443 <target-ip> 
sudo nmap --script http-devframework -p 80,443 <target-ip>
sudo nmap --script http-enum -p 80,443 <target-ip> 
sudo nmap --script http-headers -p 80,443 <target-ip> 
sudo nmap --script http-methods -p 80,443 <target-ip>
```
{% endcode %}

### WHOIS Lookup

WHOIS provides domain registration details like owner, registrar, creation date, and contact info. This is foundational for identifying domain ownership and potential attack surfaces. Modern updates include using APIs or web interfaces to bypass command-line limitations (e.g., rate limits on CLI whois). Be aware of privacy protections like GDPR, which may redact personal data.

#### Commands/Tools

* **Command-Line WHOIS**:

```shell
export TARGET="domain.tld"  
whois $TARGET
```

* **Output**: Registration details, nameservers, expiry dates.
* **Caveat**: Some registrars block bulk queries; use with sleep delays in scripts.
* **Modern Alternatives**:
* Setup Python Environment:

```bash
# Create the environment: Navigate to your project folder and run:
python3 -m venv my_project_env
# Activate the environment:
source my_project_env/bin/activate
# Install packages: Now you can use pip freely without affecting your system.
pip3 install <package-name>
# Deactivate: When you're done working, simply type:
deactivate
```

```
OR
```

**Use apt (For System-Wide Tools)**

```bash
sudo apt install python3-requests  # Example for the 'requests' library   
```

* Use Python for structured output:

```python
import whois  
domain_info = whois.whois("TARGET")  
print(domain_info)
```

* **Install**: pip3 install python-whois.
* Why: Parses output into JSON-like structure for easier analysis.
  * Web-based: Browse WHOIS via sites like whois.icann.org or domaintools.com.
    * Tool Integration: Use browse\_page tool with URL https://whois.icann.org/en/lookup?name=$TARGET and instructions like "Extract domain registration details, owner, and nameservers."
* **Other Tools**:
  * web\_search with query "whois $TARGET" for aggregated results from multiple sources.
  * For training: Compare outputs from different registrars to spot inconsistencies.

### Enumeration

**Note**: when enumerating internal domains it may be helpful to create a host file entry:

```shell
sudo sh -c "echo 'IP example.local' >> /etc/hosts"
```

### DNS Enumeration

#### Explanation

DNS enumeration reveals IP addresses, mail servers, and other records tied to a domain, helping map network infrastructure. Types include A (IPv4), PTR (reverse lookup), TXT (SPF/DMARC), MX (mail), and ANY (all). Modernize by automating with scripts and using resilient nameservers to handle failures. This passive step avoids alerting targets.

#### Commands/Tools

* **Basic A Record**:

```bash
nslookup $TARGET  
nslookup -query=A $TARGET  
dig $TARGET @$NS  
dig a $TARGET @$NS 

# Use dig for its clean output 
dig $TARGET ANY +noall +answer # Get all common records for the domain 
dig $TARGET MX +noall +answer # Get only the mail exchange records
```

* Output: IP addresses associated with the domain.
* **PTR (Reverse Lookup)**:

```shell
export IP="192.0.2.1" # Replace with target IP  
nslookup -query=PTR $IP 
dig -x $IP @$NS 
```

* Why: Identifies domain from IP, useful for verifying ownership.
* **ANY Records**:

```bash
nslookup -query=ANY $TARGET  
dig any $TARGET @$NS
```

* Caveat: Many servers block ANY queries for security; fall back to specific types.
* **TXT Records**:

```bash
nslookup -query=TXT $TARGET  
dig txt $TARGET @$NS
```

* Useful for: Security configs like SPF to prevent email spoofing.
* **MX Records**:

```bash
nslookup -query=MX $TARGET  
dig mx $TARGET @$NS
```

* Output: Mail server priorities and hosts.
* **Modern Automation**:
  * Python script for batch enumeration:

```python
import dns.resolver  
records = ['A', 'MX', 'TXT', 'NS']  
for rtype in records:  
	try:  
		answers = dns.resolver.resolve(TARGET, rtype)  
		for rdata in answers:  
			print(f"{rtype}: {rdata}")  
	except Exception as e:  
		print(f"Error for {rtype}: {e}")
```

* Install: pip install dnspython.
* Why: Handles errors, supports custom resolvers.
* **Other Tools**:
  * code\_execution to run the above Python code dynamically.
  * web\_search\_with\_snippets with query "DNS records for $TARGET" for quick public database snippets.
  * For advanced: Use x\_keyword\_search on X (Twitter) with query "$TARGET DNS leak" filter:links to find public discussions or leaks.

### Passive Subdomain Enumeration

#### Explanation

Passive enumeration discovers subdomains without querying the target directly, using public datasets like certificate logs or search engines. This reduces detection risk. Modern updates include API integrations and semantic searches for broader coverage. Sources like VirusTotal or Censys aggregate data from scans.

#### Features/Tools

* **Web Interfaces**:
  * VirusTotal: \[[https://www.virustotal.com/gui/home/url](https://www.virustotal.com/gui/home/url)] – Search for domain; view subdomains in "Relations" tab.
  * Censys: \[[https://censys.io/](https://censys.io/)] – Query hosts with services.tls.certificates.leaf\_data.names:"\*.$TARGET".
  * Crt.sh: \[[https://crt.sh/](https://crt.sh/)] – Search %.$TARGET for certificate transparency logs.
* **API-Based**:

```shell
# Subdomains via Sonar (Omnisint)  
curl -s "https://sonar.omnisint.io/subdomains/$TARGET" | jq -r '.[]' | sort -u  
# TLDs  
curl -s "https://sonar.omnisint.io/tlds/$TARGET" | jq -r '.[]' | sort -u  
# All TLD results  c
url -s "https://sonar.omnisint.io/all/$TARGET" | jq -r '.[]' | sort -u  
# Reverse DNS  
curl -s "https://sonar.omnisint.io/reverse/$IP" | jq -r '.[]' | sort -u  
# CIDR Reverse  
curl -s "https://sonar.omnisint.io/reverse/$IP/24" | jq -r '.[]' | sort -u   
```

* Install jq for JSON parsing.
* **Certificate Transparency**:

{% code overflow="wrap" %}
```shell
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```
{% endcode %}

* **Multi-Source Harvesting**:
  * Create sources.txt with: baidu, bufferoverun, crtsh, hackertarget, otx, projectdiscovery, rapiddns, sublist3r, threatcrowd, trello, urlscan, virustotal, zoomeye.

{% code overflow="wrap" %}
```shell
cat sources.txt | while read source; do theHarvester -d "$TARGET" -b $source -f "${source}-${TARGET}"; done
```
{% endcode %}

* Install: pip install theHarvester.- Why: Aggregates from multiple APIs; outputs JSON/XML.
* **Modern Alternatives**:
  * Use browse\_page with URL https://crt.sh/?q=%25.$TARGET and instructions "Extract and list unique subdomains from certificate logs."
  * Semantic search: x\_semantic\_search with query "subdomains of $TARGET" to find relevant X posts mentioning them.
* **Other Tools**:
  * web\_search with query "subdomains $TARGET site:github.com" for leaked repos.
  * Shodan.io API (via web\_search query "shodan $TARGET subdomains") for IoT/exposed devices.

### Passive Infrastructure Identification

#### Explanation

Identifies tech stack, historical changes, and archived content without active probes. Useful for spotting outdated software or forgotten endpoints. Modernize with URL archiving tools and API fetches.

#### Features/Tools

* **Web Interfaces**:
  * Netcraft: \[[https://www.netcraft.com/](https://www.netcraft.com/)] – Search for hosting info, tech stack.
  * Wayback Machine: \[[http://web.archive.org/](http://web.archive.org/)] – View historical snapshots.
* **Command-Line**:

```bash
# Wayback URLs with dates  
waybackurls -dates $TARGET > waybackurls.txt      
```

* Install: go install github.com/tomnomnom/waybackurls@latest.
* Output: URLs with timestamps for timeline analysis.
* **Modern Alternatives**:
  * Python for processing:

```python
from waybackpy import Url  
archive = Url(TARGET).archives()  
for item in archive:  
	print(item.timestamp, item.archive_url)
```

* Install: pip install waybackpy.
* **Other Tools**:
  * browse\_page with URL https://web.archive.org/web/\*/$TARGET and instructions "Summarize changes in website structure over the last 5 years."
  * web\_search\_with\_snippets query "historical infrastructure $TARGET" for quick archived insights.

### Fingerprinting

#### Explanation

Fingerprinting detects web technologies, servers, and security like WAFs (Web Application Firewalls). This informs vulnerability scanning. Modernize with verbose outputs and integrations.

#### Commands/Tools

* **Retrieve HTTP Headers**:

```shell
curl -I "http://$TARGET"
```

* Output: Server type, cookies, security headers. **Check for Verbose Server Information**

```shell
# Purpose: Send a HEAD request to inspect server responses for detailed information.
curl -I -X HEAD https://example.com
```

**Test for HTTP Methods**

{% code overflow="wrap" %}
```shell
# Purpose: Identify supported HTTP methods (e.g., GET, POST, PUT, DELETE) to discover potential vulnerabilities.
curl -I -X OPTIONS https://example.com
```
{% endcode %}

**Download and Inspect Web Page Source**

{% code overflow="wrap" %}
```shell
# Purpose: Retrieve the full HTML source of a webpage to analyze for hidden comments, endpoints, or scripts.
curl -s https://example.com > page.html
```
{% endcode %}

**Check for SSL/TLS Certificate Details**

{% code overflow="wrap" %}
```shell
Purpose: Inspect the SSL/TLS certificate to gather details like issuer, expiration, or subject alternative names. 
curl -v --insecure https://example.com 2>&1 | grep -E 'subject:|issuer:|expire'
```
{% endcode %}

**Enumerate Subdomains or Endpoints**

{% code overflow="wrap" %}
```shell
# Purpose: Test for the existence of subdomains or specific endpoints by querying URLs. 
for sub in $(cat subdomains.txt); do curl -s -o /dev/null -w "%{http_code} $sub.example.com\n" http://$sub.example.com; done
```
{% endcode %}

**Probe for API Endpoints**

```shell
Purpose: Discover API endpoints or test for exposed APIs by querying common paths.
curl -s https://example.com/api/v1/users | jq .
```

**Test for Directory Listing**

```shell
# Purpose: Check if directory listing is enabled on the target server.
curl -s https://example.com/uploads/ | grep -i "index of"
```

**Spoof User-Agent for Recon**

{% code overflow="wrap" %}
```shell
Purpose: Mimic a different browser or device to detect variations in server responses.
curl -A "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)" https://example.com
```
{% endcode %}

**Check for Robots.txt**

{% code overflow="wrap" %}
```shell
Purpose: Retrieve the robots.txt file to identify disallowed paths or hidden directories.
curl -s https://example.com/robots.txt
```
{% endcode %}

* **Tech Identification**:

```shell
whatweb <target-ip> 
whatweb -a 3 https://$TARGET -v # Aggressive mode

# List all plugins 
whatweb -l 

# Search plugins 
whatweb -I apache 
whatweb -I phpBB 
whatweb -I phpmyadmin [
whatweb -I windows 

# Use plugin 
whatweb -p phpBB <target-ip>
```

* Install: apt install whatweb.
* **Web Interfaces**:
  * Wappalyzer: \[[https://www.wappalyzer.com/](https://www.wappalyzer.com/)] – Browser extension for real-time analysis.
* **WAF Detection**:

```cs
wafw00f -v https://$TARGET
```

* Install: pip install wafw00f.
* **Screenshots**:

```shell
cat subdomains.list | aquatone -out ./aquatone -screenshot-timeout 1000      
```

* Install: Download from GitHub.
* **Software Scan**:

```bash
nikto -h $TARGET -Tuning b # Software misconfigs

## For more details enumeration
nikto -h https://example.com 
# -p: Specify ports 
nikto -p 80,3000 -h https://example.com 
# -T: Tuning [
#  1: Interesting files 
#  2: Misconfiguration 
#  3: Information Disclosure 
#  4: Injection (XSS/Script/HTML) 
nikto -T 1 2 3 -h https://example.com 

# -useragent: Custom user agent 
nikto -useragent <user-agent> -h https://example.com 
# -e: IDS evasion 
#  1: Random URI encoding 
#  7: Change the case of URL 
nikto -e 1 7 -h <target-ip>
```

* Install: apt install nikto.
* **Modern Alternatives**:
  * Use code\_execution to run WhatWeb in a sandbox.
  * view\_image for analyzing screenshots from Aquatone outputs.
* **Other Tools**:
  * web\_search query "fingerprint $TARGET site:builtwith.com" for tech stack via BuiltWith.
* **Python Automation**:

````python
import subprocess
results = []
try:
    output = subprocess.check_output(["whatweb", "-a", "3", "$TARGET"], text=True)
   results.append({"target": "$TARGET", "output": output})
    except Exception as e:
        results.append({"target": "$TARGET", "error": str(e)})
    with open("whatweb_results.json", "w") as f:
        json.dump(results, f, indent=2)
    ```
- **Alternatives**:
    - browse_page on https://builtwith.com/$TARGET ("Extract tech stack").
    - Wappalyzer browser extension.
## SSL Certificate Analysis
## SSL Certificate Analysis
It may contain the sensitive information about the target company.  
We can find it on the key icon in the URL bar in the most web browsers.
#### Commands/Tools
- **Check SSL/TLS Connection**:
```shell
openssl s_client -connect $TARGET:443
````

* Output: Raw certificate details, server response.
* Why: Displays certificate chain and connection info.
* **Scan SSL/TLS Configuration**:

```bash
sslscan $TARGET
```

* Install: apt install sslscan.
* Output: Supported ciphers, TLS versions, and certificate details.
* Why: Identifies weak protocols or ciphers (e.g., deprecated TLS 1.0).
* **Test Specific TLS Versions**:

```shell
openssl s_client -connect $TARGET:443 -tls1  
openssl s_client -connect $TARGET:443 -tls1_1  
openssl s_client -connect $TARGET:443 -tls1_2  
openssl s_client -connect $TARGET:443 -tls1_3
```

* Why: Confirms supported TLS versions; older versions (TLS 1.0/1.1) may indicate vulnerabilities.
  * Caveat: Some servers reject unsupported versions; expect connection errors.
* **Extract Certificate Content**:
  * Manual Method:
    1. Open a browser and navigate to https://$TARGET.
    2. Click the lock icon in the URL bar.
    3. Export the certificate as a .pem file (most browsers support this under "Certificate Details").
    4. Analyze:

```shell
openssl x509 -text -noout -in certificate.pem
```

* Output: Human-readable certificate details (e.g., issuer, SANs, expiry).
  * Automated Method, Python:

```python
import ssl  
import socket  
from OpenSSL import crypto  

context = ssl.create_default_context()  
with socket.create_connection((TARGET, 443)) as sock:  
	with context.wrap_socket(sock, server_hostname=TARGET) as sslsock:  
	cert = sslsock.getpeercert(True)  
	x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)  
	print(f"Issuer: {x509.get_issuer().CN}")  
	print(f"Subject: {x509.get_subject().CN}")  
	print(f"Expiry: {x509.get_notAfter().decode()}")  
	sans = x509.get_extension_count()  
	for i in range(sans):  
		ext = x509.get_extension(i)  
		if 'subjectAltName' in str(ext.get_short_name()):  
			print(f"SANs: {ext}")
```

* Install: pip install pyOpenSSL.
* Why: Automates certificate extraction and parsing; extracts SANs for subdomain discovery.

### Active Subdomain Enumeration

#### Explanation

Active methods query the target directly (e.g., brute-forcing), risking detection. Use sparingly in training. Modernize with rate-limiting and wordlist optimizations.

#### **Brute-Force**:

{% code overflow="wrap" %}
```bash
gobuster dns -q -r "$NS" -d "$TARGET" -w /path/to/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -o "gobuster_$TARGET.txt"

gobuster vhost -u http://inlanefreight.htb:SMTPO -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 60 --append-domain
```
{% endcode %}

* Install: apt install gobuster; Wordlists from SecLists GitHub.
* **Dnsenum**:

```bash
dnsenum $TARGET -f subdomains.txt
```

* Install: apt install dnsenum.
* **Other Tools**:
  * web\_search query "active subdomain enumeration tools 2025" for latest alternatives like Amass.
  * Integrate with code\_execution for custom brute-force scripts

### Virtual Hosts

#### Explanation

Discovers hidden hosts on the same IP. Useful for shared hosting environments.

#### Commands/Tools

```bash
gobuster vhost -u http://$IP -w hostnames.txt
```

* Wordlist: Custom or from SecLists.
* **Other Tools**:
  * browse\_page on virtual host testing sites with instructions "List potential vhosts for $IP."

### Crawling

#### Explanation

Crawling extracts links, forms, and data systematically. Scrapy is ideal for large-scale; modernize with handling JS-rendered sites.

#### Commands/Tools

* **Install Scrapy**:

```bash
pip3 install scrapy --break-system-packages
```

* **Custom Spider (ReconSpider Example)**:
  * Download: wget https://example.com/ReconSpider.zip; unzip ReconSpider.zip (update URL as needed).

```bash
python3 ReconSpider.py http://$TARGET  
cat results.json 
# when searching for specific properties:
cat results.json | jq '.emails'
cat results.json | jq '.comments'
```

* Why: Gathers emails, links, metadata.
* **Modern Scrapy Spider**: Create spider.py:

```python
import scrapy  
class ReconSpider(scrapy.Spider):  
	name = 'recon'  
	start_urls = [f'http://{TARGET}']  
	
	def parse(self, response):  
	# Extract links, etc.  
	yield {'url': response.url, 'title': response.css('title::text').get()}  
```

```
Run: 
```

```python
scrapy runspider spider.py -o results.json.
```

* **Other Tools**:
  * browse\_page with URL http://$TARGET and instructions "Crawl and summarize all internal links, forms, and endpoints."
  * web\_search\_with\_snippets query "crawl $TARGET endpoints" for public crawls.
  * For videos/images: view\_x\_video or view\_image if media URLs are found.

### Check Comments in HTML Source

**Purpose**: Extract hidden comments in HTML for hints (e.g., API keys, endpoints).

* **Command**:

```shell
curl -s "http://$TARGET" | grep "<!--" | sort -u
```

* Why: Filters HTML comments from page source.
* **Python Automation**:

{% code overflow="wrap" %}
```python
import requests
from bs4 import BeautifulSoup
r = requests.get(f"http://{TARGET}")
soup = BeautifulSoup(r.text, "html.parser")
comments = soup.find_all(string=lambda text: isinstance(text, str) and "<!--" in text)
for comment in comments:
    print(comment.strip())
```
{% endcode %}

* Install: pip install requests beautifulsoup4
* Why: Parses comments reliably, handles dynamic content.
* **Alternative**: browse\_page on http://$TARGET with instructions "Extract all HTML comments from the source code."

### Find Source Code

**Purpose**: Locate public source code on platforms like GitHub/GitLab for insights into the tech stack or vulnerabilities.

* **GitHub Dorks**:

```shell
$TARGET language:Python
$TARGET language:PHP
ExampleBlog language:PHP
```

* Search: Use GitHub’s search bar or web\_search query "$TARGET language:Python site:github.com".
* **Python Automation**:

```python
import requests
query = f"{TARGET}+language:Python"
url = f"https://api.github.com/search/repositories?q={query}"
headers = {"Accept": "application/vnd.github.v3+json"}
r = requests.get(url, headers=headers)
repos = r.json().get("items", [])
for repo in repos:
    print(f"Repo: {repo['html_url']}")
```

* Install: pip install requests
* Why: Queries GitHub API for repositories; respects rate limits (add token for higher limits).
* **Alternatives**:
  * web\_search\_with\_snippets query "$TARGET site:gitlab.com | site:bitbucket.org" for other platforms.
  * x\_keyword\_search on X with query "$TARGET source code leak filter:links" for exposed repos.

### HTTP Requests with Python

**Purpose**: Interact with web servers to extract data or test endpoints.

* **GET Request**:

```python
import requests
ip = "10.0.0.1"
port = 80
url = f"http://{ip}:{port}"
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
params = {"page": "2", "item": "chair"}
headers = {"User-Agent": ua}
cookies = {"PHPSESSID": "a953b5..."}
auth = requests.auth.HTTPBasicAuth("username", "password")
r = requests.get(url, params=params, headers=headers, cookies=cookies, auth=auth)
print(r.text)
```

* Why: Customizable for query parameters, authentication.
* **GET with Session**:

```python
import requests
session = requests.Session()
r = session.get(f"http://{TARGET}")
print(r.text)
```

* Why: Persists cookies across requests for stateful interactions.
* **POST Request**:

```python
import requests
url = f"http://{TARGET}/login"
data = {"username": "admin", "password": "admin"}
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
cookies = {"PHPSESSID": "a953b5..."}
r = requests.post(url, data=data, headers=headers, cookies=cookies)
print(r.text)
```

* Why: Tests forms or API endpoints.
* **POST with Session**:

```python
import requests
url = f"http://{TARGET}/comment"
data = {"name": "Mike", "comment": "Hello"}
session = requests.Session()
r = session.post(url, data=data)
print(r.text)
```

* Why: Maintains session for multi-step interactions.
* **Alternative**: Use code\_execution to run these scripts dynamically, saving results to JSON:

```python
with open("request_results.json", "w") as f:
	json.dump({"url": url, "response": r.text}, f, indent=2)
```

## Automating Recon

#### FinalRecon

**Installation:**

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
```

**Modules and options:**

```shell
Option        Description
-h, --help    # Show the help message and exit.
--url         #Specify the target URL.
--headers     #Retrieve header information for the target URL.
--sslinfo     #Get SSL certificate information for the target URL.
--whois       #Perform a Whois lookup for the target domain.
--crawl       #Crawl the target website.
--dns         #Perform DNS enumeration on the target domain.
--sub         #Enumerate subdomains for the target domain.
--dir         #Search for directories on the target website.
--wayback     #Retrieve Wayback URLs for the target.
--ps          #Perform a fast port scan on the target.
--full        #Perform a full reconnaissance scan on the target.
```

## Recon Examples:

**FinalRecon** is a Python-based tool for web reconnaissance, offering modules for header analysis, SSL certificate checking, WHOIS lookup, crawling, DNS enumeration, subdomain enumeration, directory searching, port scanning, and more. Below are example commands to demonstrate its usage for training purposes.

### 1. Check HTTP Headers

**Purpose**: Retrieve header information such as server type, content-encoding, and scripting language from a target website. **Command**:

```bash
python3 finalrecon.py --headers --url https://example.com
```

**Description**: This command fetches HTTP headers, which can reveal server software, caching mechanisms, or other configuration details useful for reconnaissance.

### 2. Analyse SSL Certificate

**Purpose**: Gather SSL/TLS certificate details, such as issuer, serial number, and expiration date, to assess the target's security. **Command**:

```bash
python3 finalrecon.py --sslinfo --url https://example.com
```

**Description**: This extracts SSL certificate information, helping identify potential misconfigurations or weak encryption.

### 3. Perform WHOIS Lookup

**Purpose**: Collect domain registration details, such as owner, registrar, and registration dates. **Command**:

```bash
python3 finalrecon.py --whois --url https://example.com
```

**Description**: WHOIS data provides insights into the domain’s ownership and history, useful for understanding the target’s background.

### 4. Crawl Target Website

**Purpose**: Fetch web pages, links, JavaScript files, and other resources from the target site. **Command**:

```bash
python3 finalrecon.py --crawl --url https://example.com
```

**Description**: Crawling maps the website’s structure, identifying internal/external links, images, and scripts that may reveal sensitive endpoints.

### 5. DNS Enumeration

**Purpose**: Query DNS records (e.g., A, AAAA, MX, TXT) to gather network information. **Command**:

```bash
python3 finalrecon.py --dns --url https://example.com
```

**Description**: This enumerates DNS records, which can reveal IP addresses, mail servers, or DMARC policies associated with the domain.

### 6. Subdomain Enumeration

**Purpose**: Discover subdomains of the target to identify additional attack surfaces. **Command**:

```bash
python3 finalrecon.py --sub --url https://example.com
```

**Description**: Uses sources like Certificate Transparency logs to find subdomains. Requires API keys for some sources (configured in keys.json).

### 7. Directory Search

**Purpose**: Identify hidden directories or files on the target web server. **Command**:

{% code overflow="wrap" %}
```bash
python3 finalrecon.py --dir --url https://example.com -e txt,php,html -w /path/to/wordlist.txt
```
{% endcode %}

**Description**: Searches for directories and files with specified extensions (e.g., .txt, .php, .html) using a custom wordlist for brute-forcing.

### 8. Fast Port Scan

**Purpose**: Scan for open ports on the target to identify running services. **Command**:

```bash
python3 finalrecon.py --ps --url https://example.com
```

**Description**: Performs a fast scan of the top 1000 ports, useful for identifying services like HTTP, SSH, or FTP.

### 9. Full Reconnaissance

**Purpose**: Run all available modules for comprehensive reconnaissance. **Command**:

```bash
python3 finalrecon.py --full --url https://example.com -o txt
```

**Description**: Executes all scans (headers, SSL, WHOIS, crawl, DNS, subdomains, directories, ports) and saves results in a text file for analysis.

### 10. Custom Configuration with API Keys

**Purpose**: Enhance subdomain enumeration using external API keys (e.g., Shodan, VirusTotal). **Command**:

```bash
python3 finalrecon.py --sub --url https://example.com -k 'shodan@your_shodan_api_key'
```

**Description**: Configures an API key in keys.json to leverage external data sources for more accurate subdomain enumeration.

### 11. Port Scanning

Identifying open ports is a fundamental step in network enumeration. **Default Port Scan** Scans for the most common TCP ports.

```bash
python3 finalrecon.py --url scanme.nmap.org --portscan
```

**Custom Port Scan** To check specific ports that you suspect might be open.

```bash
python3 finalrecon.py --url scanme.nmap.org --portscan --ports 21,22,80,443,8080
```

**Top Ports Scan** To scan the 'n' most common ports.

```bash
python3 finalrecon.py --url scanme.nmap.org --portscan --top-ports 100
```

### Notes

* **Installation**: Clone from GitHub (git clone https://github.com/thewhiteh4t/FinalRecon.git), navigate to the directory, and install dependencies (pip3 install -r requirements.txt).
* **API Keys**: Some modules (e.g., subdomain enumeration) use optional API keys. Edit finalrecon/conf/keys.json to add keys or set unused sources to null.
* **Output**: Use the -o flag to export results in txt, xml, or csv formats (e.g., -o csv).
* **Ethical Use**: Only scan targets you have permission to test. Unauthorized scanning is illegal.
* **Source**: Examples are based on FinalRecon’s documentation and usage guide from its GitHub repository.
