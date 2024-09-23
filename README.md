# WebVulnScanner
This project will be a command-line tool that scans a given website for common vulnerabilities like open ports, weak SSL/TLS certificates, outdated software, or insecure headers.
# WebVulnScanner

A **Web Vulnerability Scanner** built with Python to help identify security weaknesses in web applications. This tool performs several security checks, including **port scanning**, **SSL/TLS certificate validation**, **HTTP header analysis**, and **outdated software detection**. It’s designed to give developers and security professionals insights into potential vulnerabilities in their web applications.

---

## Features

- **Port Scanning**: Scans the top 1024 ports to identify open and vulnerable ports on a target system.
- **SSL/TLS Certificate Checking**: Validates SSL certificates and checks for expiration.
- **HTTP Header Analysis**: Detects missing security headers like Content-Security-Policy, Strict-Transport-Security, etc.
- **Outdated Software Detection**: Checks for signs of outdated or vulnerable software versions.
  
---

## Installation

### Prerequisites

- Python 3.x
- Required Python packages:
  - `nmap`
  - `requests`
  - `bs4` (BeautifulSoup)
  - `ssl`
  
To install these dependencies, run:
```bash
pip install python-nmap requests beautifulsoup4
$ python scanner.py
Enter the website to scan (without http/https): example.com

Starting scan on example.com...

Scanning example.com for open ports...
Host: example.com (www.example.com)
State: up
Protocol: tcp
Port: 80 | State: open
Port: 443 | State: open

Checking SSL certificate for example.com...
SSL Certificate expires on: 2025-10-12 00:00:00
SSL certificate is valid.

Checking HTTP headers for example.com...
Content-Security-Policy: Missing
Strict-Transport-Security: Missing
X-Frame-Options: Present
X-Content-Type-Options: Present
X-XSS-Protection: Present

Checking for outdated software on example.com...
Detected outdated software: WordPress 4.9.1
