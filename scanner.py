import nmap
import ssl
import socket
import requests
from bs4 import BeautifulSoup
from datetime import datetime

# Port Scanning
def port_scan(target):
    scanner = nmap.PortScanner()
    print(f"Scanning {target} for open ports...")

    # Scan the top 1024 ports
    scanner.scan(target, '1-1024', '-v')

    for host in scanner.all_hosts():
        print(f"Host: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        
        for protocol in scanner[host].all_protocols():
            print(f"Protocol: {protocol}")
            ports = scanner[host][protocol].keys()
            for port in ports:
                print(f"Port: {port} | State: {scanner[host][protocol][port]['state']}")


# SSL/TLS Certificate Checking
def check_ssl(target):
    print(f"\nChecking SSL certificate for {target}...")

    try:
        conn = socket.create_connection((target, 443))
        context = ssl.create_default_context()
        sock = context.wrap_socket(conn, server_hostname=target)
        cert = sock.getpeercert()

        # Certificate expiration date
        exp_date_str = cert['notAfter']
        exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
        print(f"SSL Certificate expires on: {exp_date}")

        # Check if certificate is expired
        if exp_date < datetime.now():
            print("Warning: SSL certificate is expired!")
        else:
            print("SSL certificate is valid.")

    except Exception as e:
        print(f"Error checking SSL certificate: {e}")


# HTTP Header Analysis
def check_http_headers(target):
    print(f"\nChecking HTTP headers for {target}...")

    try:
        response = requests.get(f"http://{target}")
        headers = response.headers

        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection"
        ]

        for header in security_headers:
            if header in headers:
                print(f"{header}: Present")
            else:
                print(f"{header}: Missing")

    except Exception as e:
        print(f"Error fetching HTTP headers: {e}")


# Outdated Software Detection (Optional)
def check_outdated_software(target):
    print(f"\nChecking for outdated software on {target}...")

    try:
        response = requests.get(f"http://{target}")
        soup = BeautifulSoup(response.content, 'html.parser')

        # Example: Check for specific software versions in meta tags or comments
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            if 'generator' in meta.attrs.get('name', '').lower():
                print(f"Detected software: {meta['content']}")

        # Optionally, you can expand this by comparing detected versions with known vulnerabilities.
    
    except Exception as e:
        print(f"Error scraping website: {e}")


# Main Function to Combine All Scans
def run_scanner(target):
    print(f"Starting scan on {target}...\n")

    port_scan(target)
    check_ssl(target)
    check_http_headers(target)
    check_outdated_software(target)


if __name__ == "__main__":
    target = input("Enter the website to scan (without http/https): ")
    run_scanner(target)
