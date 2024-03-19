import logging
import ipinfo
import socket
import ssl
import dns.resolver
import requests
import json
from datetime import datetime
import os.path
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)

# Function to get IP information for a given domain
def get_ip_info(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        logging.error(f"Error retrieving IP address for {domain}: {e}")
        return None

# Function to get SSL certificate expiry date for a given hostname and port
def get_ssl_expiry(hostname, port):
    try:
        cert = ssl.get_server_certificate((hostname, port))
        x509 = ssl.load_pem_x509_certificate(cert)
        expiration_date = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
        days_until_expiry = (expiration_date.date() - datetime.now().date()).days
        return expiration_date.date(), days_until_expiry
    except Exception as e:
        logging.error(f"Error checking SSL certificate: {e}")
        return None, None

# Function to check DMARC and SPF policies for a given domain
def check_dmarc_spf(domain, file=None):
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')

        dmarc_configured = False
        for record in dmarc_records:
            txt_data = record.to_text()
            if file:
                file.write(f"DMARC Record for {domain}:\n{txt_data}\n")

            if 'v=DMARC1' in txt_data:
                policy_published = None
                for item in txt_data.split(';'):
                    key_value = item.strip().split('=', 1)
                    if len(key_value) == 2:
                        key, value = key_value
                        if key.strip() == 'p':
                            policy_published = value.strip()

                if policy_published == 'reject':
                    if file:
                        file.write(f"Proper DMARC policies are set to 'reject' for {domain}\n")
                    dmarc_configured = True
                else:
                    if file:
                        file.write(f"DMARC policies are not set to 'reject' for {domain}\n")
            else:
                if file:
                    file.write(f"No DMARC record found for {domain}\n")

        spf_records = dns.resolver.resolve(domain, 'TXT')

        spf_policy_set = False
        for record in spf_records:
            txt_data = record.to_text()
            if file:
                file.write(f"SPF Record for {domain}:\n{txt_data}\n")

            if 'v=spf1' in txt_data and '-all' in txt_data:
                spf_policy_set = True
                break

        if spf_policy_set:
            if file:
                file.write(f"Proper SPF policy is set to '-all' for {domain}\n")
        else:
            if file:
                file.write(f"SPF policy is not set to '-all' for {domain}\n")

        if dmarc_configured and spf_policy_set:
            if file:
                file.write(f"DMARC and SPF are configured properly for {domain}\n")
        else:
            if file:
                file.write(f"DMARC and/or SPF are not configured properly for {domain}\n")

    except dns.resolver.NXDOMAIN:
        if file:
            file.write(f"No DMARC record found for {domain}\n")
    except dns.resolver.NoAnswer:
        if file:
            file.write(f"No TXT records found for {domain}\n")
    except dns.exception.DNSException as e:
        if file:
            file.write(f"DNS query error: {e}\n")

# Function to print open ports for a given IP and list of ports to check
def print_open_ports(ip, ports_to_check, output_file_path):
    open_ports = []

    for port in ports_to_check:
        if is_port_open(ip, port):
            open_ports.append(port)

    with open(output_file_path, 'a') as f:
        f.write(f"\n{'='*20} Open Ports for {ip} {'='*20}\n")
        f.write(f"Open Ports: {open_ports}\n")

def is_port_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)

    try:
        sock.connect((ip, port))
        return True
    except socket.error:
        return False
    finally:
        sock.close()

def find_subdomains(domain):
    resolver = dns.resolver.Resolver()
    subdomains = []
    common_prefixes = ['www', 'mail', 'blog', 'ftp', 'smtp', 'pop', 'imap', 'ns', 'ns1', 'ns2', 'ns3', 'cpanel', 'webmail', 'webdisk', 'whm', 'autodiscover', 'autoconfig', 'desktop', 'mobile', 'dev', 'staging', 'test', 'beta', 'demo', 'portal', 'secure', 'vpn', 'remote', 'download', 'uploads', 'support', 'help', 'docs', 'api', 'status', 'analytics', 'cdn', 'assets', 'img', 'static', 'files', 'media', 'video', 'audio', 'downloads', 'apps', 'app', 'beta', 'staging', 'test', 'dev', 'local', 'sandbox', 'docker', 'cloud', 'azure', 'aws', 'gcp', 'heroku', 'netlify', 'vercel', 'github', 'gitlab', 'bitbucket', 'code', 'git']

    for prefix in common_prefixes:
        subdomain = f"{prefix}.{domain}"
        try:
            resolver.resolve(subdomain, 'A')
            subdomains.append(subdomain)
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            logging.warning(f"DNS resolution for {subdomain} returned no answer")
        except dns.exception.DNSException as e:
            logging.warning(f"DNS error while resolving {subdomain}: {e}")

    return subdomains

#Define the reverse IP lookup function
def reverse_ip_lookup(ip_address, output_file_path):
    headers = {
        'authority': 'domains.yougetsignal.com',
        'accept': 'text/javascript, text/html, application/xml, text/xml, */*',
        'x-prototype-version': '1.6.0',
        'x-requested-with': 'XMLHttpRequest',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': 'https://www.yougetsignal.com',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://www.yougetsignal.com/tools/web-sites-on-web-server/',
        'accept-language': 'en-US,en;q=0.9,ar;q=0.8,fr;q=0.7',
    }

    data = {
        'remoteAddress': ip_address,
        'key': '',
        '_': ''
    }

    try:
        response = requests.post('https://domains.yougetsignal.com/domains.php', data=data, headers=headers)
        if '{"status":"Fail"' in response.text:
            with open(output_file_path, 'a') as f:
                f.write('[*] Limit reached, change your IP or wait and try again later.\n')
            time.sleep(10)  # Add a 5-second delay before the next request
            return
        try:
            domains = json.loads(response.text)['domainArray']
            if domains:
                with open(output_file_path, 'a') as f:
                    f.write(f"Associated domain(s) for {ip_address}:\n")
                    for domain in domains:
                        f.write(f"{domain[0]}\n")
            else:
                with open(output_file_path, 'a') as f:
                    f.write(f"No domains found for {ip_address}\n")
        except KeyError:
            with open(output_file_path, 'a') as f:
                f.write(f"Error processing response for {ip_address}\n")
    except Exception as e:
        with open(output_file_path, 'a') as f:
            f.write(f"Error performing lookup for {ip_address}: {e}\n")

def check_security_headers(domain, file=None):
    try:
        response = requests.get(f"https://{domain}")
        headers = response.headers

        if file:
            file.write(f"Security Headers for {domain}:\n")
            security_issues_found = False

            # Content-Security-Policy
            content_security_policy = headers.get("Content-Security-Policy", "")
            if "'unsafe-inline'" in content_security_policy or "'unsafe-eval'" in content_security_policy:
                file.write(f"Content-Security-Policy: {content_security_policy} - may allow unsafe inline or eval scripts - Security Risk!\n")
                security_issues_found = True

            # X-Frame-Options
            x_frame_options = headers.get("X-Frame-Options", "").lower()
            if x_frame_options != "none":
                file.write(f"X-Frame-Options: {x_frame_options} - not set to 'None' - Potential Security Risk!\n")
                security_issues_found = True

            # Strict-Transport-Security
            strict_transport_security = headers.get("Strict-Transport-Security", "")
            if not strict_transport_security or "max-age=0" in strict_transport_security:
                file.write(f"Strict-Transport-Security: {strict_transport_security} - not set or max-age set to 0 - Potential Security Risk!\n")
                security_issues_found = True

            # X-XSS-Protection
            x_xss_protection = headers.get("X-XSS-Protection", "")
            if x_xss_protection != "1; mode=block":
                file.write(f"X-XSS-Protection: {x_xss_protection} - not set to '1; mode=block' - Potential Security Risk!\n")
                security_issues_found = True

            # X-Content-Type-Options
            x_content_type_options = headers.get("X-Content-Type-Options", "")
            if x_content_type_options != "nosniff":
                file.write(f"X-Content-Type-Options: {x_content_type_options} - not set to 'nosniff' - Potential Security Risk!\n")
                security_issues_found = True

            # Referrer-Policy
            referrer_policy = headers.get("Referrer-Policy", "")
            if referrer_policy != "strict-origin-when-cross-origin":
                file.write(f"Referrer-Policy: {referrer_policy} - not set to 'strict-origin-when-cross-origin' - Potential Security Risk!\n")
                security_issues_found = True

            # Expect-CT
            expect_ct = headers.get("Expect-CT", "")
            if "enforce" not in expect_ct:
                file.write(f"Expect-CT: {expect_ct} - header not set to 'enforce' - Potential Security Risk!\n")
                security_issues_found = True

            # Feature-Policy
            feature_policy = headers.get("Feature-Policy", "")
            if not feature_policy:
                file.write("Feature-Policy header missing - Potential Security Risk!\n")
                security_issues_found = True

            # Content-Security-Policy-Report-Only
            content_security_policy_report_only = headers.get("Content-Security-Policy-Report-Only", "")
            if content_security_policy_report_only:
                file.write("Content-Security-Policy-Report-Only header found - Potential Security Risk!\n")
                security_issues_found = True

            # Public-Key-Pins
            public_key_pins = headers.get("Public-Key-Pins", "")
            if public_key_pins:
                file.write("Public-Key-Pins header found - Potential Security Risk!\n")
                security_issues_found = True

            # Server
            server_header = headers.get("Server", "")
            if server_header:
                file.write(f"Server: {server_header} - header found - Potential Security Risk!\n")
                security_issues_found = True

            # Add more checks for other security headers if needed

            if not security_issues_found:
                file.write("No significant security risks detected in the headers.\n")

    except requests.exceptions.RequestException as e:
        if file:
            file.write(f"Error retrieving security headers for {domain}: {e}\n")

def get_ipinfo_access_token():
    access_token = os.getenv('IPINFO_ACCESS_TOKEN')
    if access_token:
        return access_token
    else:
        logging.warning("IPinfo access token not found.")
        access_token = input("\nTo get a new IPinfo access token visit - https://ipinfo.io/developers \nPlease enter your IPinfo access token: ")
        os.environ['IPINFO_ACCESS_TOKEN'] = access_token
        print(access_token, "accepted")
        return access_token    

def process_domain(domain, output_folder):
    ip_address = get_ip_info(domain)

    if ip_address:
        access_token = get_ipinfo_access_token()
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails(ip_address)
        logging.info("Domain processing started")

        domain_folder = os.path.join(output_folder, domain)
        os.makedirs(domain_folder, exist_ok=True)

        output_file_path = os.path.join(domain_folder, 'output.txt')
        with open(output_file_path, 'w') as f:
            f.write(f"{'='*20} {domain} {'='*20}\n")
            f.write(f"Hostname: {domain}\n")
            f.write(f"IP: {details.ip}\n")
            f.write(f"City: {details.city}\n")
            f.write(f"Region: {details.region}\n")
            f.write(f"Country: {details.country}\n")
            f.write(f"Location (Latitude, Longitude): {details.loc}\n")
            f.write(f"Organization: {details.org}\n")
            f.write(f"Postal Code: {details.postal}\n")
            f.write(f"Timezone: {details.timezone}\n")

        print_open_ports(ip_address, ports_to_check, output_file_path)

        with open(output_file_path, 'a') as f:
            f.write(f"\n{'='*20} DMARC and SPF Info for {domain} {'='*20}\n")
            check_dmarc_spf(domain, file=f)
            f.write(f"\n{'='*20} Security Headers for {domain} {'='*20}\n")
            check_security_headers(domain, file=f)
        
        subdomains = find_subdomains(domain)
        if subdomains:
            with open(output_file_path, 'a') as f:
                f.write(f"\n{'='*20} Subdomains for {domain} {'='*20}\n")
                for subdomain in subdomains:
                    f.write(subdomain + "\n")
        else:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo subdomains found for {domain}\n")

        # Query MX records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            with open(output_file_path, 'a') as f:
                f.write(f"\n{'='*20} MX Records for {domain} {'='*20}\n")
                for mx in mx_records:
                    f.write(f"Mail Server: {mx.exchange} (Priority: {mx.preference})\n")
        except dns.resolver.NoAnswer:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo MX records found for {domain}\n")
        except dns.resolver.NXDOMAIN:
            with open(output_file_path, 'a') as f:
                f.write(f"\nDomain not found: {domain}\n")
        
        # Query CNAME records
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            with open(output_file_path, 'a') as f:
                f.write(f"\n{'='*20} CNAME Records for {domain} {'='*20}\n")
                for cname in cname_records:
                    f.write(f"CNAME: {cname.target}\n")
        except dns.resolver.NoAnswer:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo CNAME records found for {domain}\n")
        except dns.resolver.NXDOMAIN:
            with open(output_file_path, 'a') as f:
                f.write(f"\nDomain not found: {domain}\n")
        
        # Query TXT records
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            with open(output_file_path, 'a') as f:
                f.write(f"\n{'='*20} TXT Records for {domain} {'='*20}\n")
                for txt in txt_records:
                    f.write(f"TXT Record: {txt}\n")
        except dns.resolver.NoAnswer:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo TXT records found for {domain}\n")
        except dns.resolver.NXDOMAIN:
            with open(output_file_path, 'a') as f:
                f.write(f"\nDomain not found: {domain}\n")
        
        # Query A records
        try:
            a_records = dns.resolver.resolve(domain, 'A')
            with open(output_file_path, 'a') as f:
                f.write(f"\n{'='*20} A Records for {domain} {'='*20}\n")
                for a in a_records:
                    f.write(f"A Record: {a}\n")
        except dns.resolver.NoAnswer:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo A records found for {domain}\n")
        except dns.resolver.NXDOMAIN:
            with open(output_file_path, 'a') as f:
                f.write(f"\nDomain not found: {domain}\n")
        
        # Query PTR records
        try:
            ptr_records = dns.resolver.resolve(ip_address, 'PTR')
            with open(output_file_path, 'a') as f:
                f.write(f"\n{'='*20} PTR Records for {ip_address} {'='*20}\n")
                for ptr in ptr_records:
                    f.write(f"PTR Record: {ptr}\n")
        except dns.resolver.NoAnswer:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo PTR records found for IP address: {ip_address}: Reverse DNS lookup may be blocked or not configured.\n")
        except dns.resolver.NXDOMAIN:
            with open(output_file_path, 'a') as f:
                f.write(f"\nNo PTR records found for IP address: {ip_address}: Reverse DNS lookup may be blocked or not configured.\n")

        
        # Perform reverse IP lookup
        with open(output_file_path, 'a') as f:
            f.write(f"\n{'='*20} Reverse IP Lookup for {ip_address} {'='*20}\n")
        reverse_ip_lookup(ip_address, output_file_path)

    else:
        logging.warning(f"Unable to retrieve IP information for {domain}")

def process_domains_from_file(file_name, output_folder):
    with open(file_name, 'r') as file:
        domains = file.read().splitlines()

    outputs_folder = os.path.join(os.getcwd(), 'outputs')
    os.makedirs(outputs_folder, exist_ok=True)

    max_workers = 10  # Set the maximum number of threads to 10
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_domain, domain, outputs_folder) for domain in domains]

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error processing domain: {e}")

ports_to_check = [20, 21, 22, 23, 25, 53, 80, 110, 115, 123, 143, 161, 194, 443, 445, 465, 554, 873, 993, 995, 3389, 5631, 3306, 5432, 5900, 6379, 8333, 11211, 25565]

def main():
    input_file_name = "domain.txt"  # Use the fixed filename "domain.txt"

    try:
        process_domains_from_file(input_file_name, 'outputs')
        logging.info("All domains processed successfully")
    except Exception as e:
        logging.error(f"Error processing domains: {e}")

if __name__ == "__main__":
    main()