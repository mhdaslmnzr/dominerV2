import logging #Library for logs   
import os # Library for folder/file manipulation
#import whois  # Library for retrieving WHOIS information
import socket  # Library for socket operations
import ssl  # Library for SSL operations
#import OpenSSL  # OpenSSL library for working with SSL certificates
from datetime import datetime  # Library for working with date and time
import dns.resolver
import requests
import json

logging.basicConfig(level=logging.INFO)

# Function to get IP information for a given domain
def get_ip_info(domain):
    try:
        # Use socket to retrieve the IP address of the domain
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.error as e:
        # Handle socket errors, log an error message, and return None
        logging.error(f"Error retrieving IP address for {domain}: {e}")
        return None

# Function to get SSL certificate expiry date for a given hostname and port
def get_ssl_expiry(hostname, port):
    try:
        # Use SSL and OpenSSL to retrieve the SSL certificate and extract expiry date
        cert = ssl.get_server_certificate((hostname, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        expiration_bytes = x509.get_notAfter()
        expiration_timestamp = expiration_bytes.decode('utf-8')
        expiration_date = datetime.strptime(expiration_timestamp, '%Y%m%d%H%M%S%z').date()
        return expiration_date
    except Exception as e:
        # Handle SSL-related errors, log an error message, and return None
        logging.error(f"Error checking SSL certificate: {e}")
        return None

# Function to check DMARC and SPF policies for a given domain
def check_dmarc_spf(domain, file=None):
    try:
        # Query DMARC TXT record for the domain
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')

        dmarc_configured = False
        for record in dmarc_records:
            txt_data = record.to_text()
            if file:
                file.write(f"DMARC Record for {domain}:\n{txt_data}\n")

            # Parse and check DMARC policies from the TXT record
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

        # Query SPF TXT record for the domain
        spf_records = dns.resolver.resolve(domain, 'TXT')

        spf_policy_set = False
        for record in spf_records:
            txt_data = record.to_text()
            if file:
                file.write(f"SPF Record for {domain}:\n{txt_data}\n")

            # Check if any of the SPF records include a 'reject' policy
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
    sock.settimeout(1)

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
  for prefix in ['www', 'mail', 'blog', 'ftp']:
    try:
      resolver.resolve(prefix + '.' + domain, 'A')  # Updated line
      subdomains.append(prefix + '.' + domain)
    except dns.resolver.NXDOMAIN:
      pass
  return subdomains

# Define the reverse IP lookup function
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
                f.write('[*] Limit reached change your IP!\n')
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

# Function to process a single domain
def process_domain(domain, output_folder):
    ip_address = get_ip_info(domain)

    if ip_address:
        access_token = 'c6e0a90aaf5fd6'
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails(ip_address)

        # Create a folder for each domain within the "outputs" folder
        domain_folder = os.path.join(output_folder, domain)
        os.makedirs(domain_folder, exist_ok=True)

        # Save IPinfo details to the domain-specific output text file
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
        
        # Get domain information using whois library
        domain_info = whois.whois(domain)
        with open(output_file_path, 'a') as f:
            f.write(f"\n{'='*20} WHOIS Info for {domain} {'='*20}\n")
            if domain_info.expiration_date:
                f.write(f"Domain Expiry: {domain_info.expiration_date}\n")
            else:
                f.write("Domain Expiry: Not available\n")

        # Check DMARC and SPF policies for the domain
        with open(output_file_path, 'a') as f:
            f.write(f"\n{'='*20} DMARC and SPF Info for {domain} {'='*20}\n")
            check_dmarc_spf(domain, file=f)

        # Find subdomains and write them to the output file
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
     


# Function to process multiple domains from a file
def process_domains_from_file(file_name, output_folder):
    with open(file_name, 'r') as file:
        domains = file.read().splitlines()

    # Create the "outputs" folder (if it doesn't exist)
    outputs_folder = os.path.join(os.getcwd(), 'outputs')
    os.makedirs(outputs_folder, exist_ok=True)

    for domain in domains:
        try:
            logging.info(f"Processing domain: {domain}")
            process_domain(domain, outputs_folder)
            logging.info(f"Finished processing domain: {domain}")
        except Exception as e:
            logging.error(f"Error processing domain {domain}: {e}")

ports_to_check = [20, 21, 22, 23, 25, 53, 80, 110, 115, 123, 143, 161, 194, 443, 445, 465, 554, 873, 993, 995, 3389, 5631, 3306, 5432, 5900, 6379, 8333, 11211, 25565]

# Main function to execute the script
def main():
    # Replace 'c6e0a90aaf5fd6' with your actual IPinfo access token
    # access_token = 'c6e0a90aaf5fd6'
    
    # Ask for the input file name in the same folder of execution
    input_file_name = input("Enter the name of the input file (including extension): ")
    

    try:
        # Process domains from the input file
        process_domains_from_file(input_file_name, 'outputs')
        logging.info("All domains processed successfully")
    except Exception as e:
        logging.error(f"Error processing domains: {e}")

# Execute the main function if this script is run as the main program
if __name__ == "__main__":
    main()
