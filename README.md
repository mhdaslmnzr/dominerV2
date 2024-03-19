# pyDominer

## Overview

pyDominer is a tool designed to facilitate open-source intelligence (OSINT) gathering for domains in Python. It provides a comprehensive set of features to extract valuable information about domains, including IP addresses, SSL certificate expiry, DNS records, security headers, subdomains, and more.

## Features

- Retrieve IP information for domains.
- Check SSL certificate expiry date and days until expiry.
- Query DMARC and SPF policies for domain authentication.
- Analyze security headers for potential vulnerabilities.
- Discover subdomains using common prefixes and DNS resolution.
- Query MX, CNAME, TXT, A, and PTR records for domain reconnaissance.
- Perform reverse IP lookup to find associated domains.

## Prerequisites
Before using pyDominer, Obtain an API key from [IPinfo](https://ipinfo.io/developers)

## Usage

### Running from Source

1. Clone the repository:

   ```bash
   git clone https://github.com/mhdaslmnzr/pyDominer.git


2. Navigate to the cloned directory:

    ```bash
    cd pyDominer

3. Install the required dependencies:

    ```bash
    pip install -r requirements.txt

4. Run the script:

    ```bash
    python pyDominer.py

5. After the script finishes processing, the output will be available in the 'outputs' directory.