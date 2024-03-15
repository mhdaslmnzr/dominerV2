import requests
import json

def reverse_ip(ip_address):

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
          print('[*] Limit reached change your IP!')
          exit()
      try:
          domains = json.loads(response.text)['domainArray']
          if domains:
              print(f"Associated domain(s) for {ip_address}:")
              for domain in domains:
                  print(domain[0])
          else:
              print(f"No domains found for {ip_address}")
      except KeyError:
          print(f"Error processing response for {ip_address}")
  except Exception as e:
      print(f"Error performing lookup for {ip_address}: {e}")

# Example usage
ip_address = input("Enter an IP address: ")
reverse_ip(ip_address)
