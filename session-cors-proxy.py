#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import requests
import sys
import os
import json
import re

if len(sys.argv) < 1:
    print("Usage: gec-cors-proxy.py [port]")
    sys.exit(1)

listen_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

def load_config(config_file="config.json"):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        sys.exit(1)

def is_domain_allowed(target_domain, allowed_domains):
    """Check if the target domain is in the allowed domains list"""
    return target_domain in allowed_domains

# Load configuration
config = load_config()
KEY = config["key"]
ALLOWED_DOMAINS = config["allowed_domains"]

def parse_set_cookie_domain(set_cookie_header):
    """Extract domain from Set-Cookie header, return None if not found"""
    # Look for Domain= attribute in Set-Cookie header
    domain_match = re.search(r'Domain=([^;]+)', set_cookie_header, re.IGNORECASE)
    if domain_match:
        domain = domain_match.group(1).strip()
        return domain
    return None  # Return None when no domain specified

def get_cookies_filename(domain):
    """Generate cookies filename for domain"""
    return f"cookies.{domain}.json"

def save_cookies(domain, cookies):
    """Save all cookies for a domain to single JSON file"""
    filename = get_cookies_filename(domain)
    with open(filename, "w") as f:
        json.dump(cookies, f, indent=2)

def load_cookies(domain):
    """Load all cookies for a domain from JSON file"""
    filename = get_cookies_filename(domain)
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


session = requests.Session()

# Load initial cookies for all domains
for domain in ALLOWED_DOMAINS:
    cookies = load_cookies(domain)
    for cookie_name, cookie_data in cookies.items():
        cookie_value = cookie_data.get("value")
        cookie_domain = cookie_data.get("domain")
        if cookie_value:
            session.cookies.set(cookie_name, cookie_value, domain=cookie_domain)
            domain_info = f"domain: {cookie_domain}" if cookie_domain else "host-only"
            print(f"[INFO] {domain}: loaded {cookie_name} ({domain_info})")
    
    if not cookies:
        print(f"[INFO] {domain}: no cookies file found")
    else:
        print(f"[INFO] {domain}: loaded {len(cookies)} cookies")

class CORSProxyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        key = params.get("key", [""])[0]
        
        #key = self.headers.get('X-Proxy-Token')
        if key != KEY:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden: Invalid key")
            return

        try:
            # Parse path to extract domain and remaining path
            # Expected format: /domain.com/path/to/resource
            path_parts = self.path.lstrip('/').split('/', 1)
            
            if len(path_parts) < 1 or not path_parts[0]:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Bad Request: Domain required in path")
                return
            
            # Extract domain from first path segment, removing query parameters
            domain_part = path_parts[0].split('?')[0]
            target_domain = domain_part
            
            # Validate that the target domain is allowed
            if not is_domain_allowed(target_domain, ALLOWED_DOMAINS):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(f"Forbidden: Domain '{target_domain}' not allowed".encode())
                return
            
            # Build the target URL
            remaining_path = path_parts[1] if len(path_parts) > 1 else ""
            # Preserve query parameters (excluding our key parameter)
            query_params = []
            for param, values in params.items():
                if param != "key":
                    for value in values:
                        query_params.append(f"{param}={value}")
            
            query_string = "&".join(query_params)
            if query_string:
                query_string = "?" + query_string
            
            url = f"https://{target_domain}/{remaining_path}{query_string}"

            headers = {
                'Host': target_domain,
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Connection': 'keep-alive',
            }
            if 'If-Modified-Since' in self.headers:
                headers['If-Modified-Since'] = self.headers['If-Modified-Since']

            resp = session.get(url, headers=headers)

            self.send_response(resp.status_code)

            # Relay headers except those that can break the response
            for key, value in resp.headers.items():
                if key.lower() in ['content-encoding', 'transfer-encoding', 'content-length', 'connection', 'set-cookie']:
                    continue
                self.send_header(key, value)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', '*')
            self.end_headers()
            self.wfile.write(resp.content)

            # Parse and save cookies from the response
            all_cookies = {}
            if resp.cookies:
                for cookie in resp.cookies:
                    all_cookies[cookie.name] = {
                        "value": cookie.value,
                        "domain": cookie.domain or None
                    }
                    print(f"[INFO] {target_domain}: saving cookie {cookie.name} for domain {cookie.domain}")
            save_cookies(target_domain, all_cookies)
            print(f"[INFO] {target_domain}: saved {len(all_cookies)} cookies to file")

        except Exception as e:
            self.send_error(502, f"Proxy error: {e}")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

if __name__ == '__main__':
    print(f"Proxy listening on port {listen_port}")
    httpd = ThreadingHTTPServer(('', listen_port), CORSProxyHandler)
    httpd.serve_forever()
