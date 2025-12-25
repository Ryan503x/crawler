import csv
import re
import time
import random
import threading
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from optparse import OptionParser
from urllib.parse import urlparse, urljoin, parse_qsl, unquote
from urllib3.exceptions import InsecureRequestWarning
import requests
from bs4 import BeautifulSoup
import warnings
from bs4 import XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
from colorama import Fore, Style, init
import socket
import json
from scrapy.http import TextResponse
from scrapy.linkextractors import LinkExtractor

# Import DNS resolver with fallback
try:
    import dns.resolver  # type: ignore
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Import platform-specific modules
try:
    import msvcrt  # Windows
    WINDOWS = True
except ImportError:
    WINDOWS = False
    try:
        import select  # Unix/Linux/Mac
    except ImportError:
        select = None

# Import your custom modules (with fallbacks)
try:
    from post_data import AdvancedLoginDetector
except ImportError:
    AdvancedLoginDetector = None

try:
    from extract_comments import fetch_comments_exact
except ImportError:
    fetch_comments_exact = None

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Sensitive keywords to look for in comments
SENSITIVE_KEYWORDS = [
    'password', 'pass', 'passwordHash', 'pwd',
    'api', 'apikey', 'api_key', 'api-key', 'api-token', 'apiToken',
    'token', 'access_token', 'refresh_token', 'auth', 'auth_token',
    'client_id', 'client_secret',
    'session', 'session_id', 'sid', 'cookie', 'jwt', 'access',
    'key', 'secret', 'secret_key', 'secretKey', 'secretToken', 'vault',
    'private_key', 'privateKey', 'privatekey', 'privatekey_pem',
    'credentials', 'credential', 'clientsecret',
    'user', 'username', 'email',
    'admin', 'root', 'privilege',
    'config', 'database', 'db', 'sql',
    'hash', 'encrypt', 'decrypt', 'security', 'cert', 'pem', 'pfx',
    'csrf', 'xsrf', 'csrf_token', 'csrftoken',
    'authkey', 'auth_key', 'password_reset_token'
]

SENSITIVE_PATTERN = re.compile(
    r'(' + '|'.join(re.escape(k) for k in SENSITIVE_KEYWORDS) + r')[\s_-]*[:=]',
    re.IGNORECASE
)

# Version number pattern (strict, avoids IPv4 addresses)
# Matches sequences like 1.2.3, 10.4.12, 1.2.3-alpha, etc.,
# and explicitly rejects pure IPv4-looking numbers.
VERSION_PATTERN = re.compile(
    r'\b(?!\d{1,3}(?:\.\d{1,3}){3}\b)(?:\d+\.){2,}\d+(?:[-_a-zA-Z][a-zA-Z0-9._-]*)?'
)

# IPv4 address pattern (simple, accepts 0-255 but not strictly validated)
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)

INPUT_FIELD_PATTERN = re.compile(
    r'<input[^>]*\btype\s*=\s*["\']?password["\']?[^>]*>',
    re.IGNORECASE
)

INPUT_FIELD_WITH_VALUE_PATTERN = re.compile(
    r'<input[^>]*\btype\s*=\s*["\']?password["\']?[^>]*\bvalue\s*=\s*["\']?[^"\'>]+',
    re.IGNORECASE
)

def is_sensitive(text):
    if not text:
        return False

    if INPUT_FIELD_PATTERN.search(text):
        if INPUT_FIELD_WITH_VALUE_PATTERN.search(text):
            return True
        return False

    # Check for sensitive pattern
    match = SENSITIVE_PATTERN.search(text)
    if not match:
        return False
    
    # Special handling for "email" - require @ symbol to avoid false positives
    if match.group(1).lower() == 'email':
        # Look for @ symbol in the value after the match
        rest = text[match.end():].strip()
        if rest and '@' not in rest:
            return False
    
    return True

def get_query_params(url):
    """Return formatted query parameters for a URL."""
    try:
        parsed = urlparse(url)
    except Exception:
        return []

    if not parsed.query:
        return []

    params = []
    try:
        # Use parse_qsl to handle URL decoding properly
        # parse_qsl automatically decodes URL-encoded values
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if value:
                # Ensure value is a string and handle any encoding issues
                try:
                    if isinstance(value, bytes):
                        value_str = value.decode('utf-8', errors='replace')
                    else:
                        value_str = str(value)
                    params.append(f"{key}={value_str}")
                except Exception:
                    # Fallback: use value as-is
                    params.append(f"{key}={value}")
            else:
                params.append(key)
    except Exception as e:
        # Fallback: try to extract manually if parse_qsl fails
        try:
            query_parts = parsed.query.split('&')
            for part in query_parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    # Decode the value manually
                    try:
                        decoded_value = unquote(value, encoding='utf-8', errors='replace')
                        params.append(f"{key}={decoded_value}")
                    except Exception:
                        params.append(f"{key}={value}")
                else:
                    # Decode the key if it's URL-encoded
                    try:
                        decoded_key = unquote(part, encoding='utf-8', errors='replace')
                        params.append(decoded_key)
                    except Exception:
                        params.append(part)
        except Exception:
            pass
    
    return params

def get_user_input_with_timeout(timeout=10):
    """Get user input with timeout, cross-platform compatible"""
    start_time = time.time()
    user_input = None
    
    print(f"Enter Y/N (auto-continue in {timeout} seconds): ", end="", flush=True)
    
    while time.time() - start_time < timeout:
        try:
            if WINDOWS:
                # Windows implementation
                if msvcrt.kbhit():
                    user_input = input().strip().upper()
                    break
            else:
                # Unix/Linux/Mac implementation
                if select and select.select([sys.stdin], [], [], 0.1)[0]:
                    user_input = sys.stdin.readline().strip().upper()
                    break
        except (EOFError, KeyboardInterrupt):
            break
        except Exception:
            # If input fails, continue waiting
            pass
        
        time.sleep(0.1)
    
    return user_input

# ------------------- FIXED CRAWLER CODE ------------------- #
class AdvancedCrawler:
    def __init__(self, max_workers=10, delay_range=(0.5, 1.0), crawl_subdomains=False, debug=False):
        self.visited = set()
        self.to_visit = deque()
        self.lock = threading.Lock()
        self.url_content_map = {}  # Store HTML content for each URL
        self.url_status = {}  # HTTP status per URL
        self.failed_urls = set()
        self.timeout_urls = set()  # URLs that timed out
        self.base_domain = ""
        self.domain_ip = None  # Store resolved IP
        self.max_workers = max_workers
        self.delay_range = delay_range
        self.crawled_count = 0
        self.found_files = set()
        self.crawl_subdomains = crawl_subdomains
        self.debug = debug
        
        # Create session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.session.verify = False
        
        # Disable SSL warnings for this session
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Configure session for better performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=50,
            pool_maxsize=50,
            max_retries=1
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def pre_resolve_dns(self, domain):
        """Pre-resolve DNS to avoid lookup overhead"""
        if not DNS_AVAILABLE:
            return
            
        try:
            answers = dns.resolver.resolve(domain, 'A')
            self.domain_ip = str(answers[0])
        except Exception:
            pass

    def is_same_domain(self, target_url):
        """Check if target_url shares the same root domain - FIXED AND IMPROVED"""
        try:
            target_domain = urlparse(target_url).netloc.lower()
            base_domain = self.base_domain.lower()
            
            # Handle empty domains
            if not target_domain or not base_domain:
                return False
            
            # If subdomain crawling is disabled, only allow exact domain matches
            if not self.crawl_subdomains:
                # Exact match only (no subdomains)
                return target_domain == base_domain
            
            # Extract root domain (get last two parts for most cases)
            def get_root_domain(domain):
                parts = domain.split('.')
                if len(parts) >= 2:
                    # For domains like testphp.vulnweb.com -> vulnweb.com
                    # For domains like example.co.uk -> example.co.uk
                    if len(parts) > 2 and parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
                        return '.'.join(parts[-3:])
                    return '.'.join(parts[-2:])
                return domain
            
            base_root = get_root_domain(base_domain)
            target_root = get_root_domain(target_domain)
            
            # Check if they share the same root domain
            if base_root == target_root:
                return True
                
            # Additional check: if base domain is a subdomain of target or vice versa
            if target_domain.endswith('.' + base_root) or base_domain.endswith('.' + target_root):
                return True
                
            return False
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Domain check error for {target_url}: {e}")
            return False

    def normalize_url(self, url):
        """Normalize URL by removing fragments and standardizing - IMPROVED"""
        try:
            # Ensure URL has scheme
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            
            # Add trailing slash to base domain URLs
            path = parsed.path
            if not path and parsed.netloc:
                path = "/"
            
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return normalized
        except Exception:
            return url

    def is_non_html_resource(self, url):
        """Return True for resources we don't want to crawl (pdf/images/archives)."""
        lower = url.lower()
        non_html_exts = (
            '.pdf',
            '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
            '.zip', '.rar', '.7z', '.gz', '.tar', '.bz2', '.xz',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',  # Office documents
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',  # Media files
            '.js'  # Web assets (removed .css)
        )
        return any(lower.endswith(ext) for ext in non_html_exts)
    
    def is_css_file(self, url):
        """Return True for CSS files that should be excluded from found files."""
        return url.lower().endswith('.css')

    def fetch_url_content(self, url, retries=2, timeout=(5, 10)):
        """Fetch URL content with retries and store it - IMPROVED"""
        # Check if this is a non-HTML resource before fetching
        if self.is_non_html_resource(url):
            with self.lock:
                # Only add to found_files if it's not a CSS file
                if not self.is_css_file(url):
                    self.found_files.add(url)
            return None

        for attempt in range(retries):
            try:
                time.sleep(random.uniform(*self.delay_range))
                
                response = self.session.get(
                    url, 
                    timeout=timeout,
                    allow_redirects=True,
                    stream=True
                )
                
                # record status for any response
                with self.lock:
                    self.url_status[url] = response.status_code

                # Track redirects and update URL status for final URL
                if response.history:
                    redirect_chain = [r.url for r in response.history] + [response.url]
                    # Update status for the final URL after redirects
                    with self.lock:
                        self.url_status[response.url] = response.status_code

                if response.status_code == 404:
                    with self.lock:
                        self.failed_urls.add(url)
                    return None
                elif response.status_code not in [200, 301, 302, 303, 307, 308]:
                    return None
                
                content_type = response.headers.get('Content-Type', '').lower()
                # Accept HTML-like content; for non-HTML like PDFs, record endpoint without parsing
                if self.is_non_html_resource(url) or any(ext in content_type for ext in ['pdf', 'image', 'zip', 'octet-stream']):
                    with self.lock:
                        self.found_files.add(url)
                        self.crawled_count += 1
                    return None
                
                content = response.raw.read(1048576, decode_content=True)
                response.close()
                
                try:
                    html = content.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        html = content.decode('latin-1')
                    except UnicodeDecodeError:
                        return None
                
                # Additional check: verify it's actually HTML content
                if not any(tag in html.lower() for tag in ['<html', '<!doctype', '<body', '<head']):
                    with self.lock:
                        self.found_files.add(url)
                        self.crawled_count += 1
                    return None
                
                with self.lock:
                    self.url_content_map[url] = html
                    self.crawled_count += 1
                
                return html
                
            except requests.exceptions.Timeout:
                if attempt == retries - 1:
                    with self.lock:
                        self.timeout_urls.add(url)
            except requests.exceptions.RequestException:
                if attempt == retries - 1:
                    with self.lock:
                        self.failed_urls.add(url)
            except Exception:
                if attempt == retries - 1:
                    with self.lock:
                        self.failed_urls.add(url)
        
        return None

    def debug_extract_links(self, html, base_url):
        """Debug method to see what links are being found"""
        soup = BeautifulSoup(html, 'html.parser')
        
        if self.debug:
            print(f"\n[DEBUG] Analyzing links from: {base_url}")
        
        # Check all a tags
        a_tags = soup.find_all('a', href=True)
        if self.debug:
            print(f"[DEBUG] Found {len(a_tags)} <a> tags with href")
        
        if self.debug:
            for i, tag in enumerate(a_tags[:10]):  # Show first 10
                href = tag.get('href', '').strip()
                print(f"  [LINK {i}] {href}")
        
        # Check all link tags
        link_tags = soup.find_all('link', href=True)
        if self.debug:
            print(f"[DEBUG] Found {len(link_tags)} <link> tags with href")
            for i, tag in enumerate(link_tags[:10]):  # Show first 10
                href = tag.get('href', '').strip()
                rel = tag.get('rel', [])
                if isinstance(rel, list):
                    rel = ' '.join(rel)
                print(f"  [LINK TAG {i}] {href} (rel: {rel})")
        
        return self.extract_links(html, base_url)

    def extract_links(self, html, base_url):
        """Extract all links from HTML content using Scrapy's LinkExtractor"""
        extractor = LinkExtractor(allow_domains=[self.base_domain])
        response = TextResponse(url=base_url, body=html, encoding='utf-8')
        return [link.url for link in extractor.extract_links(response)]

    def discover_subdomains_from_html(self, html, base_url):
        """Discover subdomains from HTML content - FIXED FOR BETTER DETECTION"""
        subdomains = set()
        try:
            # Extract root domain
            def get_root_domain(domain):
                parts = domain.split('.')
                if len(parts) >= 2:
                    return '.'.join(parts[-2:])
                return domain
            
            root_domain = get_root_domain(self.base_domain)
            
            # Look for subdomain patterns in the HTML - MORE COMPREHENSIVE
            subdomain_patterns = [
                r'href=["\'](https?://[a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(root_domain) + r'[^"\'>\s]*)["\']',
                r'src=["\'](https?://[a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(root_domain) + r'[^"\'>\s]*)["\']',
                r'action=["\'](https?://[a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(root_domain) + r'[^"\'>\s]*)["\']',
                r'["\'](https?://[a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(root_domain) + r'[^"\'>\s]*)["\']',
                r'https?://([a-zA-Z0-9][a-zA-Z0-9-]*\.' + re.escape(root_domain) + r'[^"\'>\s]*)',
            ]
            
            found_subdomains = set()
            
            for pattern in subdomain_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if match:
                        # Clean up the match
                        if not match.startswith('http'):
                            match = 'http://' + match
                        
                        try:
                            parsed = urlparse(match)
                            if parsed.netloc and parsed.netloc.endswith('.' + root_domain):
                                # Normalize the URL
                                normalized_url = self.normalize_url(match)
                                if self.is_same_domain(normalized_url):
                                    found_subdomains.add(normalized_url)
                        except Exception:
                            continue
            
            # Convert to list and sort
            subdomains = sorted(list(found_subdomains))
            
            # Print discovered subdomains only when debugging
            if self.debug and subdomains:
                print(f"[SUBDOMAINS] Found {len(subdomains)} subdomains in {base_url}")
                for subdomain in subdomains:
                    print(f"  [SUBDOMAIN] {subdomain}")
                    
        except Exception as e:
            print(f"[SUBDOMAIN ERROR] {e}")
        
        return subdomains

    def discover_sveltekit_routes(self, html, base_url):
        """Discover SvelteKit specific routes and endpoints"""
        sveltekit_routes = set()
        
        # Common SvelteKit patterns
        patterns = [
            r'/_app/immutable/(.*?)\.js',
            r'/_api/([^"\'\s]+)',
            r'/api/([^"\'\s]+)',
            r'/([a-zA-Z0-9-_]+)/?\[([^]]+)\]',  # Dynamic routes like /blog/[slug]
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if isinstance(match, tuple):
                    # Handle tuple matches (like from dynamic routes)
                    route_parts = [part for part in match if part]
                    if route_parts:
                        route = '/' + '/'.join(route_parts)
                else:
                    route = '/' + match if not match.startswith('/') else match
                
                try:
                    full_url = urljoin(base_url, route)
                    if self.is_same_domain(full_url):
                        sveltekit_routes.add(full_url)
                except Exception:
                    continue
        
        return list(sveltekit_routes)

    def try_common_sveltekit_endpoints(self, base_url):
        """Try common SvelteKit endpoints that might not be linked"""
        common_endpoints = [
            "/api",
            "/_api",
            "/_app",
            "/auth",
            "/login", 
            "/register",
            "/dashboard",
            "/admin",
            "/user",
            "/profile",
            "/settings",
            "/blog",
            "/posts",
            "/products",
            "/api/auth",
            "/api/users",
            "/api/posts",
        ]
        
        endpoints_to_try = []
        for endpoint in common_endpoints:
            full_url = urljoin(base_url, endpoint)
            if self.is_same_domain(full_url):
                endpoints_to_try.append(full_url)
        
        return endpoints_to_try

    def crawl_worker(self, url):
        """Worker function for crawling URLs - FIXED FOR SUBDOMAIN RECURSION"""
        # SECURITY CHECK: Verify URL is from the same domain before processing
        if not self.is_same_domain(url):
            return None, []
            
        with self.lock:
            if url in self.visited:
                return None, []
            self.visited.add(url)
        
        # Fetch content once and store it
        html = self.fetch_url_content(url)
        if not html:
            # If we have a status and it's not 404, still consider visited for printing
            status = self.url_status.get(url)
            if status and status != 404:
                return url, []
            return None, []
        
        # Use debug method for detailed link analysis
        links = self.debug_extract_links(html, url)
        
        # ENHANCED: Discover SvelteKit specific routes
        sveltekit_routes = self.discover_sveltekit_routes(html, url)
        links.extend(sveltekit_routes)
        if self.debug and sveltekit_routes:
            print(f"[DEBUG] Found {len(sveltekit_routes)} SvelteKit routes")
        
        # Debug: Print extracted links
        if self.debug and links:
            print(f"[DEBUG] Extracted {len(links)} links from {url}")
            for link in list(links)[:10]:  # Show first 10 links
                print(f"  -> {link}")
            if len(links) > 10:
                print(f"  ... and {len(links) - 10} more")
        
        # Discover subdomains if enabled
        if self.crawl_subdomains:
            subdomains = self.discover_subdomains_from_html(html, url)
            # Add subdomains to links for crawling
            links.extend(subdomains)
        
        new_links = []
        with self.lock:
            for link in links:
                # DOUBLE SECURITY CHECK: Ensure link is from same domain before adding
                if self.is_same_domain(link) and link not in self.visited and link not in self.to_visit:
                    self.to_visit.append(link)
                    new_links.append(link)
                elif link not in self.visited and link not in self.to_visit:
                    # Debug: Show why link was rejected
                    if self.debug:
                        parsed = urlparse(link)
                        print(f"[DEBUG] Rejected link (domain mismatch): {link} (domain: {parsed.netloc}, base: {self.base_domain})")
        
        return url, new_links

    def run_crawler(self, start_url, max_urls=None):
        """Main crawler function with optional limits - IMPROVED"""
        self.visited.clear()
        self.to_visit.clear()
        self.failed_urls.clear()
        self.timeout_urls.clear()
        self.crawled_count = 0
        
        if not start_url.startswith(('http://', 'https://')):
            start_url = "http://" + start_url
            
        start_url = self.normalize_url(start_url)
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc.lower()
        
        # SECURITY CHECK: Validate the base domain
        if not self.base_domain or '.' not in self.base_domain:
            print(Fore.RED + f"Error: Invalid domain '{self.base_domain}' - Cannot proceed with crawling")
            return
        
        self.to_visit.append(start_url)
        
        # ENHANCED: Add common SvelteKit endpoints to try
        common_endpoints = self.try_common_sveltekit_endpoints(start_url)
        for endpoint in common_endpoints:
            if endpoint not in self.visited and endpoint not in self.to_visit:
                self.to_visit.append(endpoint)
                if self.debug:
                    print(f"[DEBUG] Added common endpoint to queue: {endpoint}")
        
        # Pre-resolve DNS
        self.pre_resolve_dns(self.base_domain)
        
        if self.debug:
            print("-"*50)
            print(f"[DEBUG] Starting with URL: {start_url}")
            print(f"[DEBUG] Base domain: {self.base_domain}")
        print("["+ Fore.CYAN + "*", end="")
        print("]",end="")
        if max_urls:
            print(f"Starting crawl of {start_url} (max: {max_urls} URLs)")
        else:
            print(f"Starting crawl of {start_url}")
        print(f"[INFO] Root domain: {self.base_domain}")
        print("-"*50)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while self.to_visit and (max_urls is None or self.crawled_count < max_urls):
                # Debug: Show queue status
                if self.debug:
                    print(f"[DEBUG] URLs in queue: {len(self.to_visit)}, Visited: {len(self.visited)}, Crawled: {self.crawled_count}")
                
                # Get batch of URLs to process (sorted for consistency)
                batch_urls = []
                for _ in range(min(self.max_workers * 2, len(self.to_visit))):  # Process more URLs per batch
                    try:
                        url = self.to_visit.popleft()
                        if url not in self.visited:  # Double-check not visited
                            batch_urls.append(url)
                    except IndexError:
                        break
                
                # Sort batch for consistent processing order
                batch_urls.sort()
                
                if not batch_urls:
                    break
                
                
                # Submit all URLs in batch
                futures = [executor.submit(self.crawl_worker, url) for url in batch_urls]
                
                # Wait for all to complete and process results
                for future in futures:
                    try:
                        url, new_links = future.result(timeout=15)
                        if url:
                            yield url
                    except Exception:
                        continue
        
        # Retry timeout URLs if any
        self.retry_timeout_urls()
        
        # Visit found files to get their status codes
        self.visit_found_files()

    def visit_found_files(self):
        """Visit found files to get their actual status codes"""
        if not self.found_files:
            return
        
        with ThreadPoolExecutor(max_workers=min(5, self.max_workers)) as executor:
            # Submit all found files for status checking
            futures = []
            for file_url in self.found_files:
                future = executor.submit(self.check_file_status, file_url)
                futures.append((file_url, future))
            
            # Process results as they complete
            for file_url, future in futures:
                try:
                    status = future.result(timeout=10)
                    if status:
                        with self.lock:
                            self.url_status[file_url] = status
                except Exception:
                    with self.lock:
                        self.url_status[file_url] = "ERROR"

    def check_file_status(self, url):
        """Check the status code of a file URL"""
        try:
            response = self.session.head(url, timeout=(5, 10), allow_redirects=True)
            return response.status_code
        except Exception:
            try:
                # If HEAD fails, try GET
                response = self.session.get(url, timeout=(5, 10), allow_redirects=True)
                return response.status_code
            except Exception:
                return None

    def retry_timeout_urls(self):
        """Keep retrying timeout URLs until all are processed or max attempts reached"""
        if not self.timeout_urls:
            return
        
        max_retry_attempts = 3  # Reduced retry attempts
        retry_count = {}
        
        # Initialize retry count for all timeout URLs
        for url in list(self.timeout_urls):
            retry_count[url] = 0
        
        while self.timeout_urls and max(retry_count.values()) < max_retry_attempts:
            retry_urls = sorted(list(self.timeout_urls))  # Sort for consistent retry order
            self.timeout_urls.clear()
            
            if retry_urls:
                # Use threading for faster retry
                with ThreadPoolExecutor(max_workers=min(3, self.max_workers)) as executor:
                    futures = []
                    
                    # Submit all retry URLs in parallel
                    for url in retry_urls:
                        future = executor.submit(self.fetch_url_content, url, 1, (5, 15))  # Use timeout for retries
                        futures.append((url, future))
                    
                    # Process results as they complete
                    for url, future in futures:
                        try:
                            html = future.result(timeout=20)  # Wait up to 20 seconds per URL
                            if html:
                                # Successfully retried - URL is now processed
                                pass
                            else:
                                # Still failed - increment retry count and add back
                                retry_count[url] += 1
                                if retry_count[url] < max_retry_attempts:
                                    with self.lock:
                                        self.timeout_urls.add(url)
                        except Exception:
                            # Still failed - increment retry count and add back
                            retry_count[url] += 1
                            if retry_count[url] < max_retry_attempts:
                                with self.lock:
                                    self.timeout_urls.add(url)

    def retry_failed_urls(self, endpoints_list):
        """Automatically retry 404 URLs that failed during initial crawl"""
        if not self.failed_urls:
            return
        
        retry_urls = sorted(list(self.failed_urls))  # Sort for consistent retry order
        self.failed_urls.clear()
        
        if retry_urls:        
            # Use threading for faster retry
            with ThreadPoolExecutor(max_workers=min(3, self.max_workers)) as executor:
                futures = []
                
                # Submit all retry URLs in parallel
                for url in retry_urls:
                    future = executor.submit(self.fetch_url_content, url, 1, (5, 10))  # 5s connect, 10s read for retries
                    futures.append((url, future))
                
                # Process results as they complete
                for url, future in futures:
                    try:
                        html = future.result(timeout=10)
                        if html:
                            # Process the retried URL
                            ep = Endpoint(url, html)
                            ep.fetch_parameters()
                            ep.fetch_comments()
                            endpoints_list.append(ep)  # Add to live endpoints list
                            
                            # Print the retried URL with same formatting as main crawl (no status code)
                            print(Fore.WHITE + f"{url}" + Style.RESET_ALL + " : ", end="")

                            output_parts = []
                            # 1) Query parameters (purple)
                            query_params = get_query_params(url)
                            if query_params:
                                for qp in query_params:
                                    output_parts.append(Fore.LIGHTMAGENTA_EX + qp + Style.RESET_ALL)
                            # 2) HTML inputs (blue)
                            for p in ep.html_inputs:
                                output_parts.append(Fore.LIGHTBLUE_EX + f"{p}" + Style.RESET_ALL)
                            # 3) JavaScript inputs (orange-style yellow)
                            for js in ep.js_inputs:
                                output_parts.append(Fore.YELLOW + f"{js}" + Style.RESET_ALL)
                            # 4) Buttons (green)
                            for b in ep.buttons:
                                output_parts.append(Fore.GREEN + f"{b}" + Style.RESET_ALL)
                            # 5) Hidden fields (gray)
                            for h in ep.hidden_params:
                                output_parts.append(Fore.LIGHTBLACK_EX + f"{h}" + Style.RESET_ALL)
                            # 6) Sensitive matches (red)
                            if ep.sensitive_matches:
                                for phrase in ep.sensitive_matches:
                                    output_parts.append(Fore.RED + f"{phrase}" + Style.RESET_ALL)
                            # 7) Version numbers (purple) - last
                            if ep.version_matches:
                                for ver in ep.version_matches:
                                    output_parts.append(Fore.LIGHTMAGENTA_EX + f"{ver}" + Style.RESET_ALL)
                            # 8) IP addresses (cyan) - last
                            if ep.ip_matches:
                                for ip in ep.ip_matches:
                                    output_parts.append(Fore.CYAN + f"{ip}" + Style.RESET_ALL)

                            if output_parts:
                                print(" ".join(output_parts))
                            else:
                                print()
                    except Exception:
                        continue


# ------------------- ENDPOINT CODE (COMPLETELY UNCHANGED) ------------------- #
class Endpoint:
    def __init__(self, url, html_content):
        self.url = url
        self.html_content = html_content  # Store HTML content
        # HTML and JavaScript inputs
        self.html_inputs = []   # Inputs/selects/textareas inside <form> (HTML inputs)
        self.js_inputs = []     # Inputs/selects/textareas outside <form> (likely JS-driven inputs)
        # Backwards-compatible aggregate list
        self.parameters = []
        self.buttons = []
        self.hidden_params = []
        self.placeholder = []
        self.has_comment = False
        self.comments = []
        # Detected patterns
        self.version_matches = []  # Version numbers found
        self.ip_matches = []       # IP addresses found
        self.sensitive_comments = []  # Comments with sensitive keywords
        self.sensitive_matches = []   # Exact sensitive phrases matched
        self.comment_type = ""
        
        # Create session for additional requests if needed
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False
        
        # Disable SSL warnings for this session
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def fetch_parameters(self):
        """Fetch form parameters from stored HTML content"""
        try:
            # Use the stored HTML content instead of making new request
            self._extract_forms_buttons_hidden_fallback()
            self._remove_duplicates()
            return self.parameters + self.buttons + self.hidden_params
        except Exception as e:
            return []

    def _extract_forms_buttons_hidden_fallback(self):
        """Extract form elements from stored HTML - IMPROVED"""
        try:
            soup = BeautifulSoup(self.html_content, 'html.parser')
            forms = soup.find_all('form')
            # Reset all collections
            self.html_inputs = []
            self.js_inputs = []
            self.parameters = []
            self.buttons = []
            self.hidden_params = []
            self.placeholder = []
            
            for form in forms:
                inputs = form.find_all('input')
                for input_tag in inputs:
                    name = input_tag.get('name', '')
                    input_id = input_tag.get('id', '')
                    input_type = input_tag.get('type', '').lower()
                    placeholder = input_tag.get('placeholder', '')
                    input_class = input_tag.get('class', [])
                    if isinstance(input_class, list):
                        input_class = ' '.join(input_class)
                    
                    # IMPROVED: Better field name detection with placeholder support
                    field_name = ""
                    if name and name.strip():
                        field_name = name.strip()
                    elif input_id and input_id.strip():
                        field_name = input_id.strip()
                    elif placeholder and placeholder.strip():
                        field_name = f"placeholder_{placeholder.strip()}"
                    elif input_class and input_class.strip():
                        field_name = f"class_{input_class.strip()}"
                    else:
                        # If no identifier, use a generic name with type
                        field_name = f"input_{input_type}"
                    
                    if placeholder and placeholder.strip():
                        self.placeholder.append(placeholder.strip())
                    
                    if input_type == 'hidden':
                        self.hidden_params.append(field_name)
                    elif input_type in ['submit', 'button', 'image']:
                        self.buttons.append(field_name)
                    else:
                        # Inputs inside a form are treated as HTML inputs
                        self.html_inputs.append(field_name)
                
                buttons = form.find_all('button')
                for button in buttons:
                    button_name = button.get('name', '')
                    button_id = button.get('id', '')
                    button_text = button.get_text().strip()
                    
                    if button_name:
                        self.buttons.append(button_name)
                    elif button_id:
                        self.buttons.append(button_id)
                    elif button_text:
                        self.buttons.append(button_text)
                    else:
                        self.buttons.append("button")
                
                selects = form.find_all('select')
                for select in selects:
                    select_name = select.get('name', '')
                    select_id = select.get('id', '')
                    
                    if select_name:
                        self.html_inputs.append(select_name)
                    elif select_id:
                        self.html_inputs.append(select_id)
                    else:
                        self.html_inputs.append("select")
                
                textareas = form.find_all('textarea')
                for textarea in textareas:
                    textarea_name = textarea.get('name', '')
                    textarea_id = textarea.get('id', '')
                    
                    if textarea_name:
                        self.html_inputs.append(textarea_name)
                    elif textarea_id:
                        self.html_inputs.append(textarea_id)
                    else:
                        self.html_inputs.append("textarea")
                        
            # Additionally, capture inputs/selects/textareas that are outside of <form>
            try:
                # Inputs outside forms
                for input_tag in soup.find_all('input'):
                    # Skip if this input is already processed in a form
                    if input_tag.find_parent('form'):
                        continue
                        
                    name = input_tag.get('name', '')
                    input_id = input_tag.get('id', '')
                    input_type = input_tag.get('type', '').lower()
                    placeholder = input_tag.get('placeholder', '')
                    input_class = input_tag.get('class', [])
                    if isinstance(input_class, list):
                        input_class = ' '.join(input_class)

                    # IMPROVED: Better field name detection
                    field_name = ""
                    if name and name.strip():
                        field_name = name.strip()
                    elif input_id and input_id.strip():
                        field_name = input_id.strip()
                    elif placeholder and placeholder.strip():
                        field_name = f"placeholder_{placeholder.strip()}"
                    elif input_class and input_class.strip():
                        field_name = f"class_{input_class.strip()}"
                    else:
                        field_name = f"input_{input_type}"

                    if placeholder and placeholder.strip():
                        self.placeholder.append(placeholder.strip())

                    if input_type == 'hidden':
                        self.hidden_params.append(field_name)
                    elif input_type in ['submit', 'button', 'image']:
                        self.buttons.append(field_name)
                    else:
                        # Inputs outside forms are more likely driven by JS
                        self.js_inputs.append(field_name)

                # Selects outside forms
                for select in soup.find_all('select'):
                    if select.find_parent('form'):
                        continue
                        
                    select_name = select.get('name', '')
                    select_id = select.get('id', '')
                    if select_name:
                        self.js_inputs.append(select_name)
                    elif select_id:
                        self.js_inputs.append(select_id)
                    else:
                        self.js_inputs.append("select")

                # Textareas outside forms
                for textarea in soup.find_all('textarea'):
                    if textarea.find_parent('form'):
                        continue
                        
                    textarea_name = textarea.get('name', '')
                    textarea_id = textarea.get('id', '')
                    if textarea_name:
                        self.js_inputs.append(textarea_name)
                    elif textarea_id:
                        self.js_inputs.append(textarea_id)
                    else:
                        self.js_inputs.append("textarea")
            except Exception:
                pass

        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error in form extraction: {e}")

    def _remove_duplicates(self):
        """Remove duplicate parameters"""
        # De-duplicate while preserving order
        self.html_inputs = list(dict.fromkeys(self.html_inputs))
        self.js_inputs = list(dict.fromkeys(self.js_inputs))
        # Keep aggregate parameters for backwards compatibility/use in JSON
        self.parameters = self.html_inputs + self.js_inputs
        self.buttons = list(dict.fromkeys(self.buttons))
        self.hidden_params = list(dict.fromkeys(self.hidden_params))
        self.placeholder = list(dict.fromkeys(self.placeholder))

    def fetch_comments(self):
        """Fetch comments from stored HTML content"""
        self.comments = []
        self.sensitive_comments = []
        self.sensitive_matches = []
        self.version_matches = []
        self.ip_matches = []
        self.has_comment = False
        html_comments = []
        js_comments = []

        try:
            # Extract HTML comments
            html_comments = re.findall(r'<!--(.*?)-->', self.html_content, re.DOTALL)
            # Extract JS comments
            js_comments = re.findall(r'//.*?$|/\*.*?\*/', self.html_content, re.DOTALL | re.MULTILINE)

            html_comments = [c.strip() for c in html_comments if c.strip()]
            js_comments = [c.strip() for c in js_comments if c.strip()]

            if html_comments or js_comments:
                self.has_comment = True
                self.comments = html_comments + js_comments

                # Check for sensitive keywords in comments
                for comment in self.comments:
                    if is_sensitive(comment):
                        self.sensitive_comments.append(comment)
                        try:
                            # collect exact matches like "api: value" or "password = xxx"
                            for m in SENSITIVE_PATTERN.finditer(comment):
                                key = m.group(1)
                                # Extract the value right after the pattern
                                value = ""
                                try:
                                    rest = comment[m.end():]
                                    # skip whitespace
                                    rest = rest.lstrip()
                                    if rest:
                                        if rest[0] in ('"', "'"):
                                            q = rest[0]
                                            end_idx = rest.find(q, 1)
                                            if end_idx != -1:
                                                value = rest[1:end_idx].strip()
                                        else:
                                            # capture until whitespace or strong delimiters (keep symbols like #)
                                            mval = re.match(r"([^\s,<>'" + '"' + r"()\[\]{}]+)", rest)
                                            if mval:
                                                value = mval.group(1).strip()
                                except Exception:
                                    value = ""

                                if value:
                                    self.sensitive_matches.append(f"{key}={value}")
                        except Exception:
                            pass

                if html_comments and js_comments:
                    self.comment_type = "Has HTML + JS Comment"
                elif html_comments:
                    self.comment_type = "Has HTML Comment"
                elif js_comments:
                    self.comment_type = "Has JS Comment"

                # De-duplicate matches while preserving order
                if self.sensitive_matches:
                    self.sensitive_matches = list(dict.fromkeys(self.sensitive_matches))

                # Detect version numbers and IPs across URL, parameters, buttons, hidden and comments
                try:
                    scan_pieces = [self.url]
                    scan_pieces.extend(self.parameters)
                    scan_pieces.extend(self.buttons)
                    scan_pieces.extend(self.hidden_params)
                    scan_pieces.extend(self.comments)
                    scan_text = "\n".join(str(p) for p in scan_pieces if p)

                    versions = VERSION_PATTERN.findall(scan_text)
                    ips = IP_PATTERN.findall(scan_text)

                    if versions:
                        self.version_matches = list(dict.fromkeys(versions))
                    if ips:
                        self.ip_matches = list(dict.fromkeys(ips))
                except Exception:
                    pass


        except Exception as e:
            self.has_comment = False
            self.comment_type = ""

        return self.has_comment


def main():
    parser = OptionParser()
    parser.add_option("-o", "--output", dest="output", help="Save results to CSV file", metavar="FILE")
    parser.add_option("-j", "--json-output", dest="json_output", help="Save results to JSON file", metavar="FILE")
    parser.add_option("-u", "--url", dest="base_url", help="Base URL to crawl")
    parser.add_option("-m", "--max-urls", dest="max_urls", type="int", default=None,
                     help="Maximum number of URLs to crawl (optional)")
    parser.add_option("-t", "--threads", dest="threads", type="int", default=10,
                     help="Number of threads to use for crawling (default: 10)")
    parser.add_option("--subdomains", dest="subdomains", action="store_true", default=False,
                     help="Enable subdomain crawling (default: disabled)")
    parser.add_option("--debug", dest="debug", action="store_true", default=False,
                     help="Enable debug output")
    (options, args) = parser.parse_args()
    
    output_file = options.output
    json_file = options.json_output
    base_url = options.base_url
    max_urls = options.max_urls
    threads = options.threads
    crawl_subdomains = options.subdomains
    debug = options.debug

    # Validate required parameters
    if not base_url:
        print(Fore.RED + "Error: Base URL is required. Use -u or --url option.")
        print("Example: python deepseek_project.py -u https://example.com")
        return

    endpoints = []
    start_time = time.time()
    total_crawled = 0
    
    try:
        crawler = AdvancedCrawler(max_workers=threads, crawl_subdomains=crawl_subdomains, debug=debug)
        
        # First pass: crawl all URLs
        for url in crawler.run_crawler(base_url, max_urls):
            status = crawler.url_status.get(url)
            # Skip 404 and other error status codes, only process successful ones
            if status and status >= 400:
                continue

            html_content = crawler.url_content_map.get(url)
            ep = None
            if html_content is not None and html_content != '':
                ep = Endpoint(url, html_content)
                ep.fetch_parameters()
                ep.fetch_comments()
                endpoints.append(ep)

            query_params = get_query_params(url)
            query_parts = [Fore.LIGHTMAGENTA_EX + qp + Style.RESET_ALL for qp in query_params]
            url_display = Fore.WHITE + f"{url}" + Style.RESET_ALL

            if ep:
                # Collect all output parts first
                output_parts = []
                # 1) Query parameters (purple)
                if query_parts:
                    output_parts.extend(query_parts)
                # 2) HTML inputs (blue)
                for p in ep.html_inputs:
                    output_parts.append(Fore.LIGHTBLUE_EX + f"{p}" + Style.RESET_ALL)
                # 3) JavaScript inputs (orange-style yellow)
                for js in ep.js_inputs:
                    output_parts.append(Fore.YELLOW + f"{js}" + Style.RESET_ALL)
                # 4) Buttons (green)
                for b in ep.buttons:
                    output_parts.append(Fore.GREEN + f"{b}" + Style.RESET_ALL)
                # 5) Hidden fields (gray)
                for h in ep.hidden_params:
                    output_parts.append(Fore.LIGHTBLACK_EX + f"{h}" + Style.RESET_ALL)
                # 6) Sensitive matches (red)
                if ep.sensitive_matches:
                    for phrase in ep.sensitive_matches:
                        output_parts.append(Fore.RED + f"{phrase}" + Style.RESET_ALL)
                # 7) Version numbers (purple) - last
                if ep.version_matches:
                    for ver in ep.version_matches:
                        output_parts.append(Fore.LIGHTMAGENTA_EX + f"{ver}" + Style.RESET_ALL)
                # 8) IP addresses (cyan) - last
                if ep.ip_matches:
                    for ip in ep.ip_matches:
                        output_parts.append(Fore.CYAN + f"{ip}" + Style.RESET_ALL)
                
                # Print with colon only if there are output parts
                if output_parts:
                    print(url_display + " : " + " ".join(output_parts))
                else:
                    print(url_display)
            else:
                if query_parts:
                    print(url_display + " : " + " ".join(query_parts))
                else:
                    print(url_display)
        
        total_crawled = crawler.crawled_count
        
        # Retry failed URLs
        crawler.retry_failed_urls(endpoints)

        # Summary output
        end_time = time.time()
        total_time = end_time - start_time

        print("-"*50)
        print("["+ Fore.GREEN + "+", end="")
        print("]",end="")
        print(f"Total URLs crawled: {total_crawled} URLs.")
        print("["+ Fore.GREEN + "+", end="")
        print("]",end="")
        print(f"Total Time: {total_time:.2f} seconds")
        print("["+ Fore.CYAN + "+", end="")
        print("]",end="")
        print(f"Failed URLs (404s): {len(crawler.failed_urls)} URLs.")
        print("["+ Fore.CYAN + "+", end="")
        print("]",end="")
        print(f"Timeout URLs: {len(crawler.timeout_urls)} URLs.")
        
        # Print sensitive comments summary
        sensitive_count = sum(1 for ep in endpoints if ep.sensitive_comments)
        if sensitive_count > 0:
            print("["+ Fore.RED + "!", end="")
            print(f"] Found {sensitive_count} pages with possible sensitive comments")
        
        print("-" * 50)

        if output_file:
            try:
                with open(output_file, "w", newline="", encoding="utf-8-sig") as f:  # utf-8-sig for Excel compatibility
                    writer = csv.writer(f, delimiter=',')
                    writer.writerow([
                        "URL",
                        "Query_Params",
                        "Html_Inputs",
                        "Js_Inputs",
                        "Buttons",
                        "Hidden",
                        "Sensitive_Comment",
                        "Versions",
                        "IPs",
                    ])
                    
                    for ep in endpoints:
                        # 1) Query parameters
                        query_pairs = get_query_params(ep.url)
                        query_str = ", ".join(query_pairs) if query_pairs else ""
                        # 2) HTML inputs
                        html_params = ", ".join(ep.html_inputs) if ep.html_inputs else ""
                        # 3) JavaScript inputs
                        js_params = ", ".join(ep.js_inputs) if ep.js_inputs else ""
                        # 4) Buttons
                        buttons = ", ".join(ep.buttons) if ep.buttons else ""
                        # 5) Hidden
                        hidden = ", ".join(ep.hidden_params) if ep.hidden_params else ""
                        
                        # Show actual sensitive results instead of just "Yes"
                        sensitive_comment = ""
                        if ep.sensitive_matches:
                            # Join all sensitive matches with semicolons
                            sensitive_comment = "; ".join(ep.sensitive_matches)
                        elif ep.sensitive_comments:
                            # Fallback to sensitive comments if no matches
                            sensitive_comment = "; ".join(ep.sensitive_comments)
                        
                        # 6) Versions
                        versions_str = ", ".join(ep.version_matches) if ep.version_matches else ""
                        # 7) IPs
                        ips_str = ", ".join(ep.ip_matches) if ep.ip_matches else ""

                        writer.writerow([
                            ep.url,
                            query_str,
                            html_params,
                            js_params,
                            buttons,
                            hidden,
                            sensitive_comment,
                            versions_str,
                            ips_str,
                        ])
                    
                    # Add found files to CSV with status
                    if crawler.found_files:
                        writer.writerow([])
                        writer.writerow(["Found Files:"])
                        for file_url in sorted(crawler.found_files):
                            writer.writerow([file_url, "", "", "", "", "", "", "", ""])
                    
                    # Add failed URLs to CSV (separated from alive endpoints)
                    if crawler.failed_urls:
                        writer.writerow([])
                        writer.writerow(["Failed URLs (404s):"])
                        for failed_url in sorted(crawler.failed_urls):
                            writer.writerow([failed_url, "", "", "", "", "", "", "", ""])
                    
                    print(Fore.GREEN + f"\nSuccessfully wrote to {output_file}\n")
            except Exception as e:
                print(Fore.RED + f"\nError writing to CSV: {str(e)}\n")

        # Optional JSON output
        if json_file:
            try:
                def endpoint_to_dict(ep):
                    status_code = crawler.url_status.get(ep.url, "N/A")
                    return {
                        "url": ep.url,
                        "status_code": status_code,
                        "parameters": ep.parameters,
                        "html_inputs": ep.html_inputs,
                        "js_inputs": ep.js_inputs,
                        "buttons": ep.buttons,
                        "hidden": ep.hidden_params,
                        "versions": ep.version_matches,
                        "ips": ep.ip_matches,
                        "placeholders": ep.placeholder,
                        "has_comment": ep.has_comment,
                        "comment_type": ep.comment_type,
                        "sensitive_comments": ep.sensitive_comments,
                        "sensitive_comment": "; ".join(ep.sensitive_matches) if ep.sensitive_matches else ("; ".join(ep.sensitive_comments) if ep.sensitive_comments else ""),
                        # Comments list may be large; include for completeness
                        "comments": ep.comments,
                    }

                data = {
                    "base_url": base_url,
                    "total_urls_crawled": total_crawled,
                    "duration_seconds": round(total_time, 2),
                    "endpoints": [endpoint_to_dict(ep) for ep in endpoints],
                    "found_files": sorted(crawler.found_files) if crawler.found_files else [],
                    "failed_urls_404": sorted(crawler.failed_urls) if crawler.failed_urls else [],
                    "timeout_urls": sorted(crawler.timeout_urls) if crawler.timeout_urls else [],
                }

                with open(json_file, "w", encoding="utf-8-sig") as jf:  # utf-8-sig for better Arabic support
                    json.dump(data, jf, ensure_ascii=False, indent=2)

                print(Fore.GREEN + f"\nSuccessfully wrote JSON to {json_file}\n")
            except Exception as e:
                print(Fore.RED + f"\nError writing JSON: {str(e)}\n")

    except KeyboardInterrupt:
        print("\n[!] Stopping...")
    except Exception as e:
        print(f"Main exception: {e}")

if __name__ == "__main__":
    main()