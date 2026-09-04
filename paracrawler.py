import csv
import json
import math
import random
import re
import sys
import threading
import time
import warnings
from collections import deque
from concurrent.futures import (
    FIRST_COMPLETED,
    ThreadPoolExecutor,
    wait,
)
from optparse import OptionParser
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from colorama import Fore, Style, init
from scrapy.http import TextResponse
from scrapy.linkextractors import LinkExtractor
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Prefer lxml for HTML parsing: it is several times faster than the pure-Python
# html.parser and lets a large crawl finish noticeably sooner. Fall back
# gracefully if lxml is not installed so the crawler keeps working everywhere.
try:
    import lxml  # noqa: F401  (import probe only)
    _HTML_PARSER = 'lxml'
except ImportError:
    _HTML_PARSER = 'html.parser'


def make_soup(html):
    """Build a BeautifulSoup tree using the fastest available parser."""
    try:
        return BeautifulSoup(html, _HTML_PARSER)
    except Exception:
        # A broken/missing lxml at runtime should never abort a crawl.
        return BeautifulSoup(html, 'html.parser')

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

# Public-suffix handling. tldextract is preferred, but it is only usable when
# its Public Suffix List data is available locally: some distro packages ship
# tldextract without the bundled ".tld_set_snapshot" file, and with
# suffix_list_urls=() (no network) extraction then raises FileNotFoundError.
# We probe it once at import; if it can't work offline we fall back to a
# compact built-in heuristic so scope matching keeps working without network.
try:
    TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())
    TLD_EXTRACTOR('example.com')  # force snapshot load now, so failures surface here
    _TLDEXTRACT_OK = True
except Exception:
    TLD_EXTRACTOR = None
    _TLDEXTRACT_OK = False

# Second-level labels that act as public suffixes under a 2-letter ccTLD
# (e.g. gov.sa, co.uk, com.au). Used only by the offline fallback below.
_CCTLD_SECOND_LEVELS = frozenset({
    'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'mil', 'sch', 'gob',
    'gouv', 'go', 'or', 'ne', 'gr', 'ad', 'ed', 'lg', 're', 'id', 'asn',
    'gen', 'firm', 'ind', 'res', 'med', 'pub', 'nom', 'name', 'biz', 'info',
    'mod', 'nhs', 'plc', 'ltd', 'me', 'in',
})


def _fallback_registered_domain(host):
    """Best-effort eTLD+1 without a Public Suffix List (offline heuristic)."""
    labels = host.split('.')
    if len(labels) <= 2:
        return host
    tld, sld = labels[-1], labels[-2]
    if len(tld) == 2 and sld in _CCTLD_SECOND_LEVELS:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def registered_domain(host):
    """Return the registrable domain (eTLD+1) for a host. Offline-safe.

    Falls back to a built-in heuristic when tldextract's PSL data is missing,
    so the crawler never crashes on domain parsing.
    """
    host = (host or '').lower().strip().rstrip('.')
    if not host or '.' not in host:
        return host
    if _TLDEXTRACT_OK:
        try:
            reg = TLD_EXTRACTOR(host).top_domain_under_public_suffix
            if reg:
                return reg
        except Exception:
            pass
    return _fallback_registered_domain(host)


def print_color_legend():
    """Print the result color legend once at startup."""
    print("\nResult color legend:")
    print(Fore.LIGHTMAGENTA_EX + "  Query parameters (GET Parameters)" + Style.RESET_ALL)
    print(Fore.LIGHTBLUE_EX + "  HTML inputs (POST Parameters)" + Style.RESET_ALL)
    print(Fore.YELLOW + "  JavaScript inputs" + Style.RESET_ALL)
    print(Fore.GREEN + "  Buttons" + Style.RESET_ALL)
    print(Fore.LIGHTBLACK_EX + "  Hidden fields" + Style.RESET_ALL)
    print(Fore.RED + "  Sensitive findings" + Style.RESET_ALL)
    print(Fore.LIGHTMAGENTA_EX + "  Versions" + Style.RESET_ALL)
    print(Fore.CYAN + "  IP addresses" + Style.RESET_ALL)
    print()


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
        return bool(INPUT_FIELD_WITH_VALUE_PATTERN.search(text))

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
    except Exception:
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
    def __init__(
        self,
        max_workers=10,
        delay_range=(0.1, 0.1),
        crawl_subdomains=False,
        debug=False,
        request_timeout=10.0,
        max_response_bytes=1048576,
        request_retries=1,
        https_fallback=True,
        extra_headers=None,
    ):
        self.visited = set()
        self.to_visit = deque()
        self.lock = threading.Lock()
        self.url_content_map = {}  # Store HTML content for each URL
        self.url_status = {}  # HTTP status per URL
        self.failed_urls = set()
        self.timeout_urls = set()  # URLs that timed out
        # HTTP(S) links discovered outside the configured crawl scope. These
        # are reported only and are never added to the crawl queue.
        self.out_of_scope_links = set()
        self.base_domain = ""
        self.domain_ip = None  # Store resolved IP
        self.max_workers = max(1, int(max_workers))
        self.delay_range = delay_range
        self.request_timeout = max(0.1, float(request_timeout))
        self.max_response_bytes = max(1024, int(max_response_bytes))
        self.request_retries = max(1, int(request_retries))
        self.https_fallback = bool(https_fallback)
        self.crawled_count = 0
        self.found_files = set()
        self.crawl_subdomains = crawl_subdomains
        self.debug = debug
        # Authenticated-session headers (Cookie, Authorization, custom headers).
        # Applied to every thread-local session so all requests share the auth.
        self.extra_headers = dict(extra_headers) if extra_headers else {}

        self._thread_local = threading.local()
        # Cooperative cancellation flag. Set on Ctrl+C (or when a URL limit is
        # reached) so in-flight workers stop scheduling new work and the crawl
        # unwinds promptly instead of blocking on every queued request.
        self._stop = threading.Event()
        # A single LinkExtractor is reusable and thread-safe for extract_links;
        # constructing a new one per page was needless per-request overhead.
        self._link_extractor = LinkExtractor()

    def stop(self):
        """Request cooperative shutdown of all crawl activity."""
        self._stop.set()

    def _create_session(self):
        """Create a configured HTTP session for one worker thread."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'ParaCrawler/1.0 (+https://github.com/Ryan503x/ParaCrawler)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        # Apply authenticated-session headers last so a supplied Cookie /
        # Authorization / User-Agent overrides the defaults above.
        if self.extra_headers:
            session.headers.update(self.extra_headers)
        session.verify = False
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.max_workers,
            pool_maxsize=self.max_workers,
            # ParaCrawler owns retry policy through --retries. Keeping adapter
            # retries disabled prevents each attempt from silently doubling.
            max_retries=0,
            pool_block=True,
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session

    def get_session(self):
        """Return a thread-local session to avoid sharing mutable session state."""
        if not hasattr(self._thread_local, 'session'):
            self._thread_local.session = self._create_session()
        return self._thread_local.session

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
        """Return whether a URL is inside the configured crawl scope."""
        try:
            target_host = (urlparse(target_url).hostname or '').lower().rstrip('.')
            base_host = (urlparse(f'//{self.base_domain}').hostname or '').lower().rstrip('.')
            if not target_host or not base_host:
                return False

            if not self.crawl_subdomains:
                # Treat the conventional apex/www pair as the same site. Many
                # sites immediately redirect from one form to the other, and
                # rejecting that redirect prevents the first page from loading.
                def without_www(host):
                    return host[4:] if host.startswith('www.') else host

                return (
                    target_host == base_host
                    or without_www(target_host) == without_www(base_host)
                    and (target_host.startswith('www.') or base_host.startswith('www.'))
                )

            base_reg = registered_domain(base_host)
            target_reg = registered_domain(target_host)
            if base_reg and target_reg:
                return base_reg == target_reg

            # For private/internal names with no known public suffix, only permit
            # the exact host and its descendants; never guess sibling scope.
            return target_host == base_host or target_host.endswith(f'.{base_host}')
        except (TypeError, ValueError, AttributeError) as error:
            if self.debug:
                print(f"[DEBUG] Domain check error for {target_url}: {error}")
            return False

    def normalize_url(self, url):
        """Return a stable HTTP(S) URL to reduce duplicate crawl work."""
        try:
            candidate = url.strip()
            if '://' not in candidate:
                candidate = 'http://' + candidate

            parsed = urlparse(candidate)
            scheme = parsed.scheme.lower()
            if scheme not in ('http', 'https') or not parsed.hostname:
                return url

            host = parsed.hostname.lower().rstrip('.')
            if ':' in host and not host.startswith('['):
                host = f'[{host}]'

            port = parsed.port
            if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
                host = f'{host}:{port}'

            path = re.sub(r'/+', '/', parsed.path or '/')
            if path != '/' and path.endswith('/'):
                path = path.rstrip('/')

            normalized = f'{scheme}://{host}{path}'
            if parsed.query:
                normalized += f'?{parsed.query}'
            return normalized
        except (TypeError, ValueError, AttributeError):
            return url

    def record_out_of_scope_link(self, url):
        """Retain a normalized external HTTP(S) URL without visiting it."""
        link = self.normalize_url(url)
        try:
            parsed = urlparse(link)
            if (
                parsed.scheme.lower() in ('http', 'https')
                and parsed.hostname
                and not self.is_same_domain(link)
            ):
                self.out_of_scope_links.add(link)
                return True
        except (TypeError, ValueError, AttributeError):
            pass
        return False

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

    def _request_with_safe_redirects(self, url, timeout, method='GET', max_redirects=5):
        """Follow only in-scope redirects and return the final response."""
        session = self.get_session()
        current_url = url
        redirect_codes = {301, 302, 303, 307, 308}
        request = getattr(session, method.lower())

        for _ in range(max_redirects + 1):
            request_options = {
                'timeout': timeout,
                'allow_redirects': False,
            }
            if method.upper() == 'GET':
                request_options['stream'] = True
            response = request(current_url, **request_options)
            if response.status_code not in redirect_codes:
                return response, current_url, True

            location = response.headers.get('Location')
            if not location:
                return response, current_url, False

            next_url = self.normalize_url(urljoin(current_url, location))
            if not self.is_same_domain(next_url):
                with self.lock:
                    self.record_out_of_scope_link(next_url)
                return response, current_url, False

            response.close()
            current_url = next_url

        raise requests.exceptions.TooManyRedirects(
            f"More than {max_redirects} redirects for {url}"
        )

    def fetch_url_content(self, url, retries=None, timeout=None):
        """Fetch and retain a bounded HTML response with retries."""
        if retries is None:
            retries = self.request_retries
        if timeout is None:
            timeout = (min(5.0, self.request_timeout), self.request_timeout)
        # Check if this is a non-HTML resource before fetching
        if self.is_non_html_resource(url):
            with self.lock:
                # Only add to found_files if it's not a CSS file
                if not self.is_css_file(url):
                    self.found_files.add(url)
            return None

        for attempt in range(retries):
            if self._stop.is_set():
                return None
            response = None
            try:
                # Skip the politeness delay entirely when shutting down so an
                # interrupt is not held up by sleeping worker threads.
                low, high = self.delay_range
                if high > 0 and not self._stop.is_set():
                    time.sleep(random.uniform(low, high))

                response, final_url, redirect_allowed = self._request_with_safe_redirects(url, timeout)

                # Record both the requested URL and the final in-scope URL.
                with self.lock:
                    self.url_status[url] = response.status_code
                    self.url_status[final_url] = response.status_code

                if not redirect_allowed:
                    if self.debug:
                        print(f"[DEBUG] Blocked out-of-scope or invalid redirect from {url}")
                    return None

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
                
                content = response.raw.read(self.max_response_bytes, decode_content=True)

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
            finally:
                if response is not None:
                    response.close()

        return None

    def debug_extract_links(self, html, base_url):
        """Debug method to see what links are being found.

        The extra BeautifulSoup pass here is purely diagnostic, so it only runs
        under --debug. In normal runs we skip straight to the fast extractor and
        avoid parsing every page an extra time.
        """
        if self.debug:
            print(f"\n[DEBUG] Analyzing links from: {base_url}")
            soup = make_soup(html)

            # Check all a tags
            a_tags = soup.find_all('a', href=True)
            print(f"[DEBUG] Found {len(a_tags)} <a> tags with href")
            for i, tag in enumerate(a_tags[:10]):  # Show first 10
                href = tag.get('href', '').strip()
                print(f"  [LINK {i}] {href}")

            # Check all link tags
            link_tags = soup.find_all('link', href=True)
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
        response = TextResponse(url=base_url, body=html, encoding='utf-8')
        return [link.url for link in self._link_extractor.extract_links(response)]

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
            subdomains = sorted(found_subdomains)
            
            # Print discovered subdomains only when debugging
            if self.debug and subdomains:
                print(f"[SUBDOMAINS] Found {len(subdomains)} subdomains in {base_url}")
                for subdomain in subdomains:
                    print(f"  [SUBDOMAIN] {subdomain}")
                    
        except Exception as e:
            print(f"[SUBDOMAIN ERROR] {e}")
        
        return subdomains

    def discover_sveltekit_routes(self, html, base_url):
        """Discover explicit SvelteKit assets and API paths without guessing routes."""
        routes = set()
        patterns = (
            r'["\'](/_app/immutable/[^"\']+\.js(?:\?[^"\']*)?)["\']',
            r'["\'](/_?api(?:/[^"\']*)?)["\']',
        )

        for pattern in patterns:
            for path in re.findall(pattern, html, re.IGNORECASE):
                full_url = self.normalize_url(urljoin(base_url, path))
                if self.is_same_domain(full_url):
                    routes.add(full_url)

        return sorted(routes)

    def crawl_worker(self, url):
        """Worker function for crawling URLs - FIXED FOR SUBDOMAIN RECURSION"""
        # Bail immediately if a shutdown was requested (Ctrl+C / limit reached).
        if self._stop.is_set():
            return None, []
        # SECURITY CHECK: Verify URL is from the same domain before processing
        if not self.is_same_domain(url):
            return None, []
            
        with self.lock:
            if url in self.visited:
                return None, []
            self.visited.add(url)
        
        # Fetch content once and store it
        html = self.fetch_url_content(url)
        if not html and self.https_fallback and urlparse(url).scheme == 'http':
            https_url = self.normalize_url(url.replace('http://', 'https://', 1))
            if self.is_same_domain(https_url):
                if self.debug:
                    print(f"[DEBUG] HTTP failed; trying HTTPS fallback: {https_url}")
                html = self.fetch_url_content(https_url)
                if html:
                    with self.lock:
                        self.visited.add(https_url)
                        self.timeout_urls.discard(url)
                        self.failed_urls.discard(url)
                    url = https_url

        if not html:
            # Only yield a successfully fetched non-HTML response. A blocked
            # redirect retains its 3xx status for diagnostics but was not crawled.
            status = self.url_status.get(url)
            if status and 200 <= status < 300:
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
            for raw_link in links:
                link = self.normalize_url(raw_link)
                if self.is_same_domain(link) and link not in self.visited and link not in self.to_visit:
                    self.to_visit.append(link)
                    new_links.append(link)
                elif self.record_out_of_scope_link(link):
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
        self.out_of_scope_links.clear()
        self.crawled_count = 0
        
        if not start_url.startswith(('http://', 'https://')):
            start_url = "http://" + start_url
            
        start_url = self.normalize_url(start_url)
        parsed = urlparse(start_url)
        self.base_domain = (parsed.hostname or '').lower()
        self.root_domain = registered_domain(self.base_domain) or self.base_domain
        
        # SECURITY CHECK: Validate the base domain
        if not self.base_domain or '.' not in self.base_domain:
            print(Fore.RED + f"Error: Invalid domain '{self.base_domain}' - Cannot proceed with crawling")
            return
        
        self.to_visit.append(start_url)

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
        print(f"[INFO] Root domain: {self.root_domain}")
        print("-"*50)

        # Rolling-submission scheduler.
        #
        # The previous design submitted a fixed batch and then blocked until
        # *every* URL in it finished before queuing the next batch. A single
        # slow/timeout URL stalled the whole batch, wasting worker capacity and
        # making the run feel like it "hung". Here we keep the pool continuously
        # saturated: as soon as any worker finishes we harvest its result and
        # top the pool back up. We also drive the executor manually so an
        # interrupt (or a URL-limit hit) tears everything down immediately via
        # cancel_futures instead of the context manager's blocking join.
        executor = ThreadPoolExecutor(max_workers=self.max_workers)
        in_flight = {}          # Future -> url
        dispatched = 0          # total URLs handed to workers (bounds max_urls)
        # A little headroom over max_workers keeps threads fed while results are
        # being consumed, without letting the pending queue grow unbounded.
        max_in_flight = self.max_workers * 2
        try:
            while not self._stop.is_set():
                # Top up the pool from the frontier queue.
                while (
                    self.to_visit
                    and len(in_flight) < max_in_flight
                    and (max_urls is None or dispatched < max_urls)
                ):
                    url = self.to_visit.popleft()
                    if url in self.visited:
                        continue
                    in_flight[executor.submit(self.crawl_worker, url)] = url
                    dispatched += 1

                if not in_flight:
                    break  # Nothing running and nothing queued: crawl is done.

                if self.debug:
                    print(f"[DEBUG] In-flight: {len(in_flight)}, Queue: {len(self.to_visit)}, "
                          f"Visited: {len(self.visited)}, Crawled: {self.crawled_count}")

                # Wait with a short timeout so the loop stays responsive to a
                # stop request even while requests are still outstanding.
                done, _pending = wait(
                    in_flight, timeout=0.5, return_when=FIRST_COMPLETED
                )
                for future in done:
                    in_flight.pop(future, None)
                    try:
                        url, _new_links = future.result()
                        if url:
                            yield url
                    except Exception as error:
                        if self.debug:
                            print(f"[DEBUG] Worker error: {error}")
        except BaseException:
            # Ctrl+C (KeyboardInterrupt) or the generator being closed lands
            # here: flag shutdown so running workers stop doing extra work.
            self._stop.set()
            raise
        finally:
            # Never block on shutdown: cancel anything queued and let the few
            # already-running requests unwind on their own bounded timeouts.
            executor.shutdown(wait=False, cancel_futures=True)

        # Visit found files to get their status codes (skipped if interrupted).
        if not self._stop.is_set():
            self.visit_found_files()

    def visit_found_files(self):
        """Visit found files to get their actual status codes"""
        if not self.found_files or self._stop.is_set():
            return

        executor = ThreadPoolExecutor(max_workers=min(5, self.max_workers))
        try:
            # Submit all found files for status checking
            futures = []
            for file_url in self.found_files:
                if self._stop.is_set():
                    break
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
        except BaseException:
            self._stop.set()
            raise
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    def check_file_status(self, url):
        """Check a file status without following redirects outside scope."""
        timeout = (5, 10)
        response = None
        try:
            response, _final_url, allowed = self._request_with_safe_redirects(
                url, timeout, method='HEAD'
            )
            return response.status_code if allowed else None
        except requests.exceptions.RequestException:
            if response is not None:
                response.close()
                response = None
            try:
                response, _final_url, allowed = self._request_with_safe_redirects(
                    url, timeout, method='GET'
                )
                return response.status_code if allowed else None
            except requests.exceptions.RequestException:
                return None
        finally:
            if response is not None:
                response.close()

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
            retry_urls = sorted(self.timeout_urls)  # Sort for consistent retry order
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
        
        retry_urls = sorted(self.failed_urls)  # Sort for consistent retry order
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
                            ep = Endpoint(url, html, debug=self.debug)
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


# ------------------- ENDPOINT ANALYSIS ------------------- #
class Endpoint:
    def __init__(self, url, html_content, debug=False):
        self.url = url
        self.html_content = html_content or ""
        self.debug = debug
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

    def fetch_parameters(self):
        """Fetch form parameters from stored HTML content"""
        try:
            # Use the stored HTML content instead of making new request
            self._extract_forms_buttons_hidden_fallback()
            self._remove_duplicates()
            return self.parameters + self.buttons + self.hidden_params
        except Exception:
            return []

    def _extract_forms_buttons_hidden_fallback(self):
        """Extract form elements from stored HTML - IMPROVED"""
        try:
            soup = make_soup(self.html_content)
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
        """Extract comments, sensitive values, versions, and IPv4 indicators."""
        self.comments = []
        self.sensitive_comments = []
        self.sensitive_matches = []
        self.version_matches = []
        self.ip_matches = []
        self.has_comment = False
        self.comment_type = ""

        try:
            html_comments = [
                comment.strip()
                for comment in re.findall(r'<!--(.*?)-->', self.html_content, re.DOTALL)
                if comment.strip()
            ]
            js_comments = [
                comment.strip()
                for comment in re.findall(r'//.*?$|/\*.*?\*/', self.html_content, re.DOTALL | re.MULTILINE)
                if comment.strip()
            ]
            self.comments = html_comments + js_comments
            self.has_comment = bool(self.comments)

            if html_comments and js_comments:
                self.comment_type = "Has HTML + JS Comment"
            elif html_comments:
                self.comment_type = "Has HTML Comment"
            elif js_comments:
                self.comment_type = "Has JS Comment"

            for comment in self.comments:
                if not is_sensitive(comment):
                    continue
                self.sensitive_comments.append(comment)
                for match in SENSITIVE_PATTERN.finditer(comment):
                    key = match.group(1)
                    rest = comment[match.end():].lstrip()
                    value = ""
                    if rest:
                        if rest[0] in ('"', "'"):
                            end_index = rest.find(rest[0], 1)
                            if end_index != -1:
                                value = rest[1:end_index].strip()
                        else:
                            value_match = re.match(r"([^\s,<>'\"()\[\]{}]+)", rest)
                            if value_match:
                                value = value_match.group(1).strip()
                    if value:
                        self.sensitive_matches.append(f"{key}={value}")

            self.sensitive_comments = list(dict.fromkeys(self.sensitive_comments))
            self.sensitive_matches = list(dict.fromkeys(self.sensitive_matches))

            scan_pieces = [self.url, self.html_content]
            scan_pieces.extend(self.parameters)
            scan_pieces.extend(self.buttons)
            scan_pieces.extend(self.hidden_params)
            scan_text = "\n".join(str(piece) for piece in scan_pieces if piece)
            self.ip_matches = list(dict.fromkeys(IP_PATTERN.findall(scan_text)))
            version_scan_text = IP_PATTERN.sub('', scan_text)
            self.version_matches = list(dict.fromkeys(VERSION_PATTERN.findall(version_scan_text)))
        except (TypeError, ValueError, re.error) as error:
            if self.debug:
                print(f"[DEBUG] Comment analysis error for {self.url}: {error}")

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
    parser.add_option("--delay", dest="delay", type="float", default=0.1,
                     help="Delay before each request in seconds (default: 0.1)")
    parser.add_option("--timeout", dest="timeout", type="float", default=10.0,
                     help="Read timeout in seconds (default: 10)")
    parser.add_option("--retries", dest="retries", type="int", default=1,
                     help="Attempts per URL after timeout/network errors (default: 1)")
    parser.add_option("--no-https-fallback", dest="https_fallback", action="store_false",
                     default=True, help="Do not try HTTPS when an HTTP request fails")
    parser.add_option("--max-size", dest="max_size", type="float", default=1.0,
                     help="Maximum HTML response size in MiB (default: 1)")
    parser.add_option("-c", "--cookie", dest="cookie", default=None, metavar="COOKIE",
                     help="Cookie header for an authenticated session, "
                          "e.g. -c 'sessionid=abc; csrftoken=xyz'")
    parser.add_option("-A", "--auth", "--authorization", dest="authorization", default=None,
                     metavar="AUTH",
                     help="Authorization header value, e.g. -A 'Bearer eyJ...' "
                          "or -A 'Basic dXNlcjpwYXNz'")
    parser.add_option("-H", "--header", dest="headers", action="append", default=[],
                     metavar="HEADER",
                     help="Extra request header as 'Name: Value' (repeatable), "
                          "e.g. -H 'X-Api-Key: 123'")
    (options, _args) = parser.parse_args()

    if not math.isfinite(options.delay) or options.delay < 0:
        parser.error("--delay must be a finite number greater than or equal to 0")
    if not math.isfinite(options.timeout) or options.timeout <= 0:
        parser.error("--timeout must be a finite number greater than 0")
    if not math.isfinite(options.max_size) or options.max_size <= 0:
        parser.error("--max-size must be a finite number greater than 0")
    if options.threads <= 0:
        parser.error("--threads must be greater than 0")
    if options.retries <= 0:
        parser.error("--retries must be greater than 0")
    if options.max_urls is not None and options.max_urls <= 0:
        parser.error("--max-urls must be greater than 0")

    output_file = options.output
    json_file = options.json_output
    base_url = options.base_url
    max_urls = options.max_urls
    threads = options.threads
    crawl_subdomains = options.subdomains
    debug = options.debug
    delay = options.delay
    request_timeout = options.timeout
    request_retries = options.retries
    max_response_bytes = max(1024, int(options.max_size * 1024 * 1024))

    # Build authenticated-session headers from --cookie / --auth / --header
    extra_headers = {}
    if options.cookie:
        extra_headers['Cookie'] = options.cookie
    if options.authorization:
        extra_headers['Authorization'] = options.authorization
    for raw in options.headers:
        if ':' not in raw:
            parser.error(f"invalid --header '{raw}'. Use 'Name: Value' format.")
        name, value = raw.split(':', 1)
        name, value = name.strip(), value.strip()
        if not name:
            parser.error(f"invalid --header '{raw}'. Header name is empty.")
        extra_headers[name] = value

    # Validate required parameters
    if not base_url:
        print(Fore.RED + "Error: Base URL is required. Use -u or --url option.")
        print("Example: python paracrawler.py -u https://example.com")
        return

    print_color_legend()

    endpoints = []
    start_time = time.time()
    total_crawled = 0
    
    try:
        crawler = AdvancedCrawler(
            max_workers=threads,
            delay_range=(delay, delay),
            crawl_subdomains=crawl_subdomains,
            debug=debug,
            request_timeout=request_timeout,
            max_response_bytes=max_response_bytes,
            request_retries=request_retries,
            https_fallback=options.https_fallback,
            extra_headers=extra_headers or None,
        )
        if extra_headers:
            print(Fore.CYAN + f"[INFO] Authenticated session: sending {', '.join(sorted(extra_headers))} header(s)" + Style.RESET_ALL)
        
        # First pass: crawl all URLs.
        # A Ctrl+C here stops the crawl promptly but still falls through to the
        # summary and CSV/JSON output so partial results are never lost.
        crawl_generator = crawler.run_crawler(base_url, max_urls)
        try:
          for url in crawl_generator:
            status = crawler.url_status.get(url)
            # Skip 404 and other error status codes, only process successful ones
            if status and status >= 400:
                continue

            html_content = crawler.url_content_map.get(url)
            ep = None
            if html_content is not None and html_content != '':
                ep = Endpoint(url, html_content, debug=debug)
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
        except KeyboardInterrupt:
            # Stop the crawler cooperatively, then continue to reporting/output
            # below with whatever was collected so far.
            print("\n[!] Interrupt received - stopping crawl, writing results collected so far...")
            crawler.stop()
            crawl_generator.close()

        total_crawled = crawler.crawled_count
        
        # Summary output
        end_time = time.time()
        total_time = end_time - start_time

        print("["+ Fore.CYAN + "+", end="")
        print("]",end="")
        print(f"Out-of-scope links (not visited): {len(crawler.out_of_scope_links)} URLs.")
        for external_url in sorted(crawler.out_of_scope_links):
            print(Fore.LIGHTBLACK_EX + f"  {external_url}" + Style.RESET_ALL)

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
                    # Quote every field so spreadsheet importers never treat
                    # URL punctuation (especially the colon in http://) as a
                    # column separator.
                    writer = csv.writer(f, delimiter=',', quoting=csv.QUOTE_ALL)
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

                    # External links are discoveries only: they were never fetched.
                    if crawler.out_of_scope_links:
                        writer.writerow([])
                        writer.writerow(["Out-of-Scope Links (Not Visited):"])
                        for external_url in sorted(crawler.out_of_scope_links):
                            writer.writerow([external_url, "", "", "", "", "", "", "", ""])
                    
                    print(Fore.GREEN + f"\nSuccessfully wrote to {output_file}\n")
            except Exception as e:
                print(Fore.RED + f"\nError writing to CSV: {e!s}\n")

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
                    "out_of_scope_links_not_visited": sorted(crawler.out_of_scope_links) if crawler.out_of_scope_links else [],
                }

                with open(json_file, "w", encoding="utf-8-sig") as jf:  # utf-8-sig for better Arabic support
                    json.dump(data, jf, ensure_ascii=False, indent=2)

                print(Fore.GREEN + f"\nSuccessfully wrote JSON to {json_file}\n")
            except Exception as e:
                print(Fore.RED + f"\nError writing JSON: {e!s}\n")

    except KeyboardInterrupt:
        print("\n[!] Stopping...")
    except Exception as e:
        print(f"Main exception: {e}")

if __name__ == "__main__":
    main()
