#!/usr/bin/env python3
"""
Active Reconnaissance Tool v1.0
For authorized bug bounty testing only.
Author: Sebastian Rivera
"""

import sys
import os
import re
import json
import socket
import ssl
import time
import argparse
import threading
import hashlib
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, quote, unquote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from collections import deque

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] requests no instalado: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
except ImportError:
    dns = None


# =====================================================================
#  COLORES
# =====================================================================
class C:
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    C = "\033[96m"
    W = "\033[97m"
    D = "\033[90m"
    BOLD = "\033[1m"
    X = "\033[0m"

NO_COLOR = False

def log_info(msg):
    if NO_COLOR:
        print(f"  [*] {msg}")
    else:
        print(f"  {C.B}[*]{C.X} {msg}")

def log_ok(msg):
    if NO_COLOR:
        print(f"  [+] {msg}")
    else:
        print(f"  {C.G}[+]{C.X} {msg}")

def log_warn(msg):
    if NO_COLOR:
        print(f"  [!] {msg}")
    else:
        print(f"  {C.Y}[!]{C.X} {msg}")

def log_fail(msg):
    if NO_COLOR:
        print(f"  [-] {msg}")
    else:
        print(f"  {C.R}[-]{C.X} {msg}")

def log_vuln(severity, msg):
    colors = {"CRITICAL": C.R+C.BOLD, "HIGH": C.R, "MEDIUM": C.Y, "LOW": C.B, "INFO": C.D}
    color = colors.get(severity, C.W)
    if NO_COLOR:
        print(f"  [{severity}] {msg}")
    else:
        print(f"  {color}[{severity}]{C.X} {msg}")

def banner():
    b = f"""
{C.R}{C.BOLD}    ╔══════════════════════════════════════════╗
    ║     ACTIVE RECON TOOL v1.0               ║
    ║     Bug Bounty Edition                   ║
    ╚══════════════════════════════════════════╝{C.X}
"""
    if NO_COLOR:
        b = """
    ╔══════════════════════════════════════════╗
    ║     ACTIVE RECON TOOL v1.0               ║
    ║     Bug Bounty Edition                   ║
    ╚══════════════════════════════════════════╝
"""
    print(b)


# =====================================================================
#  DISCLAIMER LEGAL
# =====================================================================
def show_disclaimer():
    """Muestra advertencia legal antes de ejecutar."""
    disclaimer = f"""
{C.R}{C.BOLD}╔══════════════════════════════════════════════════════════════╗
║                    ADVERTENCIA LEGAL                         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Esta herramienta realiza reconocimiento ACTIVO.              ║
║  Envia paquetes, solicitudes y payloads al objetivo.         ║
║                                                              ║
║  SOLO debe usarse contra targets para los cuales             ║
║  tienes AUTORIZACION EXPLICITA Y POR ESCRITO.                ║
║                                                              ║
║  Esto incluye:                                               ║
║    - Programas de bug bounty donde el target esta en scope   ║
║    - Servidores y aplicaciones propias                        ║
║    - Entornos de laboratorio / CTF                           ║
║    - Pentests con contrato firmado                            ║
║                                                              ║
║  El uso no autorizado es ILEGAL y puede resultar en          ║
║  consecuencias legales graves.                               ║
║                                                              ║
║  El autor no se hace responsable del mal uso de esta         ║
║  herramienta. USALA BAJO TU PROPIA RESPONSABILIDAD.          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{C.X}
"""
    if NO_COLOR:
        disclaimer = disclaimer.replace(C.R+C.BOLD, "").replace(C.X, "")
    print(disclaimer)

    try:
        resp = input(f"  {C.Y}[?]{C.X} Tienes autorizacion para escanear este target? (s/n): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(0)

    if resp not in ("s", "si", "y", "yes"):
        print(f"\n  {C.R}[!] Operacion cancelada. No se realizaron escaneos.{C.X}")
        sys.exit(0)
    print()


# =====================================================================
#  RATE LIMITER
# =====================================================================
class RateLimiter:
    """Controla la velocidad de requests."""
    def __init__(self, max_rps=0):
        self.max_rps = max_rps
        self.last_request = 0
        self.lock = threading.Lock()
        self.request_count = 0

    def wait(self):
        if self.max_rps <= 0:
            with self.lock:
                self.request_count += 1
            return
        with self.lock:
            now = time.time()
            min_interval = 1.0 / self.max_rps
            elapsed = now - self.last_request
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            self.last_request = time.time()
            self.request_count += 1


# =====================================================================
#  UTILIDADES
# =====================================================================
def create_session(user_agent=None, proxy=None, cookies=None, headers=None, timeout=10):
    """Crea session HTTP configurada."""
    s = requests.Session()
    s.verify = False
    s.timeout = timeout
    s.headers["User-Agent"] = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    if cookies:
        for ck in cookies.split(";"):
            if "=" in ck:
                k, v = ck.strip().split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    if headers:
        for h in headers.split(";;"):
            if ":" in h:
                k, v = h.strip().split(":", 1)
                s.headers[k.strip()] = v.strip()
    return s

def safe_request(session, method, url, rate_limiter=None, **kwargs):
    """Request con error handling y rate limiting."""
    if rate_limiter:
        rate_limiter.wait()
    try:
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        resp = session.request(method, url, **kwargs)
        return resp
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.TooManyRedirects:
        return None
    except Exception:
        return None

def get_domain(url):
    """Extrae dominio de URL."""
    return urlparse(url).hostname or ""

def get_base_url(url):
    """Normaliza base URL."""
    p = urlparse(url)
    scheme = p.scheme or "https"
    host = p.hostname or ""
    port = p.port
    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"

def resolve_host(hostname):
    """Resuelve hostname a IP."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def section_header(title):
    """Imprime header de seccion."""
    if NO_COLOR:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    else:
        print(f"\n{C.C}{'='*60}{C.X}")
        print(f"  {C.BOLD}{C.C}{title}{C.X}")
        print(f"{C.C}{'='*60}{C.X}")


# =====================================================================
#  WORDLISTS INTEGRADAS
# =====================================================================
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 515, 587, 631, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
    2049, 2082, 2083, 2086, 2087, 2096, 2181, 3000, 3001, 3128, 3268, 3306,
    3389, 3690, 4443, 4848, 5000, 5001, 5432, 5555, 5601, 5672, 5900, 5985,
    5986, 6000, 6379, 6443, 6666, 7001, 7002, 7070, 7443, 8000, 8001, 8008,
    8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8088, 8090, 8091, 8181, 8443, 8444, 8800, 8880, 8888, 8983, 9000,
    9001, 9042, 9043, 9060, 9080, 9090, 9091, 9200, 9300, 9443, 9999, 10000,
    11211, 15672, 27017, 27018, 28017, 50000, 50070
]

DIR_WORDLIST = [
    "admin", "administrator", "admin.php", "admin.html", "admin/login",
    "login", "login.php", "signin", "auth", "authenticate",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "api", "api/v1", "api/v2", "api/v3", "api/docs", "api/swagger",
    "swagger", "swagger-ui", "swagger.json", "swagger.yaml",
    "graphql", "graphiql", "graphql/console",
    "console", "dashboard", "panel", "portal", "manager",
    "config", "config.php", "config.yml", "config.json", "config.xml",
    "configuration", "settings", "setup", "install", "installer",
    ".env", ".env.bak", ".env.local", ".env.production", ".env.development",
    ".git", ".git/config", ".git/HEAD", ".gitignore",
    ".svn", ".svn/entries", ".hg",
    ".htaccess", ".htpasswd", "web.config", "nginx.conf",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
    "security.txt", ".well-known/security.txt",
    "backup", "backup.sql", "backup.zip", "backup.tar.gz", "backup.bak",
    "db", "database", "database.sql", "dump", "dump.sql",
    "test", "testing", "test.php", "test.html", "debug",
    "debug.php", "info.php", "phpinfo.php", "info", "server-info",
    "server-status", "status", "health", "healthcheck",
    "uploads", "upload", "files", "media", "images", "assets", "static",
    "tmp", "temp", "cache", "log", "logs", "error.log", "access.log",
    "private", "secret", "internal", "restricted", "confidential",
    "cgi-bin", "cgi", "scripts", "bin",
    "phpmyadmin", "pma", "phpMyAdmin", "myadmin",
    "adminer", "adminer.php",
    "webmail", "mail", "email", "roundcube",
    "cpanel", "whm", "plesk",
    "jenkins", "hudson", "bamboo", "travis",
    "jira", "confluence", "bitbucket",
    "gitlab", "git", "redmine", "bugzilla",
    "nagios", "zabbix", "grafana", "prometheus", "kibana",
    "solr", "elasticsearch", "sphinx",
    "tomcat", "manager/html", "host-manager",
    "jmx-console", "web-console", "invoker",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "actuator/mappings", "actuator/configprops", "actuator/trace",
    "metrics", "monitoring",
    "node_modules", "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock", "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile", "Pipfile.lock",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "Makefile", "Rakefile", "Gruntfile.js", "gulpfile.js", "webpack.config.js",
    "readme", "README.md", "README.txt", "CHANGELOG", "CHANGELOG.md",
    "LICENSE", "CONTRIBUTING.md",
    "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
    "xmlrpc.php", "wp-cron.php",
    "user", "users", "accounts", "account", "profile", "profiles",
    "register", "signup", "registration",
    "password", "forgot", "reset", "recover",
    "logout", "signout", "exit",
    "search", "find", "query",
    "download", "downloads", "export",
    "reports", "report", "analytics",
    "docs", "documentation", "doc", "help", "faq", "support",
    "about", "contact", "terms", "privacy", "policy",
    "old", "legacy", "archive", "archived",
    "dev", "development", "staging", "stage", "beta", "alpha",
    "sandbox", "demo", "preview",
    "v1", "v2", "version", "latest",
    "proxy", "gateway", "redirect",
    "socket.io", "sockjs", "ws", "websocket",
    "feed", "rss", "atom",
    "oauth", "oauth2", "sso", "saml", "callback",
    "token", "tokens", "session", "sessions",
    "cron", "jobs", "queue", "worker", "workers",
    ".DS_Store", "Thumbs.db", "desktop.ini",
    "error", "404", "500", "403",
    "trace.axd", "elmah.axd",
    "server", "services", "service",
    "include", "includes", "inc",
    "lib", "libs", "library",
    "src", "source", "app",
    "vendor", "third-party", "external",
    "data", "db.sqlite", "db.sqlite3",
    "wp-json/wp/v2/users",
    ".well-known/openid-configuration",
    "realms", "auth/realms",
]

SUB_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "administrator", "panel", "cpanel", "whm",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "api", "api2", "apis", "rest", "graphql",
    "dev", "development", "staging", "stage", "test", "testing",
    "beta", "alpha", "demo", "sandbox", "preview",
    "prod", "production", "live",
    "app", "apps", "application", "mobile", "m",
    "portal", "gateway", "proxy", "vpn", "remote",
    "cdn", "static", "assets", "media", "images", "img",
    "docs", "doc", "documentation", "wiki", "help", "support",
    "blog", "news", "press", "forum", "community",
    "shop", "store", "ecommerce", "cart", "checkout",
    "git", "gitlab", "github", "bitbucket", "svn", "repo",
    "jenkins", "ci", "cd", "build", "deploy",
    "jira", "confluence", "redmine", "bugzilla", "issues",
    "monitor", "monitoring", "grafana", "prometheus", "nagios", "zabbix",
    "elk", "kibana", "elasticsearch", "logstash",
    "db", "database", "mysql", "postgres", "mongo", "redis", "memcached",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "private", "corp", "corporate",
    "sso", "auth", "login", "id", "identity", "oauth",
    "email", "mx", "relay", "exchange",
    "s3", "storage", "files", "upload", "downloads",
    "status", "health", "uptime",
    "calendar", "meet", "chat", "slack", "teams",
    "crm", "erp", "hr", "finance",
    "analytics", "metrics", "stats", "reports",
    "web", "www2", "www3", "web1", "web2",
    "host", "server", "node", "cluster",
    "edge", "lb", "loadbalancer",
    "cache", "varnish", "nginx",
    "queue", "rabbit", "kafka", "mq",
    "search", "solr", "elastic",
    "payments", "pay", "billing", "invoice",
    "secure", "ssl", "tls",
    "stg", "uat", "qa", "preprod", "pre-prod",
    "v1", "v2", "api-v1", "api-v2",
]

PARAM_WORDLIST = [
    "id", "page", "file", "path", "dir", "search", "q", "query", "s",
    "url", "uri", "redirect", "return", "next", "goto", "target", "dest",
    "rurl", "return_url", "redirect_url", "callback", "continue",
    "user", "username", "email", "name", "login", "password",
    "token", "key", "api_key", "apikey", "secret", "session",
    "cmd", "command", "exec", "run", "action", "do",
    "cat", "category", "type", "sort", "order", "limit", "offset",
    "lang", "language", "locale", "country",
    "template", "theme", "view", "layout", "module", "plugin",
    "include", "require", "load", "read", "fetch", "get",
    "format", "output", "export", "download",
    "debug", "test", "verbose", "mode",
    "admin", "role", "level", "access", "permission",
    "filter", "where", "select", "from", "table",
    "host", "port", "server", "domain", "ip",
    "config", "setting", "option", "param", "data", "input", "value",
]

API_WORDLIST = [
    "api", "api/v1", "api/v2", "api/v3",
    "api/users", "api/user", "api/me", "api/profile",
    "api/admin", "api/config", "api/settings",
    "api/auth", "api/login", "api/register", "api/token",
    "api/search", "api/query",
    "api/upload", "api/files", "api/download",
    "api/health", "api/status", "api/version", "api/info",
    "api/docs", "api/swagger", "api/openapi",
    "api/graphql", "api/rest",
    "api/internal", "api/private", "api/debug",
    "api/test", "api/dev",
    "rest/api", "rest/v1", "rest/v2",
    "v1", "v2", "v3",
    "api/products", "api/orders", "api/items",
    "api/comments", "api/posts", "api/pages",
    "api/notifications", "api/messages",
    "api/roles", "api/permissions",
    "api/keys", "api/tokens", "api/sessions",
    "api/logs", "api/events", "api/audit",
    "api/export", "api/import", "api/backup",
    "_api", "__api", "api_v1", "api_v2",
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", "12345"), ("admin", "1234"),
    ("administrator", "administrator"), ("root", "root"),
    ("root", "toor"), ("root", "password"), ("root", "123456"),
    ("test", "test"), ("guest", "guest"), ("user", "user"),
    ("demo", "demo"), ("admin", "changeme"), ("admin", "default"),
    ("admin", "pass"), ("admin", "letmein"), ("tomcat", "tomcat"),
    ("manager", "manager"), ("admin", "P@ssw0rd"), ("admin", "qwerty"),
]


# =====================================================================
#  MODULE 1: PORT SCANNER
# =====================================================================
def mod_port_scan(target_host, ports, threads, timeout, rate_limiter, results):
    """Escaneo de puertos TCP connect."""
    section_header("PORT SCANNER")
    log_info(f"Escaneando {len(ports)} puertos en {target_host}...")

    open_ports = []
    closed = 0
    filtered = 0

    def scan_port(port):
        if rate_limiter:
            rate_limiter.wait()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target_host, port))
            if result == 0:
                return ("open", port)
            else:
                return ("closed", port)
        except socket.timeout:
            return ("filtered", port)
        except Exception:
            return ("error", port)
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, p): p for p in ports}
        for future in as_completed(futures):
            status, port = future.result()
            if status == "open":
                open_ports.append(port)
                log_ok(f"Puerto {port}/tcp ABIERTO")
            elif status == "filtered":
                filtered += 1
            else:
                closed += 1

    open_ports.sort()
    results["open_ports"] = open_ports
    log_info(f"Resultados: {len(open_ports)} abiertos, {closed} cerrados, {filtered} filtrados")


# =====================================================================
#  MODULE 2: SERVICE DETECTION
# =====================================================================
def mod_service_detect(target_host, open_ports, timeout, results):
    """Banner grabbing en puertos abiertos."""
    section_header("SERVICE DETECTION")

    if not open_ports:
        log_info("No hay puertos abiertos para analizar.")
        return

    services = []
    common_services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
        8443: "HTTPS-Alt", 27017: "MongoDB", 11211: "Memcached",
    }

    for port in open_ports:
        banner = ""
        service_name = common_services.get(port, "Unknown")

        # Try banner grab
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_host, port))

            # For SSL ports, wrap in SSL
            if port in (443, 8443, 993, 995, 465, 636):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=target_host)

            # Send probe for HTTP ports
            if port in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 8008, 9090):
                sock.send(f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())

            sock.settimeout(3)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
        except Exception:
            pass

        # Extract service info from banner
        if banner:
            # HTTP Server header
            srv_match = re.search(r'Server:\s*(.+)', banner, re.I)
            if srv_match:
                service_name = srv_match.group(1).strip()
            elif "SSH" in banner:
                service_name = banner.split("\n")[0].strip()
            elif "FTP" in banner:
                service_name = banner.split("\n")[0].strip()
            elif "SMTP" in banner:
                service_name = banner.split("\n")[0].strip()

        services.append({
            "port": port,
            "service": service_name,
            "banner": banner[:200] if banner else "",
        })
        log_ok(f"{port}/tcp -> {service_name}")

    results["services"] = services


# =====================================================================
#  MODULE 3: DIRECTORY BRUTEFORCE
# =====================================================================
def mod_dir_bruteforce(session, base_url, wordlist, threads, extensions, rate_limiter, results):
    """Descubrimiento de directorios y archivos."""
    section_header("DIRECTORY BRUTEFORCE")

    found = []
    total = len(wordlist)
    checked = [0]
    lock = threading.Lock()

    # Build URL list with extensions
    urls_to_check = []
    for word in wordlist:
        urls_to_check.append(f"{base_url}/{word}")
        for ext in extensions:
            urls_to_check.append(f"{base_url}/{word}.{ext}")

    log_info(f"Probando {len(urls_to_check)} paths...")

    def check_path(url):
        resp = safe_request(session, "GET", url, rate_limiter)
        with lock:
            checked[0] += 1
            if checked[0] % 100 == 0:
                log_info(f"Progreso: {checked[0]}/{len(urls_to_check)}")

        if resp is None:
            return None

        if resp.status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403, 405):
            size = len(resp.content)
            return {
                "url": url,
                "status": resp.status_code,
                "size": size,
                "redirect": resp.headers.get("Location", "") if resp.status_code in (301, 302, 307, 308) else "",
            }
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, u): u for u in urls_to_check}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                status = result["status"]
                url = result["url"]
                size = result["size"]
                redir = result.get("redirect", "")

                if status == 200:
                    log_ok(f"[{status}] {url} ({size} bytes)")
                elif status in (301, 302, 307, 308):
                    log_ok(f"[{status}] {url} -> {redir}")
                elif status == 401:
                    log_warn(f"[{status}] {url} (Auth Required)")
                elif status == 403:
                    log_warn(f"[{status}] {url} (Forbidden)")
                else:
                    log_info(f"[{status}] {url}")

    results["directories"] = sorted(found, key=lambda x: x["status"])
    log_info(f"Encontrados: {len(found)} paths")


# =====================================================================
#  MODULE 4: SUBDOMAIN BRUTEFORCE
# =====================================================================
def mod_subdomain_brute(domain, wordlist, threads, rate_limiter, results):
    """Enumeracion de subdominios via DNS."""
    section_header("SUBDOMAIN BRUTEFORCE")

    if not dns:
        log_fail("dnspython no disponible. Instalar: pip install dnspython")
        return

    found = []
    log_info(f"Probando {len(wordlist)} subdominios de {domain}...")

    def check_sub(sub):
        if rate_limiter:
            rate_limiter.wait()
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            return {"subdomain": fqdn, "ips": ips}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_sub, s): s for s in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                log_ok(f"{result['subdomain']} -> {', '.join(result['ips'])}")

    results["subdomains_brute"] = found
    log_info(f"Encontrados: {len(found)} subdominios")


# =====================================================================
#  MODULE 5: DNS ZONE TRANSFER
# =====================================================================
def mod_dns_zone_transfer(domain, results):
    """Intento de transferencia de zona DNS (AXFR)."""
    section_header("DNS ZONE TRANSFER")

    if not dns:
        log_fail("dnspython no disponible.")
        return

    results["zone_transfer"] = []

    try:
        ns_records = dns.resolver.resolve(domain, "NS")
    except Exception:
        log_fail("No se pudieron obtener nameservers.")
        return

    for ns in ns_records:
        ns_host = str(ns).rstrip(".")
        log_info(f"Intentando AXFR en {ns_host}...")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=10))
            records = []
            for name, node in zone.nodes.items():
                records.append(str(name))
            results["zone_transfer"].append({
                "nameserver": ns_host,
                "success": True,
                "records": records[:100],
            })
            log_vuln("HIGH", f"Zone transfer EXITOSO en {ns_host}! {len(records)} records.")
        except Exception:
            log_info(f"Zone transfer denegado en {ns_host} (esperado).")


# =====================================================================
#  MODULE 6: VIRTUAL HOST DISCOVERY
# =====================================================================
def mod_vhost_discover(session, target_ip, base_url, domain, wordlist, rate_limiter, results):
    """Descubrimiento de virtual hosts."""
    section_header("VIRTUAL HOST DISCOVERY")

    found = []
    parsed = urlparse(base_url)
    scheme = parsed.scheme
    port = parsed.port or (443 if scheme == "https" else 80)

    # Get baseline response
    baseline = safe_request(session, "GET", base_url, rate_limiter)
    if not baseline:
        log_fail("No se pudo obtener respuesta baseline.")
        return
    baseline_size = len(baseline.content)
    baseline_code = baseline.status_code

    log_info(f"Baseline: [{baseline_code}] {baseline_size} bytes")
    log_info(f"Probando {len(wordlist)} vhosts...")

    for vhost_prefix in wordlist:
        vhost = f"{vhost_prefix}.{domain}"
        try:
            resp = safe_request(session, "GET", f"{scheme}://{target_ip}:{port}/",
                               rate_limiter,
                               headers={"Host": vhost},
                               timeout=5)
            if resp is None:
                continue

            resp_size = len(resp.content)
            # Different response = potential vhost
            if resp.status_code != baseline_code or abs(resp_size - baseline_size) > 100:
                found.append({
                    "vhost": vhost,
                    "status": resp.status_code,
                    "size": resp_size,
                })
                log_ok(f"[{resp.status_code}] {vhost} ({resp_size} bytes)")
        except Exception:
            pass

    results["vhosts"] = found
    log_info(f"Encontrados: {len(found)} virtual hosts potenciales")


# =====================================================================
#  MODULE 7: WEB CRAWLER
# =====================================================================
class LinkParser(HTMLParser):
    """Extrae links y forms de HTML."""
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self._current_form = None
        self._current_inputs = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a":
            href = attrs_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full = urljoin(self.base_url, href)
                self.links.add(full)
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "GET").upper(),
            }
            self._current_inputs = []
        elif tag == "input" and self._current_form is not None:
            self._current_inputs.append({
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            })
        elif tag in ("textarea", "select") and self._current_form is not None:
            self._current_inputs.append({
                "name": attrs_dict.get("name", ""),
                "type": tag,
                "value": "",
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self._current_form["inputs"] = [i for i in self._current_inputs if i.get("name")]
            self.forms.append(self._current_form)
            self._current_form = None
            self._current_inputs = []


def mod_crawl(session, base_url, max_depth, max_pages, rate_limiter, results):
    """Spider/crawl del sitio."""
    section_header("WEB CRAWLER")

    domain = get_domain(base_url)
    visited = set()
    to_visit = deque([(base_url, 0)])
    all_links = set()
    all_forms = []
    all_params = set()
    all_emails = set()
    all_js_files = set()

    log_info(f"Crawling {base_url} (max depth: {max_depth}, max pages: {max_pages})...")

    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.popleft()

        # Normalize
        url = url.split("#")[0]
        if url in visited:
            continue
        if depth > max_depth:
            continue

        # Stay in scope
        if get_domain(url) != domain:
            all_links.add(url)
            continue

        visited.add(url)
        resp = safe_request(session, "GET", url, rate_limiter, allow_redirects=True)
        if resp is None:
            continue

        ct = resp.headers.get("content-type", "")
        if "html" not in ct.lower() and "text" not in ct.lower():
            continue

        html = resp.text

        # Parse links and forms
        try:
            parser = LinkParser(url)
            parser.feed(html)

            for link in parser.links:
                all_links.add(link)
                if get_domain(link) == domain and link not in visited:
                    to_visit.append((link, depth + 1))

            for form in parser.forms:
                all_forms.append(form)

        except Exception:
            pass

        # Extract URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for p in params:
            all_params.add(p)

        # Extract JS files
        js_matches = re.findall(r'src=["\']([^"\']*\.js[^"\']*)', html, re.I)
        for js in js_matches:
            full_js = urljoin(url, js)
            all_js_files.add(full_js)

        # Extract emails
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', html)
        for e in emails:
            all_emails.add(e)

    results["crawl"] = {
        "pages_visited": len(visited),
        "links_found": len(all_links),
        "forms": all_forms,
        "params": list(all_params),
        "js_files": list(all_js_files),
        "emails": list(all_emails),
        "visited_urls": list(visited),
    }

    log_ok(f"Paginas visitadas: {len(visited)}")
    log_ok(f"Links encontrados: {len(all_links)}")
    log_ok(f"Formularios: {len(all_forms)}")
    log_ok(f"Parametros URL: {len(all_params)}")
    log_ok(f"Archivos JS: {len(all_js_files)}")
    if all_emails:
        log_ok(f"Emails: {', '.join(list(all_emails)[:10])}")
    if all_forms:
        for f in all_forms[:5]:
            inputs = ", ".join([i["name"] for i in f.get("inputs", [])])
            log_info(f"  Form: {f['method']} {f['action']} [{inputs}]")


# =====================================================================
#  MODULE 8: PARAMETER DISCOVERY
# =====================================================================
def mod_param_discover(session, base_url, wordlist, rate_limiter, results):
    """Descubrimiento de parametros ocultos."""
    section_header("PARAMETER DISCOVERY")

    found_params = []

    # Get baseline
    baseline = safe_request(session, "GET", base_url, rate_limiter, allow_redirects=True)
    if not baseline:
        log_fail("No se pudo obtener respuesta baseline.")
        return
    baseline_size = len(baseline.content)
    baseline_code = baseline.status_code

    log_info(f"Baseline: [{baseline_code}] {baseline_size} bytes")
    log_info(f"Probando {len(wordlist)} parametros...")

    for param in wordlist:
        test_value = "active_recon_test_123"
        test_url = f"{base_url}?{param}={test_value}"
        resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
        if resp is None:
            continue

        resp_size = len(resp.content)
        # Check if param is reflected or changes response
        reflected = test_value in resp.text
        size_diff = abs(resp_size - baseline_size)
        code_diff = resp.status_code != baseline_code

        if reflected or size_diff > 50 or code_diff:
            found_params.append({
                "param": param,
                "reflected": reflected,
                "status": resp.status_code,
                "size_diff": size_diff,
            })
            marker = " [REFLECTED]" if reflected else ""
            log_ok(f"Param: {param} [{resp.status_code}] (diff: {size_diff} bytes){marker}")

    results["params_discovered"] = found_params
    log_info(f"Parametros encontrados: {len(found_params)}")


# =====================================================================
#  MODULE 9: TECHNOLOGY FINGERPRINT (ACTIVE)
# =====================================================================
def mod_tech_fingerprint(session, base_url, rate_limiter, results):
    """Fingerprinting activo de tecnologias."""
    section_header("TECHNOLOGY FINGERPRINT (ACTIVE)")

    techs = []

    # Probe specific paths for tech detection
    tech_probes = [
        ("/wp-login.php", "WordPress"),
        ("/wp-admin/", "WordPress"),
        ("/wp-json/wp/v2/", "WordPress REST API"),
        ("/administrator/", "Joomla"),
        ("/user/login", "Drupal"),
        ("/core/install.php", "Drupal"),
        ("/misc/drupal.js", "Drupal"),
        ("/typo3/", "TYPO3"),
        ("/umbraco/", "Umbraco"),
        ("/sitecore/", "Sitecore"),
        ("/sitefinity/", "Sitefinity"),
        ("/rails/info", "Ruby on Rails"),
        ("/elmah.axd", "ASP.NET ELMAH"),
        ("/trace.axd", "ASP.NET Trace"),
        ("/actuator", "Spring Boot"),
        ("/actuator/health", "Spring Boot Actuator"),
        ("/swagger-ui.html", "Swagger UI"),
        ("/api-docs", "Swagger/OpenAPI"),
        ("/graphql", "GraphQL"),
        ("/graphiql", "GraphiQL"),
        ("/_next/", "Next.js"),
        ("/__nuxt/", "Nuxt.js"),
        ("/static/admin/", "Django Admin"),
        ("/flask-static/", "Flask"),
        ("/laravel/", "Laravel"),
        ("/vendor/laravel/", "Laravel"),
        ("/artisan", "Laravel"),
        ("/telescope/", "Laravel Telescope"),
        ("/horizon/", "Laravel Horizon"),
        ("/nova/", "Laravel Nova"),
        ("/phpmyadmin/", "phpMyAdmin"),
        ("/adminer.php", "Adminer"),
        ("/solr/", "Apache Solr"),
        ("/kibana/", "Kibana"),
        ("/grafana/", "Grafana"),
        ("/jenkins/", "Jenkins"),
        ("/gitlab/", "GitLab"),
    ]

    for path, tech in tech_probes:
        resp = safe_request(session, "GET", f"{base_url}{path}", rate_limiter, timeout=5)
        if resp and resp.status_code in (200, 301, 302, 401, 403):
            techs.append({
                "technology": tech,
                "path": path,
                "status": resp.status_code,
            })
            log_ok(f"{tech} detectado en {path} [{resp.status_code}]")

    # Check response headers
    resp = safe_request(session, "GET", base_url, rate_limiter, allow_redirects=True)
    if resp:
        h = resp.headers
        header_checks = {
            "x-powered-by": "X-Powered-By",
            "server": "Server",
            "x-aspnet-version": "ASP.NET",
            "x-aspnetmvc-version": "ASP.NET MVC",
            "x-drupal-cache": "Drupal",
            "x-generator": "Generator",
            "x-powered-cms": "CMS",
        }
        for hdr, label in header_checks.items():
            val = h.get(hdr, "")
            if val:
                techs.append({"technology": f"{label}: {val}", "path": "/", "status": 200})
                log_ok(f"{label}: {val}")

    results["tech_active"] = techs


# =====================================================================
#  MODULE 10: WAF DETECTION
# =====================================================================
def mod_waf_detect(session, base_url, rate_limiter, results):
    """Deteccion y fingerprinting de WAF."""
    section_header("WAF DETECTION")

    waf_detected = []

    # Test with malicious payloads to trigger WAF
    payloads = [
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "{{7*7}}",
        "${7*7}",
        "| ls",
    ]

    baseline = safe_request(session, "GET", base_url, rate_limiter, allow_redirects=True)
    baseline_code = baseline.status_code if baseline else 200

    for payload in payloads:
        test_url = f"{base_url}/?test={quote(payload)}"
        resp = safe_request(session, "GET", test_url, rate_limiter)
        if resp is None:
            continue

        # Check for WAF indicators
        body = resp.text.lower()
        headers_str = str(resp.headers).lower()

        waf_sigs = {
            "Cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-cache"],
            "AWS WAF": ["awselb", "x-amzn-", "awswaf"],
            "Akamai": ["akamai", "akamaighost", "x-akamai"],
            "Imperva/Incapsula": ["incapsula", "imperva", "visid_incap"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "ModSecurity": ["modsecurity", "mod_security", "noyb"],
            "F5 BIG-IP": ["big-ip", "f5", "ts=", "bigipserver"],
            "Barracuda": ["barracuda", "barra_counter"],
            "Fortinet/FortiWeb": ["fortigate", "fortiweb", "fortibalancer"],
            "Citrix NetScaler": ["citrix", "netscaler", "ns_af"],
            "DenyAll": ["denyall", "conditionblocked"],
            "StackPath": ["stackpath"],
            "Fastly": ["fastly"],
        }

        for waf_name, sigs in waf_sigs.items():
            for sig in sigs:
                if sig in body or sig in headers_str:
                    if waf_name not in [w["waf"] for w in waf_detected]:
                        waf_detected.append({"waf": waf_name, "indicator": sig})
                        log_ok(f"WAF detectado: {waf_name} (indicator: {sig})")
                    break

        # Generic block detection
        if resp.status_code in (403, 406, 429, 503) and resp.status_code != baseline_code:
            if not waf_detected:
                waf_detected.append({"waf": "Unknown WAF", "indicator": f"HTTP {resp.status_code} on payload"})
                log_warn(f"WAF generico detectado (HTTP {resp.status_code} en payload)")

    if not waf_detected:
        log_info("No se detecto WAF.")

    results["waf_active"] = waf_detected


# =====================================================================
#  MODULE 11: CMS ENUMERATION
# =====================================================================
def mod_cms_enum(session, base_url, rate_limiter, results):
    """Enumeracion detallada de CMS."""
    section_header("CMS ENUMERATION")

    cms_info = {"cms": None, "details": []}

    # WordPress enumeration
    wp_check = safe_request(session, "GET", f"{base_url}/wp-login.php", rate_limiter)
    if wp_check and wp_check.status_code == 200 and "wp-login" in wp_check.text.lower():
        cms_info["cms"] = "WordPress"
        log_ok("CMS: WordPress detectado")

        # WP Version
        resp = safe_request(session, "GET", f"{base_url}/readme.html", rate_limiter)
        if resp and resp.status_code == 200:
            ver = re.search(r'Version\s+([\d.]+)', resp.text)
            if ver:
                cms_info["details"].append(f"Version: {ver.group(1)}")
                log_ok(f"  WordPress version: {ver.group(1)}")

        # WP Users via REST API
        resp = safe_request(session, "GET", f"{base_url}/wp-json/wp/v2/users", rate_limiter, allow_redirects=True)
        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list):
                    for u in users[:10]:
                        name = u.get("name", "") or u.get("slug", "")
                        cms_info["details"].append(f"User: {name}")
                        log_ok(f"  User: {name}")
            except Exception:
                pass

        # WP Users via author enumeration
        for i in range(1, 11):
            resp = safe_request(session, "GET", f"{base_url}/?author={i}", rate_limiter, allow_redirects=True)
            if resp and resp.status_code == 200:
                author = re.search(r'/author/([^/"]+)', resp.url)
                if author:
                    user = author.group(1)
                    if f"User: {user}" not in str(cms_info["details"]):
                        cms_info["details"].append(f"User (enum): {user}")
                        log_ok(f"  User (author enum): {user}")

        # WP Plugins
        resp = safe_request(session, "GET", base_url, rate_limiter, allow_redirects=True)
        if resp:
            plugins = set(re.findall(r'/wp-content/plugins/([^/"\s]+)', resp.text))
            for p in list(plugins)[:20]:
                cms_info["details"].append(f"Plugin: {p}")
                log_ok(f"  Plugin: {p}")

            themes = set(re.findall(r'/wp-content/themes/([^/"\s]+)', resp.text))
            for t in themes:
                cms_info["details"].append(f"Theme: {t}")
                log_ok(f"  Theme: {t}")

        # XMLRPC
        resp = safe_request(session, "POST", f"{base_url}/xmlrpc.php", rate_limiter,
                           data="<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                           headers={"Content-Type": "text/xml"})
        if resp and resp.status_code == 200 and "methodResponse" in resp.text:
            cms_info["details"].append("XMLRPC: enabled")
            log_warn("  XMLRPC habilitado (posible bruteforce vector)")

    # Joomla
    joomla_check = safe_request(session, "GET", f"{base_url}/administrator/", rate_limiter)
    if joomla_check and joomla_check.status_code == 200 and "joomla" in joomla_check.text.lower():
        cms_info["cms"] = "Joomla"
        log_ok("CMS: Joomla detectado")

        # Version
        manifest = safe_request(session, "GET", f"{base_url}/administrator/manifests/files/joomla.xml", rate_limiter)
        if manifest and manifest.status_code == 200:
            ver = re.search(r'<version>([^<]+)', manifest.text)
            if ver:
                cms_info["details"].append(f"Version: {ver.group(1)}")
                log_ok(f"  Joomla version: {ver.group(1)}")

    # Drupal
    drupal_check = safe_request(session, "GET", f"{base_url}/core/install.php", rate_limiter)
    if drupal_check and drupal_check.status_code == 200:
        cms_info["cms"] = "Drupal"
        log_ok("CMS: Drupal detectado")

        changelog = safe_request(session, "GET", f"{base_url}/CHANGELOG.txt", rate_limiter)
        if changelog and changelog.status_code == 200:
            ver = re.search(r'Drupal\s+([\d.]+)', changelog.text)
            if ver:
                cms_info["details"].append(f"Version: {ver.group(1)}")
                log_ok(f"  Drupal version: {ver.group(1)}")

    if not cms_info["cms"]:
        log_info("No se identifico CMS conocido.")

    results["cms_active"] = cms_info


# =====================================================================
#  MODULE 12: SSL/TLS AUDIT
# =====================================================================
def mod_ssl_audit(target_host, target_port, results):
    """Auditoria de SSL/TLS."""
    section_header("SSL/TLS AUDIT")

    ssl_info = {"issues": []}

    # Test various protocols
    protocols = [
        ("TLSv1.0", ssl.PROTOCOL_TLS),
        ("TLSv1.1", ssl.PROTOCOL_TLS),
        ("TLSv1.2", ssl.PROTOCOL_TLS),
    ]

    # Test connection and get cert info
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = ctx.wrap_socket(socket.socket(), server_hostname=target_host)
        conn.settimeout(10)
        conn.connect((target_host, target_port))

        cert = conn.getpeercert(binary_form=True)
        cipher = conn.cipher()
        version = conn.version()

        log_ok(f"Protocol: {version}")
        log_ok(f"Cipher: {cipher[0] if cipher else 'Unknown'}")

        ssl_info["protocol"] = version
        ssl_info["cipher"] = cipher[0] if cipher else ""

        # Parse cert
        import ssl as ssl_mod
        cert_dict = conn.getpeercert()
        if cert_dict:
            subject = dict(x[0] for x in cert_dict.get("subject", []))
            issuer = dict(x[0] for x in cert_dict.get("issuer", []))
            not_after = cert_dict.get("notAfter", "")

            log_ok(f"Subject: {subject.get('commonName', 'N/A')}")
            log_ok(f"Issuer: {issuer.get('organizationName', 'N/A')}")
            log_ok(f"Expires: {not_after}")

            ssl_info["subject"] = subject.get("commonName", "")
            ssl_info["issuer"] = issuer.get("organizationName", "")
            ssl_info["expires"] = not_after

            # Check expiry
            try:
                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if exp_date < datetime.now():
                    ssl_info["issues"].append("EXPIRED certificate")
                    log_vuln("CRITICAL", "Certificado SSL EXPIRADO")
                elif (exp_date - datetime.now()).days < 30:
                    ssl_info["issues"].append("Certificate expires within 30 days")
                    log_warn(f"Certificado expira en {(exp_date - datetime.now()).days} dias")
            except Exception:
                pass

            # Self-signed check
            if subject.get("commonName") == issuer.get("commonName"):
                ssl_info["issues"].append("Self-signed certificate")
                log_vuln("MEDIUM", "Certificado auto-firmado")

        # Weak ciphers
        if cipher:
            cipher_name = cipher[0].upper()
            if "RC4" in cipher_name:
                ssl_info["issues"].append("RC4 cipher (weak)")
                log_vuln("HIGH", "Cipher RC4 (debil)")
            if "DES" in cipher_name:
                ssl_info["issues"].append("DES cipher (weak)")
                log_vuln("HIGH", "Cipher DES (debil)")
            if "NULL" in cipher_name:
                ssl_info["issues"].append("NULL cipher (no encryption)")
                log_vuln("CRITICAL", "Cipher NULL (sin cifrado)")
            if "EXPORT" in cipher_name:
                ssl_info["issues"].append("EXPORT cipher (weak)")
                log_vuln("CRITICAL", "Cipher EXPORT (debil)")

        conn.close()

    except ssl.SSLError as e:
        log_fail(f"SSL error: {e}")
        ssl_info["error"] = str(e)
    except Exception as e:
        log_fail(f"Error: {e}")
        ssl_info["error"] = str(e)

    # Test for deprecated protocols
    for proto_name in ["TLSv1.0", "TLSv1.1"]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if proto_name == "TLSv1.0":
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1
            elif proto_name == "TLSv1.1":
                ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
            conn = ctx.wrap_socket(socket.socket(), server_hostname=target_host)
            conn.settimeout(5)
            conn.connect((target_host, target_port))
            conn.close()
            ssl_info["issues"].append(f"{proto_name} supported (deprecated)")
            log_vuln("HIGH", f"{proto_name} soportado (deprecated)")
        except Exception:
            pass

    results["ssl_audit"] = ssl_info


# =====================================================================
#  MODULE 13: HTTP METHODS
# =====================================================================
def mod_http_methods(session, base_url, rate_limiter, results):
    """Prueba de metodos HTTP."""
    section_header("HTTP METHODS")

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
    allowed = []
    dangerous = []

    for method in methods:
        resp = safe_request(session, method, base_url, rate_limiter, timeout=5)
        if resp and resp.status_code not in (405, 501):
            allowed.append({"method": method, "status": resp.status_code})
            log_ok(f"{method} -> [{resp.status_code}]")

            if method == "TRACE" and resp.status_code == 200:
                dangerous.append(method)
                log_vuln("MEDIUM", "TRACE habilitado (Cross-Site Tracing)")
            if method in ("PUT", "DELETE") and resp.status_code in (200, 201, 204):
                dangerous.append(method)
                log_vuln("HIGH", f"{method} habilitado (modificacion de recursos)")

    # Check OPTIONS for allowed methods
    resp = safe_request(session, "OPTIONS", base_url, rate_limiter)
    if resp:
        allow_header = resp.headers.get("Allow", "")
        if allow_header:
            log_info(f"Allow header: {allow_header}")

    # Method override
    override_headers = [
        "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    ]
    for oh in override_headers:
        resp = safe_request(session, "POST", base_url, rate_limiter,
                           headers={oh: "DELETE"}, timeout=5)
        if resp and resp.status_code in (200, 204):
            log_vuln("MEDIUM", f"Method override via {oh}")
            dangerous.append(f"Override: {oh}")

    results["http_methods"] = {"allowed": allowed, "dangerous": dangerous}


# =====================================================================
#  MODULE 14: CORS TESTING
# =====================================================================
def mod_cors_test(session, base_url, rate_limiter, results):
    """Test activo de CORS."""
    section_header("CORS TESTING")

    cors_issues = []
    domain = get_domain(base_url)

    tests = [
        ("https://evil.com", "Arbitrary origin"),
        (f"https://{domain}.evil.com", "Subdomain prefix"),
        (f"https://evil{domain}", "Domain suffix"),
        ("null", "Null origin"),
        (f"https://{domain}", "Same origin (baseline)"),
        (f"http://{domain}", "HTTP downgrade"),
    ]

    for origin, desc in tests:
        resp = safe_request(session, "GET", base_url, rate_limiter,
                           headers={"Origin": origin})
        if resp is None:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao and acao != f"https://{domain}":
            issue = {
                "origin_sent": origin,
                "acao": acao,
                "acac": acac,
                "description": desc,
            }

            if acao == "*":
                if acac.lower() == "true":
                    log_vuln("CRITICAL", f"CORS: Wildcard + Credentials (Origin: {origin})")
                else:
                    log_vuln("MEDIUM", f"CORS: Wildcard origin (Origin: {origin})")
                cors_issues.append(issue)
            elif acao == origin and origin not in (f"https://{domain}", f"http://{domain}"):
                if acac.lower() == "true":
                    log_vuln("HIGH", f"CORS: Origin reflejado + Credentials ({desc})")
                else:
                    log_vuln("MEDIUM", f"CORS: Origin reflejado ({desc})")
                cors_issues.append(issue)
            elif acao == "null":
                log_vuln("HIGH", "CORS: null origin permitido")
                cors_issues.append(issue)

    if not cors_issues:
        log_ok("CORS configurado correctamente.")

    results["cors_active"] = cors_issues


# =====================================================================
#  MODULE 15: SQL INJECTION PROBE
# =====================================================================
def mod_sqli_probe(session, base_url, crawl_results, rate_limiter, results):
    """Deteccion de SQL injection."""
    section_header("SQL INJECTION PROBE")

    sqli_findings = []
    sql_errors = [
        r"you have an error in your sql",
        r"warning.*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"microsoft ole db provider for sql server",
        r"microsoft sql native client error",
        r"ora-\d{5}",
        r"pg_query\(\).*failed",
        r"pg_exec\(\).*failed",
        r"postgresql.*error",
        r"valid postgresql result",
        r"sqlite.*error",
        r"sqlite3\.",
        r"jdbc\..*exception",
        r"sql syntax.*mysql",
        r"syntax error.*sql",
        r"unexpected end of sql",
        r"sql command not properly ended",
        r"odbc.*driver.*error",
        r"db2.*sql.*error",
    ]
    sql_pattern = re.compile("|".join(sql_errors), re.I)

    # Collect testable URLs from crawl
    test_urls = set()
    if crawl_results:
        for url in crawl_results.get("visited_urls", []):
            if "?" in url:
                test_urls.add(url)
        for form in crawl_results.get("forms", []):
            test_urls.add(form.get("action", base_url))

    if not test_urls:
        test_urls.add(base_url)
        log_info("No se encontraron URLs con parametros. Probando base URL.")

    payloads = ["'", '"', "' OR '1'='1", "1 OR 1=1", "' OR ''='", "1' ORDER BY 1--",
                "1 UNION SELECT NULL--", "') OR ('1'='1"]

    log_info(f"Probando {len(test_urls)} URLs con {len(payloads)} payloads...")

    for url in test_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # Test common params
            for common_param in ["id", "page", "search", "q", "user", "cat"]:
                for payload in payloads:
                    test_url = f"{url}?{common_param}={quote(payload)}"
                    resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
                    if resp and sql_pattern.search(resp.text):
                        finding = {
                            "url": url,
                            "param": common_param,
                            "payload": payload,
                            "type": "Error-based SQLi",
                            "evidence": sql_pattern.search(resp.text).group(0)[:80],
                        }
                        sqli_findings.append(finding)
                        log_vuln("CRITICAL", f"SQLi en {common_param}: {payload}")
                        break
        else:
            for param_name in params:
                for payload in payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
                    if resp and sql_pattern.search(resp.text):
                        finding = {
                            "url": url,
                            "param": param_name,
                            "payload": payload,
                            "type": "Error-based SQLi",
                            "evidence": sql_pattern.search(resp.text).group(0)[:80],
                        }
                        sqli_findings.append(finding)
                        log_vuln("CRITICAL", f"SQLi en {param_name}: {payload}")
                        break

                # Boolean-based blind test
                true_resp = safe_request(session, "GET",
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}=1 AND 1=1",
                    rate_limiter, allow_redirects=True)
                false_resp = safe_request(session, "GET",
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}=1 AND 1=2",
                    rate_limiter, allow_redirects=True)
                if true_resp and false_resp:
                    if len(true_resp.content) != len(false_resp.content) and abs(len(true_resp.content) - len(false_resp.content)) > 50:
                        finding = {
                            "url": url,
                            "param": param_name,
                            "payload": "1 AND 1=1 vs 1 AND 1=2",
                            "type": "Boolean-based Blind SQLi",
                            "evidence": f"Size diff: {abs(len(true_resp.content) - len(false_resp.content))} bytes",
                        }
                        sqli_findings.append(finding)
                        log_vuln("HIGH", f"Blind SQLi posible en {param_name} (size diff: {abs(len(true_resp.content) - len(false_resp.content))} bytes)")

    if not sqli_findings:
        log_ok("No se detecto SQL injection.")

    results["sqli"] = sqli_findings


# =====================================================================
#  MODULE 16: XSS PROBE
# =====================================================================
def mod_xss_probe(session, base_url, crawl_results, rate_limiter, results):
    """Deteccion de Cross-Site Scripting (XSS) reflejado."""
    section_header("XSS PROBE")

    xss_findings = []
    canary = "xss_probe_" + hashlib.md5(base_url.encode()).hexdigest()[:8]

    payloads = [
        (f"<script>{canary}</script>", "script tag"),
        (f'"><img src=x onerror={canary}>', "img onerror"),
        (f"'><svg/onload={canary}>", "svg onload"),
        (f"javascript:{canary}", "javascript URI"),
        (f"<{canary}>", "custom tag"),
        (f'"{canary}', "quote break"),
    ]

    # Collect testable URLs
    test_urls = set()
    if crawl_results:
        for url in crawl_results.get("visited_urls", []):
            if "?" in url:
                test_urls.add(url)

    if not test_urls:
        test_urls.add(base_url)

    log_info(f"Probando {len(test_urls)} URLs...")

    for url in test_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            params = {"q": ["test"], "search": ["test"], "s": ["test"]}
            for param_name in params:
                for payload, ptype in payloads:
                    test_url = f"{url}?{param_name}={quote(payload)}"
                    resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
                    if resp and canary in resp.text:
                        # Check if payload is reflected unencoded
                        if payload in resp.text or payload.replace('"', '&quot;') not in resp.text:
                            finding = {
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "type": f"Reflected XSS ({ptype})",
                            }
                            xss_findings.append(finding)
                            log_vuln("HIGH", f"XSS reflejado en {param_name} ({ptype})")
                            break
        else:
            for param_name in params:
                # First check if value is reflected
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}={canary}"
                resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
                if resp and canary in resp.text:
                    log_info(f"  Param {param_name} refleja input, probando payloads...")
                    for payload, ptype in payloads:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
                        if resp and payload in resp.text:
                            finding = {
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "type": f"Reflected XSS ({ptype})",
                            }
                            xss_findings.append(finding)
                            log_vuln("HIGH", f"XSS reflejado en {param_name} ({ptype})")
                            break

    # Test forms
    if crawl_results:
        for form in crawl_results.get("forms", [])[:10]:
            for inp in form.get("inputs", []):
                if inp.get("type") in ("hidden", "submit", "button"):
                    continue
                for payload, ptype in payloads[:3]:
                    data = {}
                    for i in form.get("inputs", []):
                        data[i["name"]] = i.get("value", "test")
                    data[inp["name"]] = payload

                    method = form.get("method", "GET")
                    action = form.get("action", base_url)
                    if method == "POST":
                        resp = safe_request(session, "POST", action, rate_limiter, data=data, allow_redirects=True)
                    else:
                        resp = safe_request(session, "GET", f"{action}?{urlencode(data)}", rate_limiter, allow_redirects=True)

                    if resp and payload in resp.text:
                        finding = {
                            "url": action,
                            "param": inp["name"],
                            "payload": payload,
                            "type": f"Reflected XSS in form ({ptype})",
                        }
                        xss_findings.append(finding)
                        log_vuln("HIGH", f"XSS en form input {inp['name']} ({ptype})")
                        break

    if not xss_findings:
        log_ok("No se detecto XSS reflejado.")

    results["xss"] = xss_findings


# =====================================================================
#  MODULE 17: LFI PROBE
# =====================================================================
def mod_lfi_probe(session, base_url, crawl_results, rate_limiter, results):
    """Deteccion de Local File Inclusion."""
    section_header("LFI PROBE")

    lfi_findings = []
    lfi_payloads = [
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%2f..%2f..%2fetc%2fpasswd", "root:"),
        ("..\\..\\..\\etc\\passwd", "root:"),
        ("/etc/passwd", "root:"),
        ("../../../windows/win.ini", "[fonts]"),
        ("....//....//windows/win.ini", "[fonts]"),
        ("../../../etc/shadow", "root:"),
        ("../../../etc/hosts", "localhost"),
        ("php://filter/convert.base64-encode/resource=index", "PD"),
        ("php://filter/read=string.rot13/resource=index", ""),
        ("/proc/self/environ", "SERVER_"),
    ]

    # Collect file-inclusion-prone params
    file_params = ["file", "path", "page", "include", "dir", "document", "folder",
                   "root", "pg", "style", "template", "php_path", "doc", "view",
                   "content", "layout", "mod", "conf", "load", "read", "fetch"]

    test_urls = set()
    if crawl_results:
        for url in crawl_results.get("visited_urls", []):
            if "?" in url:
                test_urls.add(url)

    if not test_urls:
        test_urls.add(base_url)

    log_info(f"Probando {len(test_urls)} URLs con {len(lfi_payloads)} payloads...")

    for url in test_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        target_params = {}
        if params:
            for p in params:
                if p.lower() in file_params:
                    target_params[p] = params[p]
            if not target_params:
                target_params = params
        else:
            target_params = {p: ["test"] for p in file_params[:5]}

        for param_name in target_params:
            for payload, indicator in lfi_payloads:
                if not indicator:
                    continue
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}={quote(payload)}"
                resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=True)
                if resp and indicator in resp.text:
                    finding = {
                        "url": url,
                        "param": param_name,
                        "payload": payload,
                        "type": "Local File Inclusion",
                        "indicator": indicator,
                    }
                    lfi_findings.append(finding)
                    log_vuln("CRITICAL", f"LFI en {param_name}: {payload}")
                    break

    if not lfi_findings:
        log_ok("No se detecto LFI.")

    results["lfi"] = lfi_findings


# =====================================================================
#  MODULE 18: OPEN REDIRECT PROBE
# =====================================================================
def mod_redirect_probe(session, base_url, crawl_results, rate_limiter, results):
    """Deteccion de Open Redirect."""
    section_header("OPEN REDIRECT PROBE")

    redirect_findings = []
    redirect_params = ["url", "redirect", "redir", "return", "next", "goto", "target",
                       "dest", "destination", "rurl", "return_url", "redirect_url",
                       "continue", "callback", "forward", "out", "view", "login_url",
                       "redirect_to", "return_to", "checkout_url", "image_url"]

    evil_urls = [
        "https://evil.com",
        "//evil.com",
        "https:evil.com",
        "/\\evil.com",
        "////evil.com",
        "https://evil.com%23.target.com",
        "https://evil.com%2f%2f",
    ]

    test_urls = set()
    if crawl_results:
        for url in crawl_results.get("visited_urls", []):
            if "?" in url:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                for p in params:
                    if p.lower() in redirect_params:
                        test_urls.add(url)

    log_info(f"Probando {len(redirect_params)} params con {len(evil_urls)} payloads...")

    # Test common redirect params on base URL
    for param in redirect_params:
        for evil in evil_urls:
            test_url = f"{base_url}?{param}={quote(evil)}"
            resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location:
                    finding = {
                        "url": base_url,
                        "param": param,
                        "payload": evil,
                        "redirect_to": location,
                    }
                    redirect_findings.append(finding)
                    log_vuln("MEDIUM", f"Open Redirect en {param} -> {location}")
                    break

    # Test crawled URLs with redirect params
    for url in test_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param_name in params:
            if param_name.lower() in redirect_params:
                for evil in evil_urls[:3]:
                    test_params = params.copy()
                    test_params[param_name] = [evil]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    resp = safe_request(session, "GET", test_url, rate_limiter, allow_redirects=False)
                    if resp and resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            finding = {
                                "url": url,
                                "param": param_name,
                                "payload": evil,
                                "redirect_to": location,
                            }
                            redirect_findings.append(finding)
                            log_vuln("MEDIUM", f"Open Redirect en {param_name} -> {location}")
                            break

    if not redirect_findings:
        log_ok("No se detecto Open Redirect.")

    results["open_redirect"] = redirect_findings


# =====================================================================
#  MODULE 19: CRLF INJECTION PROBE
# =====================================================================
def mod_crlf_probe(session, base_url, rate_limiter, results):
    """Deteccion de CRLF injection."""
    section_header("CRLF INJECTION PROBE")

    crlf_findings = []
    canary = "X-CRLF-Test: injected"

    payloads = [
        f"%0d%0a{canary}",
        f"%0D%0A{canary}",
        f"%E5%98%8A%E5%98%8D{canary}",
        f"\\r\\n{canary}",
        f"%0d%0a%0d%0a<script>alert(1)</script>",
    ]

    for payload in payloads:
        test_url = f"{base_url}/{payload}"
        resp = safe_request(session, "GET", test_url, rate_limiter)
        if resp:
            # Check if our header was injected
            if "x-crlf-test" in str(resp.headers).lower():
                finding = {
                    "url": base_url,
                    "payload": payload[:50],
                    "type": "CRLF Header Injection",
                }
                crlf_findings.append(finding)
                log_vuln("HIGH", f"CRLF injection en path: {payload[:50]}")

            # Check response body for injected content
            if "<script>alert(1)</script>" in resp.text and "alert" in payload:
                finding = {
                    "url": base_url,
                    "payload": payload[:50],
                    "type": "CRLF + XSS (Response Splitting)",
                }
                crlf_findings.append(finding)
                log_vuln("CRITICAL", "CRLF + XSS via response splitting")

    # Test in params
    for param in ["url", "redirect", "page", "path"]:
        for payload in payloads[:3]:
            test_url = f"{base_url}?{param}={payload}"
            resp = safe_request(session, "GET", test_url, rate_limiter)
            if resp and "x-crlf-test" in str(resp.headers).lower():
                crlf_findings.append({
                    "url": base_url,
                    "param": param,
                    "payload": payload[:50],
                    "type": "CRLF Header Injection in param",
                })
                log_vuln("HIGH", f"CRLF injection en param {param}")
                break

    if not crlf_findings:
        log_ok("No se detecto CRLF injection.")

    results["crlf"] = crlf_findings


# =====================================================================
#  MODULE 20: HOST HEADER INJECTION
# =====================================================================
def mod_header_inject(session, base_url, rate_limiter, results):
    """Test de Host header injection."""
    section_header("HOST HEADER INJECTION")

    findings = []

    tests = [
        ("evil.com", "Arbitrary host"),
        ("evil.com\r\nX-Injected: true", "CRLF in Host"),
        (f"{get_domain(base_url)}@evil.com", "Host with @"),
        (f"{get_domain(base_url)}.evil.com", "Subdomain append"),
        (f"evil.com/{get_domain(base_url)}", "Host with path"),
    ]

    override_headers = ["X-Forwarded-Host", "X-Host", "X-Forwarded-Server",
                        "X-Original-URL", "X-Rewrite-URL"]

    for host_value, desc in tests:
        try:
            resp = safe_request(session, "GET", base_url, rate_limiter,
                               headers={"Host": host_value}, timeout=5)
            if resp:
                if "evil.com" in resp.text or "evil.com" in resp.headers.get("Location", ""):
                    findings.append({
                        "type": desc,
                        "host": host_value,
                        "reflected_in": "body" if "evil.com" in resp.text else "Location header",
                    })
                    log_vuln("HIGH", f"Host header injection: {desc}")
        except Exception:
            pass

    for header in override_headers:
        resp = safe_request(session, "GET", base_url, rate_limiter,
                           headers={header: "evil.com"}, timeout=5)
        if resp and "evil.com" in resp.text:
            findings.append({
                "type": f"Override via {header}",
                "header": header,
            })
            log_vuln("MEDIUM", f"Host override via {header}")

    if not findings:
        log_ok("No se detecto Host header injection.")

    results["host_header"] = findings


# =====================================================================
#  MODULE 21: SUBDOMAIN TAKEOVER VERIFY
# =====================================================================
def mod_takeover_verify(session, subdomains, rate_limiter, results):
    """Verificacion de subdomain takeover."""
    section_header("SUBDOMAIN TAKEOVER VERIFICATION")

    takeover_sigs = {
        "github.io": "There isn't a GitHub Pages site here",
        "herokuapp.com": "no such app",
        "pantheon.io": "404 error unknown site",
        "tumblr.com": "There's nothing here",
        "wordpress.com": "Do you want to register",
        "teamwork.com": "Oops - We didn't find your site",
        "helpjuice.com": "We could not find what you're looking for",
        "helpscoutdocs.com": "No settings were found",
        "ghost.io": "The thing you were looking for is no longer here",
        "myshopify.com": "Sorry, this shop is currently unavailable",
        "surge.sh": "project not found",
        "bitbucket.io": "Repository not found",
        "smartling.com": "Domain is not configured",
        "acquia.com": "Web Site not found",
        "fastly.com": "Fastly error: unknown domain",
        "zendesk.com": "Help Center Closed",
        "readme.io": "Project doesnt exist",
        "statuspage.io": "Status page is not configured",
        "uservoice.com": "This UserVoice subdomain",
        "smugmug.com": "not found",
        "cargocollective.com": "404 Not Found",
        "unbounce.com": "The requested URL was not found",
        "tilda.cc": "Please renew your subscription",
        "webflow.io": "The page you are looking for doesn't exist",
        "netlify.app": "Not Found - Request ID",
        "fly.dev": "404 Not Found",
        "vercel.app": "404: NOT_FOUND",
        "render.com": "not found",
    }

    takeover_findings = []

    if not subdomains:
        log_info("No hay subdominios para verificar.")
        return

    log_info(f"Verificando {len(subdomains)} subdominios...")

    for sub_info in subdomains:
        subdomain = sub_info.get("subdomain", "")
        if not subdomain:
            continue

        # Check CNAME
        try:
            cname_answers = dns.resolver.resolve(subdomain, "CNAME") if dns else []
            for cname in cname_answers:
                cname_str = str(cname).rstrip(".")
                for service, sig in takeover_sigs.items():
                    if service in cname_str:
                        # Try to access and verify
                        for scheme in ["https", "http"]:
                            try:
                                resp = safe_request(session, "GET", f"{scheme}://{subdomain}",
                                                   rate_limiter, timeout=5, allow_redirects=True)
                                if resp and sig.lower() in resp.text.lower():
                                    takeover_findings.append({
                                        "subdomain": subdomain,
                                        "cname": cname_str,
                                        "service": service,
                                        "signature": sig,
                                    })
                                    log_vuln("CRITICAL", f"Takeover posible: {subdomain} -> {cname_str}")
                                    break
                            except Exception:
                                pass
                        break
        except Exception:
            pass

    if not takeover_findings:
        log_ok("No se detectaron subdominios vulnerables a takeover.")

    results["takeover"] = takeover_findings


# =====================================================================
#  MODULE 22: DEFAULT CREDENTIALS
# =====================================================================
def mod_default_creds(session, base_url, rate_limiter, results):
    """Test de credenciales por defecto en paneles comunes."""
    section_header("DEFAULT CREDENTIALS CHECK")

    login_pages = [
        ("/admin", "admin"),
        ("/login", "login"),
        ("/wp-login.php", "WordPress"),
        ("/administrator/", "Joomla"),
        ("/user/login", "Drupal"),
        ("/phpmyadmin/", "phpMyAdmin"),
        ("/manager/html", "Tomcat"),
        ("/jenkins/login", "Jenkins"),
    ]

    found_logins = []
    cred_findings = []

    # Find login pages
    for path, name in login_pages:
        resp = safe_request(session, "GET", f"{base_url}{path}", rate_limiter)
        if resp and resp.status_code == 200:
            has_form = "<form" in resp.text.lower() and ("password" in resp.text.lower() or "login" in resp.text.lower())
            if has_form:
                found_logins.append({"path": path, "name": name})
                log_ok(f"Login page encontrada: {path} ({name})")

    if not found_logins:
        log_info("No se encontraron paginas de login.")
        results["default_creds"] = []
        return

    # Test default credentials on found login pages
    log_info(f"Probando {len(DEFAULT_CREDS)} credenciales en {len(found_logins)} login pages...")

    for login in found_logins:
        path = login["path"]
        url = f"{base_url}{path}"
        resp = safe_request(session, "GET", url, rate_limiter, allow_redirects=True)
        if not resp:
            continue

        # Find form fields
        form_match = re.search(r'<form[^>]*>(.*?)</form>', resp.text, re.I | re.S)
        if not form_match:
            continue

        form_html = form_match.group(1)
        action = re.search(r'action=["\']([^"\']*)', resp.text, re.I)
        action_url = urljoin(url, action.group(1)) if action else url

        user_field = None
        pass_field = None
        extra_fields = {}

        inputs = re.findall(r'<input[^>]*>', form_html, re.I)
        for inp in inputs:
            name_match = re.search(r'name=["\']([^"\']*)', inp, re.I)
            type_match = re.search(r'type=["\']([^"\']*)', inp, re.I)
            value_match = re.search(r'value=["\']([^"\']*)', inp, re.I)
            if not name_match:
                continue
            name = name_match.group(1)
            inp_type = type_match.group(1).lower() if type_match else "text"
            value = value_match.group(1) if value_match else ""

            if inp_type == "password":
                pass_field = name
            elif inp_type in ("text", "email") and not user_field:
                user_field = name
            elif inp_type == "hidden":
                extra_fields[name] = value

        if not user_field or not pass_field:
            continue

        for username, password in DEFAULT_CREDS[:10]:
            data = extra_fields.copy()
            data[user_field] = username
            data[pass_field] = password

            login_resp = safe_request(session, "POST", action_url, rate_limiter,
                                     data=data, allow_redirects=True)
            if login_resp is None:
                continue

            # Check for successful login indicators
            failed_indicators = ["invalid", "incorrect", "wrong", "failed", "error",
                                "denied", "unauthorized", "bad credentials", "login failed"]
            resp_lower = login_resp.text.lower()

            is_failed = any(ind in resp_lower for ind in failed_indicators)
            is_redirect_to_dash = login_resp.url != action_url and "login" not in login_resp.url.lower()

            if not is_failed and (is_redirect_to_dash or login_resp.status_code == 200):
                if login_resp.url != url and "login" not in login_resp.url.lower():
                    cred_findings.append({
                        "url": url,
                        "username": username,
                        "password": password,
                        "service": login["name"],
                    })
                    log_vuln("CRITICAL", f"Default creds: {username}:{password} en {login['name']}")
                    break

    if not cred_findings:
        log_ok("No se encontraron credenciales por defecto.")

    results["default_creds"] = cred_findings


# =====================================================================
#  MODULE 23: API DISCOVERY
# =====================================================================
def mod_api_discover(session, base_url, threads, rate_limiter, results):
    """Descubrimiento de endpoints API."""
    section_header("API DISCOVERY")

    found_apis = []
    lock = threading.Lock()

    def check_api(path):
        url = f"{base_url}/{path}"
        resp = safe_request(session, "GET", url, rate_limiter, timeout=5)
        if resp and resp.status_code in (200, 201, 204, 301, 302, 401, 403, 405):
            ct = resp.headers.get("content-type", "")
            is_json = "json" in ct or "xml" in ct
            return {
                "path": f"/{path}",
                "status": resp.status_code,
                "content_type": ct,
                "is_api": is_json,
                "size": len(resp.content),
            }
        return None

    log_info(f"Probando {len(API_WORDLIST)} endpoints API...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_api, p): p for p in API_WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_apis.append(result)
                marker = " [API]" if result["is_api"] else ""
                log_ok(f"[{result['status']}] {result['path']} ({result['content_type'][:30]}){marker}")

    # Check for Swagger/OpenAPI
    swagger_paths = ["swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
                     "api-docs", "v2/api-docs", "v3/api-docs"]
    for sp in swagger_paths:
        resp = safe_request(session, "GET", f"{base_url}/{sp}", rate_limiter)
        if resp and resp.status_code == 200:
            ct = resp.headers.get("content-type", "")
            if "json" in ct or "yaml" in ct or "swagger" in resp.text.lower()[:200]:
                found_apis.append({
                    "path": f"/{sp}",
                    "status": 200,
                    "content_type": ct,
                    "is_api": True,
                    "swagger": True,
                })
                log_vuln("MEDIUM", f"Swagger/OpenAPI expuesto: /{sp}")

    # GraphQL check
    gql_paths = ["graphql", "graphiql", "api/graphql", "v1/graphql"]
    for gp in gql_paths:
        resp = safe_request(session, "POST", f"{base_url}/{gp}", rate_limiter,
                           json={"query": "{__schema{types{name}}}"})
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if "data" in data or "__schema" in str(data):
                    found_apis.append({
                        "path": f"/{gp}",
                        "status": 200,
                        "content_type": "graphql",
                        "is_api": True,
                        "introspection": True,
                    })
                    log_vuln("MEDIUM", f"GraphQL introspection habilitado: /{gp}")
            except Exception:
                pass

    results["api_discovery"] = found_apis
    log_info(f"Endpoints encontrados: {len(found_apis)}")


# =====================================================================
#  MODULE 24: VULNERABILITY ASSESSMENT
# =====================================================================
def mod_vuln_assessment(results):
    """Evaluacion agregada de vulnerabilidades."""
    section_header("VULNERABILITY ASSESSMENT")

    vulns = []

    # --- Port Scan ---
    open_ports = results.get("open_ports", [])
    risky_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP",
                   1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                   27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
                   9200: "Elasticsearch", 2181: "ZooKeeper", 5900: "VNC"}
    for port in open_ports:
        if port in risky_ports:
            vulns.append(("HIGH", f"Puerto riesgoso expuesto: {port} ({risky_ports[port]})",
                f"Puerto {port}/{risky_ports[port]} abierto a internet.",
                "Restringir acceso con firewall. No exponer servicios internos."))
    if len(open_ports) > 20:
        vulns.append(("MEDIUM", "Excesivos puertos abiertos",
            f"{len(open_ports)} puertos abiertos. Superficie de ataque amplia.",
            "Cerrar puertos innecesarios. Aplicar principio de minimo privilegio."))

    # --- Services ---
    services = results.get("services", [])
    for svc in services:
        banner = svc.get("banner", "").lower()
        if any(v in banner for v in ["apache/2.2", "apache/2.0", "nginx/0.", "nginx/1.0"]):
            vulns.append(("HIGH", f"Version obsoleta en puerto {svc['port']}",
                f"Servicio desactualizado: {svc['service']}",
                "Actualizar a la ultima version estable."))
        if svc["port"] == 21 and "anonymous" in banner:
            vulns.append(("HIGH", "FTP Anonymous Login Permitted",
                "FTP permite login anonimo.",
                "Deshabilitar FTP anonimo."))

    # --- Directories ---
    dirs = results.get("directories", [])
    sensitive_dirs = [".git", ".env", ".svn", "backup", "config", "phpinfo",
                      "phpmyadmin", "adminer", "server-status", "server-info",
                      "actuator", "debug", "trace.axd", "elmah.axd", "wp-config"]
    for d in dirs:
        path_lower = d["url"].lower()
        for sd in sensitive_dirs:
            if sd in path_lower and d["status"] == 200:
                vulns.append(("HIGH", f"Recurso sensible expuesto: {sd}",
                    f"{d['url']} [{d['status']}] ({d['size']} bytes)",
                    f"Bloquear acceso a {sd} en produccion."))
                break

    # --- DNS Zone Transfer ---
    zt = results.get("zone_transfer", [])
    for z in zt:
        if z.get("success"):
            vulns.append(("HIGH", "DNS Zone Transfer Exitoso",
                f"Nameserver {z['nameserver']} permite AXFR. {len(z.get('records', []))} records expuestos.",
                "Deshabilitar zone transfer a hosts no autorizados."))

    # --- SSL/TLS ---
    ssl_data = results.get("ssl_audit", {})
    for issue in ssl_data.get("issues", []):
        if "expired" in issue.lower():
            vulns.append(("CRITICAL", "Certificado SSL Expirado", issue, "Renovar certificado."))
        elif "self-signed" in issue.lower():
            vulns.append(("MEDIUM", "Certificado Auto-Firmado", issue, "Usar certificado de CA confiable."))
        elif "null" in issue.lower():
            vulns.append(("CRITICAL", "NULL Cipher", issue, "Deshabilitar NULL cipher."))
        elif "export" in issue.lower():
            vulns.append(("CRITICAL", "EXPORT Cipher", issue, "Deshabilitar EXPORT ciphers."))
        elif "rc4" in issue.lower() or "des" in issue.lower():
            vulns.append(("HIGH", "Cipher Debil", issue, "Usar ciphers modernos (AES-GCM)."))
        elif "tls" in issue.lower() and "deprecated" in issue.lower():
            vulns.append(("HIGH", "Protocolo TLS Deprecated", issue, "Deshabilitar TLS 1.0/1.1."))

    # --- CORS ---
    cors = results.get("cors_active", [])
    for c in cors:
        acac = c.get("acac", "").lower()
        acao = c.get("acao", "")
        if acao == "*" and acac == "true":
            vulns.append(("CRITICAL", "CORS: Wildcard + Credentials",
                "Cualquier sitio puede leer respuestas autenticadas.",
                "Validar origin contra whitelist. No usar * con credentials."))
        elif acao == "null":
            vulns.append(("HIGH", "CORS: Null Origin Permitido",
                "Origin null aceptado. Bypass via iframes sandboxed.",
                "No permitir null origin."))
        elif "evil.com" in acao:
            vulns.append(("HIGH", f"CORS: Origin Reflejado ({c.get('description', '')})",
                f"Server refleja origin: {acao}",
                "Validar origin contra whitelist."))

    # --- HTTP Methods ---
    methods = results.get("http_methods", {})
    for d in methods.get("dangerous", []):
        if d == "TRACE":
            vulns.append(("MEDIUM", "TRACE Method Enabled",
                "TRACE permite Cross-Site Tracing attacks.",
                "Deshabilitar TRACE en el servidor."))
        elif d in ("PUT", "DELETE"):
            vulns.append(("HIGH", f"{d} Method Enabled",
                f"Metodo {d} permite modificacion de recursos.",
                f"Deshabilitar {d} si no es necesario."))

    # --- SQLi ---
    sqli = results.get("sqli", [])
    for s in sqli:
        vulns.append(("CRITICAL", f"SQL Injection: {s['type']}",
            f"Param: {s['param']} en {s['url'][:60]}",
            "Usar prepared statements. Validar y sanitizar input."))

    # --- XSS ---
    xss = results.get("xss", [])
    for x in xss:
        vulns.append(("HIGH", f"XSS: {x['type']}",
            f"Param: {x['param']} en {x['url'][:60]}",
            "Escapar output. Implementar CSP. Validar input."))

    # --- LFI ---
    lfi = results.get("lfi", [])
    for l in lfi:
        vulns.append(("CRITICAL", "Local File Inclusion",
            f"Param: {l['param']} en {l['url'][:60]}",
            "No usar input de usuario en funciones de inclusion de archivos."))

    # --- Open Redirect ---
    redirects = results.get("open_redirect", [])
    for r in redirects:
        vulns.append(("MEDIUM", "Open Redirect",
            f"Param: {r['param']} redirige a {r.get('redirect_to', '')[:60]}",
            "Validar URLs de redireccion contra whitelist."))

    # --- CRLF ---
    crlf = results.get("crlf", [])
    for cr in crlf:
        sev = "CRITICAL" if "XSS" in cr.get("type", "") else "HIGH"
        vulns.append((sev, f"CRLF Injection: {cr['type']}",
            f"En {cr.get('url', '')[:60]}",
            "Sanitizar \\r\\n en input. Usar frameworks que previenen CRLF."))

    # --- Host Header ---
    hh = results.get("host_header", [])
    for h in hh:
        vulns.append(("HIGH", f"Host Header Injection: {h.get('type', '')}",
            f"Host value reflejado en respuesta.",
            "Configurar virtual hosts. Ignorar Host header arbitrario."))

    # --- Subdomain Takeover ---
    takeover = results.get("takeover", [])
    for t in takeover:
        vulns.append(("CRITICAL", "Subdomain Takeover",
            f"{t['subdomain']} -> {t.get('cname', '')} ({t.get('service', '')})",
            "Reclamar recurso en servicio o eliminar DNS record."))

    # --- Default Creds ---
    creds = results.get("default_creds", [])
    for c in creds:
        vulns.append(("CRITICAL", f"Default Credentials: {c.get('service', '')}",
            f"{c['username']}:{c['password']} en {c.get('url', '')[:60]}",
            "Cambiar credenciales por defecto inmediatamente."))

    # --- WAF ---
    waf = results.get("waf_active", [])
    if not waf:
        vulns.append(("INFO", "No WAF Detected",
            "No se detecto Web Application Firewall.",
            "Considerar implementar WAF (Cloudflare, AWS WAF, etc)."))

    # --- CMS ---
    cms = results.get("cms_active", {})
    if cms.get("cms"):
        details = cms.get("details", [])
        for d in details:
            if "XMLRPC: enabled" in d:
                vulns.append(("MEDIUM", "WordPress XMLRPC Enabled",
                    "xmlrpc.php habilitado. Vector de bruteforce y SSRF.",
                    "Deshabilitar xmlrpc.php o restringir acceso."))
            if "User:" in d or "User (enum):" in d:
                vulns.append(("LOW", "CMS User Enumeration",
                    f"Usuario encontrado: {d}",
                    "Deshabilitar enumeracion de usuarios."))

    # --- API ---
    apis = results.get("api_discovery", [])
    for a in apis:
        if a.get("swagger"):
            vulns.append(("MEDIUM", "Swagger/OpenAPI Documentation Exposed",
                f"API docs accesibles en {a['path']}",
                "Restringir acceso a documentacion API en produccion."))
        if a.get("introspection"):
            vulns.append(("MEDIUM", "GraphQL Introspection Enabled",
                f"GraphQL introspection en {a['path']}",
                "Deshabilitar introspection en produccion."))
        if a["status"] == 401:
            vulns.append(("INFO", f"API Endpoint Requires Auth: {a['path']}",
                f"Endpoint protegido encontrado.",
                "Verificar que autenticacion sea robusta."))

    # --- Crawl ---
    crawl = results.get("crawl", {})
    forms = crawl.get("forms", [])
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http://"):
            vulns.append(("HIGH", "Form Submits Over HTTP",
                f"Form action: {action[:60]}",
                "Cambiar form action a HTTPS."))
        inputs = form.get("inputs", [])
        has_csrf = any("csrf" in i.get("name", "").lower() or "token" in i.get("name", "").lower() for i in inputs)
        if form.get("method") == "POST" and not has_csrf:
            vulns.append(("MEDIUM", "Form POST Without CSRF Token",
                f"Form en {action[:60]} sin CSRF token visible.",
                "Implementar CSRF protection en formularios POST."))

    if crawl.get("emails"):
        vulns.append(("LOW", "Email Addresses Disclosed",
            f"{len(crawl['emails'])} email(s) encontrado(s) en el sitio.",
            "Considerar ofuscar emails para evitar spam/phishing."))

    # --- VHosts ---
    vhosts = results.get("vhosts", [])
    if vhosts:
        vulns.append(("INFO", f"Virtual Hosts Encontrados: {len(vhosts)}",
            ", ".join([v["vhost"] for v in vhosts[:5]]),
            "Verificar que vhosts no expongan aplicaciones internas."))

    # === Print Results ===
    if not vulns:
        log_ok("No se identificaron vulnerabilidades.")
        results["vulnerabilities"] = []
        return

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x[0], 5))

    results["vulnerabilities"] = [
        {"severity": v[0], "title": v[1], "description": v[2], "remediation": v[3]}
        for v in vulns
    ]

    counts = {}
    for v in vulns:
        counts[v[0]] = counts.get(v[0], 0) + 1

    severity_colors = {
        "CRITICAL": C.R + C.BOLD,
        "HIGH": C.R,
        "MEDIUM": C.Y,
        "LOW": C.B,
        "INFO": C.D,
    }

    print(f"\n  {C.BOLD}Total: {len(vulns)} hallazgos{C.X}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            color = severity_colors.get(sev, C.W)
            print(f"  {color}{sev}: {counts[sev]}{C.X}")
    print()

    for sev, title, desc, fix in vulns:
        color = severity_colors.get(sev, C.W)
        print(f"  {color}[{sev}]{C.X} {C.BOLD}{title}{C.X}")
        print(f"      {desc}")
        print(f"      {C.G}Fix:{C.X} {fix}")
        print()


# =====================================================================
#  REPORT GENERATOR
# =====================================================================
def generate_report(target, results, output_dir, rate_limiter=None):
    """Genera reporte en texto y JSON."""
    section_header("REPORT GENERATION")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = get_domain(target).replace(".", "_")

    # Text report
    txt_file = os.path.join(output_dir, f"active_recon_{domain}_{timestamp}.txt")
    with open(txt_file, "w") as f:
        f.write(f"{'='*60}\n")
        f.write(f"  ACTIVE RECON REPORT\n")
        f.write(f"  Target: {target}\n")
        f.write(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if rate_limiter:
            f.write(f"  Total Requests: {rate_limiter.request_count}\n")
        f.write(f"{'='*60}\n\n")

        # Open Ports
        ports = results.get("open_ports", [])
        if ports:
            f.write("OPEN PORTS:\n")
            for p in ports:
                svc = next((s for s in results.get("services", []) if s["port"] == p), {})
                f.write(f"  {p}/tcp - {svc.get('service', 'Unknown')}\n")
            f.write("\n")

        # Directories
        dirs = results.get("directories", [])
        if dirs:
            f.write("DIRECTORIES/FILES FOUND:\n")
            for d in dirs:
                f.write(f"  [{d['status']}] {d['url']} ({d['size']} bytes)\n")
            f.write("\n")

        # Subdomains
        subs = results.get("subdomains_brute", [])
        if subs:
            f.write("SUBDOMAINS:\n")
            for s in subs:
                f.write(f"  {s['subdomain']} -> {', '.join(s['ips'])}\n")
            f.write("\n")

        # Technologies
        techs = results.get("tech_active", [])
        if techs:
            f.write("TECHNOLOGIES:\n")
            for t in techs:
                f.write(f"  {t['technology']} ({t['path']}) [{t['status']}]\n")
            f.write("\n")

        # CMS
        cms = results.get("cms_active", {})
        if cms.get("cms"):
            f.write(f"CMS: {cms['cms']}\n")
            for d in cms.get("details", []):
                f.write(f"  {d}\n")
            f.write("\n")

        # WAF
        waf = results.get("waf_active", [])
        if waf:
            f.write("WAF DETECTED:\n")
            for w in waf:
                f.write(f"  {w['waf']} (indicator: {w['indicator']})\n")
            f.write("\n")

        # API Endpoints
        apis = results.get("api_discovery", [])
        if apis:
            f.write("API ENDPOINTS:\n")
            for a in apis:
                f.write(f"  [{a['status']}] {a['path']}\n")
            f.write("\n")

        # Crawl Summary
        crawl = results.get("crawl", {})
        if crawl:
            f.write("CRAWL SUMMARY:\n")
            f.write(f"  Pages visited: {crawl.get('pages_visited', 0)}\n")
            f.write(f"  Links found: {crawl.get('links_found', 0)}\n")
            f.write(f"  Forms: {len(crawl.get('forms', []))}\n")
            f.write(f"  JS files: {len(crawl.get('js_files', []))}\n")
            if crawl.get("emails"):
                f.write(f"  Emails: {', '.join(crawl['emails'][:10])}\n")
            f.write("\n")

        # Vulnerabilities
        vulns = results.get("vulnerabilities", [])
        if vulns:
            f.write(f"{'='*60}\n")
            f.write("VULNERABILITIES\n")
            f.write(f"{'='*60}\n\n")
            for v in vulns:
                f.write(f"[{v['severity']}] {v['title']}\n")
                f.write(f"  Description: {v['description']}\n")
                f.write(f"  Remediation: {v['remediation']}\n\n")

    log_ok(f"Reporte TXT: {txt_file}")

    # JSON report
    json_file = os.path.join(output_dir, f"active_recon_{domain}_{timestamp}.json")
    with open(json_file, "w") as f:
        json.dump({
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "total_requests": rate_limiter.request_count if rate_limiter else 0,
            "results": results,
        }, f, indent=2, default=str)

    log_ok(f"Reporte JSON: {json_file}")
    return txt_file, json_file


# =====================================================================
#  MAIN
# =====================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Active Reconnaissance Tool v1.0 - Bug Bounty Edition",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL (ej: https://example.com)")
    parser.add_argument("-m", "--modules", default="all",
                        help="""Modulos a ejecutar (separados por coma):
  portscan    - Escaneo de puertos TCP
  services    - Deteccion de servicios/banners
  dirbust     - Bruteforce de directorios
  subbrust    - Bruteforce de subdominios
  zonetrans   - DNS Zone Transfer
  vhost       - Virtual host discovery
  crawl       - Web spider/crawler
  paramdisco  - Descubrimiento de parametros
  techfp      - Technology fingerprinting
  waf         - WAF detection
  cmsenum     - CMS enumeration
  sslaudit    - SSL/TLS audit
  httpmethods - HTTP method testing
  cors        - CORS testing
  sqli        - SQL injection probe
  xss         - XSS reflection probe
  lfi         - Local file inclusion probe
  redirect    - Open redirect probe
  crlf        - CRLF injection probe
  hosthdr     - Host header injection
  takeover    - Subdomain takeover verify
  defcreds    - Default credentials check
  apidisco    - API endpoint discovery
  all         - Todos los modulos (default)""")
    parser.add_argument("-o", "--output", default=".",
                        help="Directorio de salida para reportes (default: .)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Threads para operaciones paralelas (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout HTTP en segundos (default: 10)")
    parser.add_argument("--rate-limit", type=int, default=0,
                        help="Max requests/segundo (0=sin limite, default: 0)")
    parser.add_argument("--ports", default="top100",
                        help="Puertos: top100, 1-1000, 1-65535, o lista (ej: 80,443,8080)")
    parser.add_argument("--wordlist", default=None,
                        help="Wordlist custom para dir bruteforce")
    parser.add_argument("--sublist", default=None,
                        help="Wordlist custom para subdomain bruteforce")
    parser.add_argument("--extensions", default="php,html,txt,bak,old,asp,aspx,jsp",
                        help="Extensiones para dir bruteforce (default: php,html,txt,bak,old,asp,aspx,jsp)")
    parser.add_argument("--crawl-depth", type=int, default=3,
                        help="Profundidad maxima de crawl (default: 3)")
    parser.add_argument("--crawl-pages", type=int, default=100,
                        help="Paginas maximas a crawlear (default: 100)")
    parser.add_argument("--user-agent", default=None,
                        help="User-Agent personalizado")
    parser.add_argument("--proxy", default=None,
                        help="Proxy HTTP (ej: http://127.0.0.1:8080 para Burp)")
    parser.add_argument("--cookies", default=None,
                        help="Cookies (ej: 'session=abc; token=xyz')")
    parser.add_argument("--headers", default=None,
                        help="Headers custom (separados por ;;, ej: 'Auth: Bearer x;; X-Custom: y')")
    parser.add_argument("--no-color", action="store_true",
                        help="Deshabilitar colores")
    parser.add_argument("--skip-disclaimer", action="store_true",
                        help="Saltar advertencia legal (solo para automation)")

    args = parser.parse_args()

    global NO_COLOR
    NO_COLOR = args.no_color

    banner()

    # Show disclaimer
    if not args.skip_disclaimer:
        show_disclaimer()

    target = args.target
    if not target.startswith("http"):
        target = f"https://{target}"

    parsed = urlparse(target)
    domain = parsed.hostname
    if not domain:
        log_fail("URL invalida.")
        sys.exit(1)

    base_url = get_base_url(target)
    target_ip = resolve_host(domain)

    if NO_COLOR:
        print(f"  Target: {target}")
        print(f"  Domain: {domain}")
        print(f"  IP: {target_ip or 'N/A'}")
    else:
        print(f"  {C.BOLD}Target:{C.X} {target}")
        print(f"  {C.BOLD}Domain:{C.X} {domain}")
        print(f"  {C.BOLD}IP:{C.X} {target_ip or 'N/A'}")
    print()

    if not target_ip:
        log_fail(f"No se puede resolver {domain}")
        sys.exit(1)

    # Setup
    session = create_session(args.user_agent, args.proxy, args.cookies, args.headers, args.timeout)
    rate_limiter = RateLimiter(args.rate_limit)
    results = {}
    os.makedirs(args.output, exist_ok=True)

    # Parse modules
    selected = set()
    if args.modules == "all":
        selected = {"portscan", "services", "dirbust", "subbrust", "zonetrans",
                    "vhost", "crawl", "paramdisco", "techfp", "waf", "cmsenum",
                    "sslaudit", "httpmethods", "cors", "sqli", "xss", "lfi",
                    "redirect", "crlf", "hosthdr", "takeover", "defcreds", "apidisco"}
    else:
        selected = set(m.strip() for m in args.modules.split(","))

    # Parse ports
    ports = TOP_PORTS
    if args.ports != "top100":
        if "-" in args.ports:
            start, end = args.ports.split("-")
            ports = list(range(int(start), int(end) + 1))
        else:
            ports = [int(p) for p in args.ports.split(",")]

    # Parse wordlists
    dir_wordlist = DIR_WORDLIST
    if args.wordlist and os.path.isfile(args.wordlist):
        with open(args.wordlist) as f:
            dir_wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    sub_wordlist = SUB_WORDLIST
    if args.sublist and os.path.isfile(args.sublist):
        with open(args.sublist) as f:
            sub_wordlist = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    extensions = [e.strip() for e in args.extensions.split(",")]

    start_time = time.time()

    try:
        # === EXECUTION ORDER ===

        if "portscan" in selected:
            mod_port_scan(target_ip, ports, args.threads, args.timeout, rate_limiter, results)

        if "services" in selected and results.get("open_ports"):
            mod_service_detect(target_ip, results["open_ports"], args.timeout, results)

        if "sslaudit" in selected and parsed.scheme == "https":
            mod_ssl_audit(domain, parsed.port or 443, results)

        if "subbrust" in selected:
            mod_subdomain_brute(domain, sub_wordlist, args.threads, rate_limiter, results)

        if "zonetrans" in selected and dns:
            mod_dns_zone_transfer(domain, results)

        if "vhost" in selected and target_ip:
            mod_vhost_discover(session, target_ip, base_url, domain, sub_wordlist[:50], rate_limiter, results)

        if "waf" in selected:
            mod_waf_detect(session, base_url, rate_limiter, results)

        if "techfp" in selected:
            mod_tech_fingerprint(session, base_url, rate_limiter, results)

        if "cmsenum" in selected:
            mod_cms_enum(session, base_url, rate_limiter, results)

        if "httpmethods" in selected:
            mod_http_methods(session, base_url, rate_limiter, results)

        if "cors" in selected:
            mod_cors_test(session, base_url, rate_limiter, results)

        if "crawl" in selected:
            mod_crawl(session, base_url, args.crawl_depth, args.crawl_pages, rate_limiter, results)

        crawl_results = results.get("crawl", {})

        if "dirbust" in selected:
            mod_dir_bruteforce(session, base_url, dir_wordlist, args.threads, extensions, rate_limiter, results)

        if "apidisco" in selected:
            mod_api_discover(session, base_url, args.threads, rate_limiter, results)

        if "paramdisco" in selected:
            mod_param_discover(session, base_url, PARAM_WORDLIST, rate_limiter, results)

        if "defcreds" in selected:
            mod_default_creds(session, base_url, rate_limiter, results)

        if "hosthdr" in selected:
            mod_header_inject(session, base_url, rate_limiter, results)

        if "crlf" in selected:
            mod_crlf_probe(session, base_url, rate_limiter, results)

        if "redirect" in selected:
            mod_redirect_probe(session, base_url, crawl_results, rate_limiter, results)

        if "sqli" in selected:
            mod_sqli_probe(session, base_url, crawl_results, rate_limiter, results)

        if "xss" in selected:
            mod_xss_probe(session, base_url, crawl_results, rate_limiter, results)

        if "lfi" in selected:
            mod_lfi_probe(session, base_url, crawl_results, rate_limiter, results)

        if "takeover" in selected and results.get("subdomains_brute"):
            mod_takeover_verify(session, results["subdomains_brute"], rate_limiter, results)

        # Vulnerability Assessment
        mod_vuln_assessment(results)

        # Report
        generate_report(target, results, args.output, rate_limiter)

    except KeyboardInterrupt:
        print(f"\n\n  {C.Y}[!] Escaneo interrumpido por el usuario.{C.X}")
        if results:
            generate_report(target, results, args.output, rate_limiter)

    elapsed = time.time() - start_time
    print(f"\n  {C.BOLD}Tiempo total:{C.X} {elapsed:.1f}s")
    print(f"  {C.BOLD}Total requests:{C.X} {rate_limiter.request_count}")
    print()


if __name__ == "__main__":
    main()
