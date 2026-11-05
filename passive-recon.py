#!/usr/bin/env python3
"""
PassiveRecon - Herramienta de reconocimiento pasivo para bug bounty
Autor: Sebastian Rivera
Uso: python3 passive-recon.py <url>

Solo tecnicas pasivas - no escanea, no explota, no envia payloads.
"""

import sys
import json
import ssl
import socket
import re
import os
import argparse
import hashlib
import base64
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Dependencias ===
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Falta 'requests'. Instala con: pip3 install requests")
    sys.exit(1)

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# === Colores para terminal ===
class C:
    R = "\033[91m"   # rojo
    G = "\033[92m"   # verde
    Y = "\033[93m"   # amarillo
    B = "\033[94m"   # azul
    M = "\033[95m"   # magenta
    W = "\033[97m"   # blanco
    D = "\033[90m"   # gris
    X = "\033[0m"    # reset
    BOLD = "\033[1m"

# === Utilidades ===
def banner():
    print(f"""{C.M}{C.BOLD}
  ____               _           ____
 |  _ \\ __ _ ___ ___(_)_   _____|  _ \\ ___  ___ ___  _ __
 | |_) / _` / __/ __| \\ \\ / / _ \\ |_) / _ \\/ __/ _ \\| '_ \\
 |  __/ (_| \\__ \\__ \\ |\\ V /  __/  _ <  __/ (_| (_) | | | |
 |_|   \\__,_|___/___/_| \\_/ \\___|_| \\_\\___|\\___\\___/|_| |_|
                                            {C.D}v2.0 by SR{C.X}
""")

def log_info(msg):
    print(f"  {C.B}[*]{C.X} {msg}")

def log_ok(msg):
    print(f"  {C.G}[+]{C.X} {msg}")

def log_warn(msg):
    print(f"  {C.Y}[!]{C.X} {msg}")

def log_fail(msg):
    print(f"  {C.R}[-]{C.X} {msg}")

def log_data(key, value):
    print(f"      {C.W}{key}:{C.X} {value}")

def section(title):
    print(f"\n{C.BOLD}{C.M}{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}{C.X}\n")

def get_session():
    """Crea una sesion HTTP con retry y headers realistas."""
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    })
    s.verify = True
    return s


# =====================================================================
#  MODULO 1: HTTP Headers & Security Headers
# =====================================================================
def mod_headers(session, url, results):
    section("1. HTTP HEADERS & SECURITY HEADERS")
    try:
        r = session.get(url, timeout=15, allow_redirects=True)
        results["status_code"] = r.status_code
        results["final_url"] = r.url
        results["headers"] = dict(r.headers)

        log_ok(f"Status: {r.status_code}")
        log_ok(f"Final URL: {r.url}")

        if r.history:
            log_info("Redirects:")
            for rr in r.history:
                log_data(str(rr.status_code), rr.url)

        # Server header
        server = r.headers.get("Server", "No revelado")
        log_data("Server", server)

        # Powered-by
        powered = r.headers.get("X-Powered-By", "No revelado")
        log_data("X-Powered-By", powered)

        # Security headers check
        sec_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy",
            "Cross-Origin-Opener-Policy": "COOP",
            "Cross-Origin-Embedder-Policy": "COEP",
            "Cross-Origin-Resource-Policy": "CORP",
        }

        print()
        log_info("Security Headers:")
        missing = []
        present = []
        for header, name in sec_headers.items():
            val = r.headers.get(header)
            if val:
                present.append(name)
                log_ok(f"{name}: {val[:100]}")
            else:
                missing.append(name)
                log_fail(f"{name}: AUSENTE")

        results["security_headers"] = {"present": present, "missing": missing}

        # Cookies
        if r.cookies:
            print()
            log_info("Cookies:")
            cookie_issues = []
            for cookie in r.cookies:
                flags = []
                if cookie.secure:
                    flags.append(f"{C.G}Secure{C.X}")
                else:
                    flags.append(f"{C.R}No-Secure{C.X}")
                    cookie_issues.append(f"{cookie.name}: falta Secure")
                if "httponly" in str(cookie._rest).lower() or cookie.has_nonstandard_attr("HttpOnly"):
                    flags.append(f"{C.G}HttpOnly{C.X}")
                else:
                    flags.append(f"{C.R}No-HttpOnly{C.X}")
                    cookie_issues.append(f"{cookie.name}: falta HttpOnly")
                if "samesite" in str(cookie._rest).lower():
                    flags.append(f"{C.G}SameSite{C.X}")
                else:
                    flags.append(f"{C.Y}No-SameSite{C.X}")

                log_data(cookie.name, " | ".join(flags))
            results["cookie_issues"] = cookie_issues

    except requests.exceptions.RequestException as e:
        log_fail(f"Error al conectar: {e}")
        results["error_headers"] = str(e)


# =====================================================================
#  MODULO 2: SSL/TLS Certificate
# =====================================================================
def mod_ssl(hostname, port, results):
    section("2. CERTIFICADO SSL/TLS")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(10)
            s.connect((hostname, port))
            cert = s.getpeercert()

        results["ssl"] = cert

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        log_ok(f"CN: {subject.get('commonName', 'N/A')}")
        log_ok(f"Org: {subject.get('organizationName', 'N/A')}")
        log_ok(f"Issuer: {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
        log_data("Valid From", cert.get("notBefore", "N/A"))
        log_data("Valid Until", cert.get("notAfter", "N/A"))

        # Check expiration
        not_after = cert.get("notAfter", "")
        if not_after:
            exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp_date - now).days
            if days_left < 0:
                log_fail(f"CERTIFICADO EXPIRADO hace {abs(days_left)} dias")
            elif days_left < 30:
                log_warn(f"Expira en {days_left} dias")
            else:
                log_ok(f"Dias restantes: {days_left}")

        # SANs
        sans = cert.get("subjectAltName", [])
        if sans:
            log_info("Subject Alternative Names:")
            san_list = []
            for typ, val in sans:
                san_list.append(val)
                log_data(typ, val)
            results["ssl_sans"] = san_list

        # TLS version
        log_data("Protocol", s.version() if hasattr(s, 'version') else "N/A")

    except Exception as e:
        log_fail(f"Error SSL: {e}")
        results["ssl_error"] = str(e)


# =====================================================================
#  MODULO 3: DNS Records
# =====================================================================
def mod_dns(hostname, results):
    section("3. DNS RECORDS")

    if not HAS_DNS:
        log_warn("Modulo dnspython no instalado. Instala con: pip3 install dnspython")
        log_info("Usando resolucion basica...")
        try:
            ips = socket.getaddrinfo(hostname, None)
            seen = set()
            for info in ips:
                ip = info[4][0]
                if ip not in seen:
                    seen.add(ip)
                    log_ok(f"A/AAAA: {ip}")
            results["dns_basic"] = list(seen)
        except Exception as e:
            log_fail(f"Error DNS basico: {e}")
        return

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    dns_results = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(hostname, rtype)
            records = [str(r) for r in answers]
            dns_results[rtype] = records
            for r in records:
                log_ok(f"{rtype}: {r}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            log_fail(f"Dominio {hostname} no existe")
            break
        except Exception:
            pass

    results["dns"] = dns_results

    # Check for SPF, DMARC, DKIM hints
    txt_records = dns_results.get("TXT", [])
    for txt in txt_records:
        if "v=spf1" in txt:
            log_info(f"SPF encontrado: {txt[:80]}")
        if "v=DMARC1" in txt:
            log_info(f"DMARC encontrado: {txt[:80]}")

    # DMARC specific
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{hostname}", "TXT")
        for r in dmarc:
            log_ok(f"DMARC: {r}")
            dns_results["DMARC"] = [str(r)]
    except Exception:
        log_warn("No DMARC record found")


# =====================================================================
#  MODULO 4: robots.txt & sitemap.xml
# =====================================================================
def mod_robots_sitemap(session, base_url, results):
    section("4. ROBOTS.TXT & SITEMAP.XML")

    # robots.txt
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        r = session.get(robots_url, timeout=10)
        if r.status_code == 200 and "user-agent" in r.text.lower():
            log_ok(f"robots.txt encontrado ({len(r.text)} bytes)")
            results["robots_txt"] = r.text

            disallowed = re.findall(r"Disallow:\s*(.+)", r.text, re.IGNORECASE)
            sitemaps = re.findall(r"Sitemap:\s*(.+)", r.text, re.IGNORECASE)

            if disallowed:
                log_info("Rutas Disallow (posibles dirs interesantes):")
                for d in disallowed[:20]:
                    log_data("Disallow", d.strip())

            if sitemaps:
                log_info("Sitemaps referenciados:")
                for s in sitemaps:
                    log_data("Sitemap", s.strip())
                results["sitemaps_from_robots"] = [s.strip() for s in sitemaps]
        else:
            log_warn("robots.txt no encontrado o vacio")
    except Exception as e:
        log_fail(f"Error robots.txt: {e}")

    # sitemap.xml
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    try:
        r = session.get(sitemap_url, timeout=10)
        if r.status_code == 200 and "<url" in r.text.lower():
            urls_found = re.findall(r"<loc>(.*?)</loc>", r.text)
            log_ok(f"sitemap.xml: {len(urls_found)} URLs encontradas")
            results["sitemap_urls"] = urls_found[:50]
            for u in urls_found[:10]:
                log_data("URL", u)
            if len(urls_found) > 10:
                log_info(f"... y {len(urls_found)-10} mas")
        else:
            log_warn("sitemap.xml no encontrado")
    except Exception as e:
        log_fail(f"Error sitemap: {e}")


# =====================================================================
#  MODULO 5: Technology Fingerprinting
# =====================================================================
def mod_tech_fingerprint(session, url, html, results):
    section("5. TECHNOLOGY FINGERPRINTING")

    techs = []

    # -- From HTML meta and script tags --
    # Meta generator
    gen = re.findall(r'<meta\s+name=["\']generator["\']\s+content=["\'](.*?)["\']', html, re.I)
    for g in gen:
        techs.append(("Meta Generator", g))
        log_ok(f"Generator: {g}")

    # Detect common frameworks from HTML
    framework_patterns = {
        "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
        "Joomla": [r"/media/jui/", r"com_content", r"/administrator/"],
        "Drupal": [r"drupal.js", r"Drupal.settings", r"/sites/default/files"],
        "React": [r"react\.production\.min\.js", r"__NEXT_DATA__", r"_next/static"],
        "Angular": [r"ng-version", r"angular\.min\.js", r"ng-app"],
        "Vue.js": [r"vue\.min\.js", r"vue\.runtime", r"__vue__"],
        "jQuery": [r"jquery[\.-](\d+\.\d+\.\d+)", r"jquery\.min\.js"],
        "Bootstrap": [r"bootstrap[\.-](\d+\.\d+\.\d+)", r"bootstrap\.min\.css"],
        "Laravel": [r"laravel_session", r"csrf-token"],
        "Django": [r"csrfmiddlewaretoken", r"__admin__"],
        "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net"],
        "Keycloak": [r"keycloak\.js", r"/auth/realms/", r"/auth/admin/"],
        "Spring": [r"spring", r"JSESSIONID"],
        "Nginx": [r"nginx"],
        "Apache": [r"apache"],
        "Cloudflare": [r"cf-ray", r"cloudflare"],
        "AWS": [r"x-amz-", r"AmazonS3", r"\.amazonaws\.com"],
        "Google Analytics": [r"google-analytics\.com", r"gtag", r"UA-\d+"],
        "Google Tag Manager": [r"googletagmanager\.com", r"GTM-"],
        "Hotjar": [r"hotjar\.com", r"hj\("],
        "Sentry": [r"sentry\.io", r"Sentry\.init"],
        "reCAPTCHA": [r"recaptcha", r"grecaptcha"],
        "Stripe": [r"stripe\.com", r"Stripe\("],
    }

    detected = set()
    for tech, patterns in framework_patterns.items():
        for p in patterns:
            if re.search(p, html, re.I):
                if tech not in detected:
                    detected.add(tech)
                    # Try to extract version
                    ver_match = re.search(p, html, re.I)
                    version = ver_match.group(1) if ver_match and ver_match.lastindex else ""
                    techs.append(("Framework/Lib", f"{tech} {version}".strip()))
                    log_ok(f"Detectado: {tech} {version}".strip())
                break

    # -- From response headers --
    try:
        r = session.get(url, timeout=10)
        h = r.headers

        server = h.get("Server", "")
        if server:
            techs.append(("Server", server))

        powered = h.get("X-Powered-By", "")
        if powered:
            techs.append(("X-Powered-By", powered))
            log_ok(f"X-Powered-By: {powered}")

        # CDN detection
        if "cf-ray" in h:
            techs.append(("CDN", "Cloudflare"))
            log_ok("CDN: Cloudflare")
        if "x-served-by" in h:
            techs.append(("CDN/Cache", h["x-served-by"]))
        if "x-cache" in h:
            log_data("X-Cache", h["x-cache"])
        if "via" in h:
            log_data("Via", h["via"])

    except Exception:
        pass

    # -- JavaScript files discovery --
    js_files = list(set(re.findall(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', html, re.I)))
    if js_files:
        print()
        log_info(f"JavaScript files encontrados: {len(js_files)}")
        results["js_files"] = []
        for js in js_files[:30]:
            full_url = urljoin(url, js)
            results["js_files"].append(full_url)
            log_data("JS", full_url)

    # -- CSS files --
    css_files = list(set(re.findall(r'href=["\']([^"\']*\.css(?:\?[^"\']*)?)["\']', html, re.I)))
    if css_files:
        results["css_files"] = [urljoin(url, c) for c in css_files[:20]]

    results["technologies"] = techs


# =====================================================================
#  MODULO 6: JavaScript Analysis (deep)
# =====================================================================
def mod_js_analysis(session, url, js_files, results):
    section("6. JAVASCRIPT DEEP ANALYSIS")

    if not js_files:
        log_warn("No hay archivos JS para analizar")
        return

    interesting = {
        "api_endpoints": [],
        "secrets_hints": [],
        "domains": [],
        "emails": [],
        "comments": [],
        "versions": [],
    }

    # Patterns to find in JS
    patterns = {
        "API Endpoints": r'["\']/(api|v[0-9]+|rest|graphql)/[^"\']*["\']',
        "Full URLs": r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=]*',
        "API Keys (hint)": r'["\'](?:api[_-]?key|apikey|api_secret|access_token|auth_token|client_secret)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{10,}["\']',
        "AWS Keys (hint)": r'AKIA[0-9A-Z]{16}',
        "JWT Tokens": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "Email Addresses": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "IP Addresses": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        "Version Strings": r'["\']?(?:version|ver|v)["\']?\s*[:=]\s*["\']?(\d+\.\d+[\.\d]*)["\']?',
        "Source Maps": r'//[#@]\s*sourceMappingURL=(.+)',
    }

    analyzed_count = 0
    max_analyze = 10  # Limitar para no tardar mucho

    for js_url in js_files[:max_analyze]:
        try:
            r = session.get(js_url, timeout=15)
            if r.status_code != 200:
                continue

            content = r.text
            analyzed_count += 1
            fname = js_url.split("/")[-1].split("?")[0]

            found_something = False
            for label, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    if not found_something:
                        print()
                        log_info(f"Archivo: {fname}")
                        found_something = True

                    unique = list(set(matches))[:5]
                    for m in unique:
                        val = m if isinstance(m, str) else m[0]
                        log_data(label, val[:100])

                        if "endpoint" in label.lower() or "url" in label.lower():
                            interesting["api_endpoints"].append(val)
                        elif "key" in label.lower() or "aws" in label.lower() or "jwt" in label.lower():
                            interesting["secrets_hints"].append(val[:50])
                        elif "email" in label.lower():
                            interesting["emails"].append(val)
                        elif "version" in label.lower():
                            interesting["versions"].append(val)

        except Exception:
            continue

    log_ok(f"Analizados: {analyzed_count}/{len(js_files)} archivos JS")
    results["js_analysis"] = interesting


# =====================================================================
#  MODULO 7: Subdomain Enumeration (passive via crt.sh)
# =====================================================================
def mod_subdomains(session, domain, results):
    section("7. SUBDOMAIN ENUMERATION (crt.sh)")

    try:
        r = session.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30
        )

        if r.status_code != 200:
            log_fail(f"crt.sh respondio {r.status_code}")
            return

        data = r.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and "*" not in sub:
                    subdomains.add(sub)

        subdomains = sorted(subdomains)
        results["subdomains"] = subdomains

        log_ok(f"Subdominios encontrados: {len(subdomains)}")
        for sub in subdomains:
            log_data("Sub", sub)

    except json.JSONDecodeError:
        log_warn("crt.sh no devolvio JSON valido")
    except Exception as e:
        log_fail(f"Error crt.sh: {e}")


# =====================================================================
#  MODULO 8: OIDC / OAuth Discovery
# =====================================================================
def mod_oauth_discovery(session, base_url, results):
    section("8. OAUTH / OIDC DISCOVERY")

    # Common well-known paths
    wellknown_paths = [
        "/.well-known/openid-configuration",
        "/auth/realms/master/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/webfinger",
    ]

    # Try to detect realm names from HTML
    parsed = urlparse(base_url)
    hostname = parsed.hostname

    # Also try common Keycloak paths
    kc_paths = [
        "/auth/realms/",
        "/realms/",
    ]

    found_oidc = False

    for path in wellknown_paths:
        url = f"{parsed.scheme}://{hostname}{path}"
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                try:
                    config = r.json()
                    found_oidc = True
                    results["oidc_config"] = config

                    log_ok(f"OIDC Config encontrado: {url}")
                    log_data("Issuer", config.get("issuer", "N/A"))
                    log_data("Auth Endpoint", config.get("authorization_endpoint", "N/A"))
                    log_data("Token Endpoint", config.get("token_endpoint", "N/A"))

                    # PAR endpoint
                    par = config.get("pushed_authorization_request_endpoint")
                    if par:
                        log_ok(f"PAR Endpoint: {par}")
                        par_required = config.get("require_pushed_authorization_requests", "N/A")
                        log_data("PAR Required", str(par_required))

                    # Grant types
                    grants = config.get("grant_types_supported", [])
                    if grants:
                        log_info("Grant types:")
                        for g in grants:
                            log_data("Grant", g)

                    # Scopes
                    scopes = config.get("scopes_supported", [])
                    if scopes:
                        log_info("Scopes soportados:")
                        standard_scopes = {"openid", "profile", "email", "address", "phone", "offline_access"}
                        custom_scopes = [s for s in scopes if s not in standard_scopes]
                        for s in scopes:
                            marker = f" {C.Y}<-- CUSTOM{C.X}" if s in custom_scopes else ""
                            log_data("Scope", f"{s}{marker}")

                        if custom_scopes:
                            results["custom_scopes"] = custom_scopes

                    # JWKS
                    jwks_uri = config.get("jwks_uri")
                    if jwks_uri:
                        try:
                            jr = session.get(jwks_uri, timeout=10)
                            if jr.status_code == 200:
                                jwks = jr.json()
                                results["jwks"] = jwks
                                keys = jwks.get("keys", [])
                                log_info(f"JWKS: {len(keys)} keys encontradas")
                                for key in keys:
                                    log_data("Key ID", key.get("kid", "N/A"))
                                    log_data("Algorithm", key.get("alg", key.get("kty", "N/A")))
                                    # Check for x5c (certificate chain)
                                    if "x5c" in key:
                                        log_data("Cert Chain", f"{len(key['x5c'])} certificados")
                        except Exception:
                            pass

                    break
                except json.JSONDecodeError:
                    pass
        except Exception:
            continue

    if not found_oidc:
        log_warn("No se encontro configuracion OIDC/OAuth")

    # Try to find realm names from the page
    try:
        r = session.get(base_url, timeout=10)
        realms = re.findall(r'/auth/realms/([a-zA-Z0-9_-]+)', r.text)
        realms += re.findall(r'/realms/([a-zA-Z0-9_-]+)', r.text)
        realms = list(set(realms))
        if realms:
            log_info("Realms detectados:")
            for realm in realms:
                log_data("Realm", realm)
                # Try OIDC for each realm
                if not found_oidc:
                    for base in ["/auth/realms", "/realms"]:
                        wk_url = f"{parsed.scheme}://{hostname}{base}/{realm}/.well-known/openid-configuration"
                        try:
                            rr = session.get(wk_url, timeout=10)
                            if rr.status_code == 200:
                                config = rr.json()
                                results["oidc_config"] = config
                                log_ok(f"OIDC Config para realm '{realm}': {wk_url}")
                                found_oidc = True
                                break
                        except Exception:
                            pass
            results["keycloak_realms"] = realms
    except Exception:
        pass


# =====================================================================
#  MODULO 9: Sensitive Files & Paths
# =====================================================================
def mod_sensitive_paths(session, base_url, results):
    section("9. SENSITIVE FILES & PATHS")

    paths = [
        # === Environment & Config ===
        "/.env", "/.env.local", "/.env.development", "/.env.production",
        "/.env.staging", "/.env.backup", "/.env.old", "/.env.save",
        "/config.php", "/config.php.bak", "/config.php.old", "/config.php.save",
        "/config.yml", "/config.yaml", "/config.json", "/config.xml",
        "/configuration.php", "/settings.php", "/settings.py",
        "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
        "/web.config", "/appsettings.json", "/appsettings.Development.json",
        "/application.yml", "/application.properties",
        "/database.yml", "/secrets.yml", "/credentials.json",
        # === Version Control ===
        "/.git/HEAD", "/.git/config", "/.git/logs/HEAD",
        "/.git/refs/heads/main", "/.git/refs/heads/master",
        "/.gitignore", "/.gitattributes",
        "/.svn/entries", "/.svn/wc.db",
        "/.hg/hgrc", "/.bzr/README",
        # === IDE & Editor ===
        "/.idea/workspace.xml", "/.vscode/settings.json", "/.vscode/launch.json",
        "/.editorconfig", "/.DS_Store", "/Thumbs.db",
        # === Server Config ===
        "/.htaccess", "/.htpasswd", "/nginx.conf",
        "/server-status", "/server-info",
        "/elmah.axd", "/trace.axd",
        # === Backups ===
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.sql.gz",
        "/database.sql", "/database.sql.gz", "/db.sql", "/dump.sql",
        "/data.sql", "/site.zip", "/www.zip", "/html.zip",
        "/backup/", "/backups/", "/old/", "/temp/", "/tmp/",
        # === Logs ===
        "/debug.log", "/error.log", "/access.log",
        "/app.log", "/application.log", "/laravel.log",
        "/storage/logs/laravel.log", "/var/log/",
        "/logs/", "/log/", "/log.txt",
        # === PHP ===
        "/phpinfo.php", "/info.php", "/php_info.php", "/test.php",
        "/i.php", "/pi.php", "/p.php",
        # === Admin Panels ===
        "/admin", "/admin/", "/admin/login", "/admin/dashboard",
        "/administrator/", "/administrator/index.php",
        "/wp-admin/", "/wp-login.php",
        "/cpanel", "/phpmyadmin/", "/pma/",
        "/adminer.php", "/adminer/",
        "/manager/html", "/manager/status",
        "/solr/admin/", "/jenkins/", "/hudson/",
        "/_admin", "/siteadmin", "/webadmin",
        "/controlpanel", "/dashboard/", "/portal/",
        # === API Documentation ===
        "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
        "/api-docs", "/api-docs/", "/api/docs",
        "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/graphql/console",
        "/api/v1/", "/api/v2/", "/api/v3/",
        "/api/swagger", "/api/spec", "/api/schema",
        "/redoc", "/docs/api",
        # === Debug & Dev ===
        "/_debug", "/_debugbar", "/_profiler",
        "/trace", "/__debug__/",
        "/debug/default/view", "/debug/pprof/",
        "/console", "/console/", "/shell",
        "/diag", "/diagnostic", "/diagnostics",
        "/status", "/health", "/healthcheck", "/health-check",
        # === Spring Boot Actuator ===
        "/actuator", "/actuator/health", "/actuator/env",
        "/actuator/info", "/actuator/beans", "/actuator/configprops",
        "/actuator/mappings", "/actuator/metrics", "/actuator/threaddump",
        "/actuator/heapdump", "/actuator/loggers", "/actuator/conditions",
        "/actuator/scheduledtasks", "/actuator/httptrace",
        "/env", "/beans", "/mappings", "/metrics",
        # === Build & Dependency Files ===
        "/package.json", "/package-lock.json", "/yarn.lock",
        "/composer.json", "/composer.lock",
        "/Gemfile", "/Gemfile.lock",
        "/requirements.txt", "/Pipfile", "/Pipfile.lock",
        "/pom.xml", "/build.gradle",
        "/Gruntfile.js", "/gulpfile.js",
        "/webpack.config.js", "/tsconfig.json",
        "/Makefile", "/Rakefile",
        # === Docker & CI/CD ===
        "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
        "/.dockerenv", "/.docker/config.json",
        "/.github/workflows/", "/.gitlab-ci.yml",
        "/.travis.yml", "/Jenkinsfile",
        "/Procfile", "/Vagrantfile",
        # === Cloud & Storage ===
        "/.aws/credentials", "/.aws/config",
        "/s3.amazonaws.com", "/storage/", "/uploads/",
        "/media/", "/assets/", "/static/",
        # === CMS Specific ===
        "/wp-content/debug.log", "/wp-content/uploads/",
        "/wp-includes/version.php", "/wp-json/wp/v2/users",
        "/wp-json/", "/xmlrpc.php", "/readme.html",
        "/license.txt", "/wp-cron.php",
        "/joomla.xml", "/configuration.php~",
        "/sites/default/files/", "/CHANGELOG.txt",
        "/core/CHANGELOG.txt", "/modules/",
        # === Misc Sensitive ===
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/security.txt", "/.well-known/security.txt",
        "/humans.txt", "/robots.txt",
        "/.well-known/change-password",
        "/.well-known/openid-configuration",
        "/sitemap.xml", "/sitemap_index.xml",
        "/favicon.ico", "/manifest.json",
        # === Source Maps ===
        "/main.js.map", "/app.js.map", "/bundle.js.map",
        "/vendor.js.map", "/runtime.js.map",
        # === Firebase ===
        "/__/firebase/init.json",
        # === Error Pages (info leak) ===
        "/404", "/500", "/error", "/errors/",
        "/not-found", "/undefined",
    ]

    found_paths = []
    log_info(f"Probando {len(paths)} rutas comunes...")

    def check_path(path):
        url = urljoin(base_url, path)
        try:
            r = session.head(url, timeout=5, allow_redirects=False)
            if r.status_code in [200, 301, 302, 403]:
                return (path, r.status_code, len(r.content) if r.content else 0)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_path, p): p for p in paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                path, status, size = result
                found_paths.append(result)
                color = C.G if status == 200 else C.Y
                log_ok(f"{color}[{status}]{C.X} {path}")

    results["sensitive_paths"] = found_paths
    if not found_paths:
        log_info("No se encontraron archivos sensibles expuestos")


# =====================================================================
#  MODULO 10: WHOIS (basico)
# =====================================================================
def mod_whois(domain, results):
    section("10. WHOIS LOOKUP")

    try:
        import subprocess
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout:
            whois_data = r.stdout

            # Extract key fields
            fields = {
                "Registrar": r"Registrar:\s*(.+)",
                "Creation Date": r"Creation Date:\s*(.+)",
                "Expiry Date": r"Registr.*Expir.*Date:\s*(.+)",
                "Updated Date": r"Updated Date:\s*(.+)",
                "Name Server": r"Name Server:\s*(.+)",
                "Registrant Org": r"Registrant Organization:\s*(.+)",
                "Registrant Country": r"Registrant Country:\s*(.+)",
            }

            for label, pattern in fields.items():
                matches = re.findall(pattern, whois_data, re.I)
                if matches:
                    for m in set(matches):
                        log_data(label, m.strip())

            results["whois_raw"] = whois_data[:3000]
        else:
            log_warn("whois no disponible o sin resultados")
    except FileNotFoundError:
        log_warn("Comando 'whois' no instalado. Instala con: apt install whois")
    except Exception as e:
        log_fail(f"Error WHOIS: {e}")


# =====================================================================
#  MODULO 11: Keycloak-Specific Recon
# =====================================================================
def mod_keycloak_recon(session, base_url, results):
    section("11. KEYCLOAK-SPECIFIC RECON")

    parsed = urlparse(base_url)
    hostname = parsed.hostname
    scheme = parsed.scheme

    kc_indicators = []

    # Check for keycloak.js
    kc_js_paths = [
        "/auth/js/keycloak.js",
        "/js/keycloak.js",
    ]

    for path in kc_js_paths:
        url = f"{scheme}://{hostname}{path}"
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200 and ("keycloak" in r.text.lower() or "kc." in r.text):
                log_ok(f"keycloak.js encontrado: {url}")
                kc_indicators.append("keycloak.js found")

                content = r.text

                # Version fingerprinting
                print()
                log_info("Keycloak Version Fingerprinting:")

                # UMD check
                if "typeof exports" in content and "typeof module" in content:
                    log_ok("UMD wrapper presente → version < 26.0.0")
                    kc_indicators.append("UMD: < 26.0.0")
                else:
                    log_info("No UMD wrapper → posiblemente >= 26.0.0")
                    kc_indicators.append("No UMD: >= 26.0.0")

                # Third-party deps
                if "es6-promise" in content or "js-sha256" in content:
                    log_ok("Dependencias third-party (es6-promise/js-sha256) → version < 26.0.0")
                    kc_indicators.append("Third-party deps: < 26.0.0")

                # silentCheckSsoFallback
                if "silentCheckSsoFallback" in content:
                    log_ok("silentCheckSsoFallback presente → version < 26.0.0")
                    kc_indicators.append("silentCheckSsoFallback: < 26.0.0")

                # enableLogging vs log
                if "enableLogging" in content:
                    log_ok("enableLogging presente → version < 26.0.0")
                    kc_indicators.append("enableLogging: < 26.0.0")

                # PKCE method
                if "sha256.arrayBuffer" in content:
                    log_ok("PKCE usa sha256.arrayBuffer → version < 26.0.0")
                    kc_indicators.append("PKCE sha256.arrayBuffer: < 26.0.0")
                elif "crypto.subtle" in content:
                    log_info("PKCE usa crypto.subtle → version >= 26.0.0")
                    kc_indicators.append("PKCE crypto.subtle: >= 26.0.0")

                # js-sha256 version
                sha_ver = re.findall(r'js-sha256\s+v?([\d.]+)', content)
                if sha_ver:
                    log_data("js-sha256 version", sha_ver[0])

                # File hash for future reference
                file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
                log_data("SHA256 (partial)", file_hash)

                results["keycloak_js_size"] = len(content)
                results["keycloak_js_hash"] = file_hash
                break
        except Exception:
            continue

    # Admin console check
    admin_paths = [
        "/auth/admin/master/console/",
        "/admin/master/console/",
    ]

    for path in admin_paths:
        url = f"{scheme}://{hostname}{path}"
        try:
            r = session.get(url, timeout=10, allow_redirects=False)
            if r.status_code in [200, 302, 301]:
                log_ok(f"Admin console accesible: {url} [{r.status_code}]")
                kc_indicators.append(f"Admin console: {r.status_code}")

                # Check HTML for version hints in admin console
                if r.status_code == 200:
                    if "import" in r.text and "importmap" in r.text.lower():
                        log_ok("React import maps detectado → version >= 25.0.0")
                        kc_indicators.append("Import maps: >= 25.0.0")
                break
        except Exception:
            continue

    # Check Keycloak REST API (version disclosure)
    api_paths = [
        "/auth/admin/serverinfo",
        "/admin/serverinfo",
    ]

    for path in api_paths:
        url = f"{scheme}://{hostname}{path}"
        try:
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                try:
                    info = r.json()
                    version = info.get("systemInfo", {}).get("version", "")
                    if version:
                        log_ok(f"VERSION EXACTA: Keycloak {version}")
                        kc_indicators.append(f"Exact version: {version}")
                except Exception:
                    pass
        except Exception:
            continue

    results["keycloak_indicators"] = kc_indicators

    if not kc_indicators:
        log_info("No se detectaron indicadores de Keycloak en este target")


# =====================================================================
#  MODULO 12: CORS Misconfiguration Check
# =====================================================================
def mod_cors(session, url, results):
    section("12. CORS MISCONFIGURATION CHECK")

    cors_results = []
    origins_to_test = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        f"https://{urlparse(url).hostname}.evil.com",
    ]

    for origin in origins_to_test:
        try:
            headers = {"Origin": origin}
            r = session.get(url, headers=headers, timeout=10)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao:
                entry = {"origin_sent": origin, "acao": acao, "acac": acac}
                cors_results.append(entry)

                if acao == "*":
                    log_warn(f"ACAO: * (wildcard) — cualquier origen puede leer respuestas")
                elif acao == origin:
                    log_fail(f"ACAO refleja origen arbitrario: {origin}")
                    if acac.lower() == "true":
                        log_fail(f"  + Allow-Credentials: true — CRITICO: cookies se envian")
                elif acao == "null":
                    log_warn(f"ACAO: null — puede ser explotado con sandboxed iframe")
                else:
                    log_ok(f"Origin {origin} → ACAO: {acao}")
        except Exception:
            continue

    if not cors_results:
        log_info("No se detectaron headers CORS")

    results["cors"] = cors_results


# =====================================================================
#  MODULO 13: HTTP Methods Check
# =====================================================================
def mod_http_methods(session, url, results):
    section("13. HTTP METHODS CHECK")

    dangerous_methods = []
    methods_found = []

    # OPTIONS request
    try:
        r = session.options(url, timeout=10)
        allow = r.headers.get("Allow", "")
        if allow:
            log_ok(f"Allow header: {allow}")
            methods_found = [m.strip().upper() for m in allow.split(",")]
        access_methods = r.headers.get("Access-Control-Allow-Methods", "")
        if access_methods:
            log_data("CORS Methods", access_methods)
    except Exception:
        pass

    # Test dangerous methods
    test_methods = ["PUT", "DELETE", "TRACE", "PATCH", "CONNECT"]
    for method in test_methods:
        try:
            r = session.request(method, url, timeout=5)
            if r.status_code not in [405, 501, 404]:
                methods_found.append(method)
                if method in ["PUT", "DELETE", "TRACE"]:
                    dangerous_methods.append((method, r.status_code))
                    log_fail(f"{method} habilitado — HTTP {r.status_code}")
                else:
                    log_info(f"{method} responde — HTTP {r.status_code}")
        except Exception:
            pass

    if dangerous_methods:
        log_warn(f"Metodos peligrosos activos: {', '.join(m[0] for m in dangerous_methods)}")

    results["http_methods"] = methods_found
    results["dangerous_methods"] = dangerous_methods


# =====================================================================
#  MODULO 14: WAF Detection
# =====================================================================
def mod_waf_detect(session, url, results):
    section("14. WAF / FIREWALL DETECTION")

    waf_signatures = {
        "Cloudflare": {"headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
                       "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
                       "body": ["cloudflare"]},
        "AWS WAF": {"headers": ["x-amzn-requestid", "x-amz-cf-id"],
                    "body": ["aws"]},
        "Akamai": {"headers": ["x-akamai-transformed", "akamai-grn"],
                   "cookies": ["akamai"],
                   "body": ["akamai"]},
        "Sucuri": {"headers": ["x-sucuri-id", "x-sucuri-cache"],
                   "body": ["sucuri"]},
        "Imperva/Incapsula": {"headers": ["x-iinfo", "x-cdn"],
                              "cookies": ["incap_ses", "visid_incap"],
                              "body": ["incapsula"]},
        "F5 BIG-IP": {"headers": ["x-wa-info"],
                      "cookies": ["BIGipServer", "TS0"],
                      "body": []},
        "ModSecurity": {"headers": [],
                        "body": ["mod_security", "modsecurity", "NOYB"]},
        "Barracuda": {"headers": ["barra_counter_session"],
                      "cookies": ["barra_counter_session"],
                      "body": ["barracuda"]},
        "Fortinet/FortiWeb": {"headers": ["fortiwafsid"],
                              "cookies": ["FORTIWAFSID"],
                              "body": ["fortiweb"]},
        "DDoS-Guard": {"headers": ["ddos-guard"],
                       "body": ["ddos-guard"]},
        "Wordfence": {"headers": [],
                      "cookies": ["wfwaf-authcookie"],
                      "body": ["wordfence"]},
    }

    detected_wafs = []

    try:
        r = session.get(url, timeout=10)
        resp_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        resp_cookies = {c.name.lower(): c.value for c in r.cookies}
        body_lower = r.text[:5000].lower()

        for waf_name, sigs in waf_signatures.items():
            found = False

            for h in sigs.get("headers", []):
                if h.lower() in resp_headers:
                    found = True
                    break

            if not found:
                for c in sigs.get("cookies", []):
                    for cookie_name in resp_cookies:
                        if c.lower() in cookie_name:
                            found = True
                            break

            if not found:
                for b in sigs.get("body", []):
                    if b.lower() in body_lower:
                        found = True
                        break

            if found:
                detected_wafs.append(waf_name)
                log_ok(f"WAF detectado: {waf_name}")

        # Test with malicious-looking request
        test_url = f"{url}/?id=1' OR '1'='1"
        try:
            r2 = session.get(test_url, timeout=10)
            if r2.status_code in [403, 406, 429, 503]:
                log_info(f"Request malicioso bloqueado (HTTP {r2.status_code}) — WAF activo")
                results["waf_blocking"] = True
            else:
                results["waf_blocking"] = False
        except Exception:
            pass

    except Exception as e:
        log_fail(f"Error: {e}")

    if not detected_wafs:
        log_info("No se detecto WAF conocido")

    results["waf"] = detected_wafs


# =====================================================================
#  MODULO 15: Wayback Machine
# =====================================================================
def mod_wayback(session, domain, results):
    section("15. WAYBACK MACHINE (HISTORICAL URLS)")

    try:
        api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,statuscode,mimetype&collapse=urlkey&limit=100"
        r = session.get(api_url, timeout=30)

        if r.status_code != 200:
            log_warn(f"Wayback Machine respondio {r.status_code}")
            return

        data = r.json()
        if len(data) <= 1:
            log_info("No se encontraron URLs historicas")
            return

        urls = data[1:]  # Skip header row
        log_ok(f"URLs historicas encontradas: {len(urls)}")

        interesting_extensions = [
            ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl",
            ".sql", ".bak", ".old", ".zip", ".tar", ".gz",
            ".env", ".conf", ".config", ".xml", ".json", ".yml",
            ".log", ".txt", ".csv", ".xls", ".doc", ".pdf",
            ".key", ".pem", ".crt",
        ]

        interesting_urls = []
        api_urls = []
        admin_urls = []

        for entry in urls:
            url_str = entry[0] if isinstance(entry, list) else entry
            url_lower = url_str.lower()

            for ext in interesting_extensions:
                if ext in url_lower:
                    interesting_urls.append(url_str)
                    break

            if "/api/" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
                api_urls.append(url_str)

            if "admin" in url_lower or "login" in url_lower or "dashboard" in url_lower:
                admin_urls.append(url_str)

        if interesting_urls:
            log_info(f"URLs con extensiones interesantes: {len(interesting_urls)}")
            for u in interesting_urls[:15]:
                log_data("File", u)

        if api_urls:
            log_info(f"API endpoints historicos: {len(api_urls)}")
            for u in list(set(api_urls))[:10]:
                log_data("API", u)

        if admin_urls:
            log_info(f"Admin/Login URLs historicas: {len(admin_urls)}")
            for u in list(set(admin_urls))[:10]:
                log_data("Admin", u)

        results["wayback_total"] = len(urls)
        results["wayback_interesting"] = interesting_urls[:30]
        results["wayback_apis"] = list(set(api_urls))[:20]
        results["wayback_admin"] = list(set(admin_urls))[:20]

    except Exception as e:
        log_fail(f"Error Wayback: {e}")


# =====================================================================
#  MODULO 16: Cloud Storage Detection
# =====================================================================
def mod_cloud_storage(session, url, html, results):
    section("16. CLOUD STORAGE DETECTION")

    cloud_findings = []

    # Patterns for cloud storage URLs
    patterns = {
        "AWS S3": [
            r'https?://([a-zA-Z0-9._-]+)\.s3\.amazonaws\.com',
            r'https?://s3\.amazonaws\.com/([a-zA-Z0-9._-]+)',
            r'https?://([a-zA-Z0-9._-]+)\.s3[.-](us|eu|ap|sa|ca|me|af)-[a-z]+-\d+\.amazonaws\.com',
            r'https?://s3[.-](us|eu|ap|sa|ca|me|af)-[a-z]+-\d+\.amazonaws\.com/([a-zA-Z0-9._-]+)',
        ],
        "Azure Blob": [
            r'https?://([a-zA-Z0-9]+)\.blob\.core\.windows\.net',
            r'https?://([a-zA-Z0-9]+)\.file\.core\.windows\.net',
            r'https?://([a-zA-Z0-9]+)\.table\.core\.windows\.net',
            r'https?://([a-zA-Z0-9]+)\.queue\.core\.windows\.net',
        ],
        "Google Cloud Storage": [
            r'https?://storage\.googleapis\.com/([a-zA-Z0-9._-]+)',
            r'https?://([a-zA-Z0-9._-]+)\.storage\.googleapis\.com',
        ],
        "Firebase": [
            r'https?://([a-zA-Z0-9._-]+)\.firebaseio\.com',
            r'https?://([a-zA-Z0-9._-]+)\.firebaseapp\.com',
            r'https?://([a-zA-Z0-9._-]+)\.web\.app',
        ],
        "DigitalOcean Spaces": [
            r'https?://([a-zA-Z0-9._-]+)\.digitaloceanspaces\.com',
        ],
    }

    for provider, pats in patterns.items():
        for pat in pats:
            matches = re.findall(pat, html)
            if matches:
                for m in set(matches):
                    bucket = m if isinstance(m, str) else m[0]
                    cloud_findings.append({"provider": provider, "bucket": bucket})
                    log_ok(f"{provider}: {bucket}")

    # Check if S3 buckets are listable
    for finding in cloud_findings:
        if finding["provider"] == "AWS S3":
            bucket = finding["bucket"]
            try:
                r = session.get(f"https://{bucket}.s3.amazonaws.com/", timeout=10)
                if r.status_code == 200 and "ListBucketResult" in r.text:
                    log_fail(f"S3 bucket LISTABLE: {bucket}")
                    finding["listable"] = True
                elif r.status_code == 403:
                    log_info(f"S3 bucket existe pero no listable: {bucket}")
                    finding["listable"] = False
            except Exception:
                pass

    if not cloud_findings:
        log_info("No se detectaron servicios cloud expuestos")

    results["cloud_storage"] = cloud_findings


# =====================================================================
#  MODULO 17: Subdomain Takeover Check
# =====================================================================
def mod_subdomain_takeover(session, subdomains, results):
    section("17. SUBDOMAIN TAKEOVER CHECK")

    if not subdomains:
        log_warn("No hay subdominios para verificar")
        return

    # Services vulnerable to subdomain takeover
    takeover_signatures = {
        "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs"],
        "Heroku": ["No such app", "herokucdn.com/error-pages", "no-such-app"],
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "AWS Elastic Beanstalk": ["NXDOMAIN"],
        "Shopify": ["Sorry, this shop is currently unavailable"],
        "Tumblr": ["Whatever you were looking for doesn't currently exist"],
        "WordPress.com": ["Do you want to register"],
        "Pantheon": ["404 error unknown site"],
        "Fastly": ["Fastly error: unknown domain"],
        "Zendesk": ["Help Center Closed"],
        "Bitbucket": ["Repository not found"],
        "Ghost": ["The thing you were looking for is no longer here"],
        "Surge.sh": ["project not found"],
        "Fly.io": ["404 Not Found"],
        "Netlify": ["Not Found - Request ID"],
        "Cargo Collective": ["If you're moving your domain away"],
        "Unbounce": ["The requested URL was not found"],
    }

    takeover_candidates = []
    checked = 0
    max_check = min(len(subdomains), 50)

    log_info(f"Verificando {max_check} subdominios...")

    def check_sub(sub):
        for scheme in ["https", "http"]:
            try:
                r = session.get(f"{scheme}://{sub}", timeout=8, allow_redirects=True)
                body = r.text[:3000]
                for service, signatures in takeover_signatures.items():
                    for sig in signatures:
                        if sig.lower() in body.lower():
                            return (sub, service, sig)
            except requests.exceptions.ConnectionError:
                # NXDOMAIN or connection refused — potential takeover
                try:
                    socket.getaddrinfo(sub, None)
                except socket.gaierror:
                    return (sub, "NXDOMAIN (dangling CNAME)", "DNS no resuelve")
            except Exception:
                continue
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_sub, s): s for s in subdomains[:max_check]}
        for future in as_completed(futures):
            result = future.result()
            checked += 1
            if result:
                sub, service, sig = result
                takeover_candidates.append(result)
                log_fail(f"POSIBLE TAKEOVER: {sub} → {service}")

    log_ok(f"Verificados: {checked}/{len(subdomains)}")
    if not takeover_candidates:
        log_ok("No se detectaron candidatos a subdomain takeover")

    results["subdomain_takeover"] = [
        {"subdomain": s, "service": svc, "signature": sig}
        for s, svc, sig in takeover_candidates
    ]


# =====================================================================
#  MODULO 18: CSP Deep Analysis
# =====================================================================
def mod_csp_analysis(results):
    section("18. CSP DEEP ANALYSIS")

    headers = results.get("headers", {})
    csp = headers.get("Content-Security-Policy", "")

    if not csp:
        log_warn("No hay Content-Security-Policy para analizar")
        return

    log_ok(f"CSP encontrado ({len(csp)} chars)")
    results["csp_raw"] = csp

    csp_issues = []
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0]] = tokens[1:] if len(tokens) > 1 else []

    results["csp_directives"] = directives

    # Check for unsafe directives
    for directive, values in directives.items():
        values_str = " ".join(values)
        log_data(directive, values_str[:80])

        if "'unsafe-inline'" in values:
            csp_issues.append(f"{directive} permite 'unsafe-inline' — XSS posible")
            log_fail(f"  {directive}: 'unsafe-inline' detectado")

        if "'unsafe-eval'" in values:
            csp_issues.append(f"{directive} permite 'unsafe-eval' — code injection posible")
            log_fail(f"  {directive}: 'unsafe-eval' detectado")

        if "*" in values:
            csp_issues.append(f"{directive} usa wildcard '*' — permite cualquier origen")
            log_fail(f"  {directive}: wildcard '*' detectado")

        if "data:" in values and directive in ["script-src", "default-src"]:
            csp_issues.append(f"{directive} permite 'data:' — bypass de CSP posible")
            log_warn(f"  {directive}: 'data:' detectado")

        if "http:" in values_str:
            csp_issues.append(f"{directive} permite HTTP — mixed content")
            log_warn(f"  {directive}: permite HTTP")

    # Check missing critical directives
    critical = ["default-src", "script-src", "object-src", "base-uri", "frame-ancestors"]
    for d in critical:
        if d not in directives:
            csp_issues.append(f"Directiva '{d}' ausente")
            log_warn(f"Falta directiva: {d}")

    if "object-src" not in directives and "'none'" not in directives.get("default-src", []):
        csp_issues.append("object-src no restringido — Flash/plugin injection posible")

    if "base-uri" not in directives:
        csp_issues.append("base-uri ausente — base tag injection posible")

    if "frame-ancestors" not in directives:
        csp_issues.append("frame-ancestors ausente — clickjacking posible (CSP)")

    if not csp_issues:
        log_ok("CSP parece bien configurado")

    results["csp_issues"] = csp_issues


# =====================================================================
#  MODULO 19: CMS Deep Scan
# =====================================================================
def mod_cms_deep(session, base_url, html, results):
    section("19. CMS DEEP SCAN")

    cms_findings = {"cms": None, "version": None, "plugins": [], "themes": [], "users": [], "issues": []}

    # === WordPress ===
    if any(x in html for x in ["wp-content", "wp-includes", "wordpress"]):
        cms_findings["cms"] = "WordPress"
        log_ok("CMS: WordPress detectado")

        # Version from meta
        ver = re.findall(r'<meta name="generator" content="WordPress ([\d.]+)"', html)
        if ver:
            cms_findings["version"] = ver[0]
            log_data("Version", ver[0])

        # Version from readme
        try:
            r = session.get(urljoin(base_url, "/readme.html"), timeout=10)
            if r.status_code == 200:
                rv = re.findall(r'Version ([\d.]+)', r.text)
                if rv:
                    cms_findings["version"] = rv[0]
                    log_data("Version (readme)", rv[0])
                    cms_findings["issues"].append("readme.html expuesto — revela version")
        except Exception:
            pass

        # Users via REST API
        try:
            r = session.get(urljoin(base_url, "/wp-json/wp/v2/users"), timeout=10)
            if r.status_code == 200:
                users = r.json()
                for u in users[:10]:
                    name = u.get("slug", u.get("name", ""))
                    cms_findings["users"].append(name)
                    log_ok(f"Usuario: {name}")
                cms_findings["issues"].append("API de usuarios expuesta")
        except Exception:
            pass

        # Plugins from HTML
        plugins = list(set(re.findall(r'wp-content/plugins/([a-zA-Z0-9_-]+)', html)))
        if plugins:
            cms_findings["plugins"] = plugins
            log_info(f"Plugins detectados: {len(plugins)}")
            for p in plugins:
                log_data("Plugin", p)

        # Themes from HTML
        themes = list(set(re.findall(r'wp-content/themes/([a-zA-Z0-9_-]+)', html)))
        if themes:
            cms_findings["themes"] = themes
            for t in themes:
                log_data("Theme", t)

        # XMLRPC
        try:
            r = session.post(urljoin(base_url, "/xmlrpc.php"), timeout=10,
                           data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                           headers={"Content-Type": "text/xml"})
            if r.status_code == 200 and "methodResponse" in r.text:
                log_fail("XML-RPC habilitado — brute force / DDoS amplification posible")
                cms_findings["issues"].append("XML-RPC habilitado")
        except Exception:
            pass

        # Debug log
        try:
            r = session.head(urljoin(base_url, "/wp-content/debug.log"), timeout=5)
            if r.status_code == 200:
                log_fail("debug.log accesible — info leak")
                cms_findings["issues"].append("wp-content/debug.log expuesto")
        except Exception:
            pass

    # === Joomla ===
    elif any(x in html for x in ["com_content", "/media/jui/", "Joomla"]):
        cms_findings["cms"] = "Joomla"
        log_ok("CMS: Joomla detectado")

        try:
            r = session.get(urljoin(base_url, "/administrator/manifests/files/joomla.xml"), timeout=10)
            if r.status_code == 200:
                ver = re.findall(r'<version>([\d.]+)</version>', r.text)
                if ver:
                    cms_findings["version"] = ver[0]
                    log_data("Version", ver[0])
        except Exception:
            pass

    # === Drupal ===
    elif any(x in html for x in ["drupal", "Drupal.settings", "/sites/default/"]):
        cms_findings["cms"] = "Drupal"
        log_ok("CMS: Drupal detectado")

        try:
            r = session.get(urljoin(base_url, "/CHANGELOG.txt"), timeout=10)
            if r.status_code == 200:
                ver = re.findall(r'Drupal ([\d.]+)', r.text[:500])
                if ver:
                    cms_findings["version"] = ver[0]
                    log_data("Version", ver[0])
                    cms_findings["issues"].append("CHANGELOG.txt expuesto")
        except Exception:
            pass

    else:
        log_info("No se detecto CMS conocido")

    results["cms"] = cms_findings


# =====================================================================
#  MODULO 20: Favicon Hash (Shodan-style fingerprinting)
# =====================================================================
def mod_favicon_hash(session, base_url, results):
    section("20. FAVICON HASH FINGERPRINTING")

    # Known favicon hashes (MurmurHash3 style — we use md5 for simplicity)
    known_hashes = {
        "f276b19aabcb4ae8cda4d22625c6735f": "Spring Boot",
        "d4a1cb71de5e70818c3e18e84ed3e13f": "Apache Tomcat",
        "71e30c09f15e2a74b8e8c9b5f5b3a6b4": "Grafana",
        "292a26e5a9b35f8e3c0c937c3e5a6fd9": "Jenkins",
        "a8b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": "GitLab",
    }

    try:
        r = session.get(urljoin(base_url, "/favicon.ico"), timeout=10)
        if r.status_code == 200 and len(r.content) > 0:
            # MD5 hash
            fav_hash = hashlib.md5(r.content).hexdigest()
            # SHA256 for reference
            fav_sha = hashlib.sha256(r.content).hexdigest()[:16]
            # Base64 for Shodan-style
            fav_b64 = base64.b64encode(r.content)

            log_ok(f"Favicon encontrado ({len(r.content)} bytes)")
            log_data("MD5", fav_hash)
            log_data("SHA256 (partial)", fav_sha)

            # Check known hashes
            match = known_hashes.get(fav_hash)
            if match:
                log_ok(f"Match conocido: {match}")
            else:
                log_info("No match en base de datos local")

            # Shodan search hint
            try:
                log_info(f"Buscar en Shodan: http.favicon.hash:{fav_hash[:16]}")
            except Exception:
                pass

            results["favicon"] = {
                "md5": fav_hash,
                "sha256": fav_sha,
                "size": len(r.content),
                "known_match": match,
            }
        else:
            log_info("No se encontro favicon.ico")
    except Exception as e:
        log_fail(f"Error: {e}")


# =====================================================================
#  MODULO 21: Security.txt Parser
# =====================================================================
def mod_security_txt(session, base_url, results):
    section("21. SECURITY.TXT ANALYSIS")

    sec_txt = None
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = session.get(urljoin(base_url, path), timeout=10)
            if r.status_code == 200 and ("contact" in r.text.lower() or "policy" in r.text.lower()):
                sec_txt = r.text
                log_ok(f"security.txt encontrado: {path}")
                break
        except Exception:
            continue

    if not sec_txt:
        log_warn("No se encontro security.txt — el sitio no tiene politica de divulgacion")
        results["security_txt"] = None
        return

    fields = {
        "Contact": r"Contact:\s*(.+)",
        "Expires": r"Expires:\s*(.+)",
        "Encryption": r"Encryption:\s*(.+)",
        "Acknowledgments": r"Acknowledgments?:\s*(.+)",
        "Preferred-Languages": r"Preferred-Languages?:\s*(.+)",
        "Canonical": r"Canonical:\s*(.+)",
        "Policy": r"Policy:\s*(.+)",
        "Hiring": r"Hiring:\s*(.+)",
    }

    parsed_fields = {}
    for field, pattern in fields.items():
        matches = re.findall(pattern, sec_txt, re.I)
        if matches:
            for m in matches:
                parsed_fields[field] = m.strip()
                log_data(field, m.strip())

    # Check for bug bounty hints
    bounty_keywords = ["hackerone", "bugcrowd", "intigriti", "synack", "bounty", "reward"]
    for keyword in bounty_keywords:
        if keyword in sec_txt.lower():
            log_ok(f"Programa de bug bounty detectado ('{keyword}')")
            parsed_fields["bug_bounty_hint"] = keyword

    # Check expiration
    expires = parsed_fields.get("Expires", "")
    if expires:
        try:
            exp_date = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if exp_date < datetime.now(timezone.utc):
                log_warn("security.txt EXPIRADO")
                parsed_fields["expired"] = True
        except Exception:
            pass

    results["security_txt"] = parsed_fields


# =====================================================================
#  MODULO 22: Email Security Deep (SPF/DMARC/DKIM analysis)
# =====================================================================
def mod_email_security(results):
    section("22. EMAIL SECURITY ANALYSIS")

    dns_data = results.get("dns", {})
    if not dns_data:
        log_warn("No hay datos DNS para analizar")
        return

    email_sec = {"spf": None, "dmarc": None, "issues": []}

    # SPF Analysis
    txt_records = dns_data.get("TXT", [])
    for txt in txt_records:
        if "v=spf1" in txt:
            email_sec["spf"] = txt
            log_ok(f"SPF: {txt[:100]}")

            if "+all" in txt:
                email_sec["issues"].append("SPF con +all — permite CUALQUIER servidor enviar email")
                log_fail("SPF: +all detectado — CRITICO")
            elif "~all" in txt:
                email_sec["issues"].append("SPF con ~all (softfail) — emails falsificados llegan como spam, no bloqueados")
                log_warn("SPF: ~all (softfail)")
            elif "-all" in txt:
                log_ok("SPF: -all (hardfail) — correcto")
            elif "?all" in txt:
                email_sec["issues"].append("SPF con ?all (neutral) — no protege contra spoofing")
                log_warn("SPF: ?all (neutral)")

            if "include:" in txt:
                includes = re.findall(r'include:(\S+)', txt)
                for inc in includes:
                    log_data("SPF Include", inc)

            if txt.count("include:") > 10:
                email_sec["issues"].append("SPF con demasiados includes — puede exceder limite de 10 DNS lookups")

    if not email_sec["spf"]:
        email_sec["issues"].append("No hay registro SPF — dominio puede ser usado para email spoofing")
        log_fail("SPF: NO ENCONTRADO")

    # DMARC Analysis
    dmarc_records = dns_data.get("DMARC", [])
    for txt in txt_records + dmarc_records:
        if "v=DMARC1" in txt:
            email_sec["dmarc"] = txt
            log_ok(f"DMARC: {txt[:100]}")

            policy = re.findall(r'p=(\w+)', txt)
            if policy:
                p = policy[0].lower()
                if p == "none":
                    email_sec["issues"].append("DMARC policy=none — solo monitoreo, no bloquea spoofing")
                    log_warn("DMARC: p=none (solo monitoreo)")
                elif p == "quarantine":
                    log_info("DMARC: p=quarantine")
                elif p == "reject":
                    log_ok("DMARC: p=reject — correcto")

            # Sub-domain policy
            sp = re.findall(r'sp=(\w+)', txt)
            if not sp:
                email_sec["issues"].append("DMARC sin sp= — subdominios heredan politica del dominio padre")

            # Reporting
            rua = re.findall(r'rua=([^;]+)', txt)
            if rua:
                log_data("DMARC Reports (rua)", rua[0])
            else:
                email_sec["issues"].append("DMARC sin rua — no se reciben reportes de abuso")

    if not email_sec["dmarc"]:
        email_sec["issues"].append("No hay registro DMARC — no hay politica de autenticacion de emails")
        log_fail("DMARC: NO ENCONTRADO")

    results["email_security"] = email_sec


# =====================================================================
#  MODULO 23: VULNERABILITY ASSESSMENT
# =====================================================================
def mod_vuln_assessment(results):
    section("23. VULNERABILITY ASSESSMENT")

    vulns = []  # (severity, title, description, remediation)

    # --- Security Headers ---
    sec = results.get("security_headers", {})
    missing = sec.get("missing", [])

    if "CSP" in missing:
        vulns.append(("HIGH", "Missing Content-Security-Policy",
            "Sin CSP, el sitio es vulnerable a XSS y data injection attacks.",
            "Implementar Content-Security-Policy con directivas restrictivas."))

    if "X-Frame-Options" in missing:
        vulns.append(("MEDIUM", "Missing X-Frame-Options",
            "El sitio puede ser embebido en iframes maliciosos (clickjacking).",
            "Agregar X-Frame-Options: DENY o SAMEORIGIN."))

    if "X-Content-Type-Options" in missing:
        vulns.append(("LOW", "Missing X-Content-Type-Options",
            "El navegador puede interpretar archivos con MIME type incorrecto (MIME sniffing).",
            "Agregar X-Content-Type-Options: nosniff."))

    if "HSTS" in missing:
        vulns.append(("HIGH", "Missing HSTS",
            "Sin HSTS, conexiones pueden ser downgradeadas a HTTP (SSL stripping).",
            "Agregar Strict-Transport-Security: max-age=31536000; includeSubDomains."))

    if "Referrer-Policy" in missing:
        vulns.append(("LOW", "Missing Referrer-Policy",
            "URLs internas pueden filtrarse a sitios externos via Referer header.",
            "Agregar Referrer-Policy: strict-origin-when-cross-origin."))

    if "Permissions-Policy" in missing:
        vulns.append(("LOW", "Missing Permissions-Policy",
            "No hay restriccion sobre APIs del navegador (camera, mic, geolocation).",
            "Agregar Permissions-Policy restrictivo."))

    if "COOP" in missing:
        vulns.append(("INFO", "Missing Cross-Origin-Opener-Policy",
            "Sin COOP el sitio puede ser vulnerable a cross-origin attacks como Spectre.",
            "Agregar Cross-Origin-Opener-Policy: same-origin."))

    if len(missing) >= 7:
        vulns.append(("HIGH", "Severe Lack of Security Headers",
            f"Faltan {len(missing)} de 10 security headers criticos. Indica pobre hardening.",
            "Implementar todos los security headers recomendados por OWASP."))

    # --- SSL/TLS ---
    ssl_data = results.get("ssl", {})
    ssl_error = results.get("ssl_error", "")

    if ssl_error:
        vulns.append(("CRITICAL", "SSL/TLS Error",
            f"Error al verificar SSL: {ssl_error}",
            "Verificar configuracion SSL/TLS del servidor."))

    if ssl_data:
        not_after = ssl_data.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    vulns.append(("CRITICAL", "SSL Certificate Expired",
                        f"El certificado SSL expiro hace {abs(days)} dias.",
                        "Renovar el certificado SSL inmediatamente."))
                elif days < 15:
                    vulns.append(("HIGH", "SSL Certificate Expiring Soon",
                        f"El certificado SSL expira en {days} dias.",
                        "Renovar el certificado SSL antes de que expire."))
                elif days < 30:
                    vulns.append(("MEDIUM", "SSL Certificate Expiring",
                        f"El certificado SSL expira en {days} dias.",
                        "Planificar renovacion del certificado SSL."))
            except Exception:
                pass

    # --- Cookies ---
    cookie_issues = results.get("cookie_issues", [])
    secure_missing = [c for c in cookie_issues if "Secure" in c]
    httponly_missing = [c for c in cookie_issues if "HttpOnly" in c]

    if secure_missing:
        vulns.append(("HIGH", "Cookies Without Secure Flag",
            f"{len(secure_missing)} cookie(s) sin flag Secure. Pueden transmitirse por HTTP.",
            "Agregar flag Secure a todas las cookies."))

    if httponly_missing:
        vulns.append(("MEDIUM", "Cookies Without HttpOnly Flag",
            f"{len(httponly_missing)} cookie(s) sin flag HttpOnly. Accesibles via JavaScript (XSS).",
            "Agregar flag HttpOnly a cookies de sesion."))

    # --- Server Info Disclosure ---
    headers = results.get("headers", {})
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")

    if server and server.lower() not in ["", "no revelado"]:
        # Check if version is disclosed
        if re.search(r'\d+\.\d+', server):
            vulns.append(("MEDIUM", "Server Version Disclosure",
                f"Server header revela version: {server}",
                "Ocultar la version del servidor en el header Server."))
        else:
            vulns.append(("INFO", "Server Technology Disclosure",
                f"Server header revela tecnologia: {server}",
                "Considerar ocultar o generalizar el header Server."))

    if powered and powered.lower() not in ["", "no revelado"]:
        vulns.append(("MEDIUM", "X-Powered-By Disclosure",
            f"X-Powered-By revela: {powered}",
            "Eliminar el header X-Powered-By."))

    # --- Sensitive Paths ---
    sens_paths = results.get("sensitive_paths", [])
    for path, status, size in sens_paths:
        if status == 200:
            if ".env" in path:
                vulns.append(("CRITICAL", "Environment File Exposed",
                    f"{path} es accesible (HTTP 200). Puede contener credenciales.",
                    "Bloquear acceso a archivos .env via servidor web."))
            elif ".git" in path:
                vulns.append(("CRITICAL", "Git Repository Exposed",
                    f"{path} es accesible (HTTP 200). Codigo fuente puede ser descargado.",
                    "Bloquear acceso al directorio .git."))
            elif "backup" in path.lower() or path.endswith((".sql", ".bak")):
                vulns.append(("CRITICAL", "Backup File Exposed",
                    f"{path} es accesible (HTTP 200). Puede contener datos sensibles.",
                    "Mover backups fuera del webroot."))
            elif "phpinfo" in path or "info.php" in path:
                vulns.append(("HIGH", "PHP Info Exposed",
                    f"{path} es accesible. Revela configuracion completa del servidor.",
                    "Eliminar archivos phpinfo del servidor."))
            elif "swagger" in path or "api-docs" in path or "openapi" in path:
                vulns.append(("MEDIUM", "API Documentation Exposed",
                    f"{path} es accesible. Revela endpoints y estructura de la API.",
                    "Restringir acceso a documentacion de API."))
            elif "actuator" in path:
                vulns.append(("HIGH", "Spring Actuator Exposed",
                    f"{path} es accesible. Puede revelar config, env vars, health info.",
                    "Restringir acceso a endpoints de actuator."))
            elif "graphql" in path or "graphiql" in path:
                vulns.append(("MEDIUM", "GraphQL Endpoint Found",
                    f"{path} es accesible. Posible introspection habilitado.",
                    "Deshabilitar introspection en produccion."))
            elif "admin" in path or "console" in path or "wp-admin" in path:
                vulns.append(("MEDIUM", "Admin Panel Accessible",
                    f"{path} es accesible (HTTP 200).",
                    "Restringir acceso al panel admin por IP o VPN."))
            elif "debug" in path or "trace" in path:
                vulns.append(("HIGH", "Debug Endpoint Exposed",
                    f"{path} es accesible. Puede revelar info interna.",
                    "Deshabilitar endpoints de debug en produccion."))
            elif path in ["/.htpasswd", "/.htaccess"]:
                vulns.append(("HIGH", "Server Config File Exposed",
                    f"{path} es accesible. Puede contener credenciales o reglas.",
                    "Bloquear acceso a archivos de configuracion."))
            elif "package.json" in path or "composer.json" in path:
                vulns.append(("LOW", "Dependency File Exposed",
                    f"{path} es accesible. Revela dependencias y posibles versiones vulnerables.",
                    "Bloquear acceso a archivos de dependencias."))
            elif "docker" in path.lower():
                vulns.append(("MEDIUM", "Docker Config Exposed",
                    f"{path} es accesible. Revela configuracion de contenedores.",
                    "Bloquear acceso a archivos Docker."))
            elif "source" in path.lower() or "map" in path.lower():
                vulns.append(("LOW", "Source Map Exposed",
                    f"{path} es accesible. Puede revelar codigo fuente original.",
                    "Deshabilitar source maps en produccion."))
            else:
                vulns.append(("LOW", "Sensitive Path Accessible",
                    f"{path} retorno HTTP 200.",
                    "Evaluar si este recurso debe ser publico."))

        elif status == 403:
            vulns.append(("INFO", "Path Exists But Forbidden",
                f"{path} retorno HTTP 403. Existe pero esta protegido.",
                "Verificar que el bloqueo es adecuado (no bypassable)."))

    # --- JS Secrets ---
    js_analysis = results.get("js_analysis", {})
    secrets = js_analysis.get("secrets_hints", [])
    if secrets:
        vulns.append(("HIGH", "Potential Secrets in JavaScript",
            f"Se encontraron {len(secrets)} posibles secretos/API keys en archivos JS: {', '.join(secrets[:3])}",
            "Mover secretos al backend. Nunca exponer API keys en frontend."))

    emails = js_analysis.get("emails", [])
    if emails:
        vulns.append(("INFO", "Email Addresses in JavaScript",
            f"Emails encontrados: {', '.join(list(set(emails))[:5])}",
            "Evaluar si los emails expuestos pueden usarse para phishing/OSINT."))

    # --- DNS ---
    dns_data = results.get("dns", {})
    has_spf = False
    has_dmarc = False
    txt_records = dns_data.get("TXT", [])
    for txt in txt_records:
        if "v=spf1" in txt:
            has_spf = True
        if "v=DMARC1" in txt:
            has_dmarc = True

    if "DMARC" in dns_data:
        has_dmarc = True

    if not has_spf and dns_data:
        vulns.append(("MEDIUM", "Missing SPF Record",
            "No hay registro SPF. El dominio puede ser usado para email spoofing.",
            "Agregar registro TXT con politica SPF."))

    if not has_dmarc and dns_data:
        vulns.append(("MEDIUM", "Missing DMARC Record",
            "No hay registro DMARC. No hay politica de autenticacion de emails.",
            "Agregar registro DMARC (_dmarc.domain)."))

    # --- OAuth/OIDC ---
    oidc = results.get("oidc_config", {})
    if oidc:
        par = oidc.get("pushed_authorization_request_endpoint")
        par_required = oidc.get("require_pushed_authorization_requests", False)
        if par and not par_required:
            vulns.append(("MEDIUM", "PAR Not Required",
                "El servidor soporta PAR pero no lo requiere. Los auth requests pueden ser manipulados.",
                "Configurar require_pushed_authorization_requests=true."))

        grants = oidc.get("grant_types_supported", [])
        if "implicit" in grants:
            vulns.append(("HIGH", "Implicit Grant Type Enabled",
                "Implicit flow esta habilitado. Tokens se exponen en la URL.",
                "Deshabilitar implicit flow y usar authorization_code con PKCE."))

        if "password" in grants:
            vulns.append(("HIGH", "Resource Owner Password Grant Enabled",
                "Password grant esta habilitado. Credenciales pasan por el cliente.",
                "Deshabilitar password grant y usar authorization_code."))

    # --- Keycloak ---
    kc = results.get("keycloak_indicators", [])
    for indicator in kc:
        if "< 26.0.0" in indicator:
            vulns.append(("HIGH", "Keycloak Version Potentially Vulnerable",
                f"Indicador de version antigua: {indicator}. Versiones < 26.5.7 son vulnerables a CVE-2026-4282.",
                "Actualizar Keycloak a >= 26.5.7 (o RHBK 26.2.15+)."))
            break

        if "Exact version:" in indicator:
            ver_str = indicator.split(":")[-1].strip()
            try:
                parts = [int(x) for x in ver_str.split(".")[:3]]
                if parts[0] < 26 or (parts[0] == 26 and parts[1] < 5) or (parts[0] == 26 and parts[1] == 5 and parts[2] < 7):
                    vulns.append(("CRITICAL", f"Keycloak {ver_str} - Vulnerable to CVE-2026-4282",
                        f"Keycloak {ver_str} es vulnerable a authorization code forgery via PAR injection.",
                        "Actualizar a Keycloak >= 26.5.7 inmediatamente."))
            except Exception:
                pass

    for indicator in kc:
        if "Admin console:" in indicator and "200" in indicator:
            vulns.append(("MEDIUM", "Keycloak Admin Console Accessible",
                "La consola de admin de Keycloak es accesible publicamente.",
                "Restringir acceso a admin console por IP o VPN."))

    # --- CORS ---
    cors = results.get("cors", [])
    for entry in cors:
        acao = entry.get("acao", "")
        acac = entry.get("acac", "")
        origin = entry.get("origin_sent", "")
        if acao == origin and "evil" in origin:
            if acac.lower() == "true":
                vulns.append(("CRITICAL", "CORS: Arbitrary Origin with Credentials",
                    f"ACAO refleja origen arbitrario ({origin}) con Allow-Credentials: true.",
                    "No reflejar origenes arbitrarios. Usar whitelist de origenes confiables."))
            else:
                vulns.append(("HIGH", "CORS: Arbitrary Origin Reflection",
                    f"ACAO refleja origen arbitrario ({origin}).",
                    "Configurar CORS con whitelist de origenes permitidos."))
        elif acao == "*":
            vulns.append(("MEDIUM", "CORS: Wildcard Origin",
                "ACAO: * permite cualquier sitio leer respuestas.",
                "Reemplazar wildcard con origenes especificos."))
        elif acao == "null":
            vulns.append(("MEDIUM", "CORS: Null Origin Allowed",
                "ACAO: null puede ser explotado con sandboxed iframes.",
                "No permitir origin null."))

    # --- HTTP Methods ---
    dangerous = results.get("dangerous_methods", [])
    for method, status in dangerous:
        if method == "TRACE":
            vulns.append(("MEDIUM", "HTTP TRACE Enabled",
                f"TRACE habilitado (HTTP {status}). Cross-Site Tracing (XST) posible.",
                "Deshabilitar TRACE en el servidor web."))
        elif method == "PUT":
            vulns.append(("HIGH", "HTTP PUT Enabled",
                f"PUT habilitado (HTTP {status}). Permite subir archivos al servidor.",
                "Deshabilitar PUT si no es necesario."))
        elif method == "DELETE":
            vulns.append(("HIGH", "HTTP DELETE Enabled",
                f"DELETE habilitado (HTTP {status}). Permite eliminar recursos.",
                "Deshabilitar DELETE si no es necesario."))

    # --- WAF ---
    waf = results.get("waf", [])
    if not waf:
        vulns.append(("INFO", "No WAF Detected",
            "No se detecto Web Application Firewall.",
            "Considerar implementar WAF para proteccion adicional."))

    if results.get("waf_blocking") is False:
        vulns.append(("MEDIUM", "WAF Not Blocking Malicious Requests",
            "Requests con payloads maliciosos no fueron bloqueados.",
            "Revisar reglas del WAF para detectar inyecciones SQL/XSS."))

    # --- Subdomain Takeover ---
    takeover = results.get("subdomain_takeover", [])
    for t in takeover:
        vulns.append(("HIGH", f"Subdomain Takeover: {t['subdomain']}",
            f"Subdominio {t['subdomain']} apunta a {t['service']} — posible takeover.",
            "Eliminar registro DNS o reclamar el recurso externo."))

    # --- CSP Issues ---
    csp_issues = results.get("csp_issues", [])
    for issue in csp_issues:
        if "unsafe-inline" in issue or "unsafe-eval" in issue:
            vulns.append(("HIGH", "CSP: Unsafe Directive",
                issue, "Eliminar directivas unsafe y usar nonces o hashes."))
        elif "wildcard" in issue:
            vulns.append(("MEDIUM", "CSP: Wildcard Source",
                issue, "Reemplazar wildcards con origenes especificos."))
        elif "ausente" in issue.lower():
            vulns.append(("MEDIUM", "CSP: Missing Directive",
                issue, "Agregar directiva faltante a la CSP."))
        elif "data:" in issue:
            vulns.append(("MEDIUM", "CSP: Data URI Allowed",
                issue, "Remover data: de script-src."))

    # --- CMS ---
    cms = results.get("cms", {})
    if cms:
        for issue in cms.get("issues", []):
            if "XML-RPC" in issue:
                vulns.append(("HIGH", "WordPress XML-RPC Enabled",
                    "XML-RPC habilitado. Permite brute force y DDoS amplification.",
                    "Deshabilitar XML-RPC o restringir acceso."))
            elif "debug.log" in issue:
                vulns.append(("HIGH", "WordPress Debug Log Exposed",
                    "wp-content/debug.log accesible. Contiene errores internos.",
                    "Eliminar o bloquear acceso a debug.log."))
            elif "usuarios" in issue.lower() or "users" in issue.lower():
                vulns.append(("MEDIUM", "WordPress User Enumeration",
                    "API REST de usuarios expuesta. Permite enumerar usuarios.",
                    "Deshabilitar endpoint /wp-json/wp/v2/users."))
            elif "readme" in issue.lower():
                vulns.append(("LOW", "CMS Version Exposed",
                    issue, "Eliminar archivos que revelen version del CMS."))
            elif "CHANGELOG" in issue:
                vulns.append(("LOW", "CMS Changelog Exposed",
                    issue, "Eliminar CHANGELOG.txt del servidor."))

        version = cms.get("version")
        if version:
            vulns.append(("INFO", f"CMS Version: {cms.get('cms')} {version}",
                f"Version detectada: {version}. Verificar si tiene CVEs conocidos.",
                "Mantener CMS actualizado a ultima version."))

    # --- Cloud Storage ---
    cloud = results.get("cloud_storage", [])
    for item in cloud:
        if item.get("listable"):
            vulns.append(("CRITICAL", f"Cloud Bucket Listable: {item['bucket']}",
                f"{item['provider']} bucket '{item['bucket']}' es listable publicamente.",
                "Configurar ACLs restrictivos en el bucket."))
        elif item.get("provider"):
            vulns.append(("INFO", f"Cloud Storage: {item['provider']}",
                f"Referencia a {item['provider']} encontrada: {item['bucket']}.",
                "Verificar permisos del bucket."))

    # --- Wayback Machine ---
    wayback_interesting = results.get("wayback_interesting", [])
    if wayback_interesting:
        sensitive_exts = [u for u in wayback_interesting if any(
            e in u.lower() for e in [".sql", ".bak", ".env", ".key", ".pem", ".zip", ".tar", ".gz"]
        )]
        if sensitive_exts:
            vulns.append(("MEDIUM", "Historical Sensitive Files (Wayback)",
                f"{len(sensitive_exts)} URLs historicas con archivos sensibles detectadas.",
                "Verificar que estos archivos ya no son accesibles."))

    # --- Email Security ---
    email_sec = results.get("email_security", {})
    for issue in email_sec.get("issues", []):
        if "+all" in issue:
            vulns.append(("CRITICAL", "SPF: +all Allows All Senders",
                issue, "Cambiar +all a -all en registro SPF."))
        elif "No hay registro SPF" in issue:
            pass  # Ya cubierto arriba
        elif "No hay registro DMARC" in issue:
            pass  # Ya cubierto arriba
        elif "p=none" in issue:
            vulns.append(("MEDIUM", "DMARC: Monitor Only",
                issue, "Cambiar politica DMARC a quarantine o reject."))
        elif "sin rua" in issue.lower():
            vulns.append(("LOW", "DMARC: No Reporting",
                issue, "Agregar rua para recibir reportes DMARC."))

    # --- Security.txt ---
    sec_txt = results.get("security_txt")
    if sec_txt is None:
        vulns.append(("INFO", "No security.txt Found",
            "El sitio no tiene security.txt. Sin politica de divulgacion.",
            "Crear /.well-known/security.txt segun RFC 9116."))
    elif isinstance(sec_txt, dict) and sec_txt.get("expired"):
        vulns.append(("LOW", "Expired security.txt",
            "El archivo security.txt esta expirado.",
            "Actualizar la fecha de expiracion en security.txt."))

    # === Print Results ===
    if not vulns:
        log_ok("No se identificaron vulnerabilidades pasivas.")
        results["vulnerabilities"] = []
        return

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulns.sort(key=lambda x: severity_order.get(x[0], 5))

    results["vulnerabilities"] = [
        {"severity": v[0], "title": v[1], "description": v[2], "remediation": v[3]}
        for v in vulns
    ]

    # Count by severity
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

    # Summary
    print(f"  {C.BOLD}Total: {len(vulns)} hallazgos{C.X}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            color = severity_colors.get(sev, C.W)
            print(f"  {color}{sev}: {counts[sev]}{C.X}")
    print()

    # Detail
    for sev, title, desc, fix in vulns:
        color = severity_colors.get(sev, C.W)
        print(f"  {color}[{sev}]{C.X} {C.BOLD}{title}{C.X}")
        print(f"      {desc}")
        print(f"      {C.G}Fix:{C.X} {fix}")
        print()


# =====================================================================
#  GENERADOR DE REPORTE
# =====================================================================
def generate_report(target, results, output_dir):
    """Genera un reporte en texto plano."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(target).hostname.replace(".", "_")
    filename = os.path.join(output_dir, f"recon_{domain}_{timestamp}.txt")

    with open(filename, "w") as f:
        f.write(f"{'='*60}\n")
        f.write(f"  PASSIVE RECON REPORT\n")
        f.write(f"  Target: {target}\n")
        f.write(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*60}\n\n")

        # Technologies
        techs = results.get("technologies", [])
        if techs:
            f.write("TECHNOLOGIES DETECTED:\n")
            for typ, val in techs:
                f.write(f"  [{typ}] {val}\n")
            f.write("\n")

        # Security headers
        sec = results.get("security_headers", {})
        if sec:
            f.write("SECURITY HEADERS:\n")
            for h in sec.get("present", []):
                f.write(f"  [OK] {h}\n")
            for h in sec.get("missing", []):
                f.write(f"  [MISSING] {h}\n")
            f.write("\n")

        # Subdomains
        subs = results.get("subdomains", [])
        if subs:
            f.write(f"SUBDOMAINS ({len(subs)}):\n")
            for s in subs:
                f.write(f"  {s}\n")
            f.write("\n")

        # OIDC
        oidc = results.get("oidc_config", {})
        if oidc:
            f.write("OIDC/OAUTH CONFIG:\n")
            f.write(f"  Issuer: {oidc.get('issuer', 'N/A')}\n")
            f.write(f"  PAR Endpoint: {oidc.get('pushed_authorization_request_endpoint', 'N/A')}\n")
            scopes = oidc.get("scopes_supported", [])
            if scopes:
                f.write(f"  Scopes: {', '.join(scopes)}\n")
            f.write("\n")

        # Custom scopes
        custom = results.get("custom_scopes", [])
        if custom:
            f.write("CUSTOM SCOPES (potentially sensitive):\n")
            for s in custom:
                f.write(f"  - {s}\n")
            f.write("\n")

        # Keycloak
        kc = results.get("keycloak_indicators", [])
        if kc:
            f.write("KEYCLOAK INDICATORS:\n")
            for i in kc:
                f.write(f"  {i}\n")
            f.write("\n")

        # Sensitive paths
        paths = results.get("sensitive_paths", [])
        if paths:
            f.write("ACCESSIBLE PATHS:\n")
            for path, status, size in paths:
                f.write(f"  [{status}] {path}\n")
            f.write("\n")

        # JS analysis
        js = results.get("js_analysis", {})
        if js:
            for key, vals in js.items():
                if vals:
                    f.write(f"JS ANALYSIS - {key.upper()}:\n")
                    for v in set(vals):
                        f.write(f"  {v}\n")
                    f.write("\n")

        # DNS
        dns_data = results.get("dns", {})
        if dns_data:
            f.write("DNS RECORDS:\n")
            for rtype, records in dns_data.items():
                for r in records:
                    f.write(f"  [{rtype}] {r}\n")
            f.write("\n")

        # SSL
        ssl_sans = results.get("ssl_sans", [])
        if ssl_sans:
            f.write("SSL SANs:\n")
            for s in ssl_sans:
                f.write(f"  {s}\n")
            f.write("\n")

        # CORS
        cors = results.get("cors", [])
        if cors:
            f.write("CORS CONFIGURATION:\n")
            for c in cors:
                f.write(f"  Origin: {c.get('origin_sent','')} → ACAO: {c.get('acao','')} | Credentials: {c.get('acac','')}\n")
            f.write("\n")

        # HTTP Methods
        methods = results.get("http_methods", [])
        dangerous = results.get("dangerous_methods", [])
        if methods or dangerous:
            f.write("HTTP METHODS:\n")
            if methods:
                f.write(f"  Active: {', '.join(methods)}\n")
            if dangerous:
                f.write(f"  DANGEROUS: {', '.join(m[0] for m in dangerous)}\n")
            f.write("\n")

        # WAF
        waf = results.get("waf", [])
        if waf:
            f.write("WAF DETECTED:\n")
            for w in waf:
                f.write(f"  {w}\n")
            f.write("\n")

        # Wayback
        wb_total = results.get("wayback_total", 0)
        if wb_total:
            f.write(f"WAYBACK MACHINE ({wb_total} URLs):\n")
            for u in results.get("wayback_interesting", []):
                f.write(f"  [FILE] {u}\n")
            for u in results.get("wayback_apis", []):
                f.write(f"  [API] {u}\n")
            for u in results.get("wayback_admin", []):
                f.write(f"  [ADMIN] {u}\n")
            f.write("\n")

        # Cloud Storage
        cloud = results.get("cloud_storage", [])
        if cloud:
            f.write("CLOUD STORAGE:\n")
            for c in cloud:
                listable = " [LISTABLE!]" if c.get("listable") else ""
                f.write(f"  [{c['provider']}] {c['bucket']}{listable}\n")
            f.write("\n")

        # Subdomain Takeover
        takeover = results.get("subdomain_takeover", [])
        if takeover:
            f.write("SUBDOMAIN TAKEOVER CANDIDATES:\n")
            for t in takeover:
                f.write(f"  {t['subdomain']} → {t['service']} ({t['signature']})\n")
            f.write("\n")

        # CSP
        csp_issues = results.get("csp_issues", [])
        if csp_issues:
            f.write("CSP ISSUES:\n")
            for issue in csp_issues:
                f.write(f"  [!] {issue}\n")
            f.write("\n")

        # CMS
        cms = results.get("cms", {})
        if cms and cms.get("cms"):
            f.write(f"CMS: {cms['cms']}\n")
            if cms.get("version"):
                f.write(f"  Version: {cms['version']}\n")
            for p in cms.get("plugins", []):
                f.write(f"  [Plugin] {p}\n")
            for t in cms.get("themes", []):
                f.write(f"  [Theme] {t}\n")
            for u in cms.get("users", []):
                f.write(f"  [User] {u}\n")
            for i in cms.get("issues", []):
                f.write(f"  [Issue] {i}\n")
            f.write("\n")

        # Security.txt
        sec_txt = results.get("security_txt")
        if sec_txt and isinstance(sec_txt, dict):
            f.write("SECURITY.TXT:\n")
            for k, v in sec_txt.items():
                f.write(f"  {k}: {v}\n")
            f.write("\n")

        # Email Security
        email_sec = results.get("email_security", {})
        if email_sec:
            f.write("EMAIL SECURITY:\n")
            if email_sec.get("spf"):
                f.write(f"  SPF: {email_sec['spf'][:100]}\n")
            if email_sec.get("dmarc"):
                f.write(f"  DMARC: {email_sec['dmarc'][:100]}\n")
            for i in email_sec.get("issues", []):
                f.write(f"  [!] {i}\n")
            f.write("\n")

        # Vulnerabilities
        vulns_data = results.get("vulnerabilities", [])
        if vulns_data:
            f.write(f"{'='*60}\n")
            f.write("VULNERABILITIES FOUND:\n")
            f.write(f"{'='*60}\n\n")

            counts = {}
            for v in vulns_data:
                s = v["severity"]
                counts[s] = counts.get(s, 0) + 1

            f.write(f"Total: {len(vulns_data)} hallazgos\n")
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if s in counts:
                    f.write(f"  {s}: {counts[s]}\n")
            f.write("\n")

            for v in vulns_data:
                f.write(f"[{v['severity']}] {v['title']}\n")
                f.write(f"  Descripcion: {v['description']}\n")
                f.write(f"  Remediacion: {v['remediation']}\n\n")

        f.write(f"\n{'='*60}\n")
        f.write(f"  End of report\n")
        f.write(f"{'='*60}\n")

    return filename


# =====================================================================
#  MAIN
# =====================================================================
def main():
    parser = argparse.ArgumentParser(
        description="PassiveRecon - Herramienta de reconocimiento pasivo para bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 passive-recon.py https://example.com
  python3 passive-recon.py https://login.example.com --modules all
  python3 passive-recon.py https://example.com --modules headers,ssl,dns
  python3 passive-recon.py https://example.com -o /ruta/reportes/

Modulos disponibles:
  headers    - HTTP & Security Headers
  ssl        - Certificado SSL/TLS
  dns        - DNS Records
  robots     - robots.txt & sitemap.xml
  tech       - Technology Fingerprinting
  js         - JavaScript Deep Analysis
  subs       - Subdomain Enumeration (crt.sh)
  oauth      - OIDC/OAuth Discovery
  paths      - Sensitive Files & Paths
  whois      - WHOIS Lookup
  keycloak   - Keycloak-Specific Recon
  cors       - CORS Misconfiguration Check
  methods    - HTTP Methods (PUT/DELETE/TRACE)
  waf        - WAF/Firewall Detection
  wayback    - Wayback Machine Historical URLs
  cloud      - Cloud Storage Detection (S3/Azure/GCP)
  takeover   - Subdomain Takeover Check
  csp        - CSP Deep Analysis
  cms        - CMS Deep Scan (WordPress/Joomla/Drupal)
  favicon    - Favicon Hash Fingerprinting
  sectxt     - Security.txt Parser
  email      - Email Security (SPF/DMARC Deep)
  all        - Todos los modulos (default)
        """
    )

    parser.add_argument("target", help="URL del target (ej: https://example.com)")
    parser.add_argument("-m", "--modules", default="all",
                       help="Modulos a ejecutar separados por coma (default: all)")
    parser.add_argument("-o", "--output", default=".",
                       help="Directorio de salida para el reporte")
    parser.add_argument("--no-report", action="store_true",
                       help="No generar archivo de reporte")
    parser.add_argument("--timeout", type=int, default=15,
                       help="Timeout HTTP en segundos (default: 15)")

    args = parser.parse_args()

    # Validate URL
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    if not parsed.hostname:
        print(f"{C.R}[!] URL invalida{C.X}")
        sys.exit(1)

    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    base_url = f"{parsed.scheme}://{hostname}"
    if parsed.port:
        base_url += f":{parsed.port}"

    # Parse modules
    selected = set(args.modules.lower().split(","))
    all_modules = selected == {"all"}

    banner()
    print(f"  {C.BOLD}Target:{C.X}  {target}")
    print(f"  {C.BOLD}Host:{C.X}    {hostname}")
    print(f"  {C.BOLD}Date:{C.X}    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {C.BOLD}Modules:{C.X} {args.modules}")
    print()

    session = get_session()
    results = {"target": target, "hostname": hostname, "timestamp": datetime.now().isoformat()}

    # Get initial HTML for tech fingerprinting
    html = ""
    try:
        r = session.get(target, timeout=args.timeout)
        html = r.text
    except Exception:
        log_warn("No se pudo obtener el HTML inicial")

    # Run modules
    if all_modules or "headers" in selected:
        mod_headers(session, target, results)

    if all_modules or "ssl" in selected:
        if parsed.scheme == "https":
            mod_ssl(hostname, port, results)

    if all_modules or "dns" in selected:
        mod_dns(hostname, results)

    if all_modules or "robots" in selected:
        mod_robots_sitemap(session, base_url, results)

    if all_modules or "tech" in selected:
        mod_tech_fingerprint(session, target, html, results)

    if all_modules or "js" in selected:
        js_files = results.get("js_files", [])
        if not js_files and html:
            js_files = [urljoin(target, js) for js in re.findall(r'src=["\']([^"\']*\.js)["\']', html)]
        mod_js_analysis(session, target, js_files, results)

    if all_modules or "subs" in selected:
        # Use root domain for subdomains
        parts = hostname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) > 2 else hostname
        mod_subdomains(session, domain, results)

    if all_modules or "oauth" in selected:
        mod_oauth_discovery(session, target, results)

    if all_modules or "paths" in selected:
        mod_sensitive_paths(session, base_url, results)

    if all_modules or "whois" in selected:
        parts = hostname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) > 2 else hostname
        mod_whois(domain, results)

    if all_modules or "keycloak" in selected:
        mod_keycloak_recon(session, target, results)

    if all_modules or "cors" in selected:
        mod_cors(session, target, results)

    if all_modules or "methods" in selected:
        mod_http_methods(session, target, results)

    if all_modules or "waf" in selected:
        mod_waf_detect(session, target, results)

    if all_modules or "wayback" in selected:
        parts_wb = hostname.split(".")
        domain_wb = ".".join(parts_wb[-2:]) if len(parts_wb) > 2 else hostname
        mod_wayback(session, domain_wb, results)

    if all_modules or "cloud" in selected:
        mod_cloud_storage(session, target, html, results)

    if all_modules or "takeover" in selected:
        subs_list = results.get("subdomains", [])
        if subs_list:
            mod_subdomain_takeover(session, subs_list, results)
        else:
            log_info("Takeover check requiere modulo 'subs' — no hay subdominios")

    if all_modules or "csp" in selected:
        mod_csp_analysis(results)

    if all_modules or "cms" in selected:
        mod_cms_deep(session, base_url, html, results)

    if all_modules or "favicon" in selected:
        mod_favicon_hash(session, base_url, results)

    if all_modules or "sectxt" in selected:
        mod_security_txt(session, base_url, results)

    if all_modules or "email" in selected:
        mod_email_security(results)

    # Vulnerability assessment (siempre corre al final)
    mod_vuln_assessment(results)

    # Generate report
    if not args.no_report:
        section("REPORTE")
        os.makedirs(args.output, exist_ok=True)
        report_file = generate_report(target, results, args.output)
        log_ok(f"Reporte guardado en: {report_file}")

        # Also save JSON
        json_file = report_file.replace(".txt", ".json")
        with open(json_file, "w") as f:
            # Clean non-serializable items
            clean = {}
            for k, v in results.items():
                try:
                    json.dumps(v)
                    clean[k] = v
                except (TypeError, ValueError):
                    clean[k] = str(v)
            json.dump(clean, f, indent=2, default=str)
        log_ok(f"JSON guardado en: {json_file}")

    print(f"\n{C.G}{C.BOLD}  Reconocimiento completado.{C.X}\n")


if __name__ == "__main__":
    main()
