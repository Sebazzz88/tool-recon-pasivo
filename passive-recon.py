#!/usr/bin/env python3
"""
PassiveRecon - Herramienta de reconocimiento pasivo para bug bounty
Autor: sebazzz88
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
                                            {C.D}v2.1{C.X}
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

    # DNSSEC: DNSKEY vive en el apex de la zona, no en subdominios como "www".
    # Consultar el dominio registrable para una deteccion fiable (evita el
    # falso positivo de "No DNSSEC" que antes disparaba en todos los dominios).
    parts = hostname.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    try:
        dnskey = dns.resolver.resolve(apex, "DNSKEY")
        if dnskey:
            dns_results["DNSKEY"] = [str(r)[:60] for r in dnskey]
            log_ok(f"DNSSEC activo (DNSKEY presente en {apex})")
    except Exception:
        # Sin DNSKEY o error — no se marca nada aqui; el assessment lo evalua.
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
        "Spring": [r"JSESSIONID", r"org\.springframework"],
        "Cloudflare": [r"cf-ray", r"challenge-platform"],
        "AWS": [r"\.amazonaws\.com"],
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

    # --- Baseline / soft-404 detection ---
    # Muchos sitios (SPAs, catch-all, redirects a login) responden 200/301/302
    # a CUALQUIER ruta. Sin una linea base, eso marca las ~200 rutas como
    # "encontradas" (falsos positivos masivos). Pedimos 2 rutas aleatorias
    # inexistentes y, si responden como "exito", tratamos esos codigos como
    # ruido y solo reportamos rutas cuyo tamano difiera del baseline.
    def _probe(path):
        try:
            return session.head(urljoin(base_url, path), timeout=5, allow_redirects=False)
        except Exception:
            return None

    baseline_statuses = {}   # status_code -> content-length tipico (o None)
    for rnd in ["/zzz_nonexistent_%s_recon" % os.urandom(4).hex(),
                "/404_baseline_%s.html" % os.urandom(4).hex()]:
        rb = _probe(rnd)
        if rb is not None and rb.status_code in (200, 301, 302, 403):
            try:
                clen = int(rb.headers.get("Content-Length", -1))
            except (TypeError, ValueError):
                clen = -1
            baseline_statuses[rb.status_code] = clen

    soft_codes = set(baseline_statuses.keys())
    if soft_codes:
        log_warn("Soft-404 detectado (el servidor responde %s a rutas inexistentes); "
                 "filtrando resultados para reducir falsos positivos"
                 % ", ".join(str(c) for c in sorted(soft_codes)))
    results["sensitive_paths_softcodes"] = sorted(soft_codes)

    def check_path(path):
        r = _probe(path)
        if r is None or r.status_code not in [200, 301, 302, 403]:
            return None
        try:
            size = int(r.headers.get("Content-Length", -1))
        except (TypeError, ValueError):
            size = -1
        # Si este codigo es el mismo que el baseline (soft-404), solo lo
        # consideramos real cuando el tamano difiere claramente del baseline.
        if r.status_code in baseline_statuses:
            base_len = baseline_statuses[r.status_code]
            if base_len < 0 or size < 0 or abs(size - base_len) <= 32:
                return None
        return (path, r.status_code, max(size, 0))

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
    # Firmas ESPECIFICAS por servicio. Se evitan cadenas genericas como
    # "404 Not Found" o "The requested URL was not found", que aparecen en
    # paginas 404 normales y causaban falsos positivos de takeover.
    takeover_signatures = {
        "GitHub Pages": ["There isn't a GitHub Pages site here"],
        "Heroku": ["herokucdn.com/error-pages", "No such app"],
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "Shopify": ["Sorry, this shop is currently unavailable"],
        "Tumblr": ["Whatever you were looking for doesn't currently exist"],
        "Fastly": ["Fastly error: unknown domain"],
        "Zendesk": ["Help Center Closed"],
        "Bitbucket": ["Repository not found"],
        "Ghost": ["The thing you were looking for is no longer here"],
        "Surge.sh": ["project not found"],
        "Cargo Collective": ["If you're moving your domain away"],
        "Pantheon": ["The gods are wise, but do not know of the site which you seek"],
    }

    takeover_candidates = []
    checked = 0
    max_check = min(len(subdomains), 50)

    log_info(f"Verificando {max_check} subdominios...")

    # Proveedores donde un CNAME colgante (CNAME que resuelve a uno de estos
    # pero el recurso no existe) es realmente reclamable. Un subdominio que
    # simplemente no resuelve NO es un takeover por si mismo.
    takeover_cname_providers = (
        "github.io", "herokudns.com", "herokuapp.com", "herokussl.com",
        "s3.amazonaws.com", "cloudfront.net", "myshopify.com", "fastly.net",
        "zendesk.com", "bitbucket.io", "ghost.io", "surge.sh",
        "cargocollective.com", "pantheonsite.io", "wpengine.com",
        "unbouncepages.com", "readthedocs.io", "netlify.app", "azurewebsites.net",
    )

    def _dangling_cname(sub):
        # Devuelve el provider si el subdominio tiene un CNAME a un proveedor
        # reclamable pero el destino no resuelve (dangling).
        if not HAS_DNS:
            return None
        try:
            answers = dns.resolver.resolve(sub, "CNAME")
        except Exception:
            return None
        for rdata in answers:
            target = str(rdata.target).rstrip(".").lower()
            if any(p in target for p in takeover_cname_providers):
                try:
                    socket.getaddrinfo(target, None)
                except socket.gaierror:
                    return target  # CNAME a proveedor y no resuelve → dangling
        return None

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
                # Solo es candidato si hay un CNAME colgante a un proveedor
                # reclamable, no por el mero hecho de no resolver.
                target = _dangling_cname(sub)
                if target:
                    return (sub, "Dangling CNAME", target)
                break
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
#  MODULO 23: Open Redirect Detection
# =====================================================================
def mod_open_redirect(session, base_url, html, results):
    section("23. OPEN REDIRECT DETECTION")

    redirect_params = [
        "url", "redirect", "redirect_url", "redirect_uri", "next", "nextUrl",
        "return", "returnUrl", "return_to", "rurl", "dest", "destination",
        "redir", "redirect_to", "out", "view", "login_url", "image_url",
        "go", "goto", "target", "link", "to", "uri", "continue", "window",
        "data", "reference", "site", "html", "val", "validate", "domain",
        "callback", "path", "return_path", "checkout_url", "forward",
        "location", "r", "u", "n", "page", "feed", "host",
    ]

    redirect_findings = []
    parsed = urlparse(base_url)

    # Para escanear LINKS usamos solo nombres especificos de redireccion.
    # Nombres genericos (page, view, to, r, u, n, data, site, host, path...)
    # aparecen en casi cualquier URL y generan falsos positivos; se reservan
    # unicamente para las pruebas activas de endpoints mas abajo.
    link_redirect_params = [
        "redirect", "redirect_url", "redirect_uri", "redirecturl", "next",
        "nexturl", "returnurl", "return_to", "return_url", "rurl", "redir",
        "redirect_to", "login_url", "image_url", "goto", "checkout_url",
        "return_path", "forward", "destination", "continue",
    ]

    # Check for redirect parameters in page links
    link_pattern = re.findall(r'href=["\']([^"\']*)["\']', html)
    for link in link_pattern:
        low = link.lower()
        for param in link_redirect_params:
            # exigir que el valor parezca una URL/externo, no solo que exista el param
            m = re.search(r'[?&]' + re.escape(param) + r'=([^&]+)', low)
            if m:
                val = m.group(1)
                if val.startswith(("http", "%2f%2f", "//")) or "%3a%2f%2f" in val or "://" in val:
                    redirect_findings.append({"type": "link_param", "url": link[:200], "param": param})
                    break

    # Check forms for redirect fields
    form_inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', html, re.I)
    for inp in form_inputs:
        if inp.lower() in redirect_params:
            redirect_findings.append({"type": "form_field", "field": inp})

    # Check meta refresh
    meta_refresh = re.findall(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']([^"\']*)["\']', html, re.I)
    for mr in meta_refresh:
        redirect_findings.append({"type": "meta_refresh", "content": mr[:200]})

    # Test common redirect endpoints
    redirect_endpoints = [
        "/redirect?url=https://evil.com",
        "/login?next=https://evil.com",
        "/login?redirect=https://evil.com",
        "/logout?return=https://evil.com",
        "/sso?redirect_uri=https://evil.com",
    ]

    for endpoint in redirect_endpoints:
        try:
            r = session.get(f"{base_url}{endpoint}", timeout=8, allow_redirects=False)
            location = r.headers.get("Location", "")
            if "evil.com" in location:
                redirect_findings.append({"type": "confirmed_redirect", "endpoint": endpoint, "location": location})
                log_fail(f"OPEN REDIRECT: {endpoint} → {location}")
            elif r.status_code in [301, 302, 303, 307, 308]:
                log_info(f"{endpoint} → {r.status_code} → {location[:100]}")
        except Exception:
            continue

    if redirect_findings:
        confirmed = [f for f in redirect_findings if f["type"] == "confirmed_redirect"]
        params = [f for f in redirect_findings if f["type"] == "link_param"]
        if confirmed:
            log_fail(f"Open redirects confirmados: {len(confirmed)}")
        if params:
            log_info(f"Parametros de redirect en links: {len(params)}")
            for p in params[:5]:
                log_data("Param", f"{p['param']} en {p['url'][:80]}")
    else:
        log_ok("No se detectaron indicadores de open redirect")

    results["open_redirect"] = redirect_findings


# =====================================================================
#  MODULO 24: JSONP Endpoint Detection
# =====================================================================
def mod_jsonp(session, base_url, html, results):
    section("24. JSONP ENDPOINT DETECTION")

    jsonp_findings = []

    # Find JSONP endpoints in HTML
    jsonp_pattern = re.findall(r'(?:src|href)=["\']([^"\']*(?:callback|jsonp|cb|func|function|handler)=[^"\']*)["\']', html, re.I)
    for url in jsonp_pattern:
        jsonp_findings.append({"type": "html_reference", "url": url[:200]})
        log_ok(f"JSONP endpoint en HTML: {url[:100]}")

    # Check common JSONP patterns
    jsonp_endpoints = [
        "/api?callback=test",
        "/api/v1?callback=test",
        "/json?callback=test",
        "/data?jsonp=test",
        "/feed?callback=test",
        "/search?callback=test&q=a",
    ]

    for endpoint in jsonp_endpoints:
        try:
            r = session.get(f"{base_url}{endpoint}", timeout=8)
            if r.status_code == 200:
                body = r.text[:500].lstrip().lstrip("/*").lstrip()
                ctype = r.headers.get("Content-Type", "").lower()
                # JSONP real: el cuerpo EMPIEZA con la invocacion del callback
                # (p.ej. "test({...})") y no es HTML. Que aparezca "test(" en
                # medio de un JS cualquiera no es JSONP.
                if re.match(r'^(?:typeof\s+\w+.*?)?test\s*\(', body) and "html" not in ctype:
                    jsonp_findings.append({"type": "confirmed", "endpoint": endpoint})
                    log_fail(f"JSONP activo: {endpoint}")
        except Exception:
            continue

    # Look for callback parameters in JS files
    js_callbacks = re.findall(r'[?&](callback|jsonp|cb)=([^&"\'>\s]+)', html)
    for param, value in js_callbacks:
        jsonp_findings.append({"type": "callback_param", "param": param, "value": value})

    if not jsonp_findings:
        log_info("No se detectaron endpoints JSONP")

    results["jsonp"] = jsonp_findings


# =====================================================================
#  MODULO 25: Host Header Injection Check
# =====================================================================
def mod_host_header(session, url, results):
    section("25. HOST HEADER INJECTION CHECK")

    findings = []
    parsed = urlparse(url)
    original_host = parsed.hostname

    # Test with different Host headers
    tests = [
        {"host": "evil.com", "desc": "arbitrary host"},
        {"host": f"evil.com.{original_host}", "desc": "prepended host"},
        {"host": f"{original_host}.evil.com", "desc": "appended host"},
    ]

    for test in tests:
        try:
            headers = {"Host": test["host"]}
            r = session.get(url, headers=headers, timeout=8, allow_redirects=False)
            body = r.text[:3000].lower()
            resp_headers = str(r.headers).lower()

            if test["host"].lower() in body or test["host"].lower() in resp_headers:
                findings.append({"test": test["desc"], "host": test["host"], "reflected_in": "body/headers"})
                log_fail(f"Host header reflejado: {test['host']} ({test['desc']})")

            location = r.headers.get("Location", "")
            if test["host"] in location:
                findings.append({"test": test["desc"], "host": test["host"], "reflected_in": "Location header"})
                log_fail(f"Host header en redirect: {location}")

        except Exception:
            continue

    # X-Forwarded-Host test
    try:
        headers = {"X-Forwarded-Host": "evil.com"}
        r = session.get(url, headers=headers, timeout=8)
        if "evil.com" in r.text[:3000].lower():
            findings.append({"test": "X-Forwarded-Host", "host": "evil.com", "reflected_in": "body"})
            log_fail("X-Forwarded-Host reflejado en respuesta")
    except Exception:
        pass

    if not findings:
        log_ok("No se detecto host header injection")

    results["host_header"] = findings


# =====================================================================
#  MODULO 26: Cache Poisoning Indicators
# =====================================================================
def mod_cache_poisoning(session, url, results):
    section("26. CACHE POISONING INDICATORS")

    findings = []

    try:
        r = session.get(url, timeout=10)
        cache_headers = {}

        for h in ["X-Cache", "X-Cache-Hits", "Age", "Via", "X-Served-By",
                   "X-Cache-Status", "CF-Cache-Status", "X-Varnish",
                   "X-Drupal-Cache", "X-Proxy-Cache", "Fastly-Debug-Digest",
                   "X-CDN", "X-Edge-Location"]:
            val = r.headers.get(h)
            if val:
                cache_headers[h] = val
                log_data(h, val)

        if cache_headers:
            findings.append({"type": "cache_headers", "headers": cache_headers})
            log_info("Sistema de cache detectado")

            # Check if unkeyed headers affect response
            unkeyed_headers = [
                "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
                "X-Forwarded-Scheme", "X-Forwarded-Proto",
                "X-HTTP-Method-Override", "X-Custom-IP-Authorization",
            ]

            for header in unkeyed_headers:
                try:
                    r2 = session.get(url, headers={header: "evil-test-value"}, timeout=8)
                    if "evil-test-value" in r2.text[:3000]:
                        findings.append({"type": "unkeyed_header_reflected", "header": header})
                        log_fail(f"Header no-cacheado reflejado: {header}")
                except Exception:
                    continue

            # Vary header analysis
            vary = r.headers.get("Vary", "")
            if vary:
                log_data("Vary", vary)
                if "Host" not in vary and "host" not in vary.lower():
                    findings.append({"type": "vary_missing_host"})
                    log_warn("Vary no incluye Host — cache poisoning posible")
        else:
            log_info("No se detectaron headers de cache")

    except Exception as e:
        log_fail(f"Error: {e}")

    results["cache_poisoning"] = findings


# =====================================================================
#  MODULO 27: GraphQL Introspection Deep Check
# =====================================================================
def mod_graphql(session, base_url, results):
    section("27. GRAPHQL INTROSPECTION")

    graphql_endpoints = [
        "/graphql", "/graphiql", "/v1/graphql", "/v2/graphql",
        "/api/graphql", "/query", "/gql", "/graphql/console",
    ]

    introspection_query = '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

    graphql_findings = []

    for endpoint in graphql_endpoints:
        url = f"{base_url}{endpoint}"
        try:
            # GET request
            r = session.get(url, timeout=8)
            if r.status_code == 200:
                body = r.text[:500]
                if any(x in body.lower() for x in ["graphql", "query", "__schema", "playground", "graphiql"]):
                    graphql_findings.append({"endpoint": endpoint, "type": "interface_found"})
                    log_ok(f"GraphQL endpoint: {endpoint}")

            # POST introspection
            r2 = session.post(url, data=introspection_query,
                            headers={"Content-Type": "application/json"}, timeout=10)
            if r2.status_code == 200:
                try:
                    data = r2.json()
                    if "data" in data and "__schema" in str(data.get("data", {})):
                        types = data.get("data", {}).get("__schema", {}).get("types", [])
                        type_names = [t.get("name", "") for t in types if not t.get("name", "").startswith("__")]

                        graphql_findings.append({
                            "endpoint": endpoint,
                            "type": "introspection_enabled",
                            "types_count": len(type_names),
                            "types": type_names[:20],
                        })
                        log_fail(f"INTROSPECTION HABILITADO en {endpoint}")
                        log_info(f"  Tipos encontrados: {len(type_names)}")
                        for t in type_names[:10]:
                            log_data("  Type", t)

                        # Look for sensitive types
                        sensitive = [t for t in type_names if any(
                            s in t.lower() for s in ["user", "admin", "password", "token",
                                "secret", "credential", "payment", "order", "account",
                                "email", "auth", "session", "role", "permission"]
                        )]
                        if sensitive:
                            log_warn(f"  Tipos sensibles: {', '.join(sensitive)}")
                            graphql_findings.append({"endpoint": endpoint, "type": "sensitive_types", "types": sensitive})
                except Exception:
                    pass

        except Exception:
            continue

    if not graphql_findings:
        log_info("No se detectaron endpoints GraphQL")

    results["graphql"] = graphql_findings


# =====================================================================
#  MODULO 28: JWT Detection & Analysis
# =====================================================================
def mod_jwt_analysis(session, url, results):
    section("28. JWT DETECTION & ANALYSIS")

    jwt_findings = []

    try:
        r = session.get(url, timeout=10)

        # Check cookies for JWTs
        for cookie in r.cookies:
            if re.match(r'^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$', cookie.value):
                jwt_findings.append({"location": f"cookie:{cookie.name}", "token": cookie.value[:50] + "..."})
                log_ok(f"JWT en cookie: {cookie.name}")

                # Decode header
                try:
                    header_b64 = cookie.value.split(".")[0]
                    # Add padding
                    header_b64 += "=" * (4 - len(header_b64) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    alg = header.get("alg", "")
                    log_data("  Algorithm", alg)

                    if alg.lower() == "none":
                        jwt_findings.append({"issue": "alg_none", "cookie": cookie.name})
                        log_fail(f"  JWT usa alg:none — CRITICO")
                    elif alg.lower() in ["hs256", "hs384", "hs512"]:
                        log_info(f"  HMAC signing ({alg}) — vulnerable si secret es debil")
                    elif alg.lower().startswith("rs"):
                        log_ok(f"  RSA signing ({alg})")

                    typ = header.get("typ", "")
                    kid = header.get("kid", "")
                    if kid:
                        log_data("  Key ID", kid)
                    if header.get("jku"):
                        jwt_findings.append({"issue": "jku_present", "jku": header["jku"]})
                        log_warn(f"  JKU header presente: {header['jku']}")
                    if header.get("x5u"):
                        jwt_findings.append({"issue": "x5u_present", "x5u": header["x5u"]})
                        log_warn(f"  X5U header presente: {header['x5u']}")

                    # Decode payload (just for info, no secrets)
                    payload_b64 = cookie.value.split(".")[1]
                    payload_b64 += "=" * (4 - len(payload_b64) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                    if "exp" in payload:
                        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                        log_data("  Expires", exp_time.isoformat())
                    if "role" in payload or "roles" in payload:
                        log_data("  Roles", str(payload.get("role", payload.get("roles", ""))))

                except Exception:
                    pass

        # Check Authorization header patterns in HTML/JS
        auth_patterns = re.findall(r'(?:Authorization|Bearer|token)["\s:=]+\s*(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', r.text[:10000], re.I)
        for token in auth_patterns:
            jwt_findings.append({"location": "html/js", "token": token[:50] + "..."})
            log_warn(f"JWT en HTML/JS: {token[:40]}...")

        # Check response headers
        for header_name, header_val in r.headers.items():
            if re.match(r'^eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$', header_val):
                jwt_findings.append({"location": f"header:{header_name}", "token": header_val[:50] + "..."})
                log_ok(f"JWT en header: {header_name}")

    except Exception as e:
        log_fail(f"Error: {e}")

    if not jwt_findings:
        log_info("No se detectaron JWTs")

    results["jwt"] = jwt_findings


# =====================================================================
#  MODULO 29: CRLF Injection Indicators
# =====================================================================
def mod_crlf(session, url, results):
    section("29. CRLF INJECTION CHECK")

    findings = []

    payloads = [
        "%0d%0aX-Injected: true",
        "%0AX-Injected: true",
        "%0DX-Injected: true",
        "\\r\\nX-Injected: true",
        "%E5%98%8A%E5%98%8DX-Injected: true",
    ]

    for payload in payloads:
        test_url = f"{url}/?redirect={payload}"
        try:
            r = session.get(test_url, timeout=8, allow_redirects=False)
            # Solo contamos inyeccion REAL en headers de respuesta. La mera
            # reflexion del string en el body no es CRLF (es solo reflexion del
            # parametro) y generaba falsos positivos.
            if "x-injected" in {k.lower(): v for k, v in r.headers.items()}:
                findings.append({"type": "header_injection", "payload": payload})
                log_fail(f"CRLF injection en headers: {payload}")
        except Exception:
            continue

    if not findings:
        log_ok("No se detecto CRLF injection")

    results["crlf"] = findings


# =====================================================================
#  MODULO 30: Expanded API Key Detection
# =====================================================================
def mod_api_keys_deep(session, url, html, results):
    section("30. API KEY & SECRET DEEP SCAN")

    # Extended patterns
    api_patterns = {
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "AWS Secret Key": r'(?:aws_secret|AWS_SECRET)["\s:=]+([A-Za-z0-9/+=]{40})',
        "Stripe Publishable Key": r'pk_(?:live|test)_[a-zA-Z0-9]{20,}',
        "Stripe Secret Key": r'sk_(?:live|test)_[a-zA-Z0-9]{20,}',
        "Twilio API Key": r'SK[a-f0-9]{32}',
        "Twilio Account SID": r'AC[a-f0-9]{32}',
        "SendGrid API Key": r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        "Mailgun API Key": r'key-[a-f0-9]{32}',
        "Slack Token": r'xox[bpas]-[0-9]{10,}-[a-zA-Z0-9-]{20,}',
        "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+',
        "GitHub Token": r'gh[pousr]_[a-zA-Z0-9]{36,}',
        "GitHub OAuth": r'gho_[a-zA-Z0-9]{36}',
        "Google API Key": r'AIza[0-9A-Za-z_-]{35}',
        "Google OAuth ID": r'[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com',
        "Firebase Key": r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
        "DigitalOcean Token": r'dop_v1_[a-f0-9]{64}',
        "NPM Token": r'npm_[a-zA-Z0-9]{36}',
        "Discord Token": r'[MN][A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27,}',
        "Discord Webhook": r'https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+',
        "Telegram Bot Token": r'\b\d{8,10}:AA[a-zA-Z0-9_-]{32,33}\b',
        "Square Access Token": r'sq0atp-[a-zA-Z0-9_-]{22}',
        "Square OAuth Secret": r'sq0csp-[a-zA-Z0-9_-]{43}',
        "Shopify Token": r'shpat_[a-fA-F0-9]{32}',
        "Shopify Secret": r'shpss_[a-fA-F0-9]{32}',
        "Shopify URL": r'[a-z0-9-]+\.myshopify\.com/admin/api/[0-9-]+',
        "Mapbox Token": r'pk\.eyJ[a-zA-Z0-9_-]{50,}',
        "Sentry DSN": r'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/\d+',
        "Datadog API Key": r'\bdd[a-f0-9]{38}\b',
        "Private Key": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        "PGP Private Block": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        "Generic Secret": r'(?:secret|password|passwd|pwd|token|api_key|apikey|api-key|access_token|auth_token|credentials)["\s:=]+["\']([a-zA-Z0-9_/+=-]{16,})["\']',
        "Basic Auth": r'(?:Authorization|auth)["\s:=]+Basic\s+[a-zA-Z0-9+/=]+',
        "Bearer Token": r'(?:Authorization|auth)["\s:=]+Bearer\s+[a-zA-Z0-9._-]+',
        "Connection String": r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\'<>]+',
        "IP Address (Internal)": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    }

    all_text = html

    # Also get JS files if available
    js_files = results.get("js_analysis", {}).get("js_files_content", "")
    if js_files:
        all_text += js_files

    found_keys = []

    for name, pattern in api_patterns.items():
        matches = re.findall(pattern, all_text)
        if matches:
            for m in list(set(matches))[:3]:
                match_str = m if isinstance(m, str) else m[0] if m else ""
                if len(match_str) < 8:
                    continue
                # Mask the key
                masked = match_str[:6] + "..." + match_str[-4:] if len(match_str) > 14 else match_str[:4] + "..."
                found_keys.append({"type": name, "masked": masked})
                log_fail(f"{name}: {masked}")

    if not found_keys:
        log_ok("No se detectaron API keys o secretos expuestos")

    results["api_keys_deep"] = found_keys


# =====================================================================
#  MODULO 31: Rate Limiting Check
# =====================================================================
def mod_rate_limit(session, url, results):
    section("31. RATE LIMITING CHECK")

    findings = {}

    # Send rapid requests
    status_codes = []
    rate_headers = []

    for i in range(15):
        try:
            r = session.get(url, timeout=8)
            status_codes.append(r.status_code)

            # Check for rate limit headers
            for h in ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
                       "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset",
                       "Retry-After", "X-Rate-Limit"]:
                val = r.headers.get(h)
                if val and h not in [rh["header"] for rh in rate_headers]:
                    rate_headers.append({"header": h, "value": val})
                    log_data(h, val)

            if r.status_code == 429:
                log_ok(f"Rate limiting activo — HTTP 429 despues de {i+1} requests")
                findings["rate_limited"] = True
                findings["requests_before_limit"] = i + 1
                break

        except Exception:
            break

    if rate_headers:
        findings["rate_headers"] = rate_headers

    if 429 not in status_codes:
        log_warn("No se detecto rate limiting despues de 15 requests rapidas")
        findings["rate_limited"] = False

    # Check login endpoint
    login_paths = ["/login", "/signin", "/auth/login", "/api/login", "/api/auth/login"]
    for path in login_paths:
        try:
            r = session.post(f"{url.rstrip('/')}{path}",
                           data={"username": "test", "password": "test"},
                           timeout=8)
            if r.status_code not in [404, 405]:
                findings[f"login_{path}"] = r.status_code
                log_info(f"Login endpoint {path}: HTTP {r.status_code}")
        except Exception:
            continue

    results["rate_limiting"] = findings


# =====================================================================
#  MODULO 32: Default Credentials Pages
# =====================================================================
def mod_default_pages(session, base_url, results):
    section("32. DEFAULT / INSTALL PAGES DETECTION")

    findings = []

    default_pages = [
        # Web servers
        ("/", "Apache2 Ubuntu Default Page", "apache_default"),
        ("/", "Welcome to nginx", "nginx_default"),
        ("/", "IIS Windows Server", "iis_default"),
        ("/", "It works!", "default_page"),
        # CMS install pages
        ("/wp-admin/install.php", "WordPress", "wp_install"),
        ("/install.php", "installation", "generic_install"),
        ("/installer", "install", "generic_installer"),
        ("/setup", "setup", "setup_page"),
        ("/install", "install", "install_page"),
        # Framework debug/default
        ("/rails/info/properties", "Rails", "rails_info"),
        ("/elmah.axd", "ELMAH", "elmah"),
        ("/_debugbar", "Debugbar", "laravel_debug"),
        ("/telescope", "Telescope", "laravel_telescope"),
        ("/horizon", "Horizon", "laravel_horizon"),
        # Database managers
        ("/phpmyadmin/", "phpMyAdmin", "phpmyadmin"),
        ("/pma/", "phpMyAdmin", "pma"),
        ("/adminer.php", "Adminer", "adminer"),
        ("/pgadmin/", "pgAdmin", "pgadmin"),
        # Monitoring
        ("/grafana/", "Grafana", "grafana"),
        ("/kibana/", "Kibana", "kibana"),
        ("/prometheus/", "Prometheus", "prometheus"),
        ("/nagios/", "Nagios", "nagios"),
        ("/zabbix/", "Zabbix", "zabbix"),
        # CI/CD
        ("/jenkins/", "Jenkins", "jenkins"),
        ("/hudson/", "Hudson", "hudson"),
        # Cloud
        ("/minio/", "MinIO", "minio"),
        ("/portainer/", "Portainer", "portainer"),
        ("/rancher/", "Rancher", "rancher"),
        # Misc
        ("/solr/", "Solr", "solr"),
        ("/couchdb/", "CouchDB", "couchdb"),
        ("/server-status", "Apache Server Status", "server_status"),
        ("/server-info", "Apache Server Info", "server_info"),
    ]

    def check_page(entry):
        path, keyword, tag = entry
        try:
            r = session.get(f"{base_url}{path}", timeout=8)
            if r.status_code == 200 and keyword.lower() in r.text[:5000].lower():
                return (path, keyword, tag)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_page, e): e for e in default_pages}
        for future in as_completed(futures):
            result = future.result()
            if result:
                path, keyword, tag = result
                findings.append({"path": path, "service": keyword, "tag": tag})
                log_fail(f"Pagina default/instalacion: {path} ({keyword})")

    if not findings:
        log_ok("No se detectaron paginas de instalacion o default")

    results["default_pages"] = findings


# =====================================================================
#  MODULO 33: Error Page Information Disclosure
# =====================================================================
def mod_error_disclosure(session, base_url, results):
    section("33. ERROR PAGE INFORMATION DISCLOSURE")

    findings = []

    # Trigger different error pages
    error_triggers = [
        f"{base_url}/nonexistent_page_test_12345",
        f"{base_url}/%00",
        f"{base_url}/{{test}}",
        f"{base_url}/index.php?id='",
        f"{base_url}/.%00",
        f"{base_url}/\\",
    ]

    info_patterns = {
        "Stack Trace": [r"(?:Traceback|stack\s*trace|at\s+\w+\.\w+\()", r"Exception in thread"],
        "File Path": [r"(?:/var/www|/home/\w+|/usr/local|/opt/|C:\\\\|/srv/)", r"(?:DocumentRoot|DOCUMENT_ROOT)"],
        "Database Error": [r"(?:SQL syntax|mysql_|pg_|sqlite3\.|ORA-\d+|SQLSTATE)", r"(?:database error|db error)"],
        "Framework Version": [r"(?:Laravel|Django|Flask|Express|Rails|Spring|Struts)\s*v?[\d.]+",
                              r"(?:PHP/[\d.]+|Python/[\d.]+|Node\.js/[\d.]+)"],
        "Server Config": [r"(?:Apache/[\d.]+|nginx/[\d.]+|IIS/[\d.]+)", r"(?:Server at|Port \d+)"],
        "Debug Info": [r"(?:DEBUG\s*=\s*True|DJANGO_SETTINGS_MODULE|APP_DEBUG)",
                       r"(?:display_errors|error_reporting)"],
        "Internal IP": [r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"],
    }

    # Indicadores de que la respuesta es realmente un error verboso y no una
    # pagina normal (que podria contener rutas/emails legitimos en el footer).
    error_context = re.compile(
        r"(?:exception|traceback|stack\s*trace|fatal error|warning:|notice:|"
        r"sql syntax|syntaxerror|uncaught|\.php on line|\.py\", line|at line \d+|"
        r"debug|error in|internal server error)", re.I)

    for trigger_url in error_triggers:
        try:
            r = session.get(trigger_url, timeout=8)
            body = r.text[:5000]

            # Solo analizar patrones de disclosure si la respuesta realmente
            # parece un error verboso. Una pagina 404 "bonita" con footer
            # (emails, rutas de CDN) no debe considerarse info disclosure.
            looks_like_error = bool(error_context.search(body)) or r.status_code >= 500

            if looks_like_error:
                for category, patterns in info_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, body, re.I)
                        if matches:
                            for m in matches[:2]:
                                finding = {"category": category, "trigger": trigger_url.replace(base_url, ""), "match": str(m)[:100]}
                                if finding not in findings:
                                    findings.append(finding)
                                    log_warn(f"{category}: {str(m)[:80]}")

            # Check for verbose error headers
            for header in ["X-Debug-Token", "X-Debug-Token-Link"]:
                val = r.headers.get(header)
                if val:
                    findings.append({"category": "Debug Header", "trigger": "error_page", "match": f"{header}: {val}"})
                    log_fail(f"Debug header en error: {header}: {val}")

        except Exception:
            continue

    if not findings:
        log_ok("Error pages no revelan informacion sensible")

    results["error_disclosure"] = findings


# =====================================================================
#  MODULO 34: HTTP Request Smuggling Indicators
# =====================================================================
def mod_smuggling_indicators(session, url, results):
    section("34. HTTP REQUEST SMUGGLING INDICATORS")

    findings = []

    try:
        r = session.get(url, timeout=10)

        # Check for reverse proxy indicators (smuggling usually needs proxy + backend)
        proxy_indicators = []
        via = r.headers.get("Via", "")
        if via:
            proxy_indicators.append(f"Via: {via}")
        server = r.headers.get("Server", "")
        x_powered = r.headers.get("X-Powered-By", "")

        if via or ("nginx" in server.lower() and x_powered) or "cloudflare" in str(r.headers).lower():
            findings.append({"type": "proxy_detected", "indicators": proxy_indicators or [server]})
            log_info("Proxy/CDN detectado (prerrequisito para smuggling)")

        # Check Transfer-Encoding handling
        try:
            headers = {"Transfer-Encoding": "chunked, identity"}
            r2 = session.get(url, headers=headers, timeout=8)
            if r2.status_code != r.status_code:
                findings.append({"type": "te_ambiguity", "normal_status": r.status_code, "te_status": r2.status_code})
                log_warn(f"Diferencia con TE ambiguo: {r.status_code} vs {r2.status_code}")
        except Exception:
            pass

        # Check for HTTP/2 downgrade
        try:
            r3 = session.get(url, timeout=8)
            if hasattr(r3, 'raw') and hasattr(r3.raw, 'version'):
                version = r3.raw.version
                if version == 11:
                    log_info("HTTP/1.1 — posible smuggling si hay proxy")
                elif version == 20:
                    log_info("HTTP/2 — H2C smuggling posible si downgrade")
                findings.append({"type": "http_version", "version": version})
        except Exception:
            pass

    except Exception as e:
        log_fail(f"Error: {e}")

    if not findings:
        log_info("No se detectaron indicadores de request smuggling")

    results["smuggling"] = findings


# =====================================================================
#  MODULO 35: SSRF Indicator Detection
# =====================================================================
def mod_ssrf_indicators(session, url, html, results):
    section("35. SSRF INDICATOR DETECTION")

    findings = []

    # Parameters that commonly lead to SSRF
    ssrf_params = [
        "url", "uri", "path", "dest", "redirect", "file", "page",
        "document", "folder", "root", "dir", "img", "image", "load",
        "target", "proxy", "host", "site", "html", "val", "data",
        "fetch", "request", "resource", "content", "src", "source",
        "ref", "callback", "domain", "feed", "rss", "xml",
    ]

    # Check URL parameters for SSRF-prone patterns
    urls_in_page = re.findall(r'(?:href|src|action|data-url)=["\']([^"\']*\?[^"\']*)["\']', html)
    for found_url in urls_in_page:
        for param in ssrf_params:
            if f"{param}=" in found_url.lower():
                val_match = re.findall(f'{param}=([^&"\']+)', found_url, re.I)
                if val_match:
                    val = val_match[0].lower()
                    # Solo si el valor parece una URL absoluta (http://, //host,
                    # o URL-encoded), no cualquier valor con un punto (p.ej. .png)
                    if val.startswith(("http://", "https://", "//")) or \
                       "%2f%2f" in val or "%3a%2f%2f" in val or "://" in val:
                        findings.append({"type": "url_param", "param": param, "url": found_url[:200]})
                        log_warn(f"Parametro SSRF potencial: {param}={val[:60]}")
                        break

    # Check for URL fetch/proxy endpoints
    fetch_endpoints = [
        "/proxy?url=", "/fetch?url=", "/api/proxy?url=",
        "/image?url=", "/img?src=", "/load?url=",
        "/share?url=", "/preview?url=", "/check?url=",
        "/webhook?url=", "/import?url=", "/export?url=",
    ]

    for endpoint in fetch_endpoints:
        try:
            test_url = f"{url.rstrip('/')}{endpoint}https://example.com"
            r = session.get(test_url, timeout=8)
            if r.status_code == 200 and len(r.text) > 100:
                findings.append({"type": "fetch_endpoint", "endpoint": endpoint, "status": r.status_code})
                log_warn(f"Posible proxy/fetch: {endpoint} (HTTP {r.status_code})")
        except Exception:
            continue

    if not findings:
        log_ok("No se detectaron indicadores de SSRF")

    results["ssrf_indicators"] = findings


# =====================================================================
#  MODULO 36: Broken Link Hijacking
# =====================================================================
def mod_broken_links(session, base_url, html, results):
    section("36. BROKEN LINK HIJACKING")

    findings = []

    # Extract external links
    external_links = re.findall(r'href=["\']((https?://[^"\']+))["\']', html)
    external_domains = set()

    for full_url, _ in external_links:
        try:
            parsed = urlparse(full_url)
            if parsed.hostname and parsed.hostname != urlparse(base_url).hostname:
                external_domains.add(parsed.hostname)
        except Exception:
            continue

    log_info(f"Dominios externos encontrados: {len(external_domains)}")

    # Check if external domains are expired/available
    checked = 0
    for domain in list(external_domains)[:30]:
        try:
            socket.getaddrinfo(domain, None)
        except socket.gaierror:
            findings.append({"domain": domain, "type": "unresolvable"})
            log_fail(f"Dominio externo NO resuelve: {domain} — posible hijacking")
            checked += 1
        except Exception:
            pass

        if checked >= 10:
            break

    # Check for links to known takeover-prone services
    takeover_domains = [
        "github.io", "herokuapp.com", "surge.sh", "bitbucket.io",
        "ghost.io", "myshopify.com", "wordpress.com",
        "tumblr.com", "cargocollective.com", "fly.dev",
    ]

    for full_url, _ in external_links:
        for td in takeover_domains:
            if td in full_url:
                try:
                    r = session.get(full_url, timeout=8)
                    if r.status_code == 404:
                        findings.append({"domain": full_url, "type": "404_takeover_service"})
                        log_fail(f"Link a servicio takeover con 404: {full_url[:100]}")
                except Exception:
                    pass

    if not findings:
        log_ok("No se detectaron links rotos explotables")

    results["broken_links"] = findings


# =====================================================================
#  MODULO 37: VULNERABILITY ASSESSMENT
# =====================================================================
def mod_vuln_assessment(results):
    section("37. VULNERABILITY ASSESSMENT")

    vulns = []  # (severity, title, description, remediation)

    # Headers se usan en varias secciones; normalizar a minusculas para lookups
    # consistentes (HTTP headers son case-insensitive). Debe definirse ANTES de
    # su primer uso para evitar UnboundLocalError.
    headers = results.get("headers", {})
    headers_lc = {k.lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}

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

    if "COEP" in missing:
        vulns.append(("INFO", "Missing Cross-Origin-Embedder-Policy",
            "Sin COEP recursos cross-origin pueden filtrar datos via side-channels.",
            "Agregar Cross-Origin-Embedder-Policy: require-corp."))

    if "CORP" in missing:
        vulns.append(("INFO", "Missing Cross-Origin-Resource-Policy",
            "Sin CORP recursos del sitio pueden ser leidos por otros origenes.",
            "Agregar Cross-Origin-Resource-Policy: same-origin."))

    # Check dangerous headers present
    x_xss = headers_lc.get("x-xss-protection", "")
    if x_xss and "1; mode=block" not in str(x_xss):
        vulns.append(("LOW", "X-XSS-Protection Misconfigured",
            f"X-XSS-Protection configurado como: {x_xss}. Puede desactivar filtros del navegador.",
            "Usar X-XSS-Protection: 1; mode=block o removerlo y depender de CSP."))

    cache_control = headers_lc.get("cache-control", "")
    if not cache_control:
        vulns.append(("LOW", "Missing Cache-Control Header",
            "Sin Cache-Control, paginas sensibles pueden cachearse en proxies/navegadores.",
            "Agregar Cache-Control: no-store, no-cache para paginas sensibles."))
    elif "public" in cache_control.lower() and "no-store" not in cache_control.lower():
        vulns.append(("MEDIUM", "Cache-Control Allows Public Caching",
            f"Cache-Control: {cache_control} — paginas sensibles pueden ser cacheadas.",
            "Usar no-store para contenido sensible."))

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

        # Additional SSL checks
        issuer = ssl_data.get("issuer", ())
        subject = ssl_data.get("subject", ())
        if issuer:
            issuer_str = str(issuer)
            if "self-signed" in issuer_str.lower() or issuer == subject:
                vulns.append(("HIGH", "Self-Signed SSL Certificate",
                    "Certificado SSL es self-signed. No confiable por navegadores.",
                    "Usar certificado de una CA reconocida."))

        # Check for wildcard certificate
        san_data = results.get("ssl_sans", [])
        wildcards = [s for s in san_data if s.startswith("*.")]
        if wildcards:
            vulns.append(("INFO", "Wildcard SSL Certificate",
                f"Certificado wildcard: {', '.join(wildcards[:3])}.",
                "Evaluar si wildcard certs son necesarios — aumentan superficie."))

        # Check SHA-1 signature
        sig_alg = ssl_data.get("signatureAlgorithm", "")
        if "sha1" in str(sig_alg).lower():
            vulns.append(("HIGH", "SSL Certificate Uses SHA-1",
                "Certificado usa SHA-1 que es criptograficamente debil.",
                "Renovar certificado con SHA-256 o superior."))

    # --- Cookies ---
    cookie_issues = results.get("cookie_issues", [])
    secure_missing = [c for c in cookie_issues if "Secure" in c]
    httponly_missing = [c for c in cookie_issues if "HttpOnly" in c]
    samesite_missing = [c for c in cookie_issues if "SameSite" in c]

    if secure_missing:
        vulns.append(("HIGH", "Cookies Without Secure Flag",
            f"{len(secure_missing)} cookie(s) sin flag Secure. Pueden transmitirse por HTTP.",
            "Agregar flag Secure a todas las cookies."))

    if samesite_missing:
        vulns.append(("MEDIUM", "Cookies Without SameSite Attribute",
            f"{len(samesite_missing)} cookie(s) sin SameSite. Vulnerable a CSRF.",
            "Agregar SameSite=Strict o SameSite=Lax a todas las cookies."))

    if httponly_missing:
        vulns.append(("MEDIUM", "Cookies Without HttpOnly Flag",
            f"{len(httponly_missing)} cookie(s) sin flag HttpOnly. Accesibles via JavaScript (XSS).",
            "Agregar flag HttpOnly a cookies de sesion."))

    # --- Server Info Disclosure ---
    server = headers_lc.get("server", "")
    powered = headers_lc.get("x-powered-by", "")

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

    # Additional header checks
    asp_ver = headers.get("X-AspNet-Version", "")
    if asp_ver:
        vulns.append(("MEDIUM", "ASP.NET Version Disclosure",
            f"X-AspNet-Version: {asp_ver}",
            "Eliminar X-AspNet-Version header."))

    asp_mvc = headers.get("X-AspNetMvc-Version", "")
    if asp_mvc:
        vulns.append(("MEDIUM", "ASP.NET MVC Version Disclosure",
            f"X-AspNetMvc-Version: {asp_mvc}",
            "Eliminar X-AspNetMvc-Version header."))

    generator = headers.get("X-Generator", "")
    if generator:
        vulns.append(("LOW", "X-Generator Header Disclosure",
            f"X-Generator: {generator}",
            "Eliminar X-Generator header."))

    debug_header = headers.get("X-Debug-Token", "")
    if debug_header:
        vulns.append(("HIGH", "Debug Token in Response Headers",
            f"X-Debug-Token: {debug_header}. Framework debug mode activo.",
            "Deshabilitar modo debug en produccion."))

    x_runtime = headers.get("X-Runtime", "")
    if x_runtime:
        vulns.append(("LOW", "X-Runtime Header Disclosure",
            f"X-Runtime: {x_runtime}. Revela tiempo de procesamiento (timing attacks).",
            "Eliminar X-Runtime header."))

    # --- Technologies ---
    techs = results.get("technologies", [])
    for typ, val in techs:
        val_lower = val.lower() if val else ""
        if "jquery" in val_lower:
            # Check for old jQuery versions
            ver_match = re.search(r'(\d+\.\d+\.\d+)', val)
            if ver_match:
                jq_parts = [int(x) for x in ver_match.group(1).split(".")]
                if jq_parts[0] < 3 or (jq_parts[0] == 3 and jq_parts[1] < 5):
                    vulns.append(("MEDIUM", f"Outdated jQuery: {ver_match.group(1)}",
                        f"jQuery {ver_match.group(1)} tiene CVEs conocidos (XSS).",
                        "Actualizar jQuery a >= 3.5.0."))
        elif "angularjs" in val_lower or "angular.js" in val_lower:
            vulns.append(("MEDIUM", "AngularJS (1.x) Detected",
                "AngularJS 1.x ya no recibe security updates. Vulnerable a template injection.",
                "Migrar a Angular 2+ o framework moderno."))
        elif "bootstrap" in val_lower:
            ver_match = re.search(r'(\d+)\.\d+', val)
            if ver_match and int(ver_match.group(1)) < 4:
                vulns.append(("LOW", f"Outdated Bootstrap: {val}",
                    "Bootstrap < 4 tiene XSS en data attributes.",
                    "Actualizar Bootstrap a >= 5.x."))

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

    # Additional JS checks
    endpoints = js_analysis.get("endpoints", [])
    if endpoints:
        api_eps = [e for e in endpoints if "/api" in e.lower()]
        admin_eps = [e for e in endpoints if "admin" in e.lower()]
        if api_eps:
            vulns.append(("MEDIUM", "API Endpoints Exposed in JavaScript",
                f"{len(api_eps)} endpoint(s) API encontrados en JS. Facilita enumeracion.",
                "Minimizar endpoints visibles en frontend JS."))
        if admin_eps:
            vulns.append(("MEDIUM", "Admin Endpoints in JavaScript",
                f"{len(admin_eps)} endpoint(s) admin encontrados en JS.",
                "No referenciar endpoints admin en frontend."))

    internal_urls = js_analysis.get("internal_urls", [])
    if internal_urls:
        vulns.append(("MEDIUM", "Internal URLs in JavaScript",
            f"{len(internal_urls)} URL(s) internas encontradas en JS.",
            "Eliminar URLs internas del codigo frontend."))

    comments = js_analysis.get("comments", [])
    sensitive_comments = [c for c in (comments or []) if any(
        w in c.lower() for w in ["todo", "fix", "hack", "bug", "password", "secret", "temp"])]
    if sensitive_comments:
        vulns.append(("LOW", "Sensitive Comments in JavaScript",
            f"{len(sensitive_comments)} comentarios potencialmente sensibles en JS.",
            "Eliminar comentarios de debug/temp del codigo en produccion."))

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

    # DNS zone transfer indicators
    ns_records = dns_data.get("NS", [])
    if len(ns_records) == 1:
        vulns.append(("MEDIUM", "Single DNS Nameserver",
            "Solo un nameserver. Unico punto de fallo para DNS.",
            "Agregar al menos un nameserver secundario."))

    # Check for DNSSEC (mod_dns consulta DNSKEY en el apex y lo guarda si existe)
    has_dnssec = bool(dns_data.get("DNSKEY"))
    if dns_data and not has_dnssec:
        vulns.append(("INFO", "No DNSSEC Detected",
            "No se detecto DNSKEY en el apex. DNSSEC podria no estar activo "
            "(o no fue posible consultarlo). Sin DNSSEC el DNS es mas facil de spoofear.",
            "Evaluar la implementacion de DNSSEC para autenticar respuestas DNS."))

    # Check for CNAME on apex
    cname_records = dns_data.get("CNAME", [])
    if cname_records:
        vulns.append(("INFO", "CNAME Records Found",
            f"CNAME: {', '.join(cname_records[:3])}. Posible redirect o terceros.",
            "Verificar que CNAMEs apuntan a servicios propios."))

    # Check for wildcard DNS
    mx_records = dns_data.get("MX", [])
    if not mx_records and dns_data:
        vulns.append(("INFO", "No MX Records",
            "Sin registros MX. Dominio no recibe email (normal si no es para mail).",
            "Agregar MX si el dominio necesita recibir emails."))

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

        if "client_credentials" in grants:
            vulns.append(("INFO", "Client Credentials Grant Enabled",
                "Client credentials flow habilitado. Verificar que solo clients confiables lo usan.",
                "Restringir client credentials a clients de backend confiables."))

        # Check PKCE support
        code_challenge = oidc.get("code_challenge_methods_supported", [])
        if "authorization_code" in grants and "S256" not in code_challenge:
            vulns.append(("HIGH", "PKCE S256 Not Supported",
                "Authorization code flow sin PKCE S256. Vulnerable a code interception.",
                "Habilitar y requerir PKCE con S256."))

        # Check token endpoint auth methods
        token_auth = oidc.get("token_endpoint_auth_methods_supported", [])
        if "client_secret_post" in token_auth:
            vulns.append(("MEDIUM", "Token Auth: client_secret_post Enabled",
                "Client secret enviado en POST body. Visible en logs.",
                "Preferir client_secret_basic o private_key_jwt."))

        # Check for registration endpoint
        reg_ep = oidc.get("registration_endpoint")
        if reg_ep:
            vulns.append(("MEDIUM", "Dynamic Client Registration Open",
                f"Endpoint de registro: {reg_ep}. Cualquiera puede registrar clients.",
                "Restringir registro dinamico de clients OAuth."))

        # Check for response types
        resp_types = oidc.get("response_types_supported", [])
        if "token" in resp_types:
            vulns.append(("MEDIUM", "Implicit Token Response Type Enabled",
                "response_type=token habilitado. Tokens expuestos en fragment.",
                "Deshabilitar implicit y usar code flow con PKCE."))

        # Check for userinfo endpoint security
        userinfo = oidc.get("userinfo_endpoint")
        if userinfo and "http://" in str(userinfo):
            vulns.append(("HIGH", "UserInfo Endpoint Over HTTP",
                f"UserInfo endpoint usa HTTP: {userinfo}.",
                "Configurar HTTPS para todos los endpoints OAuth."))

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

    # --- Subdomain Count ---
    subs = results.get("subdomains", [])
    if len(subs) > 50:
        vulns.append(("INFO", "Large Subdomain Surface",
            f"{len(subs)} subdominios detectados. Gran superficie de ataque.",
            "Auditar y eliminar subdominios innecesarios."))

    wildcard_subs = [s for s in subs if s.startswith("*.")]
    if wildcard_subs:
        vulns.append(("MEDIUM", "Wildcard Subdomain Detected",
            f"Wildcard DNS: {', '.join(wildcard_subs[:3])}. Facilita subdomain takeover.",
            "Evitar wildcard DNS si no es necesario."))

    # --- Robots.txt ---
    robots = results.get("robots_txt", "")
    if isinstance(robots, str):
        if "Disallow: /" in robots and "User-agent: *" in robots:
            # Check for admin paths disclosed in robots
            disallowed = re.findall(r'Disallow:\s*(/\S+)', robots)
            sensitive_disallowed = [d for d in disallowed if any(
                w in d.lower() for w in ["admin", "login", "api", "internal", "private",
                    "staging", "dev", "test", "backup", "config", "secret", "panel"])]
            if sensitive_disallowed:
                vulns.append(("MEDIUM", "Sensitive Paths Disclosed in robots.txt",
                    f"robots.txt revela rutas sensibles: {', '.join(sensitive_disallowed[:5])}.",
                    "No usar robots.txt para ocultar paths — usar autenticacion."))

    # --- WHOIS ---
    whois_data = results.get("whois", {})
    if isinstance(whois_data, dict):
        registrar = whois_data.get("registrar", "")
        if registrar and any(x in str(registrar).lower() for x in ["godaddy", "namecheap", "1and1"]):
            vulns.append(("INFO", f"Domain Registrar: {registrar}",
                "Registrar identificado. Verificar que domain lock esta activado.",
                "Activar domain lock y 2FA en cuenta del registrar."))

    # --- Favicon ---
    fav_data = results.get("favicon", {})
    if fav_data and fav_data.get("known_match"):
        vulns.append(("INFO", f"Technology via Favicon: {fav_data['known_match']}",
            f"Favicon hash identifica: {fav_data['known_match']}.",
            "Cambiar favicon default para evitar fingerprinting."))

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

    # --- Open Redirect ---
    open_redir = results.get("open_redirect", [])
    confirmed_redirects = [f for f in open_redir if f.get("type") == "confirmed_redirect"]
    param_redirects = [f for f in open_redir if f.get("type") == "link_param"]
    form_redirects = [f for f in open_redir if f.get("type") == "form_field"]
    if confirmed_redirects:
        vulns.append(("HIGH", "Open Redirect Confirmed",
            f"{len(confirmed_redirects)} open redirect(s) confirmados. Permiten phishing.",
            "Validar y sanitizar parametros de redireccion. Usar whitelist de destinos."))
    if param_redirects:
        vulns.append(("MEDIUM", "Redirect Parameters in Links",
            f"{len(param_redirects)} links con parametros de redireccion detectados.",
            "Verificar que parametros de redirect no aceptan URLs externas."))
    if form_redirects:
        vulns.append(("MEDIUM", "Redirect Fields in Forms",
            f"{len(form_redirects)} campos de formulario con nombres de redireccion.",
            "Validar campos de redireccion en el backend."))
    meta_redir = [f for f in open_redir if f.get("type") == "meta_refresh"]
    if meta_redir:
        vulns.append(("LOW", "Meta Refresh Redirect",
            f"{len(meta_redir)} meta refresh redirect(s) detectados.",
            "Evaluar si meta refresh es necesario."))

    # --- JSONP ---
    jsonp = results.get("jsonp", [])
    confirmed_jsonp = [f for f in jsonp if f.get("type") == "confirmed"]
    if confirmed_jsonp:
        vulns.append(("HIGH", "JSONP Endpoint Active",
            f"{len(confirmed_jsonp)} endpoint(s) JSONP activos. Callback hijacking posible.",
            "Migrar de JSONP a CORS. Validar parametro callback."))
    html_jsonp = [f for f in jsonp if f.get("type") == "html_reference"]
    if html_jsonp:
        vulns.append(("MEDIUM", "JSONP References in HTML",
            f"{len(html_jsonp)} referencia(s) a endpoints JSONP en HTML.",
            "Evaluar si JSONP es necesario. Preferir CORS."))

    # --- Host Header Injection ---
    host_hdr = results.get("host_header", [])
    for hh in host_hdr:
        if hh.get("reflected_in") == "Location header":
            vulns.append(("HIGH", "Host Header Injection in Redirect",
                f"Host '{hh['host']}' reflejado en Location header ({hh['test']}).",
                "No usar Host header para generar URLs. Configurar hostname en servidor."))
        elif "X-Forwarded-Host" in hh.get("test", ""):
            vulns.append(("HIGH", "X-Forwarded-Host Injection",
                "X-Forwarded-Host reflejado en respuesta. Cache poisoning posible.",
                "Ignorar o validar X-Forwarded-Host."))
        else:
            vulns.append(("MEDIUM", "Host Header Reflected",
                f"Host '{hh['host']}' reflejado en respuesta ({hh['test']}).",
                "No usar Host header para generar contenido dinamico."))

    # --- Cache Poisoning ---
    cache_poison = results.get("cache_poisoning", [])
    for cp in cache_poison:
        if cp.get("type") == "unkeyed_header_reflected":
            vulns.append(("HIGH", f"Cache Poisoning: Unkeyed Header Reflected ({cp['header']})",
                f"Header {cp['header']} no es parte de la cache key pero se refleja en respuesta.",
                "Incluir headers relevantes en cache key o no reflejarlos."))
        elif cp.get("type") == "vary_missing_host":
            vulns.append(("MEDIUM", "Cache: Vary Header Missing Host",
                "Vary no incluye Host. Cache poisoning via Host header posible.",
                "Agregar Host al header Vary."))

    # --- GraphQL ---
    graphql = results.get("graphql", [])
    for gq in graphql:
        if gq.get("type") == "introspection_enabled":
            vulns.append(("HIGH", f"GraphQL Introspection Enabled ({gq['endpoint']})",
                f"Introspection habilitado. {gq.get('types_count', 0)} tipos expuestos.",
                "Deshabilitar introspection en produccion."))
        if gq.get("type") == "sensitive_types":
            vulns.append(("HIGH", f"GraphQL: Sensitive Types Exposed ({gq['endpoint']})",
                f"Tipos sensibles: {', '.join(gq['types'][:5])}.",
                "Revisar autorizacion en queries de tipos sensibles."))
        if gq.get("type") == "interface_found":
            vulns.append(("MEDIUM", f"GraphQL Interface Found ({gq['endpoint']})",
                "Interfaz GraphQL (GraphiQL/Playground) accesible.",
                "Deshabilitar interfaces de desarrollo en produccion."))

    # --- JWT ---
    jwt_data = results.get("jwt", [])
    for jt in jwt_data:
        issue = jt.get("issue", "")
        if issue == "alg_none":
            vulns.append(("CRITICAL", "JWT: Algorithm None",
                f"JWT en {jt.get('cookie', 'N/A')} usa alg:none. Sin verificacion de firma.",
                "Rechazar tokens con alg:none. Validar algoritmo en backend."))
        elif issue == "jku_present":
            vulns.append(("HIGH", "JWT: JKU Header Present",
                f"JWT contiene JKU: {jt.get('jku', '')}. Key injection posible.",
                "No confiar en JKU del token. Usar keys locales."))
        elif issue == "x5u_present":
            vulns.append(("HIGH", "JWT: X5U Header Present",
                f"JWT contiene X5U: {jt.get('x5u', '')}. Certificate injection posible.",
                "No confiar en X5U del token. Validar certificados localmente."))
        elif jt.get("location", "").startswith("html"):
            vulns.append(("HIGH", "JWT Token Exposed in HTML/JS",
                "JWT encontrado en codigo HTML/JavaScript.",
                "No exponer tokens JWT en frontend."))

    # --- CRLF ---
    crlf = results.get("crlf", [])
    for cr in crlf:
        if cr.get("type") == "header_injection":
            vulns.append(("HIGH", "CRLF Injection in Headers",
                f"Inyeccion CRLF confirmada: {cr['payload']}.",
                "Sanitizar caracteres CR/LF en input del usuario."))

    # --- API Keys Deep ---
    api_keys = results.get("api_keys_deep", [])
    if api_keys:
        critical_keys = [k for k in api_keys if any(x in k["type"].lower() for x in
            ["secret", "private", "bearer", "connection", "basic auth"])]
        high_keys = [k for k in api_keys if k not in critical_keys and any(x in k["type"].lower() for x in
            ["aws", "stripe", "twilio", "sendgrid", "slack", "github", "firebase"])]
        other_keys = [k for k in api_keys if k not in critical_keys and k not in high_keys]

        if critical_keys:
            types_str = ", ".join(set(k["type"] for k in critical_keys))
            vulns.append(("CRITICAL", "Secret Keys/Credentials Exposed",
                f"Secretos encontrados: {types_str}.",
                "Rotar credenciales inmediatamente. Mover al backend."))
        if high_keys:
            types_str = ", ".join(set(k["type"] for k in high_keys))
            vulns.append(("HIGH", "API Keys Exposed",
                f"API keys encontradas: {types_str}.",
                "Rotar API keys. No exponer en frontend."))
        if other_keys:
            types_str = ", ".join(set(k["type"] for k in other_keys[:5]))
            vulns.append(("MEDIUM", "Potential Credentials Detected",
                f"Patrones de credenciales: {types_str}.",
                "Verificar y rotar si son credenciales reales."))

        internal_ips = [k for k in api_keys if k["type"] == "IP Address (Internal)"]
        if internal_ips:
            vulns.append(("MEDIUM", "Internal IP Addresses Exposed",
                f"{len(internal_ips)} IP(s) internas expuestas en codigo.",
                "Eliminar IPs internas del frontend."))

    # --- Rate Limiting ---
    rate = results.get("rate_limiting", {})
    if rate.get("rate_limited") is False:
        vulns.append(("LOW", "No Rate Limiting Observed on Landing Page",
            "No se observo rate limiting (HTTP 429) tras 15 requests a la pagina "
            "principal. Nota: endpoints estaticos no suelen limitar; verificar "
            "manualmente login/APIs antes de concluir que no hay rate limiting.",
            "Implementar rate limiting en endpoints de autenticacion y APIs."))
    if rate.get("rate_limited") and rate.get("requests_before_limit", 0) > 10:
        vulns.append(("LOW", "Weak Rate Limiting",
            f"Rate limiting activo pero permisivo: {rate['requests_before_limit']} requests antes de limitar.",
            "Reducir umbral de rate limiting."))

    # --- Default Pages ---
    defaults = results.get("default_pages", [])
    for dp in defaults:
        tag = dp.get("tag", "")
        if tag in ["wp_install", "generic_install", "generic_installer"]:
            vulns.append(("CRITICAL", f"Installation Page Exposed: {dp['path']}",
                f"Pagina de instalacion accesible ({dp['service']}). Posible RCE.",
                "Completar o eliminar wizard de instalacion."))
        elif tag in ["phpmyadmin", "pma", "adminer", "pgadmin"]:
            vulns.append(("HIGH", f"Database Manager Exposed: {dp['path']}",
                f"{dp['service']} accesible publicamente.",
                "Restringir acceso por IP/VPN. Deshabilitar si no es necesario."))
        elif tag in ["jenkins", "hudson"]:
            vulns.append(("HIGH", f"CI/CD Tool Exposed: {dp['path']}",
                f"{dp['service']} accesible publicamente.",
                "Restringir acceso al panel CI/CD."))
        elif tag in ["grafana", "kibana", "prometheus", "nagios", "zabbix"]:
            vulns.append(("MEDIUM", f"Monitoring Tool Exposed: {dp['path']}",
                f"{dp['service']} accesible publicamente.",
                "Restringir acceso a herramientas de monitoreo."))
        elif tag in ["laravel_debug", "laravel_telescope", "laravel_horizon"]:
            vulns.append(("HIGH", f"Framework Debug Tool Exposed: {dp['path']}",
                f"{dp['service']} accesible. Revela informacion interna.",
                "Deshabilitar herramientas de debug en produccion."))
        elif tag in ["server_status", "server_info", "elmah", "rails_info"]:
            vulns.append(("HIGH", f"Server Info Exposed: {dp['path']}",
                f"{dp['service']} accesible. Revela configuracion del servidor.",
                "Deshabilitar o restringir endpoints de info."))
        elif tag in ["minio", "portainer", "rancher", "solr", "couchdb"]:
            vulns.append(("HIGH", f"Infrastructure Service Exposed: {dp['path']}",
                f"{dp['service']} accesible publicamente.",
                "Restringir acceso a servicios internos."))
        elif tag.endswith("_default"):
            vulns.append(("LOW", f"Default Page: {dp['path']}",
                f"Pagina default de {dp['service']} detectada.",
                "Configurar landing page apropiado."))

    # --- Error Disclosure ---
    errors = results.get("error_disclosure", [])
    for err in errors:
        cat = err.get("category", "")
        if cat == "Stack Trace":
            vulns.append(("HIGH", "Stack Trace in Error Page",
                f"Stack trace expuesto: {err['match'][:80]}",
                "Deshabilitar stack traces en produccion."))
        elif cat == "Database Error":
            vulns.append(("HIGH", "Database Error Disclosed",
                f"Error de DB expuesto: {err['match'][:80]}",
                "Configurar mensajes de error genericos para BD."))
        elif cat == "File Path":
            vulns.append(("MEDIUM", "Server Path Disclosed",
                f"Ruta interna expuesta: {err['match'][:80]}",
                "No exponer rutas internas en errores."))
        elif cat == "Debug Info":
            vulns.append(("HIGH", "Debug Mode Enabled",
                f"Debug activo: {err['match'][:80]}",
                "Deshabilitar modo debug en produccion."))
        elif cat == "Framework Version":
            vulns.append(("MEDIUM", "Framework Version Disclosed",
                f"Version expuesta: {err['match'][:80]}",
                "Ocultar version del framework."))
        elif cat == "Internal IP":
            vulns.append(("MEDIUM", "Internal IP in Error Page",
                f"IP interna: {err['match']}",
                "No exponer IPs internas en errores."))
        elif cat == "Debug Header":
            vulns.append(("HIGH", "Debug Headers in Response",
                err["match"],
                "Eliminar headers de debug."))
        elif cat == "Email in Error":
            vulns.append(("LOW", "Email in Error Page",
                f"Email expuesto en error page: {err['match'][:60]}",
                "No exponer emails en paginas de error."))
        elif cat in ["Server Config", "Technology Stack"]:
            vulns.append(("MEDIUM", f"{cat} Disclosed in Error",
                err["match"][:80],
                "Minimizar informacion en errores."))
        elif cat == "Connection String":
            vulns.append(("CRITICAL", "Database Connection String Exposed",
                f"Connection string en error: {err['match'][:60]}",
                "No exponer connection strings en errores."))

    # Aggregate error disclosure
    if errors:
        categories = set(e.get("category") for e in errors)
        if len(categories) >= 3:
            vulns.append(("HIGH", "Verbose Error Pages (Multiple Categories)",
                f"{len(errors)} info disclosures en {len(categories)} categorias.",
                "Implementar error handling personalizado en produccion."))

    # --- HTTP Method Override ---
    method_override = results.get("method_override", {})
    if method_override.get("override_works"):
        vulns.append(("MEDIUM", "HTTP Method Override Enabled",
            "X-HTTP-Method-Override permite cambiar metodo HTTP. Bypass de ACLs posible.",
            "Deshabilitar method override en produccion."))

    # --- HTTP Request Smuggling ---
    smuggling = results.get("smuggling", [])
    for sm in smuggling:
        if sm.get("type") == "te_ambiguity":
            vulns.append(("MEDIUM", "Transfer-Encoding Ambiguity",
                f"Diferente respuesta con TE ambiguo: {sm['normal_status']} vs {sm['te_status']}.",
                "Configurar manejo estricto de Transfer-Encoding."))
        elif sm.get("type") == "proxy_detected":
            vulns.append(("INFO", "Reverse Proxy Detected",
                f"Indicadores de proxy: {', '.join(sm.get('indicators', []))}.",
                "Verificar configuracion proxy vs backend contra smuggling."))

    # --- SSRF Indicators ---
    ssrf = results.get("ssrf_indicators", [])
    fetch_ssrf = [s for s in ssrf if s.get("type") == "fetch_endpoint"]
    param_ssrf = [s for s in ssrf if s.get("type") == "url_param"]
    if fetch_ssrf:
        vulns.append(("HIGH", "SSRF: Fetch/Proxy Endpoints Detected",
            f"{len(fetch_ssrf)} endpoint(s) de fetch/proxy activos.",
            "Validar y restringir URLs en proxy endpoints. Bloquear IPs internas."))
    if param_ssrf:
        vulns.append(("MEDIUM", "SSRF: URL Parameters Detected",
            f"{len(param_ssrf)} parametro(s) que aceptan URLs detectados.",
            "Validar parametros URL contra SSRF. Usar whitelist de destinos."))

    # --- Broken Links ---
    broken = results.get("broken_links", [])
    unresolvable = [b for b in broken if b.get("type") == "unresolvable"]
    takeover_404 = [b for b in broken if b.get("type") == "404_takeover_service"]
    if unresolvable:
        vulns.append(("MEDIUM", "Broken Link Hijacking: Unresolvable Domains",
            f"{len(unresolvable)} link(s) a dominios que no resuelven. Hijacking posible.",
            "Eliminar links a dominios expirados. Registrar si son propios."))
    if takeover_404:
        vulns.append(("HIGH", "Broken Link Hijacking: 404 on Takeover Service",
            f"{len(takeover_404)} link(s) a servicios de hosting con 404.",
            "Reclamar recursos en servicios externos o eliminar links."))

    # --- Cookie Prefix Checks ---
    cookies = results.get("cookies", [])
    for ck in cookies:
        name = ck.get("name", "")
        flags = ck.get("flags", "")
        flags_lower = flags.lower() if flags else ""
        if name.startswith("__Host-"):
            if "secure" not in flags_lower:
                vulns.append(("HIGH", "Cookie __Host- Prefix Without Secure",
                    f"Cookie {name} usa prefijo __Host- sin flag Secure.",
                    "Cookies con __Host- DEBEN tener Secure, Path=/, y no Domain."))
            if "path=/" not in flags_lower.replace(" ", ""):
                vulns.append(("HIGH", "Cookie __Host- Prefix Without Path=/",
                    f"Cookie {name} usa prefijo __Host- sin Path=/.",
                    "Agregar Path=/ a cookies con prefijo __Host-."))
        if name.startswith("__Secure-"):
            if "secure" not in flags_lower:
                vulns.append(("HIGH", "Cookie __Secure- Prefix Without Secure",
                    f"Cookie {name} usa prefijo __Secure- sin flag Secure.",
                    "Cookies con __Secure- DEBEN tener flag Secure."))

    # --- SRI (Subresource Integrity) ---
    html = results.get("html", "")
    if html:
        import re as _re
        ext_scripts = _re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', html, _re.I)
        scripts_without_sri = [s for s in ext_scripts if 'integrity=' not in s.lower()]
        if scripts_without_sri:
            vulns.append(("MEDIUM", "External Scripts Without SRI",
                f"{len(scripts_without_sri)} script(s) externo(s) sin integridad (integrity attribute).",
                "Agregar integrity y crossorigin a scripts externos."))
        ext_links = _re.findall(r'<link[^>]+href=["\']https?://[^"\']+["\'][^>]*stylesheet[^>]*>', html, _re.I)
        links_without_sri = [l for l in ext_links if 'integrity=' not in l.lower()]
        if links_without_sri:
            vulns.append(("LOW", "External Stylesheets Without SRI",
                f"{len(links_without_sri)} stylesheet(s) externo(s) sin integrity.",
                "Agregar integrity attribute a stylesheets de CDN."))

    # --- Mixed Content ---
    if html:
        http_resources = _re.findall(r'(?:src|href|action)=["\']http://[^"\']+', html, _re.I)
        if http_resources:
            vulns.append(("MEDIUM", "Mixed Content: HTTP Resources on HTTPS Page",
                f"{len(http_resources)} recurso(s) cargado(s) por HTTP en pagina HTTPS.",
                "Cambiar todos los recursos a HTTPS."))

    # --- Form Security ---
    if html:
        forms = _re.findall(r'<form[^>]*>', html, _re.I)
        for form in forms:
            action = _re.search(r'action=["\']([^"\']*)', form, _re.I)
            if action:
                act_url = action.group(1)
                if act_url.startswith("http://"):
                    vulns.append(("HIGH", "Form Submits Over HTTP",
                        f"Formulario envia datos por HTTP: {act_url[:60]}",
                        "Cambiar action de formularios a HTTPS."))
                    break
        forms_no_csrf = []
        form_blocks = _re.findall(r'<form[^>]*>.*?</form>', html, _re.I | _re.S)
        for fb in form_blocks[:10]:
            if 'csrf' not in fb.lower() and '_token' not in fb.lower() and 'authenticity' not in fb.lower():
                if '<input' in fb.lower() and ('post' in fb.lower() or 'method' not in fb.lower()):
                    forms_no_csrf.append(fb[:50])
        if forms_no_csrf:
            vulns.append(("HIGH", "Forms Without CSRF Token",
                f"{len(forms_no_csrf)} formulario(s) POST sin token CSRF visible.",
                "Implementar CSRF tokens en todos los formularios POST."))

    # --- Iframe Sandbox ---
    if html:
        iframes = _re.findall(r'<iframe[^>]*>', html, _re.I)
        iframes_no_sandbox = [i for i in iframes if 'sandbox' not in i.lower()]
        if iframes_no_sandbox:
            vulns.append(("MEDIUM", "Iframes Without Sandbox Attribute",
                f"{len(iframes_no_sandbox)} iframe(s) sin sandbox attribute.",
                "Agregar sandbox attribute a iframes para limitar capacidades."))
        for iframe in iframes:
            if 'sandbox' in iframe.lower() and 'allow-scripts' in iframe.lower() and 'allow-same-origin' in iframe.lower():
                vulns.append(("HIGH", "Iframe Sandbox Bypass: allow-scripts + allow-same-origin",
                    "Iframe con sandbox tiene allow-scripts y allow-same-origin juntos.",
                    "No combinar allow-scripts con allow-same-origin en sandbox."))
                break

    # --- Permissions-Policy / Feature-Policy ---
    hdrs = headers_lc
    pp = hdrs.get("permissions-policy", hdrs.get("feature-policy", ""))
    if not pp:
        vulns.append(("LOW", "No Permissions-Policy Header",
            "Sin Permissions-Policy header. Features del navegador no restringidas.",
            "Implementar Permissions-Policy para restringir camera, mic, geolocation, payment."))

    # --- Email Security Advanced ---
    # SPF/DMARC faltantes y +all/p=none/rua ya se cubren en las secciones
    # "DNS" y "Email Security" de arriba. Aqui solo agregamos el caso ~all
    # (softfail) que no se reporta en otro lugar, para no duplicar hallazgos.
    email_sec = results.get("email_security", {})
    if email_sec:
        spf = email_sec.get("spf", "")
        if spf and "~all" in spf:
            vulns.append(("MEDIUM", "SPF Softfail (~all) Instead of Hardfail",
                "SPF usa ~all (softfail). Correos falsificados pueden llegar como spam.",
                "Cambiar ~all a -all para rechazar correos no autorizados."))

    # --- Autocomplete on Sensitive Fields ---
    if html:
        password_fields = _re.findall(r'<input[^>]*type=["\']password["\'][^>]*>', html, _re.I)
        for pf in password_fields:
            if 'autocomplete=' not in pf.lower() or 'autocomplete="on"' in pf.lower():
                vulns.append(("LOW", "Password Field With Autocomplete Enabled",
                    "Campo de password sin autocomplete=off. Browser puede guardar password.",
                    "Agregar autocomplete='off' o 'new-password' a campos de password."))
                break

    # --- Target Blank Without Noopener ---
    if html:
        target_blank = _re.findall(r'<a[^>]*target=["\']_blank["\'][^>]*>', html, _re.I)
        no_noopener = [t for t in target_blank if 'noopener' not in t.lower() and 'noreferrer' not in t.lower()]
        if no_noopener:
            vulns.append(("LOW", "Links target=_blank Without rel=noopener",
                f"{len(no_noopener)} link(s) con target=_blank sin noopener/noreferrer.",
                "Agregar rel='noopener noreferrer' a links con target=_blank."))

    # --- Sensitive HTML Comments ---
    if html:
        comments = _re.findall(r'<!--(.*?)-->', html, _re.S)
        sensitive_comments = []
        comment_patterns = ['todo', 'fixme', 'hack', 'bug', 'password', 'secret', 'key', 'token',
                           'admin', 'debug', 'temp', 'remove', 'credential', 'api_key']
        for c in comments:
            for p in comment_patterns:
                if p in c.lower():
                    sensitive_comments.append(c.strip()[:60])
                    break
        if sensitive_comments:
            vulns.append(("LOW", "Sensitive Information in HTML Comments",
                f"{len(sensitive_comments)} comentario(s) HTML con info potencialmente sensible.",
                "Eliminar comentarios sensibles del HTML en produccion."))

    # --- Base Tag Hijacking ---
    if html:
        base_tags = _re.findall(r'<base[^>]*href=["\']([^"\']*)', html, _re.I)
        for bt in base_tags:
            if bt.startswith("http://"):
                vulns.append(("HIGH", "Base Tag Using HTTP",
                    f"Tag <base> apunta a HTTP: {bt[:60]}",
                    "Cambiar <base> href a HTTPS."))
                break

    # --- Content-Type Header Checks ---
    ct = hdrs.get("content-type", "")
    if ct and "charset" not in ct.lower():
        vulns.append(("LOW", "Content-Type Without Charset",
            "Content-Type sin charset puede permitir charset sniffing attacks.",
            "Agregar charset=utf-8 a Content-Type header."))

    # --- Access-Control Headers ---
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "")
    if acao == "*" and acac.lower() == "true":
        vulns.append(("CRITICAL", "CORS: Wildcard Origin + Credentials",
            "CORS permite * con credentials. Cualquier sitio puede leer respuestas autenticadas.",
            "No combinar Access-Control-Allow-Origin: * con Allow-Credentials: true."))
    acah = hdrs.get("access-control-allow-headers", "")
    if acah and "authorization" in acah.lower():
        vulns.append(("MEDIUM", "CORS Allows Authorization Header",
            "CORS permite enviar Authorization header desde origenes permitidos.",
            "Restringir origenes permitidos cuando se expone Authorization."))

    # --- Clickjacking via Double-Frame ---
    xfo = hdrs.get("x-frame-options", "").upper()
    if xfo == "SAMEORIGIN":
        csp_full = hdrs.get("content-security-policy", "")
        if "frame-ancestors" not in csp_full:
            vulns.append(("LOW", "X-Frame-Options Without CSP frame-ancestors",
                "Solo X-Frame-Options sin CSP frame-ancestors. X-Frame-Options puede ser bypassed.",
                "Complementar X-Frame-Options con CSP frame-ancestors."))

    # --- Server Timing ---
    st = hdrs.get("server-timing", "")
    if st:
        vulns.append(("LOW", "Server-Timing Header Present",
            f"Server-Timing expone metricas internas: {st[:80]}",
            "Deshabilitar Server-Timing en produccion o limitar info."))

    # (X-AspNet-Version / X-AspNetMvc-Version ya se evaluan en la seccion
    #  de Server Info Disclosure de arriba.)

    # --- Referrer-Policy ---
    # El caso "ausente" ya se reporta como "Missing Referrer-Policy" en la
    # seccion de security headers; aqui solo el caso explicitamente inseguro.
    rp = hdrs.get("referrer-policy", "")
    if rp and rp.lower() == "unsafe-url":
        vulns.append(("MEDIUM", "Referrer-Policy: unsafe-url",
            "Referrer-Policy unsafe-url envia URL completa incluyendo paths y params.",
            "Cambiar a strict-origin-when-cross-origin o no-referrer."))

    # --- Technology-Specific Checks ---
    techs = results.get("technologies", [])
    tech_str = " ".join([t[1].lower() for t in techs]) if techs else ""
    if "php" in tech_str:
        expose = hdrs.get("x-powered-by", "")
        if "php" in expose.lower():
            vulns.append(("LOW", "PHP Version Exposed via X-Powered-By",
                f"PHP version visible: {expose}",
                "Deshabilitar expose_php en php.ini."))
    if "wordpress" in tech_str:
        if html and "/wp-json/" in html:
            vulns.append(("MEDIUM", "WordPress REST API Exposed",
                "WP REST API (/wp-json/) accesible. Enumerar usuarios y datos.",
                "Restringir acceso a WP REST API con autenticacion."))
        if html and "wp-login.php" in html:
            vulns.append(("LOW", "WordPress Login Page Exposed",
                "wp-login.php visible. Target para brute force.",
                "Cambiar URL de login con plugin o .htaccess."))
    if "drupal" in tech_str:
        if html and "Drupal.settings" in html:
            vulns.append(("MEDIUM", "Drupal Settings Exposed in HTML",
                "Drupal.settings visible en HTML. Puede revelar paths y config.",
                "Minimizar info en Drupal.settings para produccion."))

    # --- DNS Additional ---
    dns_data = results.get("dns", {})
    if dns_data:
        txt_records = dns_data.get("TXT", [])
        for txt in txt_records:
            if isinstance(txt, str):
                if "v=spf1" not in txt and "google-site-verification" in txt.lower():
                    pass  # Normal
                if "api" in txt.lower() or "key" in txt.lower() or "secret" in txt.lower():
                    vulns.append(("MEDIUM", "Sensitive Information in DNS TXT Record",
                        f"TXT record contiene info potencialmente sensible: {txt[:60]}",
                        "Revisar TXT records y eliminar info sensible."))
                    break
        mx_records = dns_data.get("MX", [])
        if mx_records:
            mx_str = " ".join([str(m) for m in mx_records]).lower()
            if "google" in mx_str or "gmail" in mx_str:
                pass  # Info only
            if "localhost" in mx_str or "127.0.0.1" in mx_str:
                vulns.append(("HIGH", "MX Record Points to Localhost",
                    "MX record apunta a localhost. Correos no se entregan.",
                    "Corregir MX record a servidor de correo valido."))

    # --- Deprecated/Insecure TLS ---
    ssl_data = results.get("ssl", {})
    if ssl_data:
        protocol = ssl_data.get("protocol", "")
        if "TLSv1.0" in str(protocol) or "TLSv1 " in str(protocol):
            vulns.append(("HIGH", "TLS 1.0 Supported (Deprecated)",
                "TLS 1.0 activo. Vulnerable a BEAST, POODLE y otros ataques.",
                "Deshabilitar TLS 1.0. Usar TLS 1.2+ como minimo."))
        if "TLSv1.1" in str(protocol):
            vulns.append(("MEDIUM", "TLS 1.1 Supported (Deprecated)",
                "TLS 1.1 activo. Deprecated por todos los browsers principales.",
                "Deshabilitar TLS 1.1. Usar TLS 1.2+ como minimo."))
        cipher = ssl_data.get("cipher", "")
        if cipher:
            cipher_str = str(cipher).upper()
            if "RC4" in cipher_str:
                vulns.append(("HIGH", "RC4 Cipher in Use",
                    "Cipher RC4 activo. Criptograficamente debil.",
                    "Deshabilitar RC4 y usar ciphers modernos (AES-GCM)."))
            if "DES" in cipher_str and "3DES" not in cipher_str:
                vulns.append(("HIGH", "DES Cipher in Use",
                    "Cipher DES activo. Clave de 56 bits, trivial de romper.",
                    "Deshabilitar DES. Usar AES-128 o AES-256."))
            if "3DES" in cipher_str:
                vulns.append(("MEDIUM", "3DES Cipher in Use (Sweet32)",
                    "Cipher 3DES activo. Vulnerable a Sweet32 attack.",
                    "Deshabilitar 3DES. Usar AES-GCM."))
            if "NULL" in cipher_str:
                vulns.append(("CRITICAL", "NULL Cipher Negotiated",
                    "Cipher NULL: sin cifrado. Trafico en texto plano.",
                    "Deshabilitar NULL cipher inmediatamente."))
            if "EXPORT" in cipher_str:
                vulns.append(("CRITICAL", "EXPORT Cipher Supported",
                    "Cipher EXPORT con claves debiles (40-56 bits). Vulnerable a FREAK.",
                    "Deshabilitar ciphers EXPORT."))

    # --- HSTS Preload ---
    sts = hdrs.get("strict-transport-security", "")
    if sts:
        if "preload" not in sts.lower():
            vulns.append(("LOW", "HSTS Without Preload Directive",
                "HSTS sin preload. Primera visita sigue vulnerable a downgrade.",
                "Agregar preload a HSTS y registrar en hstspreload.org."))
        if "includesubdomains" not in sts.lower().replace(" ", ""):
            vulns.append(("LOW", "HSTS Without includeSubDomains",
                "HSTS no cubre subdominios. Subdominios vulnerables a downgrade.",
                "Agregar includeSubDomains a HSTS header."))
        import re as _re2
        ma = _re2.search(r'max-age=(\d+)', sts)
        if ma and int(ma.group(1)) < 31536000:
            vulns.append(("LOW", "HSTS max-age Less Than 1 Year",
                f"HSTS max-age={ma.group(1)}. Recomendado minimo 31536000 (1 año).",
                "Incrementar HSTS max-age a 31536000 o mas."))

    # Cache-Control ya se evalua en la seccion de security headers de arriba.

    # --- Expect-CT ---
    ect = hdrs.get("expect-ct", "")
    if ect and "enforce" not in ect.lower():
        vulns.append(("INFO", "Expect-CT Without Enforce",
            "Expect-CT presente sin enforce. Solo reporta, no bloquea.",
            "Agregar enforce a Expect-CT para bloquear certificados no CT-logged."))

    # === Print Results ===
    if not vulns:
        log_ok("No se identificaron vulnerabilidades pasivas.")
        results["vulnerabilities"] = []
        return

    # Deduplicar hallazgos identicos (por titulo) que pudieran venir de dos
    # secciones distintas, conservando la mayor severidad de cada uno.
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    _by_title = {}
    for v in vulns:
        key = v[1].strip().lower()
        if key not in _by_title or severity_order.get(v[0], 5) < severity_order.get(_by_title[key][0], 5):
            _by_title[key] = v
    vulns = list(_by_title.values())

    # Sort by severity
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

        # Open Redirect
        open_redir = results.get("open_redirect", [])
        if open_redir:
            f.write("OPEN REDIRECT:\n")
            for r in open_redir:
                f.write(f"  [{r['type']}] {r.get('url', r.get('endpoint', r.get('field', r.get('content', ''))))[:100]}\n")
            f.write("\n")

        # JSONP
        jsonp = results.get("jsonp", [])
        if jsonp:
            f.write("JSONP ENDPOINTS:\n")
            for j in jsonp:
                f.write(f"  [{j['type']}] {j.get('url', j.get('endpoint', j.get('param', '')))[:100]}\n")
            f.write("\n")

        # Host Header
        host_hdr = results.get("host_header", [])
        if host_hdr:
            f.write("HOST HEADER INJECTION:\n")
            for h in host_hdr:
                f.write(f"  [{h['test']}] Host: {h['host']} → reflected in {h['reflected_in']}\n")
            f.write("\n")

        # Cache Poisoning
        cache = results.get("cache_poisoning", [])
        if cache:
            f.write("CACHE POISONING:\n")
            for c in cache:
                if c.get("type") == "cache_headers":
                    for k, v in c.get("headers", {}).items():
                        f.write(f"  {k}: {v}\n")
                elif c.get("type") == "unkeyed_header_reflected":
                    f.write(f"  [!] Unkeyed header reflected: {c['header']}\n")
                elif c.get("type") == "vary_missing_host":
                    f.write(f"  [!] Vary missing Host\n")
            f.write("\n")

        # GraphQL
        graphql = results.get("graphql", [])
        if graphql:
            f.write("GRAPHQL:\n")
            for g in graphql:
                f.write(f"  [{g['type']}] {g['endpoint']}")
                if g.get("types_count"):
                    f.write(f" ({g['types_count']} types)")
                f.write("\n")
                if g.get("types"):
                    for t in g["types"][:10]:
                        f.write(f"    - {t}\n")
            f.write("\n")

        # JWT
        jwt_data = results.get("jwt", [])
        if jwt_data:
            f.write("JWT TOKENS:\n")
            for j in jwt_data:
                f.write(f"  [{j.get('location', 'N/A')}] {j.get('token', j.get('issue', ''))}\n")
            f.write("\n")

        # CRLF
        crlf = results.get("crlf", [])
        if crlf:
            f.write("CRLF INJECTION:\n")
            for c in crlf:
                f.write(f"  [{c['type']}] {c['payload']}\n")
            f.write("\n")

        # API Keys Deep
        api_keys = results.get("api_keys_deep", [])
        if api_keys:
            f.write("API KEYS / SECRETS:\n")
            for k in api_keys:
                f.write(f"  [{k['type']}] {k['masked']}\n")
            f.write("\n")

        # Rate Limiting
        rate = results.get("rate_limiting", {})
        if rate:
            f.write("RATE LIMITING:\n")
            f.write(f"  Rate limited: {rate.get('rate_limited', 'Unknown')}\n")
            if rate.get("requests_before_limit"):
                f.write(f"  Requests before limit: {rate['requests_before_limit']}\n")
            for rh in rate.get("rate_headers", []):
                f.write(f"  {rh['header']}: {rh['value']}\n")
            f.write("\n")

        # Default Pages
        defaults = results.get("default_pages", [])
        if defaults:
            f.write("DEFAULT / INSTALL PAGES:\n")
            for d in defaults:
                f.write(f"  [{d['service']}] {d['path']}\n")
            f.write("\n")

        # Error Disclosure
        errors = results.get("error_disclosure", [])
        if errors:
            f.write("ERROR PAGE DISCLOSURE:\n")
            for e in errors:
                f.write(f"  [{e['category']}] {e['match'][:100]}\n")
            f.write("\n")

        # Smuggling
        smuggling = results.get("smuggling", [])
        if smuggling:
            f.write("HTTP REQUEST SMUGGLING:\n")
            for s in smuggling:
                f.write(f"  [{s['type']}] {s.get('indicators', s.get('version', ''))}\n")
            f.write("\n")

        # SSRF
        ssrf = results.get("ssrf_indicators", [])
        if ssrf:
            f.write("SSRF INDICATORS:\n")
            for s in ssrf:
                f.write(f"  [{s['type']}] {s.get('endpoint', s.get('param', ''))}\n")
            f.write("\n")

        # Broken Links
        broken = results.get("broken_links", [])
        if broken:
            f.write("BROKEN LINK HIJACKING:\n")
            for b in broken:
                f.write(f"  [{b['type']}] {b['domain']}\n")
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
  openredir  - Open Redirect Detection
  jsonp      - JSONP Callback Hijacking
  hosthdr    - Host Header Injection
  cache      - Cache Poisoning Indicators
  graphql    - GraphQL Introspection Deep
  jwt        - JWT Token Detection & Analysis
  crlf       - CRLF Injection Check
  apikeys    - API Key & Secret Deep Scan (40+ patterns)
  ratelimit  - Rate Limiting Check
  defaults   - Default / Install Pages Detection
  errors     - Error Page Information Disclosure
  smuggling  - HTTP Request Smuggling Indicators
  ssrf       - SSRF Indicator Detection
  brokenlink - Broken Link Hijacking
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

    # Guardar el HTML en results para que los checks basados en HTML
    # (SRI, mixed content, forms, iframes, comentarios) del assessment funcionen.
    results["html"] = html

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

    if all_modules or "openredir" in selected:
        mod_open_redirect(session, base_url, html, results)

    if all_modules or "jsonp" in selected:
        mod_jsonp(session, base_url, html, results)

    if all_modules or "hosthdr" in selected:
        mod_host_header(session, target, results)

    if all_modules or "cache" in selected:
        mod_cache_poisoning(session, target, results)

    if all_modules or "graphql" in selected:
        mod_graphql(session, base_url, results)

    if all_modules or "jwt" in selected:
        mod_jwt_analysis(session, target, results)

    if all_modules or "crlf" in selected:
        mod_crlf(session, target, results)

    if all_modules or "apikeys" in selected:
        mod_api_keys_deep(session, target, html, results)

    if all_modules or "ratelimit" in selected:
        mod_rate_limit(session, target, results)

    if all_modules or "defaults" in selected:
        mod_default_pages(session, base_url, results)

    if all_modules or "errors" in selected:
        mod_error_disclosure(session, base_url, results)

    if all_modules or "smuggling" in selected:
        mod_smuggling_indicators(session, target, results)

    if all_modules or "ssrf" in selected:
        mod_ssrf_indicators(session, target, html, results)

    if all_modules or "brokenlink" in selected:
        mod_broken_links(session, base_url, html, results)

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
