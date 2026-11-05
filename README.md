# PassiveRecon

**Autor:** Sebastian Rivera ([@Sebazzz88](https://github.com/Sebazzz88))

Herramienta de **reconocimiento pasivo** para bug bounty y auditoría de seguridad web. Recopila información de un objetivo usando **únicamente técnicas pasivas**: no escanea puertos, no explota, no envía payloads ofensivos. Analiza respuestas HTTP normales, registros públicos (DNS, WHOIS, certificados, Wayback) y la propia superficie del sitio para identificar tecnologías, configuraciones débiles y posibles puntos de interés.

> ⚠️ **Solo para targets autorizados.** Úsalo exclusivamente sobre sistemas de los que tengas permiso explícito (programas de bug bounty en alcance, tus propios activos, pentesting contratado). El uso no autorizado puede ser ilegal.

---

## ¿Qué hace?

Ejecuta hasta **36 módulos** de análisis y genera un reporte con los hallazgos clasificados por severidad. Entre otras cosas:

### Información y fingerprinting
- **headers** — Cabeceras HTTP y de seguridad (HSTS, CSP, X-Frame-Options, etc.)
- **ssl** — Auditoría de certificado y configuración TLS
- **dns** — Registros DNS (A, MX, TXT, NS…)
- **whois** — Datos de registro del dominio
- **tech** — Fingerprinting de tecnologías, frameworks y servidores
- **favicon** — Hash del favicon para identificar el stack
- **cms_deep** — Detección profunda de CMS (WordPress, Joomla, Drupal…)
- **keycloak** — Reconocimiento específico de Keycloak

### Superficie y descubrimiento
- **robots** — robots.txt y sitemap.xml
- **paths** — Rutas y archivos sensibles comunes
- **subdomains** — Descubrimiento de subdominios
- **wayback** — URLs históricas vía Wayback Machine
- **js** — Análisis de archivos JavaScript (endpoints, secretos, rutas)
- **oauth** — Descubrimiento de endpoints OAuth/OIDC
- **graphql** — Detección de endpoints e introspección GraphQL
- **api_keys** — Búsqueda de claves y tokens expuestos
- **cloud_storage** — Buckets y almacenamiento en la nube (S3, Azure, GCP…)
- **default_pages** — Páginas por defecto de paneles y servicios

### Configuración y seguridad
- **cors** — Configuración CORS
- **http_methods** — Métodos HTTP permitidos (PUT, DELETE, TRACE…)
- **waf** — Detección de WAF/firewall (Cloudflare, AWS, Akamai…)
- **csp** — Análisis profundo de Content-Security-Policy
- **security_txt** — security.txt
- **email_security** — SPF, DMARC y seguridad de correo
- **jwt** — Análisis de tokens JWT
- **host_header** — Indicadores de Host Header Injection
- **cache_poisoning** — Indicadores de cache poisoning
- **crlf** — Indicadores de CRLF injection
- **open_redirect** — Indicadores de open redirect
- **jsonp** — Endpoints JSONP
- **ssrf** — Indicadores de SSRF
- **smuggling** — Indicadores de HTTP Request Smuggling
- **rate_limit** — Comportamiento de rate limiting
- **error_disclosure** — Fugas de información en errores
- **broken_links** — Enlaces rotos / posible hijacking
- **subdomain_takeover** — Verificación de subdomain takeover
- **vulns** — Evaluación agregada de vulnerabilidades sobre todos los módulos

Al final produce un **reporte `.txt` y `.json`** con los hallazgos ordenados por severidad.

---

## Requisitos

- Python 3.8+
- `requests`
- `dnspython` (opcional, habilita el módulo DNS)

```bash
pip3 install requests dnspython
```

## Instalación

```bash
git clone https://github.com/Sebazzz88/tool-recon-pasivo.git
cd tool-recon-pasivo
pip3 install requests dnspython
```

## Uso

```bash
python3 passive-recon.py <url>
```

### Ejemplos

```bash
# Escaneo completo (todos los módulos)
python3 passive-recon.py https://example.com

# Solo módulos concretos
python3 passive-recon.py https://example.com -m headers,ssl,dns,tech

# Guardar el reporte en otro directorio
python3 passive-recon.py https://example.com -o ./reportes

# Sin generar archivo de reporte (solo salida en pantalla)
python3 passive-recon.py https://example.com --no-report
```

### Opciones

| Opción | Descripción |
|--------|-------------|
| `target` | URL del objetivo (ej: `https://example.com`) |
| `-m`, `--modules` | Módulos a ejecutar separados por coma (default: `all`) |
| `-o`, `--output` | Directorio de salida para el reporte (default: `.`) |
| `--no-report` | No generar archivo de reporte |
| `--timeout` | Timeout HTTP en segundos (default: `15`) |

---

## Aviso legal

Esta herramienta se proporciona con fines **educativos y de pruebas de seguridad autorizadas**. El autor no se hace responsable del mal uso. Asegúrate de contar siempre con autorización por escrito antes de analizar cualquier sistema.
