"""
Shannon MCP Server — Zero-Config Autonomous Pentesting Engine

A self-contained penetration testing MCP server.
Just provide a URL (and optionally a GitHub repo URL for source code analysis).
No Docker, no Temporal, no folder management — it does everything for you.

Tools:
    - start_pentest   : Full autonomous pentest (just give a URL)
    - quick_scan      : Fast 10-second security header & config check
    - get_scan_status : Check progress of a running scan
    - get_scan_report : Retrieve the final security report
"""

import asyncio
import logging
import sys
import os
import json
import uuid
import time
import tempfile
import subprocess
import re
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, quote

# Configure logging — stderr only for MCP servers
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("shannon")

from fastmcp import FastMCP

mcp = FastMCP(name="shannon-pentest")

# ═══════════════════════════════════════════════════════════════════════
#  Storage — in-memory scan store + persistent reports
# ═══════════════════════════════════════════════════════════════════════
SCANS: dict = {}
REPORTS_DIR = Path(tempfile.gettempdir()) / "shannon-reports"
REPORTS_DIR.mkdir(exist_ok=True)
logger.info(f"Reports directory: {REPORTS_DIR}")


# ═══════════════════════════════════════════════════════════════════════
#  Data Classes
# ═══════════════════════════════════════════════════════════════════════
@dataclass
class Finding:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cvss_estimate: float = 0.0


@dataclass
class ScanState:
    scan_id: str
    url: str
    repo_url: str = ""
    status: str = "initializing"
    current_phase: str = ""
    progress: int = 0
    total_phases: int = 6
    findings: list = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    error: str = ""
    recon_data: dict = field(default_factory=dict)
    endpoints: list = field(default_factory=list)
    report_path: str = ""
    phase_log: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
#  HTTP Helpers
# ═══════════════════════════════════════════════════════════════════════
async def _http_get(url, headers=None, allow_redirects=True, timeout=10):
    """Safe async HTTP GET."""
    import httpx
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=allow_redirects, timeout=timeout
        ) as client:
            return await client.get(url, headers=headers or {})
    except Exception as e:
        logger.debug(f"GET {url} failed: {e}")
        return None


async def _http_post(url, data=None, json_data=None, headers=None, timeout=10):
    """Safe async HTTP POST."""
    import httpx
    try:
        async with httpx.AsyncClient(
            verify=False, follow_redirects=True, timeout=timeout
        ) as client:
            return await client.post(
                url, data=data, json=json_data, headers=headers or {}
            )
    except Exception as e:
        logger.debug(f"POST {url} failed: {e}")
        return None


# ═══════════════════════════════════════════════════════════════════════
#  Phase 1: Reconnaissance
# ═══════════════════════════════════════════════════════════════════════
async def phase_recon(scan: ScanState):
    scan.current_phase = "🔍 Reconnaissance"
    scan.progress = 1
    scan.phase_log.append("Phase 1: Reconnaissance started")

    parsed = urlparse(scan.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    recon = {
        "target": scan.url,
        "base_url": base_url,
        "hostname": parsed.hostname,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "scheme": parsed.scheme,
        "path": parsed.path,
        "technologies": [],
        "headers": {},
        "cookies": [],
        "server": "Unknown",
        "powered_by": "Not disclosed",
        "status_code": 0,
    }

    # Fetch the main page
    resp = await _http_get(scan.url)
    if not resp:
        scan.findings.append(
            Finding(
                severity="CRITICAL",
                category="Connectivity",
                title="Target Unreachable",
                description=f"Could not connect to {scan.url}. The target may be down or blocking requests.",
                remediation="Verify the target is running and accessible from this network.",
            )
        )
        scan.recon_data = recon
        return

    recon["status_code"] = resp.status_code
    recon["headers"] = dict(resp.headers)
    recon["server"] = resp.headers.get("server", "Not disclosed")
    recon["powered_by"] = resp.headers.get("x-powered-by", "Not disclosed")

    if resp.headers.get("x-powered-by"):
        recon["technologies"].append(resp.headers["x-powered-by"])
    if resp.headers.get("server"):
        recon["technologies"].append(resp.headers["server"])

    # Cookie collection
    for name, value in resp.cookies.items():
        recon["cookies"].append({"name": name, "value": str(value)[:30] + "..."})

    # Technology fingerprinting from HTML
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(resp.text, "html.parser")
        html_lower = resp.text.lower()

        tech_sigs = {
            "React": ["react", "_react", "__next_data__", "reactroot", "react-root"],
            "Next.js": ["__next_data__", "_next/", "next/"],
            "Vue.js": ["vue", "__vue__", "v-bind", "v-if", "v-for"],
            "Angular": ["ng-", "angular", "ng-app", "ng-version"],
            "Svelte": ["svelte", "__svelte"],
            "Express": ["express"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["flask", "werkzeug"],
            "FastAPI": ["fastapi", "openapi"],
            "Laravel": ["laravel", "csrf-token"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "Tailwind CSS": ["tailwindcss", "tailwind"],
            "Socket.IO": ["socket.io"],
            "WebSocket": ["websocket", "ws://", "wss://"],
        }
        for tech, sigs in tech_sigs.items():
            if any(s in html_lower for s in sigs):
                recon["technologies"].append(tech)

        # Extract links and endpoints
        links = set()
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith("/") or href.startswith(base_url):
                links.add(urljoin(base_url, href))

        for tag in soup.find_all("form", action=True):
            links.add(urljoin(base_url, tag["action"]))

        for script in soup.find_all("script", src=True):
            links.add(urljoin(base_url, script["src"]))

        # Extract API endpoints from inline scripts
        for script in soup.find_all("script"):
            if script.string:
                for pattern in [
                    r'["\'](/api/[^"\']+)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.\w+\(["\']([^"\']+)["\']',
                    r'["\'](/v\d+/[^"\']+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                ]:
                    matches = re.findall(pattern, script.string)
                    for m in matches:
                        links.add(urljoin(base_url, m))

        scan.endpoints = list(links)[:100]

    except ImportError:
        logger.warning("beautifulsoup4 not installed — HTML analysis limited")
    except Exception as e:
        logger.warning(f"HTML parsing error: {e}")

    recon["technologies"] = list(set(recon["technologies"]))
    scan.recon_data = recon
    scan.phase_log.append(
        f"Phase 1 done: {len(scan.endpoints)} endpoints, "
        f"technologies: {recon['technologies']}"
    )


# ═══════════════════════════════════════════════════════════════════════
#  Phase 2: Security Headers Analysis
# ═══════════════════════════════════════════════════════════════════════
async def phase_security_headers(scan: ScanState):
    scan.current_phase = "🛡️ Security Headers Analysis"
    scan.progress = 2
    scan.phase_log.append("Phase 2: Security Headers started")

    headers = scan.recon_data.get("headers", {})
    headers_lower = {k.lower(): v for k, v in headers.items()}

    checks = [
        (
            "strict-transport-security",
            "HTTP Strict Transport Security (HSTS)",
            "HIGH" if scan.recon_data.get("scheme") == "https" else "MEDIUM",
            "HSTS header is missing. Browsers won't enforce HTTPS.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ),
        (
            "content-security-policy",
            "Content Security Policy (CSP)",
            "MEDIUM",
            "No CSP header. Application is vulnerable to XSS and data injection.",
            "Add: Content-Security-Policy: default-src 'self'",
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options",
            "LOW",
            "Missing X-Content-Type-Options. Browser MIME-sniffing may cause XSS.",
            "Add: X-Content-Type-Options: nosniff",
        ),
        (
            "x-frame-options",
            "X-Frame-Options (Clickjacking)",
            "MEDIUM",
            "Missing X-Frame-Options. Vulnerable to clickjacking attacks.",
            "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
        ),
        (
            "referrer-policy",
            "Referrer Policy",
            "LOW",
            "No Referrer-Policy. Sensitive URLs may leak via Referer header.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin",
        ),
        (
            "permissions-policy",
            "Permissions Policy",
            "LOW",
            "No Permissions-Policy. Browser features are unrestricted.",
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ),
    ]

    for header_key, name, severity, desc, fix in checks:
        if header_key not in headers_lower:
            scan.findings.append(
                Finding(
                    severity=severity,
                    category="Security Headers",
                    title=f"Missing {name}",
                    description=desc,
                    remediation=fix,
                )
            )

    # Information leakage checks
    if "server" in headers_lower and headers_lower["server"] not in (
        "",
        "cloudflare",
    ):
        scan.findings.append(
            Finding(
                severity="LOW",
                category="Information Disclosure",
                title="Server Version Disclosed",
                description=f"Server header exposes: {headers_lower['server']}",
                evidence=f"Server: {headers_lower['server']}",
                remediation="Remove or mask the Server header.",
            )
        )

    if "x-powered-by" in headers_lower:
        scan.findings.append(
            Finding(
                severity="LOW",
                category="Information Disclosure",
                title="Technology Stack Disclosed (X-Powered-By)",
                description=f"X-Powered-By: {headers_lower['x-powered-by']}",
                evidence=f"X-Powered-By: {headers_lower['x-powered-by']}",
                remediation="Remove the X-Powered-By header.",
            )
        )

    scan.phase_log.append(f"Phase 2 done: checked {len(checks)} security headers")


# ═══════════════════════════════════════════════════════════════════════
#  Phase 3: Vulnerability Scanning
# ═══════════════════════════════════════════════════════════════════════
async def phase_vuln_scan(scan: ScanState):
    scan.current_phase = "⚡ Vulnerability Scanning"
    scan.progress = 3
    scan.phase_log.append("Phase 3: Vulnerability Scanning started")

    base_url = scan.recon_data.get("base_url", "")
    parsed = urlparse(scan.url)

    # ── 3a. CORS Misconfiguration ──
    for origin in [
        "https://evil.com",
        "null",
        f"{parsed.scheme}://{parsed.hostname}.evil.com",
    ]:
        resp = await _http_get(scan.url, headers={"Origin": origin})
        if resp and "access-control-allow-origin" in resp.headers:
            acao = resp.headers["access-control-allow-origin"]
            if acao == origin or acao == "*":
                creds = resp.headers.get("access-control-allow-credentials", "")
                scan.findings.append(
                    Finding(
                        severity="HIGH" if creds.lower() == "true" else "MEDIUM",
                        category="CORS Misconfiguration",
                        title="Permissive CORS Policy",
                        description=f"Server reflects Origin '{origin}' in ACAO header.",
                        evidence=f"Origin: {origin} → ACAO: {acao}, Credentials: {creds}",
                        remediation="Use a strict CORS whitelist. Never reflect arbitrary origins.",
                        cvss_estimate=7.5 if creds.lower() == "true" else 5.3,
                    )
                )
                break

    # ── 3b. Reflected XSS Testing ──
    xss_payloads = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
    ]
    query_params = parse_qs(parsed.query)
    for param_name, param_values in query_params.items():
        for payload in xss_payloads[:2]:
            test_url = scan.url.replace(
                f"{param_name}={param_values[0]}", f"{param_name}={quote(payload)}"
            )
            resp = await _http_get(test_url)
            if resp and payload in resp.text:
                scan.findings.append(
                    Finding(
                        severity="HIGH",
                        category="Cross-Site Scripting (XSS)",
                        title=f"Reflected XSS in '{param_name}'",
                        description=f"Parameter '{param_name}' reflects input without sanitization.",
                        evidence=f"Payload: {payload}",
                        remediation="Sanitize inputs. Use context-aware output encoding.",
                        cvss_estimate=6.1,
                    )
                )
                break

    # ── 3c. SQL Injection Testing ──
    sqli_payloads = ["'", "' OR '1'='1", "1; DROP TABLE--", "' UNION SELECT NULL--"]
    error_signatures = [
        "sql syntax",
        "mysql",
        "sqlite",
        "postgresql",
        "oracle",
        "odbc",
        "syntax error",
        "unclosed quotation",
        "pg_query",
        "unterminated string",
    ]
    for param_name, param_values in query_params.items():
        for payload in sqli_payloads[:2]:
            test_url = scan.url.replace(
                f"{param_name}={param_values[0]}", f"{param_name}={quote(payload)}"
            )
            resp = await _http_get(test_url)
            if resp:
                resp_lower = resp.text.lower()
                for sig in error_signatures:
                    if sig in resp_lower:
                        scan.findings.append(
                            Finding(
                                severity="CRITICAL",
                                category="SQL Injection",
                                title=f"SQL Injection in '{param_name}'",
                                description="Database error triggered by SQL payload.",
                                evidence=f"Payload: {payload} → matched: {sig}",
                                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                                cvss_estimate=9.8,
                            )
                        )
                        break

    # ── 3d. Open Redirect ──
    redirect_params = [
        "url", "redirect", "next", "return", "returnUrl",
        "redirect_uri", "continue", "dest", "go", "target",
    ]
    for param in redirect_params:
        test_url = f"{base_url}/?{param}=https://evil.com"
        resp = await _http_get(test_url, allow_redirects=False, timeout=5)
        if resp and resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if "evil.com" in location:
                scan.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Open Redirect",
                        title=f"Open Redirect via '{param}'",
                        description="Application redirects to attacker-controlled URLs.",
                        evidence=f"?{param}=https://evil.com → Location: {location}",
                        remediation="Validate redirect URLs against a whitelist.",
                    )
                )

    # ── 3e. Path Traversal ──
    for path in [
        "../../../../etc/passwd",
        "..\\..\\..\\..\\windows\\system32\\config\\sam",
    ]:
        resp = await _http_get(f"{base_url}/{path}", timeout=5)
        if resp and ("root:" in resp.text or "[boot loader]" in resp.text):
            scan.findings.append(
                Finding(
                    severity="CRITICAL",
                    category="Path Traversal",
                    title="Directory Traversal / Local File Inclusion",
                    description="Server returns system files via path traversal.",
                    evidence=f"Path: {path}",
                    remediation="Validate/sanitize file paths. Use chroot or sandboxed access.",
                    cvss_estimate=9.1,
                )
            )
            break

    # ── 3f. Sensitive Files & Endpoints ──
    sensitive = [
        ("/.env", "Environment Variables File", "CRITICAL"),
        ("/.git/config", "Git Configuration", "HIGH"),
        ("/.git/HEAD", "Git HEAD Reference", "HIGH"),
        ("/debug", "Debug Endpoint", "MEDIUM"),
        ("/actuator", "Spring Boot Actuator", "HIGH"),
        ("/actuator/env", "Actuator Environment", "CRITICAL"),
        ("/swagger-ui.html", "Swagger UI", "LOW"),
        ("/graphql", "GraphQL Endpoint", "INFO"),
        ("/server-status", "Apache Server Status", "HIGH"),
        ("/phpinfo.php", "PHP Info Page", "HIGH"),
        ("/admin", "Admin Panel", "MEDIUM"),
        ("/wp-admin", "WordPress Admin", "MEDIUM"),
        ("/.DS_Store", "macOS Metadata Leak", "LOW"),
        ("/api/v1", "API v1 Endpoint", "INFO"),
        ("/robots.txt", "Robots.txt", "INFO"),
        ("/.well-known/security.txt", "Security.txt", "INFO"),
    ]
    for path, name, severity in sensitive:
        resp = await _http_get(f"{base_url}{path}", timeout=5)
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            is_real = False
            if path == "/.env" and any(
                k in resp.text.upper()
                for k in ["KEY", "SECRET", "PASSWORD", "TOKEN", "DATABASE"]
            ):
                is_real = True
            elif path.startswith("/.git") and (
                "ref:" in resp.text or "[core]" in resp.text
            ):
                is_real = True
            elif severity in ("CRITICAL", "HIGH") and path not in ("/.env", "/.git/config", "/.git/HEAD"):
                is_real = True
            elif severity in ("MEDIUM", "LOW", "INFO"):
                is_real = True

            if is_real:
                scan.findings.append(
                    Finding(
                        severity=severity,
                        category="Sensitive Exposure",
                        title=f"Accessible: {name} ({path})",
                        description=f"Found at {base_url}{path}",
                        evidence=f"HTTP {resp.status_code}, {len(resp.text)} bytes",
                        remediation=f"Restrict access to {path}.",
                    )
                )

    scan.phase_log.append(f"Phase 3 done: tested CORS, XSS, SQLi, redirects, paths")


# ═══════════════════════════════════════════════════════════════════════
#  Phase 4: Authentication & Session Testing
# ═══════════════════════════════════════════════════════════════════════
async def phase_auth_testing(scan: ScanState):
    scan.current_phase = "🔐 Authentication & Session Testing"
    scan.progress = 4
    scan.phase_log.append("Phase 4: Auth testing started")

    base_url = scan.recon_data.get("base_url", "")

    # Test common login endpoints
    auth_paths = [
        "/login", "/signin", "/auth/login", "/api/auth/login",
        "/api/login", "/api/v1/auth/login", "/api/auth/signin",
    ]

    for endpoint in auth_paths:
        resp = await _http_get(f"{base_url}{endpoint}", timeout=5)
        if resp and resp.status_code in (200, 405, 401):
            # Default credential testing
            creds_list = [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": "123456"},
                {"email": "admin@admin.com", "password": "admin"},
                {"username": "test", "password": "test"},
            ]
            for creds in creds_list:
                post_resp = await _http_post(
                    f"{base_url}{endpoint}", json_data=creds, timeout=5
                )
                if post_resp and post_resp.status_code in (200, 302):
                    body = post_resp.text.lower()
                    if any(
                        k in body
                        for k in ["token", "session", "success", "welcome", "dashboard", "jwt"]
                    ):
                        user = creds.get("username") or creds.get("email")
                        scan.findings.append(
                            Finding(
                                severity="CRITICAL",
                                category="Authentication",
                                title=f"Default Credentials Work at {endpoint}",
                                description=f"Login succeeded with {user}:{creds['password']}",
                                evidence=f"POST {endpoint} → HTTP {post_resp.status_code}",
                                remediation="Change default credentials. Enforce strong password policies.",
                                cvss_estimate=9.8,
                            )
                        )
                        break

            # Rate limiting check
            status_codes = []
            for i in range(6):
                r = await _http_post(
                    f"{base_url}{endpoint}",
                    json_data={"username": "admin", "password": f"wrong{i}"},
                    timeout=3,
                )
                if r:
                    status_codes.append(r.status_code)

            if len(status_codes) >= 5 and all(c != 429 for c in status_codes):
                scan.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Authentication",
                        title=f"No Rate Limiting on {endpoint}",
                        description=f"No rate limit after {len(status_codes)} failed attempts.",
                        evidence=f"Status codes: {status_codes}",
                        remediation="Implement rate limiting (e.g. 5 attempts/minute). Add CAPTCHA.",
                    )
                )
            break  # Found a login endpoint, stop searching

    # Cookie security
    resp = await _http_get(scan.url)
    if resp:
        raw_cookies = []
        if hasattr(resp.headers, "multi_items"):
            raw_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]

        for cookie_str in raw_cookies:
            cookie_lower = cookie_str.lower()
            cookie_name = cookie_str.split("=")[0].strip()

            if "httponly" not in cookie_lower:
                scan.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Session Security",
                        title=f"Cookie '{cookie_name}' Missing HttpOnly",
                        description="Cookie accessible via JavaScript (XSS amplification).",
                        evidence=f"Set-Cookie: {cookie_str[:80]}",
                        remediation="Add HttpOnly flag.",
                    )
                )
            if (
                "secure" not in cookie_lower
                and scan.recon_data.get("scheme") == "https"
            ):
                scan.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="Session Security",
                        title=f"Cookie '{cookie_name}' Missing Secure Flag",
                        description="Cookie may be sent over unencrypted HTTP.",
                        remediation="Add Secure flag on HTTPS sites.",
                    )
                )
            if "samesite" not in cookie_lower:
                scan.findings.append(
                    Finding(
                        severity="LOW",
                        category="Session Security",
                        title=f"Cookie '{cookie_name}' Missing SameSite",
                        description="CSRF risk — cookie sent in cross-site requests.",
                        remediation="Add SameSite=Strict or SameSite=Lax.",
                    )
                )

    scan.phase_log.append("Phase 4 done: auth endpoints, default creds, cookies")


# ═══════════════════════════════════════════════════════════════════════
#  Phase 5: Source Code Analysis (auto-clone)
# ═══════════════════════════════════════════════════════════════════════
async def phase_source_analysis(scan: ScanState):
    scan.current_phase = "📝 Source Code Analysis"
    scan.progress = 5

    if not scan.repo_url:
        scan.phase_log.append("Phase 5: Skipped (no repo_url provided)")
        return

    scan.phase_log.append(f"Phase 5: Cloning {scan.repo_url}")

    repo_dir = Path(tempfile.mkdtemp(prefix="shannon-src-"))
    src_dir = repo_dir / "src"

    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", scan.repo_url, str(src_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            scan.findings.append(
                Finding(
                    severity="INFO",
                    category="Source Code",
                    title="Repository Clone Failed",
                    description=f"Could not clone {scan.repo_url}: {proc.stderr[:200]}",
                )
            )
            return

        code_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
            ".rb", ".php", ".env", ".yaml", ".yml", ".json", ".toml",
            ".cs", ".rs", ".swift", ".kt",
        }

        # ── Secret scanning ──
        secret_patterns = [
            (r'(?i)(api[_-]?key|apiKey)\s*[=:]\s*["\']([^"\']{10,})["\']', "API Key"),
            (r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']', "Password/Secret"),
            (r'(?i)(token|jwt)\s*[=:]\s*["\']([^"\']{10,})["\']', "Token"),
            (r'(?i)(aws_access_key|aws_secret)\s*[=:]\s*["\']([A-Za-z0-9/+=]{16,})["\']', "AWS Key"),
            (r'(?i)mongodb(\+srv)?://[^\s"\']+', "MongoDB URI"),
            (r'(?i)postgres(ql)?://[^\s"\']+', "PostgreSQL URI"),
            (r'(?i)mysql://[^\s"\']+', "MySQL URI"),
            (r'(?i)redis://[^\s"\']+', "Redis URI"),
        ]

        false_positive_words = [
            "process.env", "os.environ", "os.getenv", "${", "{{",
            "ENV[", "YOUR_", "xxx", "placeholder", "example",
            "REPLACE", "INSERT", "CHANGE_ME",
        ]

        # ── Dangerous code patterns ──
        dangerous_fns = {
            "eval(": ("Code Injection", "HIGH", "eval() executes arbitrary code"),
            "exec(": ("Code Injection", "HIGH", "exec() executes arbitrary code"),
            "innerHTML": ("XSS Risk", "MEDIUM", "innerHTML allows HTML injection"),
            "dangerouslySetInnerHTML": ("XSS Risk", "MEDIUM", "Bypasses React sanitization"),
            "os.system(": ("Command Injection", "HIGH", "os.system() is command-injectable"),
            "subprocess.call(": ("Command Injection", "MEDIUM", "May pass unsanitized input"),
            "pickle.loads": ("Deserialization", "HIGH", "Unsafe deserialization → RCE"),
            "yaml.load(": ("Deserialization", "MEDIUM", "Use yaml.safe_load instead"),
            "document.write": ("XSS Risk", "MEDIUM", "document.write can inject scripts"),
            "shell=True": ("Command Injection", "HIGH", "shell=True allows injection"),
        }

        files_scanned = 0
        for fpath in src_dir.rglob("*"):
            if not fpath.is_file() or fpath.suffix not in code_extensions:
                continue
            if any(skip in str(fpath) for skip in ["node_modules", ".git", "__pycache__", "vendor", "dist", "build"]):
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                rel = fpath.relative_to(src_dir)
                files_scanned += 1

                # Secrets
                for pattern, secret_type in secret_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        match_str = str(matches[0])
                        if any(fp in match_str for fp in false_positive_words):
                            continue
                        scan.findings.append(
                            Finding(
                                severity="HIGH",
                                category="Hardcoded Secrets",
                                title=f"{secret_type} in {rel}",
                                description=f"Potential hardcoded {secret_type.lower()} found.",
                                evidence=f"File: {rel}",
                                remediation="Use environment variables or a secrets manager.",
                            )
                        )

                # Dangerous patterns
                for func, (title, severity, desc) in dangerous_fns.items():
                    if func in content:
                        scan.findings.append(
                            Finding(
                                severity=severity,
                                category="Dangerous Code",
                                title=f"{title}: {func} in {rel}",
                                description=desc,
                                evidence=f"File: {rel}",
                                remediation=f"Review {func} usage. Ensure no unsanitized user input.",
                            )
                        )
            except Exception:
                pass

        # Dependency analysis (package.json)
        pkg_json = src_dir / "package.json"
        if pkg_json.exists():
            try:
                pkg = json.loads(pkg_json.read_text())
                deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                scan.findings.append(
                    Finding(
                        severity="INFO",
                        category="Dependencies",
                        title=f"Node.js project with {len(deps)} dependencies",
                        description="Run `npm audit` for a full dependency vulnerability check.",
                        remediation="Run: npm audit --production",
                    )
                )
            except Exception:
                pass

        # requirements.txt check
        req_txt = src_dir / "requirements.txt"
        if req_txt.exists():
            scan.findings.append(
                Finding(
                    severity="INFO",
                    category="Dependencies",
                    title="Python requirements.txt found",
                    description="Run `pip-audit` for dependency vulnerability scanning.",
                    remediation="Run: pip-audit -r requirements.txt",
                )
            )

        scan.phase_log.append(f"Phase 5 done: scanned {files_scanned} source files")

    except subprocess.TimeoutExpired:
        scan.findings.append(
            Finding(
                severity="INFO",
                category="Source Code",
                title="Clone Timed Out",
                description=f"Cloning {scan.repo_url} timed out after 120s.",
            )
        )
    except Exception as e:
        logger.error(f"Source analysis failed: {e}")
    finally:
        import shutil
        shutil.rmtree(repo_dir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════
#  Phase 6: Report Generation
# ═══════════════════════════════════════════════════════════════════════
async def phase_report(scan: ScanState) -> str:
    scan.current_phase = "📄 Report Generation"
    scan.progress = 6

    elapsed = time.time() - scan.start_time

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in scan.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    risk_score = (
        sev_counts["CRITICAL"] * 10
        + sev_counts["HIGH"] * 7
        + sev_counts["MEDIUM"] * 4
        + sev_counts["LOW"] * 1
    )
    risk_level = (
        "CRITICAL"
        if risk_score >= 30
        else "HIGH"
        if risk_score >= 15
        else "MEDIUM"
        if risk_score >= 5
        else "LOW"
    )
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    lines = [
        "# 🔒 Shannon Security Assessment Report\n",
        f"**Target:** {scan.url}  ",
        f"**Scan ID:** {scan.scan_id}  ",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"**Duration:** {elapsed:.1f} seconds  ",
        f"**Risk Level:** {risk_emoji.get(risk_level, '⚪')} **{risk_level}**  ",
        f"**Source Code:** {'✅ Analyzed' if scan.repo_url else '⚠️ Not provided'}  ",
        "",
        "---\n",
        "## 📊 Executive Summary\n",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {sev_counts['CRITICAL']} |",
        f"| 🟠 High | {sev_counts['HIGH']} |",
        f"| 🟡 Medium | {sev_counts['MEDIUM']} |",
        f"| 🔵 Low | {sev_counts['LOW']} |",
        f"| ⚪ Info | {sev_counts['INFO']} |",
        f"| **Total** | **{len(scan.findings)}** |",
        "",
        f"**Risk Score:** {risk_score}/100\n",
        "## 🔍 Reconnaissance Summary\n",
        f"- **Server:** {scan.recon_data.get('server', 'N/A')}",
        f"- **Technologies:** {', '.join(scan.recon_data.get('technologies', [])) or 'Not detected'}",
        f"- **Endpoints Found:** {len(scan.endpoints)}",
        f"- **Cookies:** {len(scan.recon_data.get('cookies', []))}",
        "",
    ]

    # Group findings by category
    categories: dict = {}
    for f in scan.findings:
        categories.setdefault(f.category, []).append(f)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    lines.append("## 🔎 Detailed Findings\n")

    if not scan.findings:
        lines.append("✅ No significant vulnerabilities detected.\n")
    else:
        num = 1
        for cat in sorted(categories):
            lines.append(f"### {cat}\n")
            for f in sorted(categories[cat], key=lambda x: sev_order.get(x.severity, 5)):
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(f.severity, "⚪")
                lines.append(f"#### {num}. {emoji} [{f.severity}] {f.title}\n")
                lines.append(f"**Description:** {f.description}\n")
                if f.evidence:
                    lines.append(f"**Evidence:**\n```\n{f.evidence}\n```\n")
                if f.remediation:
                    lines.append(f"**Remediation:** {f.remediation}\n")
                num += 1

    # Recommendations
    lines.append("## 🛡️ Recommendations\n")
    rec_num = 1
    if sev_counts["CRITICAL"] > 0:
        lines.append(f"{rec_num}. **URGENT:** Fix {sev_counts['CRITICAL']} critical findings immediately.")
        rec_num += 1
    if sev_counts["HIGH"] > 0:
        lines.append(f"{rec_num}. **HIGH PRIORITY:** Address {sev_counts['HIGH']} high-severity issues within 48 hours.")
        rec_num += 1
    if sev_counts["MEDIUM"] > 0:
        lines.append(f"{rec_num}. **MEDIUM:** Resolve {sev_counts['MEDIUM']} medium issues within 1 week.")
        rec_num += 1
    lines.append(f"{rec_num}. Implement a Web Application Firewall (WAF).")
    rec_num += 1
    lines.append(f"{rec_num}. Add security scanning to your CI/CD pipeline.")
    rec_num += 1
    lines.append(f"{rec_num}. Schedule regular penetration tests.\n")

    # Scan phases log
    lines.append("## 📋 Scan Phases\n")
    for log_entry in scan.phase_log:
        lines.append(f"- {log_entry}")
    lines.append("")

    lines.append("---")
    lines.append("*Generated by Shannon Zero-Config Pentest Engine*")

    report_text = "\n".join(lines)

    # Save to disk
    report_path = REPORTS_DIR / f"shannon-report-{scan.scan_id}.md"
    report_path.write_text(report_text, encoding="utf-8")
    scan.report_path = str(report_path)

    scan.phase_log.append(f"Phase 6 done: report saved to {report_path}")
    return report_text


# ═══════════════════════════════════════════════════════════════════════
#  Pentest Pipeline
# ═══════════════════════════════════════════════════════════════════════
async def _run_pentest(scan: ScanState) -> str:
    """Execute the full 6-phase pentest pipeline."""
    try:
        scan.status = "running"
        await phase_recon(scan)
        await phase_security_headers(scan)
        await phase_vuln_scan(scan)
        await phase_auth_testing(scan)
        await phase_source_analysis(scan)
        report = await phase_report(scan)
        scan.status = "completed"
        scan.end_time = time.time()
        return report
    except Exception as e:
        scan.status = "failed"
        scan.error = str(e)
        scan.end_time = time.time()
        logger.error(f"Scan {scan.scan_id} failed: {e}")
        raise


# ═══════════════════════════════════════════════════════════════════════
#  MCP Tools
# ═══════════════════════════════════════════════════════════════════════
@mcp.tool()
async def start_pentest(url: str, repo_url: str = "") -> str:
    """Run a full autonomous penetration test. Just give a URL!

    Shannon handles everything automatically — no Docker, no Temporal,
    no folder management. Optionally provide a GitHub repo URL for
    source code analysis.

    Args:
        url: Target URL to pentest (e.g. http://localhost:3000 or https://example.com).
        repo_url: Optional Git repository URL for source code analysis
                  (e.g. https://github.com/user/repo.git).

    Returns:
        Complete security assessment report in markdown.
    """
    if not url or not url.strip():
        return "❌ Error: URL cannot be empty"

    scan_id = uuid.uuid4().hex[:8]
    scan = ScanState(scan_id=scan_id, url=url.strip(), repo_url=repo_url.strip())
    SCANS[scan_id] = scan

    logger.info(f"🚀 Starting pentest {scan_id} → {url}")

    try:
        report = await _run_pentest(scan)
        elapsed = scan.end_time - scan.start_time

        header = (
            f"✅ Shannon pentest completed!\n\n"
            f"  Scan ID    : {scan_id}\n"
            f"  Target     : {url}\n"
            f"  Duration   : {elapsed:.1f}s\n"
            f"  Findings   : {len(scan.findings)}\n"
            f"  Report     : {scan.report_path}\n\n"
            f"{'═' * 60}\n\n"
        )
        return header + report
    except Exception as e:
        return f"❌ Scan failed: {str(e)}"


@mcp.tool()
async def quick_scan(url: str) -> str:
    """Fast 10-second security check — headers, cookies & misconfigs only.

    Use this for a rapid overview before running a full pentest.

    Args:
        url: Target URL to scan.

    Returns:
        Quick security assessment summary.
    """
    if not url or not url.strip():
        return "❌ Error: URL cannot be empty"

    scan = ScanState(scan_id="quick", url=url.strip())
    await phase_recon(scan)
    await phase_security_headers(scan)

    result = f"⚡ Quick Scan: {url}\n{'─' * 50}\n\n"

    # Technologies
    techs = scan.recon_data.get("technologies", [])
    if techs:
        result += f"🔧 Technologies: {', '.join(techs)}\n\n"

    if scan.findings:
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in scan.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        result += f"📊 Summary: {sev_counts['CRITICAL']}C / {sev_counts['HIGH']}H / {sev_counts['MEDIUM']}M / {sev_counts['LOW']}L / {sev_counts['INFO']}I\n\n"

        for f in scan.findings:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(f.severity, "⚪")
            result += f"{emoji} [{f.severity}] {f.title}\n"
            if f.remediation:
                result += f"   → {f.remediation}\n"
            result += "\n"
    else:
        result += "✅ No issues found.\n"

    result += f"\n💡 For a full pentest: start_pentest(url='{url}')"
    return result


@mcp.tool()
async def get_scan_status(scan_id: str) -> str:
    """Check progress of a running or completed scan.

    Args:
        scan_id: The scan ID returned by start_pentest.

    Returns:
        Status report with progress details.
    """
    scan = SCANS.get(scan_id)
    if not scan:
        available = list(SCANS.keys())
        return f"❌ Scan not found: {scan_id}\nAvailable scans: {available or 'none'}"

    elapsed = (scan.end_time or time.time()) - scan.start_time
    emoji = {"running": "🔄", "completed": "✅", "failed": "❌", "initializing": "⏳"}.get(scan.status, "❓")

    return (
        f"{emoji} Scan: {scan_id}\n"
        f"{'─' * 40}\n"
        f"  Status   : {scan.status.upper()}\n"
        f"  Phase    : {scan.current_phase} ({scan.progress}/{scan.total_phases})\n"
        f"  Target   : {scan.url}\n"
        f"  Elapsed  : {elapsed:.1f}s\n"
        f"  Findings : {len(scan.findings)}\n"
        f"  Report   : {scan.report_path or 'pending'}\n"
    )


@mcp.tool()
async def get_scan_report(scan_id: str) -> str:
    """Retrieve the full security report for a completed scan.

    Args:
        scan_id: The scan ID of a completed scan.

    Returns:
        Full markdown security report.
    """
    scan = SCANS.get(scan_id)
    if not scan:
        return f"❌ No scan found with ID: {scan_id}"

    if scan.status != "completed":
        return f"⏳ Scan not yet complete. Status: {scan.status} — Phase: {scan.current_phase}"

    if scan.report_path and Path(scan.report_path).exists():
        return Path(scan.report_path).read_text(encoding="utf-8")

    return "❌ Report file not found on disk."


# ═══════════════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════════════
def main():
    logger.info("🚀 Shannon Zero-Config Pentest MCP Server starting...")
    logger.info("Tools: start_pentest, quick_scan, get_scan_status, get_scan_report")
    mcp.run(transport="http", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
