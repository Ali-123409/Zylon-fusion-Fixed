"""
 ███████╗██╗██████╗  ██████╗ ███████╗
 ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
   ███╔╝ ██║██████╔╝██║   ██║███████╗
  ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
 ███████╗██║██║     ╚██████╔╝███████║
 ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝

 ZYLON FUSION - Variables & Constants
 Termux Non-Root Compatible
"""

import os
import platform

# ============================================================================
# FRAMEWORK INFORMATION
# ============================================================================

ZYLON_VERSION = "4.2.0"
ZYLON_CODENAME = "Nuclear Fusion v4.2 - ParamSpider + LinkFinder + Arjun + Ghauri + CMSeeK + Sherlock + TEHQEEQ"
ZYLON_AUTHOR = "Zylon"
ZYLON_DEBUG = False

# ============================================================================
# PATHS & DIRECTORIES
# ============================================================================

HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".zylon")
CURRENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(CURRENT_DIR, "data")
REPORTS_DIR = os.path.join(CONFIG_DIR, "reports")
WORDLISTS_DIR = os.path.join(DATA_DIR, "wordlists")
LOG_DIR = os.path.join(CONFIG_DIR, "logs")

# ============================================================================
# HTTP & NETWORK SETTINGS
# ============================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]

DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3
VERIFY_SSL = False
FOLLOW_REDIRECTS = True
MAX_THREADS = 20
REQUEST_DELAY = 0.1

# ============================================================================
# PORT SCANNING (CONNECT SCAN - NO ROOT NEEDED)
# ============================================================================

DEFAULT_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
    139: 'netbios', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
    993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
    3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
    6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
    8888: 'sun-answerbook', 9090: 'zeus-admin', 27017: 'mongodb',
}

FULL_PORT_RANGE = range(1, 65536)
QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
               993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017]

# ============================================================================
# SECURITY HEADERS
# ============================================================================

SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'recommended': 'max-age=31536000; includeSubDomains',
        'weight': 15,
        'description': 'Enforces HTTPS connections'
    },
    'Content-Security-Policy': {
        'recommended': "default-src 'self'",
        'weight': 15,
        'description': 'Prevents XSS and data injection attacks'
    },
    'X-Content-Type-Options': {
        'recommended': 'nosniff',
        'weight': 10,
        'description': 'Prevents MIME type sniffing'
    },
    'X-Frame-Options': {
        'recommended': 'DENY or SAMEORIGIN',
        'weight': 10,
        'description': 'Prevents clickjacking'
    },
    'X-XSS-Protection': {
        'recommended': '1; mode=block',
        'weight': 5,
        'description': 'Enables browser XSS filter'
    },
    'Referrer-Policy': {
        'recommended': 'strict-origin-when-cross-origin',
        'weight': 10,
        'description': 'Controls referrer information'
    },
    'Permissions-Policy': {
        'recommended': 'camera=(), microphone=(), geolocation=()',
        'weight': 10,
        'description': 'Controls browser feature access'
    },
    'Cross-Origin-Opener-Policy': {
        'recommended': 'same-origin',
        'weight': 5,
        'description': 'Isolates browsing context'
    },
    'Cross-Origin-Resource-Policy': {
        'recommended': 'same-origin',
        'weight': 5,
        'description': 'Prevents cross-origin resource leaks'
    },
    'Cache-Control': {
        'recommended': 'no-store for sensitive pages',
        'weight': 5,
        'description': 'Controls caching behavior'
    },
}

# ============================================================================
# SQL INJECTION PAYLOADS
# ============================================================================

SQLI_PAYLOADS = [
    "'", '"', "1'", '1"', "' OR '1'='1", '" OR "1"="1',
    "' OR '1'='1' --", '" OR "1"="1" --', "' OR '1'='1' #",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "admin'--",
    "' OR 1=1--", "' OR 'x'='x", "' AND 1=1--",
    "1' ORDER BY 1--", "1' ORDER BY 2--",
    "1; DROP TABLE users--", "' OR SLEEP(5)--",
    "1' AND SLEEP(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]

SQLI_ERRORS = [
    "SQL syntax", "MySQL", "ORA-", "PostgreSQL", "Microsoft SQL",
    "ODBC Driver", "SQLite", "JDBC", "Oracle error", "Syntax error",
    "unclosed quotation", "SQL command not properly ended",
    "mysql_fetch", "mysql_num_rows", "pg_query", "sqlite_query",
    "Warning: mysql", "valid MySQL result", "check the manual",
    "MySQLSyntaxErrorException", "postgresql.util.PSQLException",
]

# ============================================================================
# XSS PAYLOADS
# ============================================================================

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><iframe src="javascript:alert(1)">',
    "<math><mtext><table><mglyph><style><!--</style>",
    "{{7*7}}",  # Template injection
    "${7*7}",   # Template injection
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
]

# ============================================================================
# CORS TEST ORIGINS
# ============================================================================

CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null", 
    "https://evil.{target}",
    "https://{target}.evil.com",
]

# ============================================================================
# DIRECTORY BRUTE FORCE WORDLIST
# ============================================================================

COMMON_DIRS = [
    '/', '/admin', '/administrator', '/login', '/dashboard', '/api',
    '/api/v1', '/api/v2', '/backup', '/config', '/console',
    '/css', '/js', '/img', '/images', '/uploads', '/files',
    '/tmp', '/temp', '/test', '/debug', '/dev', '/staging',
    '/.env', '/.git', '/.git/HEAD', '/.git/config', '/.svn',
    '/.DS_Store', '/.htaccess', '/.htpasswd', '/wp-admin',
    '/wp-login.php', '/wp-content', '/wp-includes', '/xmlrpc.php',
    '/robots.txt', '/sitemap.xml', '/favicon.ico', '/crossdomain.xml',
    '/server-status', '/server-info', '/phpinfo.php', '/info.php',
    '/cgi-bin/', '/.well-known/', '/.well-known/security.txt',
    '/swagger-ui/', '/swagger/', '/api-docs', '/graphql',
    '/actuator', '/actuator/health', '/actuator/env',
    '/jenkins', '/.ssh', '/id_rsa', '/database', '/db',
    '/phpmyadmin', '/mysql', '/adminer', '/pgadmin',
    '/solr', '/elastic', '/kibana', '/grafana',
    '/.aws/credentials', '/.env.backup', '/.env.local',
    '/config.json', '/config.yml', '/config.yaml',
    '/package.json', '/composer.json', '/Gemfile',
    '/Dockerfile', '/docker-compose.yml', '/.dockerenv',
]

# ============================================================================
# WAF SIGNATURES
# ============================================================================

WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', 'cloudflare'],
        'cookies': ['__cfduid', 'cf_clearance'],
        'status_code': [403],
        'body': ['cloudflare', 'cf-browser-verification', 'Attention Required']
    },
    'AWS WAF': {
        'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
        'cookies': [],
        'status_code': [403],
        'body': ['AWS WAF', 'Request blocked']
    },
    'Akamai': {
        'headers': ['x-akamai-transformed', 'x-cache'],
        'cookies': ['akamai'],
        'status_code': [403],
        'body': ['Access Denied', 'akamai']
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'cookies': [],
        'status_code': [403],
        'body': ['Sucuri', 'sucuri.net']
    },
    'Imperva/Incapsula': {
        'headers': ['x-iinfo', 'x-cdn'],
        'cookies': ['visid_incap', 'incap_ses'],
        'status_code': [403],
        'body': ['Incapsula', 'Incapsula incident']
    },
    'ModSecurity': {
        'headers': [],
        'cookies': [],
        'status_code': [403, 501],
        'body': ['ModSecurity', 'Not Acceptable']
    },
    'F5 BIG-IP': {
        'headers': ['x-wa-info', 'f5'],
        'cookies': ['BIGipServer', 'F5'],
        'status_code': [403],
        'body': ['F5', 'BIG-IP']
    },
}

# ============================================================================
# TECHNOLOGY FINGERPRINT SIGNATURES
# ============================================================================

TECH_SIGNATURES = {
    'WordPress': {
        'meta': ['generator', 'WordPress'],
        'files': ['wp-content', 'wp-includes', 'wp-login.php'],
        'headers': {},
        'cookies': ['wordpress'],
        'js_patterns': [],
    },
    'Joomla': {
        'meta': ['generator', 'Joomla'],
        'files': ['/administrator/'],
        'headers': {},
        'cookies': [],
        'js_patterns': [],
    },
    'Drupal': {
        'meta': ['generator', 'Drupal'],
        'files': ['/misc/drupal.js', '/sites/default/'],
        'headers': {'X-Drupal-Cache': ''},
        'cookies': ['Drupal.visitor'],
        'js_patterns': [],
    },
    'React': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': [],
        'js_patterns': ['react', 'reactDOM', '__NEXT_DATA__'],
    },
    'Vue.js': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': [],
        'js_patterns': ['vue', 'Vue', '__vue__'],
    },
    'Angular': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': [],
        'js_patterns': ['angular', 'ng-version'],
    },
    'jQuery': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': [],
        'js_patterns': ['jQuery', 'jquery'],
    },
    'nginx': {
        'meta': [],
        'files': [],
        'headers': {'Server': 'nginx'},
        'cookies': [],
        'js_patterns': [],
    },
    'Apache': {
        'meta': [],
        'files': [],
        'headers': {'Server': 'Apache'},
        'cookies': [],
        'js_patterns': [],
    },
    'Cloudflare': {
        'meta': [],
        'files': [],
        'headers': {'cf-ray': ''},
        'cookies': ['__cfduid'],
        'js_patterns': [],
    },
    'Laravel': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': ['laravel_session'],
        'js_patterns': [],
    },
    'Django': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': ['csrftoken'],
        'js_patterns': [],
    },
    'Express.js': {
        'meta': [],
        'files': [],
        'headers': {'X-Powered-By': 'Express'},
        'cookies': [],
        'js_patterns': [],
    },
    'PHP': {
        'meta': [],
        'files': [],
        'headers': {'X-Powered-By': 'PHP'},
        'cookies': ['PHPSESSID'],
        'js_patterns': [],
    },
    'Next.js': {
        'meta': [],
        'files': ['/_next/'],
        'headers': {'x-nextjs-cache': ''},
        'cookies': [],
        'js_patterns': ['__NEXT_DATA__'],
    },
}

# ============================================================================
# CLOUD BUCKET PATTERNS
# ============================================================================

CLOUD_BUCKET_PATTERNS = {
    'AWS S3': 'https://{name}.s3.amazonaws.com',
    'Google Cloud Storage': 'https://storage.googleapis.com/{name}',
    'Azure Blob': 'https://{name}.blob.core.windows.net',
    'DigitalOcean Spaces': 'https://{name}.ams3.digitaloceanspaces.com',
}

# ============================================================================
# SENSITIVE JS PATTERNS
# ============================================================================

SENSITIVE_JS_PATTERNS = {
    'API Keys': [
        r'api[_-]?key\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
        r'apikey\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
    ],
    'AWS Access Key': [
        r'AKIA[0-9A-Z]{16}',
    ],
    'AWS Secret Key': [
        r'(?i)aws_secret_access_key\s*[:=]\s*["\'][a-zA-Z0-9/+=]{40}["\']',
    ],
    'Google API Key': [
        r'AIza[0-9A-Za-z_-]{35}',
    ],
    'Private Key': [
        r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
    ],
    'Authorization Token': [
        r'(?i)authorization\s*[:=]\s*["\']?(bearer|basic|token)\s+[a-zA-Z0-9._-]+',
    ],
    'JWT Token': [
        r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    ],
    'Database Connection': [
        r'(?i)(mongodb|postgres|mysql|redis)://[^\s"\'<>]+',
    ],
    'Email Address': [
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    ],
    'Internal IP': [
        r'(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
    ],
}

# ============================================================================
# V2.0 - API ENDPOINT DISCOVERY PATHS
# ============================================================================

API_ENDPOINTS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/admin", "/api/me",
    "/api/auth", "/api/login", "/api/register", "/api/logout",
    "/api/config", "/api/settings", "/api/search", "/api/query",
    "/api/data", "/api/upload", "/api/download", "/api/export",
    "/api/import", "/api/files", "/api/docs", "/api/swagger",
    "/api/openapi", "/api/graphql", "/api/rest", "/api/health",
    "/api/status", "/api/profile", "/api/account", "/api/posts",
    "/api/comments", "/api/orders", "/api/products", "/api/cart",
    "/api/payment", "/api/checkout", "/api/webhook", "/api/callback",
    "/api/notification", "/api/message", "/api/email", "/api/token",
    "/api/verify", "/api/reset", "/api/confirm", "/api/activate",
    "/api/otp", "/api/2fa", "/api/session", "/api/role",
    "/api/permission", "/api/log", "/api/audit", "/api/report",
    "/api/dashboard", "/api/analytics", "/api/metrics", "/api/batch",
    "/swagger.json", "/swagger-ui", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/openapi.yaml", "/api/swagger.json",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/v1/users", "/v1/auth", "/v1/admin", "/v1/data",
    "/v2/users", "/v2/auth", "/v2/admin", "/v2/data",
    "/rest/api", "/rest/v1", "/rest/v2",
    "/graphql", "/graphiql",
    "/oauth/token", "/oauth/authorize", "/oauth/revoke",
    "/health", "/status", "/info", "/metrics",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/configprops", "/actuator/beans",
]

# ============================================================================
# V2.0 - RATE LIMIT TEST ENDPOINTS
# ============================================================================

RATE_LIMIT_ENDPOINTS = [
    "/login", "/signin", "/auth/login", "/api/login",
    "/register", "/signup", "/auth/register",
    "/api/v1/login", "/api/auth/token",
    "/password-reset", "/forgot-password",
    "/api/v1/register", "/oauth/token",
    "/api/otp/verify", "/api/otp/resend",
    "/2fa/verify", "/api/v1/2fa",
    "/wp-login.php", "/administrator/login",
]

# ============================================================================
# V2.0 - SENSITIVE FILES DEEP SCANNER
# ============================================================================

SENSITIVE_FILES_DEEP = [
    # Version control
    ".git/config", ".git/HEAD", ".git/refs/heads/master",
    ".git/refs/heads/main", ".svn/entries", ".svn/wc.db",
    ".hg/store", ".hg/hgrc", ".bzr/checkout",
    # Environment & config
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.backup", ".env.bak", ".env.save",
    ".env~", ".env.swp", ".env.old",
    "config.php", "config.yml", "config.yaml", "config.json",
    "config.inc.php", "config.ini", "config.asp", "config.aspx",
    "wp-config.php", "wp-config.php.bak", "wp-config.php~",
    "wp-config.php.save", "settings.py", "settings.php",
    "application.properties", "application.yml",
    "appsettings.json", "web.config",
    # Database dumps
    "database.sql", "db.sql", "dump.sql", "backup.sql",
    "export.sql", "mysql.sql", "db_backup.sql",
    "database.db", "data.db", "app.db", "sqlite.db",
    # Backup archives
    "backup.zip", "backup.tar.gz", "backup.rar", "backup.tar",
    "site.zip", "www.zip", "web.zip", "public.zip",
    "htdocs.zip", "home.zip", "root.zip",
    "backup.tar.bz2", "backup.7z", "db.zip",
    # Log files
    "error.log", "access.log", "debug.log", "app.log",
    "php_error.log", "mysql_error.log", "apache_error.log",
    "nginx_error.log", "laravel.log", "django.log",
    "production.log", "development.log", "test.log",
    # Server info
    "phpinfo.php", "info.php", "test.php", "pi.php",
    "server-status", "server-info",
    # CMS specific
    "wp-admin/install.php", "wp-admin/upgrade.php",
    "wp-content/debug.log", "wp-content/backups/",
    "xmlrpc.php", "wp-cron.php",
    # API & docs
    "swagger.json", "swagger.yaml", "openapi.json",
    "api-docs.json", "graphql", "graphiql",
    # Docker & CI/CD
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerenv", "Jenkinsfile", ".gitlab-ci.yml",
    ".travis.yml", "bitbucket-pipelines.yml",
    # Cloud credentials
    ".aws/credentials", ".aws/config",
    ".google/cloud.json", "service-account.json",
    "credentials.json", "client_secret.json",
    # Other sensitive
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "README.md", "CHANGELOG.md", "LICENSE",
    "package.json", "composer.json", "Gemfile",
    "requirements.txt", "Pipfile", "pom.xml",
    ".htaccess", ".htpasswd", ".DS_Store",
    "id_rsa", "id_rsa.pub", "authorized_keys",
    "known_hosts", "ssh_config",
]

# ============================================================================
# V2.0 - EMAIL ENUMERATION PATTERNS
# ============================================================================

EMAIL_PATTERNS = [
    "{first}@{domain}", "{first}.{last}@{domain}",
    "{first}_{last}@{domain}", "{f}{last}@{domain}",
    "{first}{l}@{domain}", "{last}.{first}@{domain}",
    "{last}_{first}@{domain}", "{l}{first}@{domain}",
    "{first}{last}@{domain}", "{first}.{l}@{domain}",
    "{f}.{last}@{domain}", "{first}-{last}@{domain}",
    "{last}{first}@{domain}", "{last}.{f}@{domain}",
    "{first}.{last}2@{domain}", "{first}2@{domain}",
]

# ============================================================================
# V2.0 - SUBDOMAIN TAKEOVER SIGNATURES
# ============================================================================

TAKEOVER_SIGNATURES = {
    "GitHub Pages": {"cname": "github.io", "response": "There isn't a GitHub Pages site here", "status": [404]},
    "Heroku": {"cname": "herokuapp.com", "response": "No such app", "status": [404]},
    "AWS S3": {"cname": "aws.com", "response": "NoSuchBucket", "status": [404]},
    "Shopify": {"cname": "shopify.com", "response": "Sorry, this shop is currently unavailable", "status": [410]},
    "Tumblr": {"cname": "tumblr.com", "response": "Whatever you were looking for doesn't currently exist", "status": [404]},
    "Wordpress": {"cname": "wordpress.com", "response": "Do you want to register", "status": [200]},
    "Teamwork": {"cname": "teamwork.com", "response": "Oops - We didn't find your site", "status": [404]},
    "Help Scout": {"cname": "helpscout.net", "response": "No settings were found for this company", "status": [404]},
    "Cargo": {"cname": "cargocollective.com", "response": "If you're moving your domain away from Cargo", "status": [404]},
    "Statuspage": {"cname": "statuspage.io", "response": "You are being redirected", "status": [301]},
    "Surge": {"cname": "surge.sh", "response": "project not found", "status": [404]},
    "Bitbucket": {"cname": "bitbucket.io", "response": "Repository not found", "status": [404]},
    "Intercom": {"cname": "intercom.help", "response": "This page is reserved for artistic dogs", "status": [404]},
    "Webflow": {"cname": "webflow.io", "response": "The page you're looking for doesn't exist or has been moved", "status": [404]},
    "Readme": {"cname": "readme.io", "response": "Project doesnt exist", "status": [404]},
    "Fly": {"cname": "fly.dev", "response": "404 Not Found", "status": [404]},
    "Vercel": {"cname": "vercel.app", "response": "The deployment could not be found", "status": [404]},
    "Netlify": {"cname": "netlify.app", "response": "Not Found", "status": [404]},
    "Pantheon": {"cname": "pantheon.io", "response": "404 error unknown site", "status": [404]},
    "Zendesk": {"cname": "zendesk.com", "response": "Help Center Closed", "status": [404]},
    "Freshdesk": {"cname": "freshdesk.com", "response": "There is no helpdesk here", "status": [404]},
    "GitLab": {"cname": "gitlab.io", "response": "The page you're looking for could not be found", "status": [404]},
    "MyShopify": {"cname": "myshopify.com", "response": "Sorry, this shop is currently unavailable", "status": [404]},
    "Uservoice": {"cname": "uservoice.com", "response": "This UserVoice subdomain is currently available", "status": [404]},
}

# ============================================================================
# V2.0 - TECH VERSION SIGNATURES WITH VERSION EXTRACTION
# ============================================================================

TECH_VERSION_SIGNATURES = {
    "Apache": {
        "header": "Server",
        "regex": r"Apache/([\d.]+)",
    },
    "nginx": {
        "header": "Server",
        "regex": r"nginx/([\d.]+)",
    },
    "PHP": {
        "header": "X-Powered-By",
        "regex": r"PHP/([\d.]+)",
    },
    "Express": {
        "header": "X-Powered-By",
        "regex": r"Express/([\d.]+)",
    },
    "WordPress": {
        "meta": "generator",
        "regex": r"WordPress\s+([\d.]+)",
    },
    "Joomla": {
        "meta": "generator",
        "regex": r"Joomla!\s*([\d.]+)",
    },
    "Drupal": {
        "meta": "generator",
        "regex": r"Drupal\s+([\d.]+)",
    },
    "OpenSSL": {
        "header": "Server",
        "regex": r"OpenSSL/([\d.a-z]+)",
    },
    "jQuery": {
        "js_pattern": r"jquery[.-]?([\d.]+)",
    },
    "React": {
        "js_pattern": r"react.*?version.*?([\d.]+)",
    },
    "Next.js": {
        "header": "x-nextjs-cache",
        "meta": "next-head-count",
        "regex": r"Next\.js\s*([\d.]+)",
    },
    "Laravel": {
        "cookie": "laravel_session",
        "header_check": True,
    },
    "Django": {
        "cookie": "csrftoken",
        "header_check": True,
    },
}

# ============================================================================
# V2.0 - CVE LOOKUP API
# ============================================================================

CVE_API = "https://cve.circl.lu/api"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ============================================================================
# V2.0 - BROKEN LINK STATUS CODES
# ============================================================================

BROKEN_LINK_CODES = [404, 410, 500, 502, 503]

# ============================================================================
# ORIGIN IP FINDER - CDN IP RANGES (for filtering CDN IPs from results)
# ============================================================================

CDN_IP_RANGES = {
    'Cloudflare': [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
        '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
        '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ],
    'Akamai': [
        '23.0.0.0/12', '23.32.0.0/11', '23.64.0.0/14',
        '23.72.0.0/13', '72.246.0.0/15', '95.100.0.0/14',
        '184.24.0.0/13', '184.84.0.0/14',
    ],
    'AWS CloudFront': [
        '13.224.0.0/14', '13.249.0.0/16', '18.154.0.0/15',
        '18.64.0.0/14', '52.46.0.0/17', '52.82.128.0/19',
        '54.192.0.0/16', '54.230.0.0/16', '54.239.128.0/18',
        '99.84.0.0/16', '204.246.160.0/19', '205.251.192.0/19',
    ],
    'Sucuri': [
        '192.124.249.0/24', '192.88.134.0/23',
    ],
    'Incapsula': [
        '199.83.128.0/21', '198.177.120.0/21',
        '45.60.0.0/18', '45.60.64.0/18',
    ],
    'Fastly': [
        '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24',
        '103.245.222.0/23', '103.245.224.0/24', '104.156.80.0/20',
        '151.101.0.0/16', '157.52.64.0/18', '172.111.64.0/18',
        '199.27.72.0/21', '199.232.0.0/16',
    ],
    'StackPath': [
        '151.139.0.0/16', '209.107.0.0/17',
    ],
    'Microsoft Azure CDN': [
        '13.107.0.0/16',  # IPv4 only; IPv6 excluded for ipaddress compatibility
    ],
}

# Public DNS resolvers for multi-resolver cross-validation
PUBLIC_DNS_RESOLVERS = [
    '8.8.8.8',       # Google
    '8.8.4.4',       # Google
    '1.1.1.1',       # Cloudflare
    '1.0.0.1',       # Cloudflare
    '9.9.9.9',       # Quad9
    '208.67.222.222', # OpenDNS
    '208.67.220.220', # OpenDNS
]

# Paths that may trigger error pages leaking internal IPs
ERROR_TRIGGER_PATHS = [
    '/.%2e/.', '/..%252f', '/..;/', '/..%c0%af',
    '/cgi-bin/', '/.env', '/debug', '/trace',
    '/status', '/health', '/metrics', '/info',
    '/phpinfo.php', '/server-status', '/server-info',
    '/.git/config', '/.svn/entries', '/.DS_Store',
    '/wp-config.php~', '/backup.tar.gz', '/.env.bak',
]

# Common subdomains to check for CNAME/origin leaks
ORIGIN_CHECK_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'webmail', 'dev', 'staging', 'api',
    'app', 'portal', 'test', 'old', 'beta', 'blog', 'shop', 'cdn',
    'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'vpn', 'remote',
]
