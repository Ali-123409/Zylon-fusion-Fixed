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

ZYLON_VERSION = "1.0.0"
ZYLON_CODENAME = "Fusion"
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

FULL_PORT_RANGE = list(range(1, 65536))
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
    "https://null", 
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
    },
    'Joomla': {
        'meta': ['generator', 'Joomla'],
        'files': ['/administrator/'],
        'headers': {},
        'cookies': [],
    },
    'Drupal': {
        'meta': ['generator', 'Drupal'],
        'files': ['/misc/drupal.js', '/sites/default/'],
        'headers': {'X-Drupal-Cache': ''},
        'cookies': ['Drupal.visitor'],
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
    },
    'Apache': {
        'meta': [],
        'files': [],
        'headers': {'Server': 'Apache'},
        'cookies': [],
    },
    'Cloudflare': {
        'meta': [],
        'files': [],
        'headers': {'cf-ray': ''},
        'cookies': ['__cfduid'],
    },
    'Laravel': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': ['laravel_session'],
    },
    'Django': {
        'meta': [],
        'files': [],
        'headers': {},
        'cookies': ['csrftoken'],
    },
    'Express.js': {
        'meta': [],
        'files': [],
        'headers': {'X-Powered-By': 'Express'},
        'cookies': [],
    },
    'PHP': {
        'meta': [],
        'files': [],
        'headers': {'X-Powered-By': 'PHP'},
        'cookies': ['PHPSESSID'],
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
