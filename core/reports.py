"""
ZYLON FUSION - Report Engine
Generates JSON, HTML, and PDF reports
Termux Non-Root Compatible
"""

import os
import json
from datetime import datetime
from core.var import ZYLON_VERSION, ZYLON_CODENAME, HOME_DIR


class ReportEngine:
    """Advanced Report Generation Engine"""

    def __init__(self):
        self.reports_dir = os.path.join(HOME_DIR, '.zylon', 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)

    def save_json(self, results, target):
        """Save scan results as JSON"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"zylon_{target}_{timestamp}.json"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        return filepath

    def generate_html_report(self, results, target):
        """Generate comprehensive HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"zylon_{target}_{timestamp}.html"
        filepath = os.path.join(self.reports_dir, filename)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZYLON FUSION - Security Report: {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #0a0a0f; color: #e0e0e0; line-height: 1.6;
        }}
        .header {{ 
            background: linear-gradient(135deg, #1a0a2e, #16213e, #0f3460);
            padding: 30px; text-align: center; border-bottom: 3px solid #e94560;
        }}
        .header h1 {{ color: #e94560; font-size: 28px; margin-bottom: 5px; }}
        .header .subtitle {{ color: #f0a500; font-size: 16px; }}
        .header .meta {{ color: #888; font-size: 12px; margin-top: 10px; }}
        .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
        .summary-grid {{ 
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px; margin: 20px 0;
        }}
        .summary-card {{ 
            background: #16213e; padding: 20px; border-radius: 10px;
            border-left: 4px solid #e94560; text-align: center;
        }}
        .summary-card .number {{ font-size: 36px; color: #e94560; font-weight: bold; }}
        .summary-card .label {{ color: #888; font-size: 14px; margin-top: 5px; }}
        .section {{ 
            background: #16213e; padding: 20px; margin: 15px 0; 
            border-radius: 10px; border: 1px solid #1a1a3e;
        }}
        .section h2 {{ 
            color: #f0a500; font-size: 20px; margin-bottom: 15px;
            border-bottom: 1px solid #333; padding-bottom: 10px;
        }}
        .finding {{ 
            background: #0f3460; padding: 12px; margin: 8px 0;
            border-radius: 5px; border-left: 4px solid #e94560;
        }}
        .finding.critical {{ border-left-color: #ff0000; }}
        .finding.high {{ border-left-color: #e94560; }}
        .finding.medium {{ border-left-color: #f0a500; }}
        .finding.low {{ border-left-color: #00ff00; }}
        .finding.info {{ border-left-color: #00aaff; }}
        .tag {{ 
            display: inline-block; padding: 2px 8px; border-radius: 3px;
            font-size: 11px; font-weight: bold; margin-right: 5px;
        }}
        .tag.critical {{ background: #ff0000; color: #fff; }}
        .tag.high {{ background: #e94560; color: #fff; }}
        .tag.medium {{ background: #f0a500; color: #000; }}
        .tag.low {{ background: #00ff00; color: #000; }}
        .tag.info {{ background: #00aaff; color: #fff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #0f3460; color: #f0a500; padding: 10px; text-align: left; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #1a1a3e; }}
        tr:hover {{ background: #1a1a3e; }}
        pre {{ 
            background: #0a0a0f; padding: 12px; border-radius: 5px;
            overflow-x: auto; font-size: 12px; color: #00ff00;
        }}
        .risk-meter {{ 
            height: 8px; background: #1a1a2e; border-radius: 4px; overflow: hidden;
        }}
        .risk-meter .fill {{ height: 100%; border-radius: 4px; transition: width 0.5s; }}
        .footer {{ 
            text-align: center; padding: 20px; color: #666;
            border-top: 1px solid #333; margin-top: 30px;
        }}
        .severity-critical {{ color: #ff0000; }}
        .severity-high {{ color: #e94560; }}
        .severity-medium {{ color: #f0a500; }}
        .severity-low {{ color: #00ff00; }}
        .severity-info {{ color: #00aaff; }}
        @media (max-width: 768px) {{
            .container {{ padding: 0 10px; }}
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>ZYLON FUSION</h1>
        <div class="subtitle">Security Assessment Report</div>
        <div class="meta">
            Target: {target} | 
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 
            Version: {ZYLON_VERSION} ({ZYLON_CODENAME})
        </div>
    </div>
    
    <div class="container">
"""

        # Count findings by severity
        total_findings = 0
        critical = 0
        high = 0
        medium = 0
        low = 0

        findings_data = results.get('findings', {})

        # Analyze severity of findings
        for category, data in findings_data.items():
            if isinstance(data, dict):
                if data.get('vulnerable') or data.get('misconfigured') or data.get('exposed'):
                    high += 1
                    total_findings += 1
                elif data.get('issues') and len(data.get('issues', [])) > 0:
                    medium += 1
                    total_findings += 1
                elif 'error' in data:
                    low += 1
                    total_findings += 1
                elif data:
                    low += 1
                    total_findings += 1

        # Summary cards
        html += f"""
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{total_findings}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="number severity-critical">{critical}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="number severity-high">{high}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="number severity-medium">{medium}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="number severity-low">{low}</div>
                <div class="label">Low/Info</div>
            </div>
        </div>
"""

        # Detailed sections for each scan category
        category_titles = {
            'recon': 'Reconnaissance',
            'whois': 'WHOIS Information',
            'geoip': 'Geo-IP Location',
            'dns': 'DNS Records',
            'subdomains': 'Subdomain Discovery',
            'ports': 'Port Scan Results',
            'banners': 'Service Banners',
            'headers': 'Security Headers Analysis',
            'ssl': 'SSL/TLS Analysis',
            'sqli': 'SQL Injection Scan',
            'xss': 'Cross-Site Scripting (XSS) Scan',
            'directories': 'Directory Brute Force',
            'wordpress': 'WordPress Security Scan',
            'cors': 'CORS Misconfiguration',
            'open_redirect': 'Open Redirect Detection',
            'crlf': 'CRLF Injection Scan',
            'cookies': 'Cookie Security Analysis',
            'javascript': 'JavaScript Sensitive Data',
            'cloud_buckets': 'Cloud Storage Bucket Scan',
            'waf': 'WAF Detection',
            'tech_stack': 'Technology Fingerprinting',
        }

        for category, title in category_titles.items():
            if category in findings_data and findings_data[category]:
                data = findings_data[category]
                severity_class = 'info'
                if isinstance(data, dict):
                    if data.get('vulnerable') or data.get('misconfigured') or data.get('exposed'):
                        severity_class = 'high'
                    elif data.get('issues') and len(data.get('issues', [])) > 0:
                        severity_class = 'medium'

                html += f"""
        <div class="section">
            <h2><span class="tag {severity_class}">{severity_class.upper()}</span> {title}</h2>
            <pre>{json.dumps(data, indent=2, default=str, ensure_ascii=False)}</pre>
        </div>
"""

        html += f"""
        <div class="footer">
            <p>Generated by ZYLON FUSION v{ZYLON_VERSION} ({ZYLON_CODENAME})</p>
            <p>For authorized security testing only</p>
        </div>
    </div>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        return filepath
