#!/usr/bin/env python3
"""
ZYLON FUSION v2.5 NUCLEAR - Container Security Engine
======================================================
Fused from: DEEPCE (https://github.com/stealthcopter/deepce)
Purpose: Docker/Container enumeration, privilege escalation, and escape detection
Architecture: Pure Python reimplementation of DEEPCE shell checks
Python 3.13 Compatible | Termux Non-Root
"""

import os
import sys
import re
import subprocess
import platform
from pathlib import Path

from core.shared_infra import shared_session, regex_cache, oob_provider

# ============================================================================
# CONTAINER DETECTION
# ============================================================================

class ContainerEngine:
    """Docker/Container Security Testing Engine"""
    
    def __init__(self):
        self.results = {
            'container_detected': False,
            'container_type': 'unknown',
            'is_root': False,
            'dangerous_groups': [],
            'docker_available': False,
            'docker_sock': False,
            'privileged': False,
            'capabilities': [],
            'mounts': [],
            'interesting_files': [],
            'secrets': [],
            'escape_vectors': [],
            'cve_checks': [],
        }
    
    def _run_cmd(self, cmd, timeout=10):
        """Run shell command safely"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip(), result.stderr.strip(), result.returncode
        except (subprocess.TimeoutExpired, Exception):
            return '', '', -1
    
    def _file_exists(self, path):
        """Check if file exists"""
        return os.path.exists(path)
    
    def _file_readable(self, path):
        """Check if file is readable"""
        return os.path.isfile(path) and os.access(path, os.R_OK)
    
    # ----------------------------------------------------------------
    # CONTAINER DETECTION
    # ----------------------------------------------------------------
    
    def detect_container(self):
        """Detect if running inside a container"""
        # Method 1: Check for .dockerenv
        if self._file_exists('/.dockerenv'):
            self.results['container_detected'] = True
            self.results['container_type'] = 'Docker'
            return True
        
        # Method 2: Check /proc/1/cgroup for docker/kubepods
        stdout, _, _ = self._run_cmd('cat /proc/1/cgroup 2>/dev/null')
        if stdout:
            if '/docker/' in stdout:
                self.results['container_detected'] = True
                self.results['container_type'] = 'Docker'
                return True
            elif '/kubepod' in stdout:
                self.results['container_detected'] = True
                self.results['container_type'] = 'Kubernetes'
                return True
            elif '/lxc/' in stdout:
                self.results['container_detected'] = True
                self.results['container_type'] = 'LXC'
                return True
        
        # Method 3: Check environment variables
        env_container = os.environ.get('container', '')
        if env_container == 'lxc' or env_container == 'docker':
            self.results['container_detected'] = True
            self.results['container_type'] = env_container.upper()
            return True
        
        return self.results['container_detected']
    
    # ----------------------------------------------------------------
    # USER CHECK
    # ----------------------------------------------------------------
    
    def check_user(self):
        """Check current user and group memberships"""
        # Root check
        stdout, _, _ = self._run_cmd('id -u')
        if stdout.strip() == '0':
            self.results['is_root'] = True
        
        # Group check
        stdout, _, _ = self._run_cmd('id')
        dangerous = ['docker', 'lxd', 'root', 'sudo', 'wheel']
        if stdout:
            for group in dangerous:
                if group in stdout.lower():
                    self.results['dangerous_groups'].append(group)
        
        # Sudo check
        stdout, _, rc = self._run_cmd('sudo -n -l 2>/dev/null')
        if rc == 0 and stdout:
            self.results['dangerous_groups'].append('passwordless_sudo')
    
    # ----------------------------------------------------------------
    # DOCKER CHECK
    # ----------------------------------------------------------------
    
    def check_docker(self):
        """Check Docker availability and version"""
        # Docker binary
        stdout, _, rc = self._run_cmd('which docker 2>/dev/null')
        if rc == 0 and stdout:
            self.results['docker_available'] = True
        
        # Docker version
        stdout, _, _ = self._run_cmd('docker version --format "{{.Server.Version}}" 2>/dev/null')
        if stdout:
            self._check_docker_cves(stdout.strip())
        
        # Docker socket
        sock_paths = ['/var/run/docker.sock', '/run/docker.sock']
        for sock in sock_paths:
            if self._file_exists(sock):
                self.results['docker_sock'] = True
                # Check if writable
                if os.access(sock, os.W_OK):
                    self.results['escape_vectors'].append({
                        'method': 'docker_socket',
                        'severity': 'CRITICAL',
                        'description': f'Docker socket {sock} is writable - can create containers to escape',
                        'exploit': f'docker run -v /:/mnt --rm -it alpine chroot /mnt sh'
                    })
        
        # Check mount info for docker.sock
        stdout, _, _ = self._run_cmd('cat /proc/self/mountinfo 2>/dev/null | grep docker.sock')
        if stdout:
            self.results['docker_sock'] = True
    
    def _check_docker_cves(self, version):
        """Check Docker version against known CVEs"""
        cves = [
            {
                'cve': 'CVE-2019-13139',
                'affected': '< 18.09.5',
                'description': 'Command execution via URL parsing',
                'check': self._version_lt(version, '18.09.5')
            },
            {
                'cve': 'CVE-2019-5736',
                'affected': '< 18.09.3',
                'description': 'Container escape by overwriting runC binary',
                'check': self._version_lt(version, '18.09.3')
            },
            {
                'cve': 'CVE-2019-5021',
                'affected': 'Alpine 3.3-3.5',
                'description': 'Blank root password in Alpine',
                'check': self._check_alpine_cve()
            },
        ]
        
        for cve in cves:
            if cve['check']:
                self.results['cve_checks'].append(cve)
    
    def _version_lt(self, current, target):
        """Compare version strings"""
        try:
            curr_parts = [int(x) for x in current.split('.')]
            tgt_parts = [int(x) for x in target.split('.')]
            for c, t in zip(curr_parts, tgt_parts):
                if c < t:
                    return True
                elif c > t:
                    return False
            return len(curr_parts) < len(tgt_parts)
        except (ValueError, AttributeError):
            return False
    
    def _check_alpine_cve(self):
        """Check Alpine blank password CVE"""
        if self._file_readable('/etc/alpine-release'):
            stdout, _, _ = self._run_cmd('cat /etc/alpine-release')
            if stdout:
                ver = stdout.strip()
                return self._version_lt(ver, '3.6.0') and not self._version_lt(ver, '3.3.0')
        return False
    
    # ----------------------------------------------------------------
    # CAPABILITIES CHECK
    # ----------------------------------------------------------------
    
    def check_capabilities(self):
        """Check Linux capabilities"""
        # Method 1: capsh
        stdout, _, rc = self._run_cmd('capsh --print 2>/dev/null')
        if rc == 0 and stdout:
            dangerous_caps = [
                'cap_sys_admin', 'cap_sys_ptrace', 'cap_sys_module',
                'cap_sys_rawio', 'cap_dac_override', 'cap_dac_read_search',
                'cap_mknod', 'cap_net_admin', 'cap_net_raw'
            ]
            for cap in dangerous_caps:
                if cap in stdout.lower():
                    self.results['capabilities'].append(cap)
                    
                    # SYS_MODULE = kernel module escape
                    if cap == 'cap_sys_module':
                        self.results['escape_vectors'].append({
                            'method': 'sys_module',
                            'severity': 'CRITICAL',
                            'description': 'CAP_SYS_MODULE allows loading kernel modules - host escape possible',
                            'exploit': 'Load malicious kernel module for host RCE'
                        })
                    
                    # SYS_ADMIN = many escape vectors
                    if cap == 'cap_sys_admin':
                        self.results['escape_vectors'].append({
                            'method': 'sys_admin',
                            'severity': 'HIGH',
                            'description': 'CAP_SYS_ADMIN grants broad privileges including cgroup manipulation',
                            'exploit': 'cgroup release_agent escape'
                        })
        
        # Method 2: /proc/self/status
        elif self._file_readable('/proc/self/status'):
            stdout, _, _ = self._run_cmd('cat /proc/self/status | grep CapEff')
            if stdout:
                hex_caps = stdout.split(':')[-1].strip()
                self.results['capabilities'].append(f'Raw CapEff: {hex_caps}')
    
    # ----------------------------------------------------------------
    # PRIVILEGED MODE CHECK
    # ----------------------------------------------------------------
    
    def check_privileged(self):
        """Check if container is running in privileged mode"""
        stdout, _, rc = self._run_cmd('fdisk -l 2>/dev/null')
        if rc == 0 and stdout and len(stdout.strip().split('\n')) > 1:
            self.results['privileged'] = True
            self.results['escape_vectors'].append({
                'method': 'privileged_mode',
                'severity': 'CRITICAL',
                'description': 'Container running in privileged mode - can access host block devices',
                'exploit': 'cgroup release_agent escape or direct device access'
            })
        
        # Alternative check: count devices in /dev
        try:
            dev_count = len(os.listdir('/dev'))
            if dev_count > 20:  # Normal container has few devices
                self.results['privileged'] = True
        except Exception:
            pass
    
    # ----------------------------------------------------------------
    # MOUNT ENUMERATION
    # ----------------------------------------------------------------
    
    def check_mounts(self):
        """Check mounted filesystems for sensitive data"""
        stdout, _, _ = self._run_cmd('cat /proc/self/mountinfo 2>/dev/null')
        if not stdout:
            return
        
        boring_mounts = ['/proc', '/sys', '/dev', 'cgroup', 'mqueue', 'docker',
                        'shm', 'pts', 'devpts', 'tmpfs', 'overlay', 'proc']
        
        for line in stdout.split('\n'):
            parts = line.split()
            if len(parts) < 5:
                continue
            
            mount_point = parts[4] if len(parts) > 4 else ''
            
            # Skip boring mounts
            skip = False
            for b in boring_mounts:
                if b in mount_point:
                    skip = True
                    break
            if skip:
                continue
            
            self.results['mounts'].append(mount_point)
            
            # Check for docker.sock mount
            if 'docker.sock' in line:
                self.results['escape_vectors'].append({
                    'method': 'docker_sock_mount',
                    'severity': 'CRITICAL',
                    'description': 'Docker socket is mounted - can create containers',
                    'exploit': 'Use docker.sock API to spawn privileged container'
                })
            
            # Check for host / mount
            if 'perdir=/' in line and 'perdir=/proc' not in line and 'perdir=/sys' not in line:
                self.results['escape_vectors'].append({
                    'method': 'host_root_mount',
                    'severity': 'HIGH',
                    'description': 'Host root filesystem appears to be mounted',
                    'exploit': 'Direct access to host files'
                })
    
    # ----------------------------------------------------------------
    # INTERESTING FILES
    # ----------------------------------------------------------------
    
    def find_interesting_files(self):
        """Search for interesting files and secrets"""
        # Environment variables
        env_secrets = []
        for key, value in os.environ.items():
            if any(s in key.lower() for s in ['pass', 'secret', 'key', 'token', 'api', 'auth']):
                env_secrets.append(f'{key}={value[:20]}***')
        
        if env_secrets:
            self.results['secrets'].extend(env_secrets)
        
        # Process environment (if readable)
        stdout, _, _ = self._run_cmd('cat /proc/*/environ 2>/dev/null | tr "\\0" "\\n" | grep -i "pass\\|secret\\|key\\|token" | head -20')
        if stdout:
            for line in stdout.split('\n'):
                if line.strip() and line.strip() not in self.results['secrets']:
                    self.results['secrets'].append(line.strip()[:50])
        
        # Shadow file
        if self._file_readable('/etc/shadow'):
            stdout, _, _ = self._run_cmd('cat /etc/shadow 2>/dev/null | grep -v "^\\*" | grep -v "^!" | head -10')
            if stdout:
                self.results['interesting_files'].append({
                    'file': '/etc/shadow',
                    'content': stdout[:200],
                    'severity': 'CRITICAL'
                })
        
        # Common sensitive paths
        sensitive_paths = [
            '/.env', '/.git/config', '/.svn/entries', '/.htpasswd',
            '/app/config.py', '/app/settings.py', '/app/.env',
            '/var/run/secrets/', '/run/secrets/',
            '/root/.ssh/id_rsa', '/root/.bash_history',
            '/etc/kubernetes/', '/var/lib/kubelet/',
        ]
        
        for path in sensitive_paths:
            if self._file_exists(path):
                self.results['interesting_files'].append({
                    'file': path,
                    'severity': 'HIGH',
                    'content': 'exists'
                })
        
        # App directories
        app_dirs = [
            '/var/jenkins_home', '/var/lib/rabbitmq', '/var/lib/mysql',
            '/etc/nginx', '/var/lib/redis', '/etc/traefik',
            '/var/lib/postgresql', '/opt/bitnami', '/app',
        ]
        
        for d in app_dirs:
            if os.path.isdir(d):
                self.results['interesting_files'].append({
                    'file': d,
                    'severity': 'MEDIUM',
                    'content': 'directory exists'
                })
    
    # ----------------------------------------------------------------
    # CONTAINER ESCAPE METHODS
    # ----------------------------------------------------------------
    
    def check_escape_vectors(self):
        """Check all container escape vectors"""
        # Escape 1: Docker command
        if self.results['docker_available'] or self.results['docker_sock']:
            if 'docker' in self.results['dangerous_groups'] or self.results['is_root']:
                if not any(e['method'] == 'docker_command' for e in self.results['escape_vectors']):
                    self.results['escape_vectors'].append({
                        'method': 'docker_command',
                        'severity': 'CRITICAL',
                        'description': 'User can run docker commands - mount host FS and chroot',
                        'exploit': 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh'
                    })
        
        # Escape 2: Privileged cgroup
        if self.results['privileged']:
            if not any(e['method'] == 'cgroup_escape' for e in self.results['escape_vectors']):
                self.results['escape_vectors'].append({
                    'method': 'cgroup_escape',
                    'severity': 'CRITICAL',
                    'description': 'Privileged container - cgroup release_agent escape possible',
                    'exploit': 'Mount cgroup, set release_agent, trigger for host RCE'
                })
        
        # Escape 3: Docker socket via curl
        if self.results['docker_sock']:
            stdout, _, _ = self._run_cmd('which curl 2>/dev/null')
            if stdout:
                if not any(e['method'] == 'docker_sock_curl' for e in self.results['escape_vectors']):
                    self.results['escape_vectors'].append({
                        'method': 'docker_sock_curl',
                        'severity': 'CRITICAL',
                        'description': 'Docker socket + curl = create container via API',
                        'exploit': 'curl -XPOST --unix-socket /var/run/docker.sock -d \'{"Image":"alpine","Cmd":["chroot","/mnt","sh"],"Binds":["/:/mnt:rw"]}\' http://localhost/containers/create'
                    })
    
    # ----------------------------------------------------------------
    # FULL SCAN
    # ----------------------------------------------------------------
    
    def full_scan(self):
        """Run complete container security scan"""
        self.detect_container()
        self.check_user()
        self.check_docker()
        self.check_capabilities()
        self.check_privileged()
        self.check_mounts()
        self.find_interesting_files()
        self.check_escape_vectors()
        
        return self.results


# ============================================================================
# CONSOLE INTERFACE
# ============================================================================

def run_container_scan(console=None):
    """Interactive container security scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.panel import Panel
    from rich.table import Table
    
    console.print(Panel(
        "[bold cyan]CONTAINER SECURITY ENGINE[/bold cyan]\n"
        "[yellow]Fused from: DEEPCE | Zero-Dependency Docker Security[/yellow]\n"
        "[green]Checks: Container detection, user/groups, Docker access, capabilities,\n"
        "         privileged mode, mounts, secrets, escape vectors, CVEs[/green]",
        border_style="bright_cyan"
    ))
    
    engine = ContainerEngine()
    
    console.print("\n[cyan][*] Running container security scan...[/cyan]\n")
    
    with console.status("[bold green]Scanning container security...", spinner="dots"):
        results = engine.full_scan()
    
    # Display results
    # Container detection
    if results['container_detected']:
        console.print(f"[bold green][+] Container DETECTED: {results['container_type']}[/bold green]")
    else:
        console.print("[yellow][-] Not running inside a container (or detection evaded)[/yellow]")
    
    # User info
    console.print(f"\n[cyan]═══ USER INFO ═══[/cyan]")
    console.print(f"  Root: {'[red]YES[/red]' if results['is_root'] else '[green]NO[/green]'}")
    if results['dangerous_groups']:
        console.print(f"  Dangerous Groups: [red]{', '.join(results['dangerous_groups'])}[/red]")
    
    # Docker
    console.print(f"\n[cyan]═══ DOCKER STATUS ═══[/cyan]")
    console.print(f"  Docker Available: {'[red]YES[/red]' if results['docker_available'] else '[green]NO[/green]'}")
    console.print(f"  Docker Socket: {'[red]YES[/red]' if results['docker_sock'] else '[green]NO[/green]'}")
    console.print(f"  Privileged Mode: {'[red]YES[/red]' if results['privileged'] else '[green]NO[/green]'}")
    
    # Capabilities
    if results['capabilities']:
        console.print(f"\n[cyan]═══ CAPABILITIES ═══[/cyan]")
        for cap in results['capabilities']:
            console.print(f"  [yellow]{cap}[/yellow]")
    
    # Mounts
    if results['mounts']:
        console.print(f"\n[cyan]═══ INTERESTING MOUNTS ═══[/cyan]")
        for mount in results['mounts'][:10]:
            console.print(f"  [yellow]{mount}[/yellow]")
    
    # Interesting files
    if results['interesting_files']:
        console.print(f"\n[cyan]═══ INTERESTING FILES ═══[/cyan]")
        for f in results['interesting_files'][:15]:
            severity_color = 'red' if f.get('severity') == 'CRITICAL' else 'yellow' if f.get('severity') == 'HIGH' else 'cyan'
            console.print(f"  [{severity_color}][{f.get('severity', '?')}] {f['file']}[/{severity_color}]")
    
    # Secrets
    if results['secrets']:
        console.print(f"\n[cyan]═══ SECRETS FOUND ═══[/cyan]")
        for s in results['secrets'][:10]:
            console.print(f"  [red]{s}[/red]")
    
    # CVE Checks
    if results['cve_checks']:
        console.print(f"\n[cyan]═══ VULNERABLE CVEs ═══[/cyan]")
        for cve in results['cve_checks']:
            console.print(f"  [red]{cve['cve']}: {cve['description']} (affected: {cve['affected']})[/red]")
    
    # Escape vectors
    if results['escape_vectors']:
        console.print(f"\n[bold red]═══ ESCAPE VECTORS ({len(results['escape_vectors'])}) ═══[/bold red]")
        for i, escape in enumerate(results['escape_vectors'], 1):
            severity_color = 'red' if escape['severity'] == 'CRITICAL' else 'yellow'
            console.print(f"\n  [{severity_color}][{escape['severity']}] {escape['method']}[/{severity_color}]")
            console.print(f"  {escape['description']}")
            console.print(f"  [cyan]Exploit: {escape['exploit']}[/cyan]")
    else:
        console.print("\n[green][+] No container escape vectors found.[/green]")


if __name__ == "__main__":
    run_container_scan()
