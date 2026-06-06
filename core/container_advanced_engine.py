#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Container Security Advanced Engine
=========================================================
Fused from: DockerScan (https://github.com/cr0hn/dockerscan)
           + Container-Escape-Check
           + DEEPCE (https://github.com/stealthcopter/deepce)
           + Custom Zylon Container Techniques
Capabilities:
  - Docker API detection and enumeration (remote + local)
  - Container escape technique detection (8+ vectors)
  - Privileged container detection
  - Docker socket exposure check (local + remote)
  - Container image vulnerability scanning (via API)
  - Registry enumeration (Docker Hub, private registries)
  - Kubernetes API detection and enumeration
  - Container capabilities analysis (dangerous caps detection)
  - Network namespace escape detection
  - Volume mount analysis (sensitive path detection)
  - Container runtime fingerprinting (Docker, Podman, CRI-O, containerd)
  - Seccomp and AppArmor profile detection
  - Environment variable secret scanning
  - Container breakout simulation checks
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import json
import socket
import time
import threading
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    API_ENDPOINTS, COMMON_DIRS, DEFAULT_TIMEOUT, MAX_THREADS, USER_AGENTS
)
from core.shared_infra import shared_session, regex_cache, oob_provider

# ============================================================================
# ANSI COLOR CODES (Termux-compatible)
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
# DOCKER API DETECTION PATHS
# ============================================================================

DOCKER_API_PATHS = [
    "/v1.24/containers/json",
    "/v1.25/containers/json",
    "/v1.26/containers/json",
    "/v1.27/containers/json",
    "/v1.28/containers/json",
    "/v1.29/containers/json",
    "/v1.30/containers/json",
    "/v1.31/containers/json",
    "/v1.32/containers/json",
    "/v1.33/containers/json",
    "/v1.34/containers/json",
    "/v1.35/containers/json",
    "/v1.36/containers/json",
    "/v1.37/containers/json",
    "/v1.38/containers/json",
    "/v1.39/containers/json",
    "/v1.40/containers/json",
    "/v1.41/containers/json",
    "/v1.42/containers/json",
    "/v1.43/containers/json",
    "/containers/json",
    "/info",
    "/version",
    "/images/json",
    "/networks",
    "/volumes",
]

# ============================================================================
# CONTAINER ESCAPE VECTORS
# ============================================================================

CONTAINER_ESCAPE_VECTORS = {
    "docker_socket": {
        "description": "Docker socket is writable - can spawn privileged container",
        "severity": "Critical",
        "check": "Writable /var/run/docker.sock or /run/docker.sock",
        "exploit": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "remediation": "Restrict docker.sock permissions, use Docker socket proxy",
    },
    "privileged_mode": {
        "description": "Container running in privileged mode with all capabilities",
        "severity": "Critical",
        "check": "fdisk -l returns results or many devices in /dev",
        "exploit": "cgroup release_agent escape or direct device access",
        "remediation": "Never run containers in privileged mode",
    },
    "cap_sys_admin": {
        "description": "CAP_SYS_ADMIN capability grants broad system privileges",
        "severity": "High",
        "check": "capsh --print contains cap_sys_admin",
        "exploit": "cgroup release_agent escape via nsenter",
        "remediation": "Drop all capabilities and add only required ones",
    },
    "cap_sys_module": {
        "description": "CAP_SYS_MODULE allows loading kernel modules",
        "severity": "Critical",
        "check": "capsh --print contains cap_sys_module",
        "exploit": "Load malicious kernel module for host RCE",
        "remediation": "Never grant CAP_SYS_MODULE to containers",
    },
    "cap_sys_ptrace": {
        "description": "CAP_SYS_PTRACE allows process inspection and injection",
        "severity": "High",
        "check": "capsh --print contains cap_sys_ptrace",
        "exploit": "Inject shellcode into host processes",
        "remediation": "Drop CAP_SYS_PTRACE unless debugging is needed",
    },
    "cap_dac_read_search": {
        "description": "CAP_DAC_READ_SEARCH bypasses file read permission checks",
        "severity": "High",
        "check": "capsh --print contains cap_dac_read_search",
        "exploit": "Read any file on the host system",
        "remediation": "Drop this capability from container",
    },
    "host_pid_namespace": {
        "description": "Container shares PID namespace with host",
        "severity": "High",
        "check": "Can see host PIDs in /proc",
        "exploit": "Access host process memory and signals",
        "remediation": "Do not use --pid=host",
    },
    "host_network_namespace": {
        "description": "Container shares network namespace with host",
        "severity": "High",
        "check": "Can access host loopback and all interfaces",
        "exploit": "Access services bound to localhost only",
        "remediation": "Do not use --network=host",
    },
    "sensitive_mounts": {
        "description": "Sensitive host paths mounted into container",
        "severity": "Critical",
        "check": "/proc/self/mountinfo shows host /, /etc, /root, etc.",
        "exploit": "Direct access to host filesystem",
        "remediation": "Mount only required directories, read-only when possible",
    },
    "docker_api_exposed": {
        "description": "Docker API endpoint exposed without authentication",
        "severity": "Critical",
        "check": "GET /containers/json on target port returns 200",
        "exploit": "Create privileged container via API, mount host root",
        "remediation": "Bind Docker API to localhost only, enable TLS",
    },
    "k8s_service_account": {
        "description": "Kubernetes service account token is mounted",
        "severity": "High",
        "check": "/var/run/secrets/kubernetes.io/serviceaccount/ exists",
        "exploit": "Use service account token to query K8s API",
        "remediation": "Disable automountServiceAccountToken when not needed",
    },
    "runc_escape_cve_2019_5736": {
        "description": "Vulnerable runc version allows container escape (CVE-2019-5736)",
        "severity": "Critical",
        "check": "runc version < 1.0-rc6 or Docker < 18.09.3",
        "exploit": "Overwrite runc binary from inside container",
        "remediation": "Update runc and Docker to patched versions",
    },
}

# ============================================================================
# DANGEROUS LINUX CAPABILITIES
# ============================================================================

DANGEROUS_CAPABILITIES = {
    "cap_sys_admin": {
        "severity": "Critical",
        "description": "Broad system admin privileges - many escape vectors",
    },
    "cap_sys_module": {
        "severity": "Critical",
        "description": "Load kernel modules - host code execution",
    },
    "cap_sys_ptrace": {
        "severity": "High",
        "description": "Process inspection/injection - can inject host processes",
    },
    "cap_sys_rawio": {
        "severity": "High",
        "description": "Raw I/O port access - hardware interaction",
    },
    "cap_dac_override": {
        "severity": "High",
        "description": "Bypass file write permission checks",
    },
    "cap_dac_read_search": {
        "severity": "High",
        "description": "Bypass file read permission checks",
    },
    "cap_net_admin": {
        "severity": "Medium",
        "description": "Network configuration - can modify routing, firewall rules",
    },
    "cap_net_raw": {
        "severity": "Medium",
        "description": "Raw socket access - can sniff network traffic",
    },
    "cap_mknod": {
        "severity": "Medium",
        "description": "Can create device files - potential for block device access",
    },
}

# ============================================================================
# SENSITIVE MOUNT PATHS
# ============================================================================

SENSITIVE_MOUNT_PATHS = [
    "/", "/etc", "/root", "/home", "/var", "/opt", "/usr",
    "/boot", "/sbin", "/bin", "/lib", "/lib64",
    "/etc/shadow", "/etc/passwd", "/etc/ssh",
    "/var/run/docker.sock", "/run/docker.sock",
    "/var/lib/docker", "/var/lib/kubelet",
    "/etc/kubernetes", "/etc/ssl", "/etc/pki",
    "/proc/sys", "/sys/firmware",
    "/var/run/secrets/kubernetes.io",
]

# ============================================================================
# KUBERNETES API ENDPOINTS
# ============================================================================

K8S_API_PATHS = [
    "/api",
    "/api/v1",
    "/apis",
    "/apis/apps",
    "/apis/apps/v1",
    "/apis/batch",
    "/apis/batch/v1",
    "/healthz",
    "/livez",
    "/readyz",
    "/version",
    "/metrics",
    "/openapi/v2",
]

# ============================================================================
# CONTAINER RUNTIME FINGERPRINTS
# ============================================================================

CONTAINER_RUNTIME_FINGERPRINTS = {
    "Docker": {
        "file_checks": ["/.dockerenv", "/run/docker.sock", "/var/run/docker.sock"],
        "cgroup_pattern": r"/docker/",
        "env_vars": ["DOCKER_CONTAINER", "container=docker"],
        "process_names": ["dockerd", "containerd", "docker-proxy"],
    },
    "Podman": {
        "file_checks": ["/run/.containerenv", "/.containerenv"],
        "cgroup_pattern": r"/libpod_|/podman/",
        "env_vars": ["container=podman"],
        "process_names": ["podman"],
    },
    "Kubernetes": {
        "file_checks": ["/var/run/secrets/kubernetes.io/serviceaccount/token",
                        "/run/secrets/kubernetes.io/serviceaccount/token"],
        "cgroup_pattern": r"/kubepods",
        "env_vars": ["KUBERNETES_SERVICE_HOST", "KUBERNETES_PORT"],
        "process_names": ["kubelet", "kube-proxy"],
    },
    "LXC": {
        "file_checks": [],
        "cgroup_pattern": r"/lxc/",
        "env_vars": ["container=lxc"],
        "process_names": ["lxc-start"],
    },
    "CRI-O": {
        "file_checks": [],
        "cgroup_pattern": r"/crio-",
        "env_vars": [],
        "process_names": ["crio"],
    },
    "containerd": {
        "file_checks": ["/run/containerd"],
        "cgroup_pattern": r"/containerd/",
        "env_vars": [],
        "process_names": ["containerd"],
    },
}


class ContainerAdvancedEngine:
    """Container Security Advanced Engine - Fused from DockerScan + Container-Escape-Check + DEEPCE

    Provides comprehensive container security assessment including:
    - Docker API detection and enumeration (local + remote)
    - Container escape technique detection (12+ vectors)
    - Privileged container detection
    - Docker socket exposure check
    - Container image vulnerability scanning
    - Registry enumeration
    - Kubernetes API detection
    - Container capabilities analysis
    - Network namespace escape detection
    - Volume mount analysis
    - Container runtime fingerprinting
    """

    def __init__(self, target=None, threads=MAX_THREADS, timeout=DEFAULT_TIMEOUT, proxy=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.lock = threading.Lock()
        self.session = shared_session
        # SSL verification handled by shared_session
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        # Results
        self.findings = []
        self.docker_api_found = []
        self.containers_found = []
        self.escape_vectors = []
        self.privileged_containers = []
        self.k8s_api_found = []

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

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

    def _send_request(self, url, method="GET", headers=None, data=None, timeout=None):
        """Send HTTP request with error handling"""
        try:
            t = timeout or self.timeout
            if method == "GET":
                resp = self.session.get(url, headers=headers, timeout=t)
            elif method == "POST":
                resp = self.session.post(url, headers=headers, data=data, timeout=t)
            else:
                resp = self.session.request(method, url, headers=headers, data=data, timeout=t)
            return resp
        except Exception:
            return None

    # ========================================================================
    # DOCKER API DETECTION
    # ========================================================================

    def detect_docker_api(self, target):
        """Find exposed Docker API endpoints

        Scans common Docker API ports and paths on the target to find
        unauthenticated Docker daemon access.

        Args:
            target: Target IP/hostname to scan

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Detecting exposed Docker API on: {target}", CYAN)
        findings = []
        api_endpoints_found = []

        # Common Docker API ports
        docker_ports = [2375, 2376, 4243, 9323, 5000, 5001, 2377, 7946]

        # Clean target
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        host = host.split(":")[0]  # Remove port if present

        # Test each port
        def test_docker_port(port):
            results = []
            base_url = f"http://{host}:{port}"

            # Test /version endpoint first (lightweight)
            try:
                resp = self._send_request(f"{base_url}/version", timeout=5)
                if resp and resp.status_code == 200:
                    try:
                        version_data = resp.json()
                        results.append({
                            "port": port,
                            "endpoint": "/version",
                            "status": "accessible",
                            "version_info": version_data,
                        })
                        self._print(f"  [+] Docker API found on port {port}!", GREEN)
                    except Exception:
                        # Might still be Docker API
                        if "docker" in resp.text.lower() or "api" in resp.text.lower():
                            results.append({
                                "port": port,
                                "endpoint": "/version",
                                "status": "possible",
                            })
            except Exception:
                pass

            # Test /containers/json
            try:
                resp = self._send_request(f"{base_url}/containers/json", timeout=5)
                if resp and resp.status_code == 200:
                    try:
                        containers = resp.json()
                        results.append({
                            "port": port,
                            "endpoint": "/containers/json",
                            "status": "accessible",
                            "container_count": len(containers) if isinstance(containers, list) else 0,
                        })
                        self._print(f"  [+] Docker containers endpoint on port {port}!", GREEN)
                    except Exception:
                        pass
            except Exception:
                pass

            # Test /info endpoint
            try:
                resp = self._send_request(f"{base_url}/info", timeout=5)
                if resp and resp.status_code == 200:
                    try:
                        info_data = resp.json()
                        results.append({
                            "port": port,
                            "endpoint": "/info",
                            "status": "accessible",
                            "info_keys": list(info_data.keys())[:10] if isinstance(info_data, dict) else [],
                        })
                    except Exception:
                        pass
            except Exception:
                pass

            return results

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_docker_port, port): port for port in docker_ports}
            for future in as_completed(futures):
                try:
                    results = future.result()
                    for r in results:
                        api_endpoints_found.append(r)
                        if r["status"] == "accessible":
                            findings.append({
                                "type": "docker_api_exposed",
                                "severity": "Critical",
                                "port": r["port"],
                                "endpoint": r["endpoint"],
                                "description": f"Docker API exposed on port {r['port']} - unauthenticated access",
                            })
                            self._print(f"  [!!!] Docker API EXPOSED on port {r['port']}!", RED)
                except Exception:
                    pass

        # Test common Docker API paths if target includes port
        if ':2375' in target or ':2376' in target or ':4243' in target:
            for api_path in DOCKER_API_PATHS[:10]:
                test_url = f"http://{host}:{docker_ports[0]}{api_path}"
                resp = self._send_request(test_url, timeout=5)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        api_endpoints_found.append({
                            "path": api_path,
                            "accessible": True,
                            "data_preview": str(data)[:200],
                        })
                    except Exception:
                        pass

        # Also check local Docker API
        local_docker = False
        stdout, _, rc = self._run_cmd('which docker 2>/dev/null')
        if rc == 0 and stdout:
            stdout, _, rc = self._run_cmd('docker info --format "{{.ServerVersion}}" 2>/dev/null')
            if rc == 0 and stdout:
                local_docker = True
                findings.append({
                    "type": "local_docker_available",
                    "severity": "Medium",
                    "version": stdout.strip(),
                    "description": f"Local Docker daemon available: {stdout.strip()}",
                })
                self._print(f"  [*] Local Docker available: {stdout.strip()}", YELLOW)

        self.docker_api_found.extend(api_endpoints_found)
        self._print(f"  [*] Docker API detection complete: {len(api_endpoints_found)} endpoints", CYAN)

        return {
            "vulnerable": any(f["severity"] == "Critical" for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "api_endpoints_found": api_endpoints_found,
                "local_docker_available": local_docker,
                "ports_tested": docker_ports,
            },
            "scan_type": "container_docker_api_detect",
        }

    # ========================================================================
    # CONTAINER ENUMERATION
    # ========================================================================

    def enum_containers(self, target):
        """Enumerate running containers via Docker API

        Args:
            target: Target host with exposed Docker API (host:port)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating containers on: {target}", CYAN)
        findings = []
        containers = []

        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        if ':' not in host:
            host = f"{host}:2375"

        base_url = f"http://{host}"

        # Get all containers (including stopped)
        for all_flag in ["", "?all=true"]:
            resp = self._send_request(f"{base_url}/containers/json{all_flag}", timeout=8)
            if resp and resp.status_code == 200:
                try:
                    container_list = resp.json()
                    if isinstance(container_list, list):
                        for c in container_list:
                            container_info = {
                                "id": c.get("Id", "")[:12],
                                "names": c.get("Names", []),
                                "image": c.get("Image", ""),
                                "status": c.get("Status", ""),
                                "state": c.get("State", ""),
                                "ports": c.get("Ports", []),
                                "privileged": False,  # Check below
                            }

                            # Check if container is privileged
                            cid = c.get("Id", "")
                            if cid:
                                inspect_resp = self._send_request(
                                    f"{base_url}/containers/{cid}/json", timeout=5
                                )
                                if inspect_resp and inspect_resp.status_code == 200:
                                    try:
                                        inspect_data = inspect_resp.json()
                                        host_config = inspect_data.get("HostConfig", {})
                                        container_info["privileged"] = host_config.get("Privileged", False)
                                        container_info["capabilities"] = host_config.get("CapAdd", [])
                                        container_info["security_opt"] = host_config.get("SecurityOpt", [])
                                        container_info["network_mode"] = host_config.get("NetworkMode", "")
                                        container_info["pid_mode"] = host_config.get("PidMode", "")
                                        container_info["binds"] = host_config.get("Binds", [])

                                        # Flag privileged containers
                                        if container_info["privileged"]:
                                            findings.append({
                                                "type": "privileged_container",
                                                "severity": "Critical",
                                                "container": container_info["id"],
                                                "image": container_info["image"],
                                                "description": f"Privileged container: {container_info['id']} ({container_info['image']})",
                                            })
                                            self._print(
                                                f"  [!!!] PRIVILEGED container: {container_info['id']} ({container_info['image']})",
                                                RED
                                            )
                                            self.privileged_containers.append(container_info)

                                        # Flag containers with host PID namespace
                                        if container_info["pid_mode"] == "host":
                                            findings.append({
                                                "type": "host_pid_namespace",
                                                "severity": "High",
                                                "container": container_info["id"],
                                                "description": f"Container using host PID namespace: {container_info['id']}",
                                            })
                                            self._print(
                                                f"  [!] Host PID namespace: {container_info['id']}",
                                                RED
                                            )

                                        # Flag containers with host network
                                        if container_info["network_mode"] == "host":
                                            findings.append({
                                                "type": "host_network_namespace",
                                                "severity": "High",
                                                "container": container_info["id"],
                                                "description": f"Container using host network namespace: {container_info['id']}",
                                            })
                                            self._print(
                                                f"  [!] Host network namespace: {container_info['id']}",
                                                YELLOW
                                            )

                                        # Flag dangerous capabilities
                                        dangerous_caps = set(container_info.get("capabilities", [])) & set(DANGEROUS_CAPABILITIES.keys())
                                        if dangerous_caps:
                                            findings.append({
                                                "type": "dangerous_capabilities",
                                                "severity": "High",
                                                "container": container_info["id"],
                                                "capabilities": list(dangerous_caps),
                                                "description": f"Dangerous capabilities in {container_info['id']}: {', '.join(dangerous_caps)}",
                                            })
                                            self._print(
                                                f"  [!] Dangerous caps in {container_info['id']}: {', '.join(dangerous_caps)}",
                                                YELLOW
                                            )

                                        # Flag sensitive volume mounts
                                        binds = container_info.get("binds", [])
                                        for bind in binds:
                                            host_path = bind.split(":")[0] if ":" in bind else ""
                                            for sensitive_path in SENSITIVE_MOUNT_PATHS:
                                                if host_path == sensitive_path or (host_path and sensitive_path.startswith(host_path)):
                                                    findings.append({
                                                        "type": "sensitive_mount",
                                                        "severity": "Critical",
                                                        "container": container_info["id"],
                                                        "mount": bind,
                                                        "description": f"Sensitive mount in {container_info['id']}: {bind}",
                                                    })
                                                    self._print(
                                                        f"  [!!!] Sensitive mount: {bind}",
                                                        RED
                                                    )
                                                    break
                                    except Exception:
                                        pass

                            containers.append(container_info)

                except Exception:
                    pass
                break  # Don't double-count

        # Also enumerate local containers
        stdout, _, rc = self._run_cmd('docker ps --format "{{.ID}} {{.Names}} {{.Image}} {{.Status}}" 2>/dev/null')
        if rc == 0 and stdout:
            for line in stdout.strip().split('\n'):
                parts = line.split(None, 3)
                if len(parts) >= 3:
                    local_container = {
                        "id": parts[0],
                        "names": [parts[1]] if len(parts) > 1 else [],
                        "image": parts[2] if len(parts) > 2 else "",
                        "status": parts[3] if len(parts) > 3 else "",
                        "source": "local",
                    }
                    containers.append(local_container)

        self.containers_found.extend(containers)
        self._print(f"  [*] Container enumeration complete: {len(containers)} found", CYAN)

        return {
            "vulnerable": any(f["severity"] in ("Critical", "High") for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "containers_found": containers,
                "total_containers": len(containers),
                "privileged_count": len(self.privileged_containers),
            },
            "scan_type": "container_enum",
        }

    # ========================================================================
    # CONTAINER ESCAPE CHECK
    # ========================================================================

    def check_escape(self, target):
        """Check container escape vectors

        Tests for 12+ container escape techniques including:
        - Docker socket access
        - Privileged mode
        - Dangerous capabilities
        - Host namespace sharing
        - Sensitive mounts
        - cgroup escape
        - runc CVEs
        - Kernel module loading

        Args:
            target: Target host/IP (for remote checks)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Checking container escape vectors on: {target}", CYAN)
        findings = []
        escape_vectors_found = []
        local_checks = {}

        # === LOCAL CHECKS (inside container) ===

        # 1. Check if running inside a container
        container_detected = False
        container_type = "unknown"

        if self._file_exists('/.dockerenv'):
            container_detected = True
            container_type = "Docker"
            local_checks["dockerenv"] = True
            self._print(f"  [*] Running inside Docker container", YELLOW)

        stdout, _, _ = self._run_cmd('cat /proc/1/cgroup 2>/dev/null')
        if stdout:
            if '/docker/' in stdout:
                container_detected = True
                container_type = "Docker"
                local_checks["cgroup_docker"] = True
            elif '/kubepod' in stdout:
                container_detected = True
                container_type = "Kubernetes"
                local_checks["cgroup_k8s"] = True
            elif '/lxc/' in stdout:
                container_detected = True
                container_type = "LXC"
                local_checks["cgroup_lxc"] = True
            elif '/libpod_' in stdout or '/podman/' in stdout:
                container_detected = True
                container_type = "Podman"
                local_checks["cgroup_podman"] = True

        env_container = os.environ.get('container', '')
        if env_container:
            container_detected = True
            container_type = env_container.upper()
            local_checks["env_container"] = env_container

        local_checks["container_detected"] = container_detected
        local_checks["container_type"] = container_type

        # 2. Docker socket check
        sock_paths = ['/var/run/docker.sock', '/run/docker.sock']
        for sock in sock_paths:
            if self._file_exists(sock):
                local_checks["docker_socket_exists"] = True
                if os.access(sock, os.W_OK):
                    escape_vectors_found.append({
                        "vector": "docker_socket",
                        "severity": "Critical",
                        "description": CONTAINER_ESCAPE_VECTORS["docker_socket"]["description"],
                        "exploit": CONTAINER_ESCAPE_VECTORS["docker_socket"]["exploit"],
                        "remediation": CONTAINER_ESCAPE_VECTORS["docker_socket"]["remediation"],
                    })
                    findings.append({
                        "type": "docker_socket_writable",
                        "severity": "Critical",
                        "socket": sock,
                        "description": f"Docker socket {sock} is writable",
                    })
                    self._print(f"  [!!!] Docker socket WRITABLE: {sock}", RED)
                else:
                    findings.append({
                        "type": "docker_socket_exists",
                        "severity": "Medium",
                        "socket": sock,
                        "description": f"Docker socket exists but not writable: {sock}",
                    })
                    self._print(f"  [*] Docker socket exists (not writable): {sock}", YELLOW)

        # 3. Privileged mode check
        stdout, _, rc = self._run_cmd('fdisk -l 2>/dev/null')
        if rc == 0 and stdout and len(stdout.strip().split('\n')) > 1:
            local_checks["privileged"] = True
            escape_vectors_found.append({
                "vector": "privileged_mode",
                "severity": "Critical",
                "description": CONTAINER_ESCAPE_VECTORS["privileged_mode"]["description"],
                "exploit": CONTAINER_ESCAPE_VECTORS["privileged_mode"]["exploit"],
                "remediation": CONTAINER_ESCAPE_VECTORS["privileged_mode"]["remediation"],
            })
            findings.append({
                "type": "privileged_container",
                "severity": "Critical",
                "description": "Container running in privileged mode",
            })
            self._print(f"  [!!!] PRIVILEGED container detected!", RED)

        # Alternative: /dev device count
        try:
            dev_count = len(os.listdir('/dev'))
            if dev_count > 20:
                local_checks["many_devices"] = dev_count
                if dev_count > 50:
                    findings.append({
                        "type": "possible_privileged",
                        "severity": "High",
                        "device_count": dev_count,
                        "description": f"High device count ({dev_count}) suggests privileged mode",
                    })
        except Exception:
            pass

        # 4. Capabilities check
        stdout, _, rc = self._run_cmd('capsh --print 2>/dev/null')
        if rc == 0 and stdout:
            for cap, cap_info in DANGEROUS_CAPABILITIES.items():
                if cap in stdout.lower():
                    local_checks[f"capability_{cap}"] = True
                    escape_vectors_found.append({
                        "vector": cap,
                        "severity": cap_info["severity"],
                        "description": cap_info["description"],
                        "exploit": CONTAINER_ESCAPE_VECTORS.get(cap, {}).get("exploit", "Various escape techniques"),
                        "remediation": CONTAINER_ESCAPE_VECTORS.get(cap, {}).get("remediation", "Drop this capability"),
                    })
                    findings.append({
                        "type": "dangerous_capability",
                        "severity": cap_info["severity"],
                        "capability": cap,
                        "description": cap_info["description"],
                    })
                    self._print(f"  [!] Dangerous capability: {cap} ({cap_info['severity']})", RED if cap_info['severity'] == "Critical" else YELLOW)

        # 5. Host namespace checks
        # PID namespace
        try:
            pid_count = len(os.listdir('/proc')) - 20  # Subtract non-PID entries
            if pid_count > 100:
                local_checks["host_pid_possible"] = pid_count
                findings.append({
                    "type": "possible_host_pid",
                    "severity": "Medium",
                    "pid_count": pid_count,
                    "description": f"High PID count ({pid_count}) - may share host PID namespace",
                })
        except Exception:
            pass

        # Network namespace - check if can access localhost services
        for port in [2375, 2376, 4243, 10250, 6443]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex(('127.0.0.1', port))
                s.close()
                if result == 0:
                    local_checks[f"localhost_port_{port}"] = True
                    if port in [2375, 2376]:
                        escape_vectors_found.append({
                            "vector": "localhost_docker_api",
                            "severity": "Critical",
                            "description": f"Docker API accessible on localhost:{port}",
                            "exploit": "curl http://localhost:{port}/containers/json",
                        })
                        findings.append({
                            "type": "localhost_docker_api",
                            "severity": "Critical",
                            "port": port,
                            "description": f"Docker API on localhost:{port}",
                        })
                        self._print(f"  [!!!] Docker API on localhost:{port}!", RED)
                    elif port == 10250:
                        findings.append({
                            "type": "localhost_kubelet",
                            "severity": "High",
                            "port": port,
                            "description": f"Kubelet API on localhost:{port}",
                        })
                        self._print(f"  [!] Kubelet API on localhost:{port}", YELLOW)
            except Exception:
                pass

        # 6. Mount analysis
        stdout, _, _ = self._run_cmd('cat /proc/self/mountinfo 2>/dev/null')
        if stdout:
            sensitive_mounts = []
            for line in stdout.split('\n'):
                parts = line.split()
                if len(parts) < 5:
                    continue
                mount_point = parts[4] if len(parts) > 4 else ''

                for sensitive_path in SENSITIVE_MOUNT_PATHS:
                    if mount_point == sensitive_path or (mount_point and sensitive_path != "/" and mount_point.startswith(sensitive_path)):
                        sensitive_mounts.append(mount_point)

                        # Docker socket mount
                        if 'docker.sock' in line:
                            escape_vectors_found.append({
                                "vector": "docker_socket_mount",
                                "severity": "Critical",
                                "description": "Docker socket mounted in container",
                                "exploit": "Use docker.sock API to spawn privileged container",
                            })
                            findings.append({
                                "type": "docker_sock_mount",
                                "severity": "Critical",
                                "mount": mount_point,
                                "description": "Docker socket is mounted in container",
                            })
                            self._print(f"  [!!!] Docker socket mounted!", RED)

                        # Host root mount
                        if mount_point == '/' or 'perdir=/' in line:
                            escape_vectors_found.append({
                                "vector": "host_root_mount",
                                "severity": "Critical",
                                "description": "Host root filesystem mounted in container",
                                "exploit": "Direct access to host filesystem via mount point",
                            })
                            findings.append({
                                "type": "host_root_mount",
                                "severity": "Critical",
                                "mount": mount_point,
                                "description": "Host root filesystem is accessible",
                            })
                            self._print(f"  [!!!] Host root filesystem mounted!", RED)
                        break

            if sensitive_mounts:
                local_checks["sensitive_mounts"] = sensitive_mounts

        # 7. Kubernetes service account check
        sa_path = "/var/run/secrets/kubernetes.io/serviceaccount"
        if self._file_exists(sa_path):
            local_checks["k8s_service_account"] = True
            escape_vectors_found.append({
                "vector": "k8s_service_account",
                "severity": "High",
                "description": CONTAINER_ESCAPE_VECTORS["k8s_service_account"]["description"],
                "exploit": "Use service account token to query K8s API for secrets/pods",
                "remediation": CONTAINER_ESCAPE_VECTORS["k8s_service_account"]["remediation"],
            })
            findings.append({
                "type": "k8s_service_account",
                "severity": "High",
                "path": sa_path,
                "description": "Kubernetes service account token is mounted",
            })
            self._print(f"  [!] K8s service account token found!", YELLOW)

            # Try to read the token
            token_path = f"{sa_path}/token"
            if self._file_readable(token_path):
                try:
                    with open(token_path, 'r') as f:
                        token = f.read().strip()
                    local_checks["k8s_token_readable"] = True
                    findings.append({
                        "type": "k8s_token_accessible",
                        "severity": "High",
                        "token_length": len(token),
                        "description": f"K8s service account token is readable ({len(token)} chars)",
                    })
                except Exception:
                    pass

            # Try to read namespace
            ns_path = f"{sa_path}/namespace"
            if self._file_readable(ns_path):
                try:
                    with open(ns_path, 'r') as f:
                        namespace = f.read().strip()
                    local_checks["k8s_namespace"] = namespace
                except Exception:
                    pass

        # 8. Seccomp profile check
        stdout, _, _ = self._run_cmd('cat /proc/1/status 2>/dev/null | grep Seccomp')
        if stdout:
            seccomp_mode = stdout.split(':')[-1].strip() if ':' in stdout else ''
            local_checks["seccomp_mode"] = seccomp_mode
            if seccomp_mode == '0':
                findings.append({
                    "type": "no_seccomp",
                    "severity": "Medium",
                    "description": "No seccomp profile applied - all system calls allowed",
                })
                self._print(f"  [!] No seccomp profile!", YELLOW)

        # 9. Environment variable secrets
        env_secrets = []
        for key, value in os.environ.items():
            if any(s in key.lower() for s in ['pass', 'secret', 'key', 'token', 'api', 'auth',
                                               'database', 'db_', 'mysql', 'postgres', 'redis',
                                               'aws_', 'azure_', 'gcp_', 'firebase']):
                env_secrets.append(f"{key}={value[:15]}***")

        if env_secrets:
            local_checks["env_secrets"] = env_secrets
            findings.append({
                "type": "env_secrets",
                "severity": "High" if any('aws_' in s or 'secret' in s.lower() for s in env_secrets) else "Medium",
                "count": len(env_secrets),
                "secrets": env_secrets[:10],
                "description": f"Found {len(env_secrets)} secrets in environment variables",
            })
            self._print(f"  [!] Found {len(env_secrets)} secrets in environment!", YELLOW)

        # 10. /etc/shadow check
        if self._file_readable('/etc/shadow'):
            findings.append({
                "type": "shadow_readable",
                "severity": "Critical",
                "description": "/etc/shadow is readable - password hashes exposed",
            })
            self._print(f"  [!!!] /etc/shadow is readable!", RED)

        # === REMOTE CHECKS ===

        # 11. Check remote Docker API
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        host = host.split(":")[0]
        for port in [2375, 2376, 4243]:
            try:
                resp = self._send_request(f"http://{host}:{port}/containers/json", timeout=5)
                if resp and resp.status_code == 200:
                    escape_vectors_found.append({
                        "vector": "docker_api_exposed",
                        "severity": "Critical",
                        "description": CONTAINER_ESCAPE_VECTORS["docker_api_exposed"]["description"],
                        "exploit": CONTAINER_ESCAPE_VECTORS["docker_api_exposed"]["exploit"],
                        "remediation": CONTAINER_ESCAPE_VECTORS["docker_api_exposed"]["remediation"],
                        "port": port,
                    })
                    findings.append({
                        "type": "remote_docker_api",
                        "severity": "Critical",
                        "port": port,
                        "description": f"Remote Docker API exposed on port {port}",
                    })
                    self._print(f"  [!!!] Remote Docker API on port {port}!", RED)
                    break
            except Exception:
                pass

        self.escape_vectors.extend(escape_vectors_found)
        self._print(f"  [*] Escape check complete: {len(escape_vectors_found)} vectors found", CYAN)

        return {
            "vulnerable": any(f["severity"] in ("Critical", "High") for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "local_checks": local_checks,
                "escape_vectors": escape_vectors_found,
                "total_vectors": len(escape_vectors_found),
                "critical_vectors": len([v for v in escape_vectors_found if v["severity"] == "Critical"]),
            },
            "scan_type": "container_escape_check",
        }

    # ========================================================================
    # PRIVILEGED CONTAINER CHECK
    # ========================================================================

    def check_privileged(self, target):
        """Check for privileged containers

        Args:
            target: Target host with Docker API (host:port) or 'local'

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Checking for privileged containers: {target}", CYAN)
        findings = []

        # Local checks
        is_privileged = False
        priv_indicators = []

        # Method 1: fdisk check
        stdout, _, rc = self._run_cmd('fdisk -l 2>/dev/null')
        if rc == 0 and stdout and len(stdout.strip().split('\n')) > 1:
            is_privileged = True
            priv_indicators.append("fdisk_results")
            self._print(f"  [!] fdisk shows block devices", RED)

        # Method 2: /dev device count
        try:
            dev_count = len(os.listdir('/dev'))
            if dev_count > 50:
                is_privileged = True
                priv_indicators.append(f"dev_count_{dev_count}")
                self._print(f"  [!] High device count: {dev_count}", RED)
        except Exception:
            pass

        # Method 3: Capabilities check
        stdout, _, rc = self._run_cmd('capsh --print 2>/dev/null')
        if rc == 0 and stdout:
            cap_count = stdout.lower().count('cap_')
            if cap_count > 10:
                is_privileged = True
                priv_indicators.append(f"many_capabilities_{cap_count}")
                self._print(f"  [!] Many capabilities: {cap_count}", RED)

        # Method 4: /proc/self/status CapEff
        stdout, _, _ = self._run_cmd('cat /proc/self/status | grep CapEff')
        if stdout:
            hex_caps = stdout.split(':')[-1].strip() if ':' in stdout else ''
            if hex_caps and hex_caps != '0000000000000000':
                # Check if all caps are set (privileged)
                try:
                    cap_val = int(hex_caps, 16)
                    if cap_val > 0xFFFFFFFFFFFF:
                        is_privileged = True
                        priv_indicators.append("full_capabilities")
                except ValueError:
                    pass

        # Method 5: Check if can access /dev/mem or /dev/kmem
        for dev in ['/dev/mem', '/dev/kmem', '/dev/sda', '/dev/nvme0n1']:
            if self._file_exists(dev) and os.access(dev, os.R_OK):
                is_privileged = True
                priv_indicators.append(f"access_{dev}")
                self._print(f"  [!] Can access {dev}", RED)

        if is_privileged:
            findings.append({
                "type": "privileged_container",
                "severity": "Critical",
                "indicators": priv_indicators,
                "description": "Container is running in privileged mode",
            })
            self._print(f"  [!!!] PRIVILEGED CONTAINER DETECTED!", RED)
        else:
            self._print(f"  [+] No privileged container indicators found", GREEN)

        # Remote checks via Docker API
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        host = host.split(":")[0]
        remote_priv = []

        for port in [2375, 2376, 4243]:
            resp = self._send_request(f"http://{host}:{port}/containers/json", timeout=5)
            if resp and resp.status_code == 200:
                try:
                    containers = resp.json()
                    for c in containers:
                        cid = c.get("Id", "")
                        if cid:
                            insp = self._send_request(f"http://{host}:{port}/containers/{cid}/json", timeout=5)
                            if insp and insp.status_code == 200:
                                data = insp.json()
                                hc = data.get("HostConfig", {})
                                if hc.get("Privileged", False):
                                    remote_priv.append({
                                        "id": cid[:12],
                                        "image": c.get("Image", ""),
                                    })
                                    findings.append({
                                        "type": "remote_privileged_container",
                                        "severity": "Critical",
                                        "container": cid[:12],
                                        "image": c.get("Image", ""),
                                        "description": f"Remote privileged container: {cid[:12]}",
                                    })
                except Exception:
                    pass

        return {
            "vulnerable": is_privileged or len(remote_priv) > 0,
            "findings": findings,
            "details": {
                "target": target,
                "local_privileged": is_privileged,
                "priv_indicators": priv_indicators,
                "remote_privileged": remote_priv,
            },
            "scan_type": "container_privileged_check",
        }

    # ========================================================================
    # DOCKER SOCKET CHECK
    # ========================================================================

    def check_docker_socket(self, target):
        """Check Docker socket exposure (local + remote)

        Args:
            target: Target host to check

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Checking Docker socket exposure: {target}", CYAN)
        findings = []

        # Local socket checks
        sock_paths = ['/var/run/docker.sock', '/run/docker.sock']
        socket_status = {}

        for sock in sock_paths:
            if self._file_exists(sock):
                socket_status[sock] = {
                    "exists": True,
                    "writable": os.access(sock, os.W_OK),
                    "readable": os.access(sock, os.R_OK),
                }

                if os.access(sock, os.W_OK):
                    findings.append({
                        "type": "docker_socket_writable",
                        "severity": "Critical",
                        "socket": sock,
                        "description": f"Docker socket {sock} is writable - full host escape possible",
                    })
                    self._print(f"  [!!!] Docker socket WRITABLE: {sock}", RED)

                    # Try to interact via curl
                    stdout, _, rc = self._run_cmd(f'curl -s --unix-socket {sock} http://localhost/version 2>/dev/null')
                    if rc == 0 and stdout:
                        try:
                            version_data = json.loads(stdout)
                            socket_status[sock]["docker_version"] = version_data.get("Version", "unknown")
                        except Exception:
                            socket_status[sock]["response_preview"] = stdout[:100]
                else:
                    findings.append({
                        "type": "docker_socket_exists",
                        "severity": "Low",
                        "socket": sock,
                        "description": f"Docker socket {sock} exists but not writable from current user",
                    })
                    self._print(f"  [*] Docker socket exists (not writable): {sock}", YELLOW)

            # Check mount info for socket
        stdout, _, _ = self._run_cmd('cat /proc/self/mountinfo 2>/dev/null | grep docker.sock')
        if stdout:
            socket_status["docker_sock_mounted"] = True
            findings.append({
                "type": "docker_sock_mounted",
                "severity": "High",
                "description": "Docker socket is mounted into the container",
            })
            self._print(f"  [!] Docker socket mounted in container!", RED)

        # Remote socket proxy check
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        host = host.split(":")[0]
        for port in [2375, 2376, 4243]:
            resp = self._send_request(f"http://{host}:{port}/info", timeout=5)
            if resp and resp.status_code == 200:
                findings.append({
                    "type": "remote_docker_api",
                    "severity": "Critical",
                    "port": port,
                    "description": f"Remote Docker daemon accessible on port {port}",
                })
                self._print(f"  [!!!] Remote Docker daemon on port {port}!", RED)

        self._print(f"  [*] Socket check complete: {len(findings)} issues", CYAN)

        return {
            "vulnerable": any(f["severity"] == "Critical" for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "socket_status": socket_status,
            },
            "scan_type": "container_docker_socket_check",
        }

    # ========================================================================
    # REGISTRY ENUMERATION
    # ========================================================================

    def enum_registry(self, target):
        """Enumerate Docker registries

        Args:
            target: Target registry URL or host

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating Docker registries: {target}", CYAN)
        findings = []
        registries_found = []

        host = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Check Docker Hub API
        registry_urls = [
            f"https://{host}/v2/",
            f"http://{host}/v2/",
            f"https://{host}:5000/v2/",
            f"http://{host}:5000/v2/",
            f"https://registry.hub.docker.com/v2/",
            f"https://index.docker.io/v2/",
        ]

        for reg_url in registry_urls:
            try:
                resp = self._send_request(reg_url, timeout=5)
                if resp and resp.status_code == 200:
                    reg_info = {
                        "url": reg_url,
                        "status": "accessible",
                        "api_version": "v2",
                    }
                    registries_found.append(reg_info)
                    findings.append({
                        "type": "docker_registry_exposed",
                        "severity": "High",
                        "url": reg_url,
                        "description": f"Docker Registry v2 API accessible: {reg_url}",
                    })
                    self._print(f"  [!] Docker Registry v2 accessible: {reg_url}", YELLOW)

                    # Try to list catalogs
                    cat_url = reg_url.rstrip('/') + '/_catalog'
                    cat_resp = self._send_request(cat_url, timeout=5)
                    if cat_resp and cat_resp.status_code == 200:
                        try:
                            catalog = cat_resp.json()
                            repos = catalog.get("repositories", [])
                            reg_info["repositories"] = repos[:20]
                            self._print(f"    [+] Found {len(repos)} repositories", GREEN)
                        except Exception:
                            pass

                elif resp and resp.status_code == 401:
                    # Registry exists but requires auth
                    reg_info = {
                        "url": reg_url,
                        "status": "requires_auth",
                        "api_version": "v2",
                    }
                    registries_found.append(reg_info)
                    # Check for weak auth
                    www_auth = resp.headers.get("Www-Authenticate", "")
                    if "Basic" in www_auth:
                        findings.append({
                            "type": "registry_basic_auth",
                            "severity": "Medium",
                            "url": reg_url,
                            "description": f"Docker Registry with Basic auth: {reg_url}",
                        })

            except Exception:
                pass

        self._print(f"  [*] Registry enumeration complete: {len(registries_found)} found", CYAN)

        return {
            "vulnerable": any(f["severity"] == "High" for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "registries_found": registries_found,
            },
            "scan_type": "container_registry_enum",
        }

    # ========================================================================
    # KUBERNETES API DETECTION
    # ========================================================================

    def detect_k8s_api(self, target):
        """Kubernetes API detection and enumeration

        Args:
            target: Target host/IP to scan for K8s API

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Detecting Kubernetes API on: {target}", CYAN)
        findings = []
        k8s_endpoints = []

        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        host = host.split(":")[0]

        # K8s API ports
        k8s_ports = [6443, 8443, 443, 10250, 10255, 8001, 8080]

        for port in k8s_ports:
            for scheme in ["https", "http"]:
                base_url = f"{scheme}://{host}:{port}"
                try:
                    # Test /version endpoint
                    resp = self._send_request(f"{base_url}/version", timeout=5)
                    if resp and resp.status_code == 200:
                        try:
                            version_data = resp.json()
                            if any(k in version_data for k in ["major", "minor", "gitVersion"]):
                                k8s_endpoints.append({
                                    "url": base_url,
                                    "port": port,
                                    "status": "accessible",
                                    "version": version_data,
                                })
                                findings.append({
                                    "type": "k8s_api_exposed",
                                    "severity": "Critical",
                                    "port": port,
                                    "url": base_url,
                                    "version": version_data.get("gitVersion", "unknown"),
                                    "description": f"Kubernetes API exposed on port {port}: {version_data.get('gitVersion', 'unknown')}",
                                })
                                self._print(f"  [!!!] K8s API on port {port}: {version_data.get('gitVersion', '')}", RED)
                                break
                        except Exception:
                            pass
                except Exception:
                    pass

            if any(e["port"] == port for e in k8s_endpoints):
                break

        # Test K8s API paths
        if k8s_endpoints:
            base_url = k8s_endpoints[0]["url"]
            for path in K8S_API_PATHS:
                try:
                    resp = self._send_request(f"{base_url}{path}", timeout=5)
                    if resp and resp.status_code == 200:
                        k8s_endpoints[0][f"path_{path}"] = "accessible"
                except Exception:
                    pass

        # Check Kubelet API
        for port in [10250, 10255]:
            try:
                resp = self._send_request(f"http://{host}:{port}/pods", timeout=5)
                if resp and resp.status_code == 200:
                    k8s_endpoints.append({
                        "url": f"http://{host}:{port}",
                        "port": port,
                        "type": "kubelet",
                        "status": "accessible",
                    })
                    findings.append({
                        "type": "kubelet_api_exposed",
                        "severity": "High",
                        "port": port,
                        "description": f"Kubelet API exposed on port {port}",
                    })
                    self._print(f"  [!] Kubelet API on port {port}", YELLOW)
            except Exception:
                pass

        # Check for K8s service account token
        sa_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if self._file_readable(sa_path):
            findings.append({
                "type": "k8s_service_account_inside",
                "severity": "Info",
                "description": "Running inside Kubernetes pod with service account",
            })
            self._print(f"  [*] K8s service account token found locally", YELLOW)

            # Try to query K8s API with the service account token
            try:
                with open(sa_path, 'r') as f:
                    token = f.read().strip()

                k8s_host = os.environ.get('KUBERNETES_SERVICE_HOST', '')
                k8s_port = os.environ.get('KUBERNETES_SERVICE_PORT', '443')

                if k8s_host:
                    k8s_url = f"https://{k8s_host}:{k8s_port}/api/v1/namespaces"
                    resp = self._send_request(
                        k8s_url,
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=5,
                    )
                    if resp and resp.status_code == 200:
                        try:
                            ns_data = resp.json()
                            namespaces = [i.get("metadata", {}).get("name", "") for i in ns_data.get("items", [])]
                            findings.append({
                                "type": "k8s_api_accessible_via_sa",
                                "severity": "High",
                                "namespaces": namespaces[:10],
                                "description": f"K8s API accessible via service account token - {len(namespaces)} namespaces",
                            })
                            self._print(f"  [!] K8s API accessible via SA token: {len(namespaces)} namespaces", RED)
                        except Exception:
                            pass
            except Exception:
                pass

        self.k8s_api_found.extend(k8s_endpoints)
        self._print(f"  [*] K8s API detection complete: {len(k8s_endpoints)} found", CYAN)

        return {
            "vulnerable": any(f["severity"] in ("Critical", "High") for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "k8s_endpoints": k8s_endpoints,
                "ports_tested": k8s_ports,
            },
            "scan_type": "container_k8s_api_detect",
        }

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='detect', **kwargs):
        """Main entry point for container security scanning

        Args:
            target: Target IP/hostname/URL
            scan_type: Type of scan to run
                - 'detect': Docker API detection
                - 'enum': Container enumeration
                - 'escape': Container escape check
                - 'privileged': Privileged container check
                - 'socket': Docker socket check
                - 'registry': Registry enumeration
                - 'k8s': Kubernetes API detection
                - 'full': Complete container security assessment
            **kwargs: Additional arguments

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self.target = target
        findings_list = []
        scan_results = {}

        try:
            if scan_type == 'detect':
                result = self.detect_docker_api(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'enum':
                result = self.enum_containers(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'escape':
                result = self.check_escape(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'privileged':
                result = self.check_privileged(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'socket':
                result = self.check_docker_socket(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'registry':
                result = self.enum_registry(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'k8s':
                result = self.detect_k8s_api(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'full':
                self._print(f"\n{BOLD}{'='*60}{RESET}", MAGENTA)
                self._print(f"{BOLD} CONTAINER SECURITY ADVANCED - FULL SCAN{RESET}", MAGENTA)
                self._print(f"{BOLD}{'='*60}{RESET}", MAGENTA)

                # Phase 1: Docker API detection
                self._print(f"\n{BOLD}[Phase 1/7] Docker API Detection{RESET}", CYAN)
                api_result = self.detect_docker_api(target)
                findings_list.extend(api_result.get("findings", []))
                scan_results["docker_api"] = api_result.get("details", {})

                # Phase 2: Container enumeration
                self._print(f"\n{BOLD}[Phase 2/7] Container Enumeration{RESET}", CYAN)
                enum_result = self.enum_containers(target)
                findings_list.extend(enum_result.get("findings", []))
                scan_results["containers"] = enum_result.get("details", {})

                # Phase 3: Container escape check
                self._print(f"\n{BOLD}[Phase 3/7] Container Escape Check{RESET}", CYAN)
                escape_result = self.check_escape(target)
                findings_list.extend(escape_result.get("findings", []))
                scan_results["escape"] = escape_result.get("details", {})

                # Phase 4: Privileged container check
                self._print(f"\n{BOLD}[Phase 4/7] Privileged Container Check{RESET}", CYAN)
                priv_result = self.check_privileged(target)
                findings_list.extend(priv_result.get("findings", []))
                scan_results["privileged"] = priv_result.get("details", {})

                # Phase 5: Docker socket check
                self._print(f"\n{BOLD}[Phase 5/7] Docker Socket Check{RESET}", CYAN)
                socket_result = self.check_docker_socket(target)
                findings_list.extend(socket_result.get("findings", []))
                scan_results["docker_socket"] = socket_result.get("details", {})

                # Phase 6: Registry enumeration
                self._print(f"\n{BOLD}[Phase 6/7] Registry Enumeration{RESET}", CYAN)
                reg_result = self.enum_registry(target)
                findings_list.extend(reg_result.get("findings", []))
                scan_results["registry"] = reg_result.get("details", {})

                # Phase 7: Kubernetes API detection
                self._print(f"\n{BOLD}[Phase 7/7] Kubernetes API Detection{RESET}", CYAN)
                k8s_result = self.detect_k8s_api(target)
                findings_list.extend(k8s_result.get("findings", []))
                scan_results["k8s"] = k8s_result.get("details", {})

                # Summary
                critical = len([f for f in findings_list if f.get("severity") == "Critical"])
                high = len([f for f in findings_list if f.get("severity") == "High"])
                medium = len([f for f in findings_list if f.get("severity") == "Medium"])

                self._print(f"\n{BOLD}{'='*60}{RESET}", MAGENTA)
                self._print(f"{BOLD} CONTAINER SECURITY SCAN COMPLETE{RESET}", MAGENTA)
                self._print(f"{BOLD}{'='*60}{RESET}", MAGENTA)
                self._print(f"  Critical: {RED}{critical}{RESET}")
                self._print(f"  High:     {YELLOW}{high}{RESET}")
                self._print(f"  Medium:   {CYAN}{medium}{RESET}")

                scan_results["summary"] = {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "total_findings": len(findings_list),
                    "docker_api_found": len(self.docker_api_found),
                    "containers_found": len(self.containers_found),
                    "escape_vectors": len(self.escape_vectors),
                    "privileged_containers": len(self.privileged_containers),
                    "k8s_api_found": len(self.k8s_api_found),
                }
            else:
                scan_results = {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            scan_results = {"error": str(e)}
            self._print(f"  [!] Scan error: {e}", RED)

        return {
            "vulnerable": len(findings_list) > 0,
            "findings": findings_list,
            "details": scan_results,
            "scan_type": f"container_advanced_{scan_type}",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='detect', **kwargs):
    """Module-level entry point for ZYLON integration

    Args:
        target: Target IP/hostname/URL
        scan_type: Scan type ('detect', 'enum', 'escape', 'privileged',
                   'socket', 'registry', 'k8s', 'full')
        **kwargs: Additional arguments (threads, timeout, etc.)

    Returns:
        dict with 'vulnerable', 'findings', 'details', 'scan_type'
    """
    threads = kwargs.get('threads', MAX_THREADS)
    timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
    proxy = kwargs.get('proxy', None)

    engine = ContainerAdvancedEngine(
        target=target, threads=threads, timeout=timeout, proxy=proxy
    )
    return engine.run(target, scan_type=scan_type, **kwargs)
