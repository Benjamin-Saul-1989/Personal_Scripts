"""
Docker Vulnerability Scanner
=============================
Connects to a remote Docker host via SSH and audits:
  - Image versions  (outdated / untagged / known-risky base images)
  - Exposed ports & network risks
  - Container misconfigurations  (privileged, root user, no limits, etc.)
  - Secrets leaking through environment variables

Usage
-----
    pip install paramiko requests
    python docker_vuln_scanner.py --host 192.168.1.10 --user ubuntu
    python docker_vuln_scanner.py --host myserver.com --user admin --key ~/.ssh/id_rsa --txt report.txt

SSH auth priority: --key  →  --password  →  SSH agent / ~/.ssh/id_rsa (auto)
"""

__version__ = "1.0.0"
__author__  = "Your Name"
__license__ = "MIT"

import argparse
import json
import os
import re
import sys
from datetime import datetime

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import requests
except ImportError:
    requests = None

# ── ANSI colours ───────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# Severity colours
SEV = {
    "CRITICAL": f"{BOLD}\033[95m[CRITICAL]{RESET}",   # magenta-bold
    "HIGH":     f"{BOLD}{RED}[HIGH]    {RESET}",
    "MEDIUM":   f"{BOLD}{YELLOW}[MEDIUM]  {RESET}",
    "LOW":      f"{BOLD}{GREEN}[LOW]     {RESET}",
    "INFO":     f"{BOLD}{CYAN}[INFO]    {RESET}",
}
SEV_PLAIN = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]    ",
    "MEDIUM":   "[MEDIUM]  ",
    "LOW":      "[LOW]     ",
    "INFO":     "[INFO]    ",
}

_W = 62

# ── Banner ─────────────────────────────────────────────────────────────────────
BANNER = (
    f"\n{CYAN}{'═' * _W}{RESET}\n"
    f"{CYAN}{BOLD}"
    f"  ██████╗  ██████╗  ██████╗██╗  ██╗███████╗██████╗ \n"
    f"  ██╔══██╗██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗\n"
    f"  ██║  ██║██║   ██║██║     █████╔╝ █████╗  ██████╔╝\n"
    f"  ██║  ██║██║   ██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗\n"
    f"  ██████╔╝╚██████╔╝╚██████╗██║  ██╗███████╗██║  ██║\n"
    f"  ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝\n"
    f"{RESET}"
    f"{CYAN}{'─' * _W}{RESET}\n"
    f"  {BOLD}{'Program':<14}{RESET}  Docker Vulnerability Scanner\n"
    f"  {BOLD}{'Version':<14}{RESET}  {__version__}\n"
    f"  {BOLD}{'Author':<14}{RESET}  {__author__}\n"
    f"  {BOLD}{'License':<14}{RESET}  {__license__}\n"
    f"  {BOLD}{'Transport':<14}{RESET}  Remote SSH → Docker CLI\n"
    f"  {BOLD}{'Checks':<14}{RESET}  Images · Ports · Misconfigs · Secrets\n"
    f"  {BOLD}{'Usage':<14}{RESET}  python docker_vuln_scanner.py --host <ip> --user <user>\n"
    f"{CYAN}{'═' * _W}{RESET}\n"
)

# ── Helpers ────────────────────────────────────────────────────────────────────

def section(title: str) -> None:
    print(f"\n{CYAN}{'─' * _W}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─' * _W}{RESET}")


def finding(severity: str, msg: str, detail: str = "") -> dict:
    """Print a colour-coded finding and return a dict for the report."""
    tag = SEV.get(severity, SEV["INFO"])
    print(f"  {tag}  {msg}")
    if detail:
        print(f"           {DIM}{detail}{RESET}")
    return {"severity": severity, "message": msg, "detail": detail}


def info(msg: str) -> None:
    print(f"  {CYAN}·{RESET}  {msg}")


# ── SSH connection ─────────────────────────────────────────────────────────────

def ssh_connect(host: str, user: str, port: int,
                key_path: str, password: str) -> "paramiko.SSHClient | None":
    if paramiko is None:
        print(f"{RED}paramiko not installed.  Run: pip install paramiko{RESET}")
        sys.exit(1)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs = dict(hostname=host, port=port, username=user, timeout=15)

    if key_path:
        connect_kwargs["key_filename"] = os.path.expanduser(key_path)
    elif password:
        connect_kwargs["password"] = password
    else:
        # Try agent / default keys automatically
        connect_kwargs["look_for_keys"] = True
        connect_kwargs["allow_agent"]   = True

    try:
        client.connect(**connect_kwargs)
        print(f"  {GREEN}✔{RESET}  Connected to {BOLD}{user}@{host}:{port}{RESET}")
        return client
    except paramiko.AuthenticationException:
        print(f"{RED}SSH authentication failed for {user}@{host}{RESET}")
    except paramiko.SSHException as exc:
        print(f"{RED}SSH error: {exc}{RESET}")
    except Exception as exc:
        print(f"{RED}Connection failed: {exc}{RESET}")
    return None


def ssh_run(client: "paramiko.SSHClient", cmd: str) -> str:
    """Run a command over SSH and return stdout as a string."""
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=30)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        return out
    except Exception:
        return ""


# ── Check 1 – Image versions ───────────────────────────────────────────────────

# Base images with known risky defaults
RISKY_BASES = {
    "latest":    ("MEDIUM", "Using ':latest' tag — image version is unpinned and may change unexpectedly"),
    "alpine":    ("LOW",    "Alpine is minimal but ensure packages are patched"),
}
OLD_BASE_PATTERNS = [
    (r"ubuntu:1[0-8]\.", "HIGH",   "Old Ubuntu LTS — likely contains unpatched CVEs"),
    (r"debian:[0-8]\b",  "HIGH",   "Old Debian release — end of life"),
    (r"centos:[0-7]\b",  "HIGH",   "CentOS 7 or older — EOL or approaching EOL"),
    (r"node:[0-9]\b",    "HIGH",   "Old Node.js major version — likely EOL"),
    (r"python:2\.",      "HIGH",   "Python 2 is EOL since Jan 2020"),
    (r"python:3\.[0-6]", "MEDIUM", "Python 3.6 or older — EOL"),
]

def check_images(client, findings: list) -> list:
    section("Image Version Audit")
    raw = ssh_run(client, "docker images --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.CreatedSince}}|{{.Size}}'")
    if not raw:
        finding("INFO", "No images found or docker not accessible")
        return findings

    images = []
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) < 4:
            continue
        ref, img_id, created, size = parts[0], parts[1], parts[2], parts[3]
        info(f"Image  {BOLD}{ref:<45}{RESET}  {DIM}{created}  {size}{RESET}")
        images.append({"ref": ref, "id": img_id, "created": created, "size": size})

        tag = ref.split(":")[-1] if ":" in ref else "latest"

        # Untagged / latest
        if tag == "latest" or tag == "<none>":
            findings.append(finding("MEDIUM",
                f"{ref} — unpinned ':latest' tag",
                "Pin images to a specific digest or version tag for reproducibility."))

        # EOL / risky base patterns
        for pattern, sev, msg in OLD_BASE_PATTERNS:
            if re.search(pattern, ref, re.IGNORECASE):
                findings.append(finding(sev, f"{ref} — {msg}",
                    "Upgrade to a supported version and rebuild."))

    return findings


# ── Check 2 – Exposed ports & networks ────────────────────────────────────────

SENSITIVE_PORTS = {
    22:    ("LOW",      "SSH exposed — ensure key-auth only, no password auth"),
    23:    ("CRITICAL", "Telnet exposed — plaintext protocol, replace with SSH"),
    2375:  ("CRITICAL", "Docker daemon exposed unencrypted (no TLS)"),
    2376:  ("HIGH",     "Docker TLS port exposed — verify client cert is required"),
    3306:  ("HIGH",     "MySQL/MariaDB port exposed to host network"),
    5432:  ("HIGH",     "PostgreSQL port exposed to host network"),
    6379:  ("HIGH",     "Redis exposed — Redis has no auth by default"),
    27017: ("HIGH",     "MongoDB exposed — often left without auth"),
    9200:  ("HIGH",     "Elasticsearch exposed — no auth by default"),
    5601:  ("MEDIUM",   "Kibana exposed — may reveal sensitive log data"),
    8080:  ("LOW",      "HTTP alt-port exposed — ensure no admin UI is accessible"),
    8443:  ("LOW",      "HTTPS alt-port exposed"),
    4243:  ("CRITICAL", "Legacy Docker daemon port — unauthenticated access"),
}

def check_ports(client, findings: list) -> list:
    section("Exposed Ports & Network Risks")

    # Container port mappings
    raw = ssh_run(client,
        "docker ps --format '{{.Names}}|{{.Ports}}|{{.Networks}}'")
    if not raw:
        finding("INFO", "No running containers found")
        return findings

    containers_seen = set()
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) < 3:
            continue
        name, ports_str, networks = parts[0], parts[1], parts[2]
        containers_seen.add(name)

        if not ports_str.strip():
            info(f"{name}  — no ports exposed")
            continue

        # Parse port mappings like 0.0.0.0:3306->3306/tcp
        for mapping in ports_str.split(","):
            mapping = mapping.strip()
            m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)->(\d+)", mapping)
            if not m:
                continue
            bind_ip, host_port, container_port = m.group(1), int(m.group(2)), int(m.group(3))

            bound_all = bind_ip == "0.0.0.0"
            sev_base, reason = SENSITIVE_PORTS.get(host_port,
                               SENSITIVE_PORTS.get(container_port, (None, None)))

            if sev_base and reason:
                sev = "CRITICAL" if (sev_base == "CRITICAL" and bound_all) else sev_base
                findings.append(finding(sev,
                    f"{name} → port {host_port} ({mapping.strip()})",
                    reason + (" [BOUND TO ALL INTERFACES]" if bound_all else "")))
            else:
                lvl = "MEDIUM" if bound_all else "LOW"
                findings.append(finding(lvl,
                    f"{name} → port {host_port} bound to {'0.0.0.0 (all interfaces)' if bound_all else bind_ip}",
                    "Consider binding to 127.0.0.1 unless external access is required."))

    # Host network mode
    raw_host = ssh_run(client,
        "docker ps --filter network=host --format '{{.Names}}'")
    for cname in raw_host.splitlines():
        if cname.strip():
            findings.append(finding("HIGH",
                f"{cname} — running in host network mode",
                "Host networking bypasses Docker's network isolation entirely."))

    return findings


# ── Check 3 – Container misconfigurations ─────────────────────────────────────

def check_misconfigs(client, findings: list) -> list:
    section("Container Misconfiguration Audit")

    raw = ssh_run(client, "docker ps -q")
    container_ids = [c.strip() for c in raw.splitlines() if c.strip()]

    if not container_ids:
        finding("INFO", "No running containers to inspect")
        return findings

    for cid in container_ids:
        inspect_raw = ssh_run(client, f"docker inspect {cid}")
        if not inspect_raw:
            continue
        try:
            data = json.loads(inspect_raw)[0]
        except (json.JSONDecodeError, IndexError):
            continue

        name       = data.get("Name", cid).lstrip("/")
        host_cfg   = data.get("HostConfig", {})
        cfg        = data.get("Config", {})
        state      = data.get("State", {})

        # Privileged mode
        if host_cfg.get("Privileged"):
            findings.append(finding("CRITICAL",
                f"{name} — running in PRIVILEGED mode",
                "Privileged containers have full host kernel capabilities. Remove --privileged."))

        # Running as root
        user = cfg.get("User", "")
        if not user or user in ("root", "0", "0:0"):
            findings.append(finding("HIGH",
                f"{name} — running as root (no USER set)",
                "Add a non-root USER in the Dockerfile or use --user flag."))

        # Dangerous capabilities
        cap_add = host_cfg.get("CapAdd") or []
        dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
        for cap in cap_add:
            if cap.upper() in dangerous_caps:
                findings.append(finding("HIGH",
                    f"{name} — dangerous capability: {cap}",
                    "Drop this capability unless strictly required."))

        # No memory limit
        mem = host_cfg.get("Memory", 0)
        if mem == 0:
            findings.append(finding("MEDIUM",
                f"{name} — no memory limit set",
                "Set --memory to prevent a single container from exhausting host RAM."))

        # No CPU limit
        cpu = host_cfg.get("NanoCpus", 0)
        if cpu == 0:
            findings.append(finding("LOW",
                f"{name} — no CPU limit set",
                "Set --cpus to prevent CPU starvation of other containers."))

        # Read-only root filesystem
        if not host_cfg.get("ReadonlyRootfs", False):
            findings.append(finding("LOW",
                f"{name} — root filesystem is writable",
                "Use --read-only to reduce attack surface if the app allows it."))

        # Restart policy
        restart = (host_cfg.get("RestartPolicy") or {}).get("Name", "no")
        if restart == "always":
            findings.append(finding("LOW",
                f"{name} — restart=always may auto-restart a compromised container",
                "Consider 'on-failure' with a max-retry count instead."))

        # Security options
        sec_opt = host_cfg.get("SecurityOpt") or []
        has_seccomp  = any("seccomp" in s for s in sec_opt)
        has_apparmor = any("apparmor" in s for s in sec_opt)
        if not has_seccomp:
            findings.append(finding("MEDIUM",
                f"{name} — no seccomp profile applied",
                "Apply a seccomp profile to restrict syscalls available to the container."))
        if not has_apparmor:
            findings.append(finding("LOW",
                f"{name} — no AppArmor profile applied",
                "An AppArmor profile adds MAC layer protection."))

        # PID namespace sharing
        if host_cfg.get("PidMode") == "host":
            findings.append(finding("CRITICAL",
                f"{name} — sharing host PID namespace",
                "The container can see and signal all host processes."))

        # IPC namespace sharing
        if host_cfg.get("IpcMode") in ("host", "shareable"):
            findings.append(finding("HIGH",
                f"{name} — sharing host IPC namespace",
                "Shared IPC allows cross-container and host memory access."))

        info(f"Inspected  {BOLD}{name}{RESET}")

    return findings


# ── Check 4 – Secrets in environment variables ─────────────────────────────────

SECRET_PATTERNS = [
    (r"(?i)(password|passwd|pwd)\s*=\s*.+",         "HIGH",     "Password found in env var"),
    (r"(?i)(secret|api_?key|apikey)\s*=\s*.+",      "HIGH",     "Secret/API key in env var"),
    (r"(?i)(token|auth_?token)\s*=\s*.+",           "HIGH",     "Auth token in env var"),
    (r"(?i)(aws_access_key_id)\s*=\s*.+",           "CRITICAL", "AWS Access Key ID exposed"),
    (r"(?i)(aws_secret_access_key)\s*=\s*.+",       "CRITICAL", "AWS Secret Access Key exposed"),
    (r"(?i)(database_url|db_url|db_uri)\s*=\s*.+",  "HIGH",     "Database URL (may contain creds)"),
    (r"(?i)(private_?key|rsa_?key)\s*=\s*.+",       "CRITICAL", "Private key material in env var"),
    (r"(?i)(stripe|twilio|sendgrid|slack).*key\s*=\s*.+", "HIGH", "Third-party service key exposed"),
    (r"(?i)(jwt_?secret|jwt_?key)\s*=\s*.+",        "HIGH",     "JWT secret in env var"),
    (r"(?i)(smtp_pass|mail_pass|email_pass)\s*=\s*.+","HIGH",   "Email password in env var"),
]

def _redact(val: str) -> str:
    """Show only first 4 chars + asterisks."""
    if "=" not in val:
        return val
    k, v = val.split("=", 1)
    redacted = v[:4] + "*" * max(4, len(v) - 4) if len(v) > 4 else "****"
    return f"{k}={redacted}"

def check_secrets(client, findings: list) -> list:
    section("Secrets / Environment Variable Audit")

    raw = ssh_run(client, "docker ps -q")
    container_ids = [c.strip() for c in raw.splitlines() if c.strip()]

    if not container_ids:
        finding("INFO", "No running containers to inspect")
        return findings

    for cid in container_ids:
        inspect_raw = ssh_run(client, f"docker inspect --format='{{{{.Name}}}}' {cid}")
        name = inspect_raw.lstrip("/").strip() or cid

        env_raw = ssh_run(client,
            f"docker inspect --format='{{{{range .Config.Env}}}}{{{{.}}}}|{{{{end}}}}' {cid}")
        env_vars = [e.strip() for e in env_raw.split("|") if e.strip()]

        found_any = False
        for env_var in env_vars:
            for pattern, sev, label in SECRET_PATTERNS:
                if re.search(pattern, env_var):
                    findings.append(finding(sev,
                        f"{name} — {label}",
                        f"Variable: {_redact(env_var)}  →  Use Docker secrets or a vault instead."))
                    found_any = True
                    break

        if not found_any:
            info(f"{BOLD}{name}{RESET} — no obvious secrets detected in env vars")

    return findings


# ── Severity summary ───────────────────────────────────────────────────────────

def print_summary(findings: list) -> dict:
    section("Scan Summary")
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts[sev]
        bar = "█" * min(n, 30)
        tag = SEV[sev]
        print(f"  {tag}  {bar} {n}")

    total = sum(counts.values())
    print(f"\n  {BOLD}Total findings:{RESET} {total}")

    if counts["CRITICAL"] > 0:
        print(f"\n  {RED}{BOLD}ACTION REQUIRED — {counts['CRITICAL']} critical issue(s) found!{RESET}")
    elif counts["HIGH"] > 0:
        print(f"\n  {YELLOW}{BOLD}High-severity issues detected — review and remediate promptly.{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}No critical or high issues found.{RESET}")

    print()
    return counts


# ── TXT report ─────────────────────────────────────────────────────────────────

def save_txt_report(host: str, findings: list, counts: dict, path: str) -> None:
    W = _W
    lines = []
    lines.append("=" * W)
    lines.append("  DOCKER VULNERABILITY SCANNER — REPORT")
    lines.append(f"  Version   : {__version__}")
    lines.append(f"  Host      : {host}")
    lines.append(f"  Generated : {datetime.utcnow().isoformat()} UTC")
    lines.append("=" * W)

    # Group findings by severity
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = [f for f in findings if f.get("severity") == sev]
        if not group:
            continue
        lines.append(f"\n{'─' * W}")
        lines.append(f"  {SEV_PLAIN[sev]}  ({len(group)} finding{'s' if len(group)!=1 else ''})")
        lines.append(f"{'─' * W}")
        for f in group:
            lines.append(f"  {SEV_PLAIN[sev]}  {f['message']}")
            if f.get("detail"):
                lines.append(f"           → {f['detail']}")

    lines.append(f"\n{'=' * W}")
    lines.append("  SUMMARY")
    lines.append(f"{'─' * W}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"  {SEV_PLAIN[sev]}  {counts.get(sev, 0)}")
    lines.append(f"  {'Total':<12}  {sum(counts.values())}")
    lines.append("=" * W + "\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\n{GREEN}{BOLD}TXT report saved  → {path}{RESET}")


# ── CLI entry point ────────────────────────────────────────────────────────────

def main() -> None:
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Docker Vulnerability Scanner — audits a remote Docker host over SSH"
    )
    parser.add_argument("--host",     required=True,  help="Remote host IP or hostname")
    parser.add_argument("--user",     default="root", help="SSH username (default: root)")
    parser.add_argument("--port",     default=22, type=int, help="SSH port (default: 22)")
    parser.add_argument("--key",      default="",     help="Path to SSH private key (e.g. ~/.ssh/id_rsa)")
    parser.add_argument("--password", default="",     help="SSH password (prefer key auth)")
    parser.add_argument("--txt",      default="",     help="Save plain-text report to this path")
    parser.add_argument("--skip-images",   action="store_true", help="Skip image version check")
    parser.add_argument("--skip-ports",    action="store_true", help="Skip port/network check")
    parser.add_argument("--skip-misconfig",action="store_true", help="Skip misconfiguration check")
    parser.add_argument("--skip-secrets",  action="store_true", help="Skip secrets/env-var check")
    args = parser.parse_args()

    print(f"{BOLD}Host:{RESET}  {CYAN}{args.user}@{args.host}:{args.port}{RESET}")
    print(f"{BOLD}Time:{RESET}  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}\n")

    # SSH connect
    section("SSH Connection")
    client = ssh_connect(args.host, args.user, args.port, args.key, args.password)
    if client is None:
        sys.exit(1)

    # Docker sanity check
    docker_version = ssh_run(client, "docker version --format '{{.Server.Version}}'")
    if not docker_version:
        print(f"{RED}Could not reach Docker daemon on remote host.{RESET}")
        print(f"{DIM}Ensure the SSH user has permission to run docker commands (e.g. is in the docker group).{RESET}")
        client.close()
        sys.exit(1)
    print(f"  {GREEN}✔{RESET}  Docker server version: {BOLD}{docker_version}{RESET}")

    findings: list[dict] = []

    if not args.skip_images:
        findings = check_images(client, findings)
    if not args.skip_ports:
        findings = check_ports(client, findings)
    if not args.skip_misconfig:
        findings = check_misconfigs(client, findings)
    if not args.skip_secrets:
        findings = check_secrets(client, findings)

    client.close()

    counts = print_summary(findings)

    if args.txt:
        save_txt_report(f"{args.user}@{args.host}:{args.port}", findings, counts, args.txt)


if __name__ == "__main__":
    main()
