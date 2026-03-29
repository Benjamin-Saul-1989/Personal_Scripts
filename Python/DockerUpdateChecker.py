"""
Usage
-----
    pip install paramiko requests
    python docker_update_checker.py --host 192.168.1.10 --user ubuntu
    python docker_update_checker.py --host myserver.com --user admin --key ~/.ssh/id_rsa
    python docker_update_checker.py --host 10.0.0.5   --user root  --txt report.txt

SSH auth priority: --key  →  --password  →  SSH agent / default keys (auto)
"""

__version__ = "1.2.0"
__author__  = "Benjamin"
__license__ = "MIT"

import argparse
import os
import sys
import json
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import requests
except ImportError:
    requests = None

# ── ANSI ───────────────────────────────────────────────────────────────────────
R   = "\033[0m"
B   = "\033[1m"
DIM = "\033[2m"
G   = "\033[92m"
Y   = "\033[93m"
RE  = "\033[91m"
CY  = "\033[96m"
MAG = "\033[95m"

_W = 72

# ── SSH helpers ────────────────────────────────────────────────────────────────

def ssh_connect(host, user, port, key_path, password):
    if paramiko is None:
        print(f"{RE}paramiko not installed.  Run: pip install paramiko{R}")
        sys.exit(1)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=host, port=port, username=user, timeout=15)
    if key_path:
        kw["key_filename"] = os.path.expanduser(key_path)
    elif password:
        kw["password"] = password
    else:
        kw["look_for_keys"] = True
        kw["allow_agent"]   = True
    try:
        client.connect(**kw)
        print(f"  {G}✔{R}  Connected  {B}{user}@{host}:{port}{R}")
        return client
    except paramiko.AuthenticationException:
        print(f"{RE}Authentication failed for {user}@{host}{R}")
    except Exception as exc:
        print(f"{RE}Connection error: {exc}{R}")
    return None


def ssh_run(client, cmd):
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=30)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""

# ── Docker image helpers ───────────────────────────────────────────────────────

def get_running_containers(client):
    """
    Returns a list of dicts:
      name, container_id, image_ref, local_digest, created, status, ports
    """
    fmt = "{{.Names}}|{{.ID}}|{{.Image}}|{{.Status}}|{{.Ports}}"
    raw = ssh_run(client, f"docker ps --format '{fmt}'")
    containers = []
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) < 5:
            continue
        name, cid, image_ref, status, ports = parts
        containers.append({
            "name":         name.strip(),
            "id":           cid.strip()[:12],
            "image_ref":    image_ref.strip(),
            "status":       status.strip(),
            "ports":        ports.strip(),
            "local_digest": "",
            "remote_digest": "",
            "update_status": "unknown",
            "remote_tag":   "",
        })
    return containers


def get_local_digest(client, image_ref):
    """Get the RepoDigest of the locally pulled image."""
    raw = ssh_run(
        client,
        f"docker inspect --format='{{{{index .RepoDigests 0}}}}' {image_ref} 2>/dev/null"
    )
    # Format: image@sha256:abc...
    if "@sha256:" in raw:
        return raw.split("@sha256:")[-1].strip()
    return ""


def parse_image_ref(image_ref):
    """
    Split an image reference into (registry, repository, tag).
    Examples:
      nginx:latest           → (hub, library/nginx, latest)
      redis:7.2              → (hub, library/redis, 7.2)
      myrepo/app:1.0         → (hub, myrepo/app, 1.0)
      ghcr.io/org/img:main   → (ghcr.io, org/img, main)
    """
    tag = "latest"
    if ":" in image_ref.split("/")[-1]:
        image_ref, tag = image_ref.rsplit(":", 1)

    # Custom registry?
    parts = image_ref.split("/")
    if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry   = parts[0]
        repository = "/".join(parts[1:])
    else:
        registry = "registry-1.docker.io"
        # Official images live under library/
        if len(parts) == 1:
            repository = f"library/{image_ref}"
        else:
            repository = image_ref

    return registry, repository, tag


def hub_token(repository):
    """Get an anonymous Bearer token for Docker Hub pulls."""
    if requests is None:
        return None
    try:
        r = requests.get(
            "https://auth.docker.io/token",
            params={"service": "registry.docker.io",
                    "scope":   f"repository:{repository}:pull"},
            timeout=10,
        )
        return r.json().get("token") if r.ok else None
    except Exception:
        return None


def get_remote_digest(registry, repository, tag):
    """
    Fetch the manifest digest from the registry for the given tag.
    Returns (digest_hex, canonical_tag) or ("", tag).
    """
    if requests is None:
        return "", tag

    headers = {
        "Accept": (
            "application/vnd.docker.distribution.manifest.v2+json,"
            "application/vnd.oci.image.manifest.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json"
        )
    }

    if registry == "registry-1.docker.io":
        token = hub_token(repository)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        base_url = "https://registry-1.docker.io"
    else:
        base_url = f"https://{registry}"

    url = f"{base_url}/v2/{repository}/manifests/{tag}"
    try:
        r = requests.head(url, headers=headers, timeout=10)
        if r.status_code == 200:
            digest = r.headers.get("Docker-Content-Digest", "")
            if digest.startswith("sha256:"):
                return digest[7:], tag
        # If tag is 'latest' and that fails, it still counts as unknown
        return "", tag
    except Exception:
        return "", tag


def check_for_newer_tag(registry, repository, tag):
    """
    For Docker Hub official/user images, try to find a numerically
    higher patch/minor tag than the current one.
    Returns the best candidate tag string, or "" if none found.
    """
    if requests is None or registry != "registry-1.docker.io":
        return ""
    if tag == "latest":
        return ""   # can't meaningfully compare 'latest'

    token = hub_token(repository)
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Use Docker Hub catalog API (only works for non-library repos via Hub API v2)
    hub_repo = repository  # e.g. library/nginx or myuser/myapp
    try:
        url = f"https://hub.docker.com/v2/repositories/{hub_repo}/tags?page_size=100&ordering=last_updated"
        r = requests.get(url, timeout=10)
        if not r.ok:
            return ""
        tags_data = r.json().get("results", [])
        available = [t["name"] for t in tags_data if t.get("name")]

        # Filter to tags that look like version numbers
        import re
        ver_pat = re.compile(r"^\d+(\.\d+)*(-\w+)?$")
        ver_tags = [t for t in available if ver_pat.match(t)]

        def ver_key(t):
            nums = re.findall(r"\d+", t)
            return tuple(int(n) for n in nums)

        cur_nums = tuple(int(n) for n in re.findall(r"\d+", tag))
        newer = [t for t in ver_tags if ver_key(t) > cur_nums]
        if newer:
            newer.sort(key=ver_key, reverse=True)
            return newer[0]
    except Exception:
        pass
    return ""

# ── Table renderer ─────────────────────────────────────────────────────────────

def _trunc(s, n):
    return (s[:n-1] + "…") if len(s) > n else s


STATUS_COLOUR = {
    "up-to-date": G,
    "update-available": Y,
    "unknown": DIM,
    "error": RE,
}

STATUS_LABEL = {
    "up-to-date":       f"{G}✔ up to date{R}",
    "update-available": f"{Y}↑ update available{R}",
    "unknown":          f"{DIM}? unknown{R}",
    "error":            f"{RE}✖ error{R}",
}

STATUS_PLAIN = {
    "up-to-date":       "up to date",
    "update-available": "UPDATE AVAILABLE",
    "unknown":          "unknown",
    "error":            "error",
}


def print_table(containers):
    # Column widths
    CW = {
        "name":    22,
        "image":   30,
        "tag":     10,
        "local":   14,
        "remote":  14,
        "newer":   12,
        "status":  22,
    }
    total = sum(CW.values()) + len(CW) * 3 + 1

    def row(name, image, tag, local, remote, newer, status, colour=False):
        if colour:
            return (
                f"│ {_trunc(name,  CW['name']):<{CW['name']}} "
                f"│ {_trunc(image, CW['image']):<{CW['image']}} "
                f"│ {_trunc(tag,   CW['tag']):<{CW['tag']}} "
                f"│ {_trunc(local, CW['local']):<{CW['local']}} "
                f"│ {_trunc(remote,CW['remote']):<{CW['remote']}} "
                f"│ {_trunc(newer, CW['newer']):<{CW['newer']}} "
                f"│ {status} │"
            )
        return (
            f"│ {_trunc(name,  CW['name']):<{CW['name']}} "
            f"│ {_trunc(image, CW['image']):<{CW['image']}} "
            f"│ {_trunc(tag,   CW['tag']):<{CW['tag']}} "
            f"│ {_trunc(local, CW['local']):<{CW['local']}} "
            f"│ {_trunc(remote,CW['remote']):<{CW['remote']}} "
            f"│ {_trunc(newer, CW['newer']):<{CW['newer']}} "
            f"│ {_trunc(status,CW['status']):<{CW['status']}} │"
        )

    sep   = "├─" + "─┼─".join("─"*w for w in CW.values()) + "─┤"
    top   = "┌─" + "─┬─".join("─"*w for w in CW.values()) + "─┐"
    bot   = "└─" + "─┴─".join("─"*w for w in CW.values()) + "─┘"

    print(f"\n{CY}{top}{R}")
    hdr = row("Container", "Image", "Tag", "Local (sha)", "Remote (sha)", "Newer tag", "Status")
    print(f"{CY}{B}{hdr}{R}")
    print(f"{CY}{sep}{R}")

    updates = 0
    for c in containers:
        st  = c["update_status"]
        col = STATUS_COLOUR.get(st, DIM)
        lbl = STATUS_LABEL.get(st, st)
        # Pad label to fixed width (strip ANSI for length calc)
        import re
        plain_lbl = re.sub(r"\033\[[0-9;]*m", "", lbl)
        pad = CW["status"] - len(plain_lbl)
        lbl_padded = lbl + " " * max(pad, 0)

        r_line = row(
            c["name"],
            c["image_ref"].split(":")[0].split("/")[-1] if "/" in c["image_ref"] else c["image_ref"].split(":")[0],
            c.get("tag", "latest"),
            c["local_digest"][:12]  if c["local_digest"]  else "—",
            c["remote_digest"][:12] if c["remote_digest"] else "—",
            c.get("newer_tag", "")  or "—",
            lbl_padded,
            colour=True,
        )
        print(f"{col}{r_line}{R}")

        if st == "update-available":
            updates += 1

    print(f"{CY}{bot}{R}")

    # Legend
    print(f"\n  {G}✔{R} up to date   {Y}↑{R} update available   {DIM}?{R} unknown\n")

    # Summary line
    total_c = len(containers)
    utd = sum(1 for c in containers if c["update_status"] == "up-to-date")
    unk = sum(1 for c in containers if c["update_status"] == "unknown")
    print(f"  {B}Containers scanned:{R} {total_c}   "
          f"{G}{B}Up to date:{R} {utd}   "
          f"{Y}{B}Updates available:{R} {updates}   "
          f"{DIM}Unknown:{R} {unk}")
    print()
    return updates


# ── TXT report ─────────────────────────────────────────────────────────────────

def save_txt(containers, host, path):
    W = 80
    lines = []
    lines.append("=" * W)
    lines.append("  DOCKER UPDATE CHECKER — REPORT")
    lines.append(f"  Version   : {__version__}")
    lines.append(f"  Host      : {host}")
    lines.append(f"  Generated : {datetime.utcnow().isoformat()} UTC")
    lines.append("=" * W)

    col_fmt = f"  {{:<22}} {{:<32}} {{:<12}} {{:<14}} {{:<14}} {{:<16}} {{}}"
    lines.append(col_fmt.format(
        "Container", "Image", "Tag", "Local (sha)", "Remote (sha)", "Newer tag", "Status"
    ))
    lines.append("  " + "─" * (W - 2))

    for c in containers:
        lines.append(col_fmt.format(
            _trunc(c["name"], 22),
            _trunc(c["image_ref"].split(":")[0], 32),
            _trunc(c.get("tag", "latest"), 12),
            (c["local_digest"][:12]  if c["local_digest"]  else "—"),
            (c["remote_digest"][:12] if c["remote_digest"] else "—"),
            (c.get("newer_tag", "") or "—"),
            STATUS_PLAIN.get(c["update_status"], "unknown"),
        ))

    lines.append("  " + "─" * (W - 2))
    updates = sum(1 for c in containers if c["update_status"] == "update-available")
    lines.append(f"\n  Containers scanned  : {len(containers)}")
    lines.append(f"  Up to date          : {sum(1 for c in containers if c['update_status']=='up-to-date')}")
    lines.append(f"  Updates available   : {updates}")
    lines.append(f"  Unknown             : {sum(1 for c in containers if c['update_status']=='unknown')}")
    lines.append("\n" + "=" * W + "\n")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  {G}✔{R}  TXT report saved → {B}{path}{R}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Check running Docker containers for available image updates via SSH"
    )
    parser.add_argument("--host",     required=True,  help="Remote host IP or hostname")
    parser.add_argument("--user",     default="root", help="SSH username (default: root)")
    parser.add_argument("--port",     default=22, type=int, help="SSH port (default: 22)")
    parser.add_argument("--key",      default="",     help="Path to SSH private key")
    parser.add_argument("--password", default="",     help="SSH password")
    parser.add_argument("--txt",      default="",     help="Save plain-text report to this file")
    args = parser.parse_args()

    # ── Connect ────────────────────────────────────────────────────────────────
    print(f"{CY}{'─' * _W}{R}")
    print(f"{B}  SSH Connection{R}")
    print(f"{CY}{'─' * _W}{R}")

    client = ssh_connect(args.host, args.user, args.port, args.key, args.password)
    if not client:
        sys.exit(1)

    ver = ssh_run(client, "docker version --format '{{.Server.Version}}'")
    if not ver:
        print(f"{RE}  Cannot reach Docker daemon. Is the user in the docker group?{R}")
        client.close(); sys.exit(1)
    print(f"  {G}✔{R}  Docker daemon version: {B}{ver}{R}")

    # ── Gather containers ──────────────────────────────────────────────────────
    print(f"\n{CY}{'─' * _W}{R}")
    print(f"{B}  Discovering containers{R}")
    print(f"{CY}{'─' * _W}{R}")

    containers = get_running_containers(client)
    if not containers:
        print(f"  {DIM}No running containers found.{R}")
        client.close(); return

    print(f"  {G}✔{R}  Found {B}{len(containers)}{R} running container(s)\n")

    # ── Check each image ───────────────────────────────────────────────────────
    print(f"{CY}{'─' * _W}{R}")
    print(f"{B}  Checking for updates{R}")
    print(f"{CY}{'─' * _W}{R}")

    for c in containers:
        ref = c["image_ref"]
        registry, repository, tag = parse_image_ref(ref)
        c["tag"] = tag

        print(f"  {DIM}→{R}  {B}{c['name']:<20}{R}  {CY}{ref}{R}", end="  ", flush=True)

        # Local digest
        local_digest = get_local_digest(client, ref)
        c["local_digest"] = local_digest

        # Remote digest
        remote_digest, _ = get_remote_digest(registry, repository, tag)
        c["remote_digest"] = remote_digest

        # Determine status
        if not local_digest or not remote_digest:
            c["update_status"] = "unknown"
            print(f"{DIM}[unknown — could not fetch digest]{R}")
        elif local_digest == remote_digest:
            c["update_status"] = "up-to-date"
            print(f"{G}[up to date]{R}")
        else:
            c["update_status"] = "update-available"
            # Try to find a specific newer tag
            newer = check_for_newer_tag(registry, repository, tag)
            c["newer_tag"] = newer
            label = f"newer tag: {newer}" if newer else "new digest on same tag"
            print(f"{Y}[UPDATE AVAILABLE — {label}]{R}")

    client.close()

    # ── Print table ────────────────────────────────────────────────────────────
    print(f"\n{CY}{'─' * _W}{R}")
    print(f"{B}  Results{R}")
    print(f"{CY}{'─' * _W}{R}")

    print_table(containers)

    # ── Save TXT ───────────────────────────────────────────────────────────────
    if args.txt:
        save_txt(containers, f"{args.user}@{args.host}:{args.port}", args.txt)


if __name__ == "__main__":
    main()
