#!/usr/bin/env python3
"""A small, non-exploitative scanner for systems you are authorized to assess."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import re
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path


DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 8080, 8443)
MAX_PORTS = 32
MAX_RESPONSE_HEADER_BYTES = 16_384


@dataclass
class HttpResult:
    status: str | None
    headers: dict[str, str]
    error: str | None = None


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    try:
        for item in value.split(","):
            port = int(item.strip())
            if not 1 <= port <= 65535:
                raise ValueError
            if port not in ports:
                ports.append(port)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use comma-separated port numbers from 1 to 65535") from exc
    if not ports:
        raise argparse.ArgumentTypeError("provide at least one port")
    if len(ports) > MAX_PORTS:
        raise argparse.ArgumentTypeError(f"scan at most {MAX_PORTS} ports per run")
    return ports


def validate_target(value: str) -> str:
    target = value.strip()
    if not target or any(char.isspace() for char in target) or "://" in target or any(char in target for char in "/?#@"):
        raise argparse.ArgumentTypeError("provide a hostname or IP address, not a URL or network range")
    if target.startswith("[") and target.endswith("]"):
        target = target[1:-1]
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        if len(target) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?", target):
            raise argparse.ArgumentTypeError("provide a valid hostname or IP address")
        return target.rstrip(".")


def resolve_target(target: str) -> str:
    try:
        addresses = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve target: {exc}") from exc
    if not addresses:
        raise ValueError("target did not resolve to an address")
    # Pin all probes to one resolved address for a predictable, single-host scan.
    return addresses[0][4][0]


def probe_port(address: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def read_http_headers(target: str, address: str, port: int, timeout: float, use_tls: bool) -> HttpResult:
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target)
        host_header = f"[{target}]" if ":" in target and not target.startswith("[") else target
        request = f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: MiniVulnScanner/1.0\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode("ascii", errors="ignore"))
        stream = sock.makefile("rb")
        status_line = stream.readline(2048).decode("iso-8859-1", errors="replace").strip()
        headers: dict[str, str] = {}
        total = len(status_line)
        while total < MAX_RESPONSE_HEADER_BYTES:
            line = stream.readline(4096)
            if not line or line in (b"\r\n", b"\n"):
                break
            total += len(line)
            name, sep, value = line.decode("iso-8859-1", errors="replace").partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
        return HttpResult(status_line or None, headers)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return HttpResult(None, {}, str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def apache_version_finding(server_header: str) -> str | None:
    match = re.search(r"Apache(?:/|\s+)(\d+)\.(\d+)\.(\d+)", server_header, re.IGNORECASE)
    if not match:
        return None
    version = tuple(map(int, match.groups()))
    # Apache's own advisory says several 2.4.0–2.4.59 issues were fixed in 2.4.60.
    if version[:2] == (2, 4) and version <= (2, 4, 59):
        return (
            f"Apache {'.'.join(map(str, version))} is older than 2.4.60. Apache lists multiple "
            "issues affecting versions through 2.4.59; review the vendor advisory and upgrade guidance. "
            "This banner alone does not confirm exploitability."
        )
    return None


def collect_findings(http_result: HttpResult, use_tls: bool) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    headers = http_result.headers
    server_header = headers.get("server")
    if server_header:
        findings.append(("info", f"Server banner disclosed: {server_header}"))
        outdated = apache_version_finding(server_header)
        if outdated:
            findings.append(("review", outdated))
    expected = [
        ("x-content-type-options", "X-Content-Type-Options"),
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options (or a frame-ancestors CSP directive)"),
    ]
    for header_name, label in expected:
        if header_name not in headers and not (header_name == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", "").lower()):
            findings.append(("review", f"Response did not include {label}; check whether this control applies to the application."))
    if use_tls and "strict-transport-security" not in headers:
        findings.append(("review", "HTTPS response did not include Strict-Transport-Security; review whether HSTS is appropriate."))
    return findings


def make_report(target: str, address: str, ports: list[int], open_ports: list[int], findings: list[tuple[str, str]], http_statuses: dict[int, str]) -> str:
    lines = [
        "# Vulnerability scan report",
        "",
        f"- Target: `{target}` (resolved to `{address}`)",
        f"- Scan time (UTC): {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"- Ports checked: {', '.join(map(str, ports))}",
        "- Method: bounded TCP connection checks and HTTP HEAD response-header review; no exploit attempts.",
        "",
        "## Open ports",
        "",
    ]
    if open_ports:
        lines.extend(f"- `{port}`" + (f" — HTTP response: {http_statuses[port]}" if port in http_statuses else "") for port in open_ports)
    else:
        lines.append("No open ports found among the selected ports.")
    lines.extend(["", "## Findings", ""])
    if findings:
        for severity, description in findings:
            lines.append(f"- **{severity.title()}** — {description}")
    else:
        lines.append("No checks in this small scanner raised a finding.")
    lines.extend([
        "",
        "## Limits",
        "",
        "This is a learning aid, not a penetration test or proof that a system is secure. Firewalls, proxies, "
        "backported fixes, hidden services, and application-specific configuration can change results. Verify "
        "version findings with the vendor and review the full configuration. Scan only systems you own or are "
        "explicitly authorized to assess.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="A small, non-exploitative scanner for one authorized host.")
    parser.add_argument("target", type=validate_target, help="one hostname or IP address (not a URL or CIDR range)")
    parser.add_argument("--ports", type=parse_ports, default=list(DEFAULT_PORTS), help="comma-separated ports; default is a small common-port list")
    parser.add_argument("--timeout", type=float, default=0.6, help="connection timeout in seconds (0.1–2.0; default: 0.6)")
    parser.add_argument("--output", type=Path, default=Path("vulnerability-report.md"), help="Markdown report path")
    args = parser.parse_args()
    if not 0.1 <= args.timeout <= 2.0:
        parser.error("--timeout must be between 0.1 and 2.0 seconds")

    try:
        address = resolve_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Checking {args.target} ({address}) on {len(args.ports)} selected ports…")
    open_ports: list[int] = []
    findings: list[tuple[str, str]] = []
    statuses: dict[int, str] = {}
    for port in args.ports:
        if not probe_port(address, port, args.timeout):
            continue
        open_ports.append(port)
        print(f"  Open: {port}")
        if port in (80, 8080):
            result = read_http_headers(args.target, address, port, args.timeout, use_tls=False)
        elif port in (443, 8443):
            result = read_http_headers(args.target, address, port, args.timeout, use_tls=True)
        else:
            continue
        if result.status:
            statuses[port] = result.status
            findings.extend((severity, f"Port {port}: {description}") for severity, description in collect_findings(result, port in (443, 8443)))
        elif result.error:
            findings.append(("info", f"Port {port} accepted a connection, but the HTTP/TLS check could not complete: {result.error}"))

    report = make_report(args.target, address, args.ports, open_ports, findings, statuses)
    try:
        args.output.write_text(report, encoding="utf-8")
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        return 1
    print(f"Report saved to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
