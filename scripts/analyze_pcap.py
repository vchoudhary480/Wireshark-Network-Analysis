#!/usr/bin/env python3
"""
analyze_pcap.py - scans a pcap file for security issues

Takes a packet capture file and looks for stuff like plaintext passwords,
unencrypted traffic, DNS leaks, etc. Prints a summary with severity ratings.

Usage: python analyze_pcap.py <pcap_file>
"""

import sys
import os
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, ARP, ICMP
except ImportError:
    print("You need scapy installed. Run: pip install scapy")
    sys.exit(1)


# ports where traffic shouldn't be unencrypted
INSECURE_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    69: "TFTP",
}


def classify_packet(pkt):
    """Figure out what protocol a packet is using."""
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        port = dport if dport < 1024 else sport

        port_map = {
            80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH",
            23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
        }
        return port_map.get(port, "TCP/Other")

    elif pkt.haslayer(UDP):
        if pkt.haslayer(DNS):
            return "DNS"
        return "UDP/Other"
    elif pkt.haslayer(ARP):
        return "ARP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"


def find_telnet_creds(packets):
    """
    Pull out telnet keystrokes. Telnet sends each character one at a time
    so we need to reconstruct the session by collecting bytes per source IP.
    """
    sessions = defaultdict(list)
    creds = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        if pkt[TCP].dport != 23 and pkt[TCP].sport != 23:
            continue

        try:
            payload = pkt[Raw].load
        except Exception:
            continue

        # client -> server traffic (the stuff the user typed)
        if pkt[TCP].dport == 23:
            src = pkt[IP].src if pkt.haslayer(IP) else "unknown"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
            key = f"{src}->{dst}"
            sessions[key].append(payload)

    # try to reconstruct what was typed
    for session_key, payloads in sessions.items():
        typed = b""
        for p in payloads:
            # skip telnet negotiation bytes (start with 0xff)
            if p and p[0] != 0xff:
                typed += p

        decoded = typed.decode("ascii", errors="ignore").strip()
        if decoded:
            # first line is usually the username, stuff after is commands/password
            lines = [l.strip() for l in decoded.replace("\r\n", "\n").replace("\r", "\n").split("\n") if l.strip()]
            src_ip = session_key.split("->")[0]
            dst_ip = session_key.split("->")[1]

            creds.append({
                "session": session_key,
                "typed_chars": decoded,
                "lines": lines,
                "src": src_ip,
                "dst": dst_ip,
            })

    return creds


def find_ftp_creds(packets):
    """Look for FTP USER and PASS commands sent in cleartext."""
    found = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        if pkt[TCP].dport != 21 and pkt[TCP].sport != 21:
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue

        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "?"

        if payload.upper().startswith("USER "):
            found.append({
                "type": "username",
                "value": payload[5:].strip(),
                "src": src, "dst": dst
            })
        elif payload.upper().startswith("PASS "):
            pw = payload[5:].strip()
            masked = pw[0] + "*" * (len(pw) - 1) if pw else "***"
            found.append({
                "type": "password",
                "value": masked,
                "src": src, "dst": dst
            })

    return found


def find_http_requests(packets):
    """Grab unencrypted HTTP requests."""
    requests = []
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        if pkt[TCP].dport != 80:
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        for method in methods:
            if payload.startswith(method):
                lines = payload.split("\r\n")
                host = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                requests.append({
                    "method": method,
                    "request_line": lines[0][:80],
                    "host": host,
                    "src": pkt[IP].src if pkt.haslayer(IP) else "?",
                })
                break

    return requests


def find_dns_queries(packets):
    """Collect unique DNS lookups."""
    seen = set()
    queries = []

    for pkt in packets:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue

        try:
            domain = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            continue

        if domain and domain not in seen:
            seen.add(domain)
            queries.append({
                "domain": domain,
                "src": pkt[IP].src if pkt.haslayer(IP) else "?",
            })

    return queries


def find_insecure_ports(packets):
    """Check for traffic on ports that shouldn't be unencrypted."""
    flagged = {}

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        dport = pkt[TCP].dport
        if dport in INSECURE_PORTS and dport not in flagged:
            flagged[dport] = {
                "port": dport,
                "service": INSECURE_PORTS[dport],
                "src": pkt[IP].src if pkt.haslayer(IP) else "?",
            }

    return list(flagged.values())


def run(pcap_path):
    """Main analysis - load the pcap and run all checks."""
    if not os.path.exists(pcap_path):
        print(f"Can't find file: {pcap_path}")
        sys.exit(1)

    print(f"Loading {pcap_path}...")
    packets = rdpcap(pcap_path)
    print(f"Got {len(packets)} packets\n")

    # protocol stats
    proto_counts = Counter()
    src_ips = Counter()
    dst_ips = Counter()

    for pkt in packets:
        proto_counts[classify_packet(pkt)] += 1
        if pkt.haslayer(IP):
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1

    # run all the checks
    telnet_creds = find_telnet_creds(packets)
    ftp_creds = find_ftp_creds(packets)
    http_reqs = find_http_requests(packets)
    dns_queries = find_dns_queries(packets)
    insecure = find_insecure_ports(packets)

    # collect findings with severity
    findings = []

    if telnet_creds:
        for cred in telnet_creds:
            findings.append({
                "sev": "CRITICAL",
                "title": "Telnet session with plaintext keystrokes",
                "detail": f"User input captured from {cred['src']} to {cred['dst']} ({len(cred['lines'])} lines recovered)",
                "proto": "Telnet",
            })

    if ftp_creds:
        for c in ftp_creds:
            findings.append({
                "sev": "CRITICAL",
                "title": f"FTP {c['type']} in plaintext",
                "detail": f"{c['type']}: {c['value']} (from {c['src']} to {c['dst']})",
                "proto": "FTP",
            })

    if http_reqs:
        post_count = sum(1 for r in http_reqs if r["method"] == "POST")
        findings.append({
            "sev": "HIGH",
            "title": f"Unencrypted HTTP traffic ({len(http_reqs)} requests)",
            "detail": f"{len(http_reqs)} HTTP requests without TLS" +
                       (f", including {post_count} POST requests" if post_count else ""),
            "proto": "HTTP",
        })

    if dns_queries:
        findings.append({
            "sev": "MEDIUM",
            "title": f"DNS queries in plaintext ({len(dns_queries)} unique domains)",
            "detail": "browsing patterns visible to anyone on the network",
            "proto": "DNS",
        })

    # flag insecure ports we haven't already covered
    covered_ports = set()
    if telnet_creds: covered_ports.add(23)
    if ftp_creds: covered_ports.add(21)
    if http_reqs: covered_ports.add(80)

    for entry in insecure:
        if entry["port"] not in covered_ports:
            findings.append({
                "sev": "MEDIUM",
                "title": f"Insecure protocol: {entry['service']} (port {entry['port']})",
                "detail": f"traffic from {entry['src']}",
                "proto": entry["service"],
            })

    # --- print everything ---

    print("=" * 60)
    print("  PCAP ANALYSIS REPORT")
    print(f"  File: {os.path.basename(pcap_path)}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Packets: {len(packets)}")
    print("=" * 60)

    # protocol breakdown
    print("\n--- Protocol breakdown ---")
    total = sum(proto_counts.values())
    for proto, count in proto_counts.most_common():
        pct = count / total * 100 if total else 0
        bar = "#" * int(pct / 2)
        print(f"  {proto:<15} {count:>6}  ({pct:4.1f}%)  {bar}")

    # top talkers
    print("\n--- Top source IPs ---")
    for ip, count in src_ips.most_common(5):
        print(f"  {ip:<20} {count:>6} packets")

    print("\n--- Top destination IPs ---")
    for ip, count in dst_ips.most_common(5):
        print(f"  {ip:<20} {count:>6} packets")

    # telnet keystrokes
    if telnet_creds:
        print("\n--- TELNET KEYSTROKES (plaintext!) ---")
        for cred in telnet_creds:
            print(f"  Session: {cred['session']}")
            print(f"  Recovered input:")
            for line in cred["lines"][:10]:
                print(f"    > {line}")
            if len(cred["lines"]) > 10:
                print(f"    ... and {len(cred['lines']) - 10} more lines")

    # ftp creds
    if ftp_creds:
        print("\n--- FTP CREDENTIALS (plaintext!) ---")
        for c in ftp_creds:
            print(f"  [{c['type'].upper()}] {c['value']}  ({c['src']} -> {c['dst']})")

    # http requests
    if http_reqs:
        print(f"\n--- HTTP requests ({len(http_reqs)} total, no encryption) ---")
        for req in http_reqs[:10]:
            print(f"  [{req['method']}] {req['host']}  {req['request_line'][:60]}")
        if len(http_reqs) > 10:
            print(f"  ... and {len(http_reqs) - 10} more")

    # dns
    if dns_queries:
        print(f"\n--- DNS queries ({len(dns_queries)} unique domains) ---")
        for q in dns_queries[:15]:
            print(f"  {q['src']:<18} looked up {q['domain']}")
        if len(dns_queries) > 15:
            print(f"  ... and {len(dns_queries) - 15} more")

    # findings summary
    print("\n" + "=" * 60)
    print(f"  FINDINGS ({len(findings)} issues)")
    print("=" * 60)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["sev"], 99))

    icons = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]"}

    for i, f in enumerate(findings, 1):
        print(f"\n  {icons.get(f['sev'], '[ ]')} {f['sev']} - #{i}: {f['title']}")
        print(f"      Protocol: {f['proto']}")
        print(f"      {f['detail']}")

    if not findings:
        print("\n  No issues found.")

    # totals
    crit = sum(1 for f in findings if f["sev"] == "CRITICAL")
    high = sum(1 for f in findings if f["sev"] == "HIGH")
    med = sum(1 for f in findings if f["sev"] == "MEDIUM")
    print(f"\n  Total: {crit} critical, {high} high, {med} medium")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_pcap.py <pcap_file>")
        print("Example: python analyze_pcap.py captures/telnet-cooked.pcap")
        sys.exit(1)

    run(sys.argv[1])
