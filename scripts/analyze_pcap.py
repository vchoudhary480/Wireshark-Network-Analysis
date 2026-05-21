#!/usr/bin/env python3
"""
analyze_pcap.py

Scans a pcap file for security problems — plaintext passwords,
unencrypted traffic, DNS leaks, that kind of thing. Prints a
summary with severity ratings and MITRE ATT&CK references.

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

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 993: "IMAPS", 995: "POP3S",
}


def classify_packet(pkt):
    """
    Figure out what protocol a packet belongs to.
    Checks both source and destination ports against known services
    so we correctly classify both directions of a conversation.
    """
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if dport in SERVICE_PORTS:
            return SERVICE_PORTS[dport]
        if sport in SERVICE_PORTS:
            return SERVICE_PORTS[sport]
        return "TCP/Other"

    elif pkt.haslayer(UDP):
        return "DNS" if pkt.haslayer(DNS) else "UDP/Other"
    elif pkt.haslayer(ARP):
        return "ARP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    return "Other"


def strip_telnet_negotiation(data):
    """
    Telnet shoves control sequences into the data stream using IAC
    (Interpret As Command, 0xFF). We need to strip those out to get
    at the actual text the user typed.

    The sequences look like:
      FF FB xx  = WILL option
      FF FC xx  = WON'T option
      FF FD xx  = DO option
      FF FE xx  = DON'T option
      FF FA ... FF F0 = subnegotiation block
      FF FF = literal 0xFF (escaped)
    """
    cleaned = bytearray()
    i = 0

    while i < len(data):
        if data[i] == 0xFF:
            if i + 1 >= len(data):
                break

            cmd = data[i + 1]

            if cmd == 0xFF:
                cleaned.append(0xFF)
                i += 2
            elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):
                i += 3  # 3-byte command
            elif cmd == 0xFA:
                # subnegotiation — skip everything until FF F0
                end = data.find(b'\xff\xf0', i)
                if end == -1:
                    break
                i = end + 2
            else:
                i += 2  # other 2-byte command
        else:
            cleaned.append(data[i])
            i += 1

    return bytes(cleaned)


def find_telnet_creds(packets):
    """
    Reconstruct telnet sessions. Collects all client->server payloads,
    strips IAC negotiation, and tries to decode what was typed.
    """
    sessions = defaultdict(bytearray)
    results = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            continue
        if pkt[TCP].dport != 23 and pkt[TCP].sport != 23:
            continue

        try:
            payload = pkt[Raw].load
        except Exception:
            continue

        # we only want client->server (dport 23), that's what the user typed
        if pkt[TCP].dport == 23:
            key = f"{pkt[IP].src}->{pkt[IP].dst}"
            sessions[key].extend(payload)

    for session_key, raw_data in sessions.items():
        cleaned = strip_telnet_negotiation(raw_data)
        decoded = cleaned.decode("ascii", errors="ignore").strip()

        if not decoded:
            continue

        lines = [
            l.strip() for l in
            decoded.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            if l.strip()
        ]

        src_ip, dst_ip = session_key.split("->")
        results.append({
            "session": session_key,
            "lines": lines,
            "src": src_ip,
            "dst": dst_ip,
        })

    return results


def find_ftp_creds(packets):
    """Pull FTP USER and PASS commands out of the capture."""
    found = []

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            continue
        if pkt[TCP].dport != 21 and pkt[TCP].sport != 21:
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
        except UnicodeDecodeError:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst

        if payload.upper().startswith("USER "):
            found.append({
                "type": "username", "value": payload[5:].strip(),
                "src": src, "dst": dst,
            })
        elif payload.upper().startswith("PASS "):
            pw = payload[5:].strip()
            masked = pw[0] + "*" * (len(pw) - 1) if len(pw) > 1 else "***"
            found.append({
                "type": "password", "value": masked,
                "src": src, "dst": dst,
            })

    return found


def find_http_requests(packets):
    """Find unencrypted HTTP requests."""
    reqs = []
    methods = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD")

    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
            continue
        if pkt[TCP].dport != 80:
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            continue

        for method in methods:
            if not payload.startswith(method):
                continue

            lines = payload.split("\r\n")
            host = ""
            for line in lines:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            reqs.append({
                "method": method,
                "request_line": lines[0][:80],
                "host": host,
                "src": pkt[IP].src,
            })
            break

    return reqs


def find_dns_queries(packets):
    """Collect unique DNS domain lookups."""
    seen = set()
    queries = []

    for pkt in packets:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue
        try:
            domain = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except (UnicodeDecodeError, AttributeError):
            continue

        if domain and domain not in seen:
            seen.add(domain)
            queries.append({
                "domain": domain,
                "src": pkt[IP].src if pkt.haslayer(IP) else "unknown",
            })

    return queries


def find_insecure_ports(packets):
    """Flag traffic on ports that shouldn't be unencrypted."""
    flagged = {}
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        dport = pkt[TCP].dport
        if dport in INSECURE_PORTS and dport not in flagged:
            flagged[dport] = {
                "port": dport,
                "service": INSECURE_PORTS[dport],
                "src": pkt[IP].src,
            }
    return list(flagged.values())


def build_findings(telnet_creds, ftp_creds, http_reqs, dns_queries, insecure_ports):
    """Put together the findings list with severities and MITRE IDs."""
    findings = []

    for cred in telnet_creds:
        findings.append({
            "sev": "CRITICAL",
            "title": "Telnet session with plaintext keystrokes",
            "detail": f"Recovered {len(cred['lines'])} lines of user input from {cred['src']} to {cred['dst']}",
            "proto": "Telnet",
            "mitre": "T1040 (Network Sniffing), T1078 (Valid Accounts)",
        })

    for c in ftp_creds:
        findings.append({
            "sev": "CRITICAL",
            "title": f"FTP {c['type']} sent in cleartext",
            "detail": f"{c['type']}: {c['value']} ({c['src']} -> {c['dst']})",
            "proto": "FTP",
            "mitre": "T1040 (Network Sniffing), T1078 (Valid Accounts)",
        })

    if http_reqs:
        post_count = sum(1 for r in http_reqs if r["method"] == "POST")
        detail = f"{len(http_reqs)} HTTP requests without TLS"
        if post_count:
            detail += f" — {post_count} of those are POSTs (possible form data)"
        findings.append({
            "sev": "HIGH",
            "title": f"Unencrypted HTTP traffic ({len(http_reqs)} requests)",
            "detail": detail,
            "proto": "HTTP",
            "mitre": "T1040 (Network Sniffing)",
        })

    if dns_queries:
        findings.append({
            "sev": "MEDIUM",
            "title": f"DNS queries in plaintext ({len(dns_queries)} unique domains)",
            "detail": "browsing patterns exposed to anyone on the network",
            "proto": "DNS",
            "mitre": "T1016 (System Network Configuration Discovery)",
        })

    # catch insecure ports we haven't already reported on
    covered = set()
    if telnet_creds: covered.add(23)
    if ftp_creds: covered.add(21)
    if http_reqs: covered.add(80)

    for entry in insecure_ports:
        if entry["port"] not in covered:
            findings.append({
                "sev": "MEDIUM",
                "title": f"Traffic on insecure port: {entry['service']} ({entry['port']})",
                "detail": f"from {entry['src']}",
                "proto": entry["service"],
                "mitre": "T1040 (Network Sniffing)",
            })

    return findings


def print_report(pcap_path, packets, proto_counts, src_ips, dst_ips,
                 telnet_creds, ftp_creds, http_reqs, dns_queries, findings):
    """Print the whole report to stdout."""

    print("=" * 60)
    print("  PCAP ANALYSIS REPORT")
    print(f"  File: {os.path.basename(pcap_path)}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Packets: {len(packets)}")
    print("=" * 60)

    print("\n--- Protocol breakdown ---")
    total = sum(proto_counts.values())
    for proto, count in proto_counts.most_common():
        pct = count / total * 100 if total else 0
        bar = "#" * int(pct / 2)
        print(f"  {proto:<15} {count:>6}  ({pct:4.1f}%)  {bar}")

    print("\n--- Top source IPs ---")
    for ip, count in src_ips.most_common(5):
        print(f"  {ip:<20} {count:>6} packets")

    print("\n--- Top destination IPs ---")
    for ip, count in dst_ips.most_common(5):
        print(f"  {ip:<20} {count:>6} packets")

    if telnet_creds:
        print("\n--- TELNET KEYSTROKES (plaintext!) ---")
        for cred in telnet_creds:
            print(f"  Session: {cred['session']}")
            print(f"  Recovered input:")
            for line in cred["lines"][:10]:
                print(f"    > {line}")
            if len(cred["lines"]) > 10:
                print(f"    ... and {len(cred['lines']) - 10} more lines")

    if ftp_creds:
        print("\n--- FTP CREDENTIALS (plaintext!) ---")
        for c in ftp_creds:
            print(f"  [{c['type'].upper()}] {c['value']}  ({c['src']} -> {c['dst']})")

    if http_reqs:
        print(f"\n--- HTTP requests ({len(http_reqs)} total, unencrypted) ---")
        for req in http_reqs[:10]:
            print(f"  [{req['method']}] {req['host']}  {req['request_line'][:60]}")
        if len(http_reqs) > 10:
            print(f"  ... and {len(http_reqs) - 10} more")

    if dns_queries:
        print(f"\n--- DNS queries ({len(dns_queries)} unique domains) ---")
        for q in dns_queries[:15]:
            print(f"  {q['src']:<18} looked up {q['domain']}")
        if len(dns_queries) > 15:
            print(f"  ... and {len(dns_queries) - 15} more")

    print("\n" + "=" * 60)
    print(f"  FINDINGS ({len(findings)} issues)")
    print("=" * 60)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f["sev"], 99))

    icons = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[.]"}

    for i, f in enumerate(findings, 1):
        icon = icons.get(f["sev"], "[ ]")
        print(f"\n  {icon} {f['sev']} - #{i}: {f['title']}")
        print(f"      Protocol: {f['proto']}")
        print(f"      MITRE ATT&CK: {f['mitre']}")
        print(f"      {f['detail']}")

    if not findings:
        print("\n  Nothing found.")

    crit = sum(1 for f in findings if f["sev"] == "CRITICAL")
    high = sum(1 for f in findings if f["sev"] == "HIGH")
    med = sum(1 for f in findings if f["sev"] == "MEDIUM")
    print(f"\n  Total: {crit} critical, {high} high, {med} medium")
    print("=" * 60)


def run(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"Can't find file: {pcap_path}")
        sys.exit(1)

    print(f"Loading {pcap_path}...")
    packets = rdpcap(pcap_path)
    print(f"Got {len(packets)} packets\n")

    proto_counts = Counter()
    src_ips = Counter()
    dst_ips = Counter()

    for pkt in packets:
        proto_counts[classify_packet(pkt)] += 1
        if pkt.haslayer(IP):
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1

    telnet_creds = find_telnet_creds(packets)
    ftp_creds = find_ftp_creds(packets)
    http_reqs = find_http_requests(packets)
    dns_queries = find_dns_queries(packets)
    insecure = find_insecure_ports(packets)

    findings = build_findings(telnet_creds, ftp_creds, http_reqs, dns_queries, insecure)

    print_report(pcap_path, packets, proto_counts, src_ips, dst_ips,
                 telnet_creds, ftp_creds, http_reqs, dns_queries, findings)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_pcap.py <pcap_file>")
        print("Example: python analyze_pcap.py captures/telnet-cooked.pcap")
        sys.exit(1)

    run(sys.argv[1])
