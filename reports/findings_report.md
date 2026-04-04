# Network Traffic Analysis - Findings Report

**Analyst:** Vishwa Prakash Choudhary
**Date:** April 3, 2026
**Tools:** Wireshark 4.6.4, Python 3 (Scapy)
**Capture:** telnet-cooked.pcap (Wireshark sample capture)
**Environment:** Windows 11

---

## Overview

I analyzed a sample Telnet packet capture to demonstrate how insecure protocols expose sensitive data on a network. The capture contains a complete Telnet login session between two hosts, and I used both Wireshark (manual inspection) and a custom Python script (automated analysis) to extract and document the vulnerabilities.

---

## Capture Summary

- **File:** telnet-cooked.pcap
- **Total packets:** 92
- **Protocol:** 100% Telnet (TCP port 23)
- **Client:** 192.168.0.2 (48 packets sent)
- **Server:** 192.168.0.1 (44 packets sent)

The capture is a "cooked" Telnet session, meaning keystrokes are sent line-by-line rather than character-by-character. This made it straightforward to reconstruct what the user typed.

---

## Finding 1 - Plaintext credential transmission (Critical)

Telnet sends all data without any encryption. The login credentials were fully visible in the packet capture:

- **Username:** `fake`
- **Password:** `user`

I confirmed this two ways:
1. In Wireshark, by filtering for `telnet` and using Follow > TCP Stream (right-click any Telnet packet), which displays the full session as readable text.
2. With my Python script (`analyze_pcap.py`), which automatically parsed the packet payloads and recovered the credentials programmatically.

An attacker on the same network segment only needs a packet sniffer running to capture these credentials in real time. No decryption needed, no special tools — the data is right there.

---

## Finding 2 - Full command history exposed (Critical)

Beyond the login, every command the user ran after authenticating was also captured in plaintext:

```
> fake                          (username)
> user                          (password)
> /sbin/ping www.yahoo.com      (network connectivity test)
> /sbin/ping www.yahoo.com      (repeated)
> ls                            (directory listing)
> ls -a                         (directory listing with hidden files)
> exit                          (end session)
```

This means an attacker doesn't just get the password — they get a full record of what the user did on the system. In a real scenario, this could reveal file structures, running services, internal hostnames, or other sensitive information about the target system.

---

## Finding 3 - No session encryption at any layer (High)

Looking at the packet details in Wireshark, the entire session runs over raw TCP with no encryption layer:

| Layer | Protocol | Encrypted? |
|-------|----------|------------|
| 2 - Data Link | Ethernet | No |
| 3 - Network | IPv4 | No |
| 4 - Transport | TCP (port 23) | No |
| 7 - Application | Telnet | No |

There's no TLS, no SSH tunnel, nothing. Compare this to SSH (port 22), where everything above the TCP layer is encrypted and packet inspection only shows encrypted gibberish.

---

## Automated analysis output

Running my Python script against the capture:

```
$ python scripts/analyze_pcap.py captures/telnet-cooked.pcap

============================================================
  PCAP ANALYSIS REPORT
  File: telnet-cooked.pcap
  Date: 2026-04-03 20:16
  Packets: 92
============================================================

--- Protocol breakdown ---
  Telnet            92  (100.0%)

--- Top source IPs ---
  192.168.0.2            48 packets
  192.168.0.1            44 packets

--- TELNET KEYSTROKES (plaintext!) ---
  Session: 192.168.0.2->192.168.0.1
  Recovered input:
    > fake
    > user
    > /sbin/ping www.yahoo.com
    > /sbin/ping www.yahoo.com
    > ls
    > ls -a
    > exit

============================================================
  FINDINGS (1 issues)
============================================================

  [!!] CRITICAL - #1: Telnet session with plaintext keystrokes
      Protocol: Telnet
      User input captured from 192.168.0.2 to 192.168.0.1 (7 lines recovered)

  Total: 1 critical, 0 high, 0 medium
============================================================
```

---

## Recommendations

1. **Replace Telnet with SSH.** SSH provides the same remote access functionality with full encryption. Every modern operating system supports it out of the box.
2. **Block port 23 at the firewall.** If Telnet isn't needed (and it almost never is), block it at the network perimeter so it can't be used even accidentally.
3. **Monitor for Telnet traffic.** IDS/IPS rules can flag any Telnet activity on the network as a policy violation. Snort and Suricata both have built-in signatures for this.
4. **Audit legacy systems.** Older network equipment (switches, routers, embedded devices) sometimes only supports Telnet. These should be identified and either upgraded or isolated on a separate management VLAN.

---

*Vishwa Prakash Choudhary
