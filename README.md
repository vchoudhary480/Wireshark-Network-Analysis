# Wireshark Network Traffic Analysis

Captured and analyzed network traffic to identify security vulnerabilities. Analyzed a Telnet sample capture (credential interception) and live home network traffic (DNS leaks, unencrypted HTTP). Built a Python script that automates detection of plaintext credentials, insecure protocols, and information leakage on any pcap file.

## What I did

Two types of analysis:

**Sample capture** (`telnet-cooked.pcap`) — Recovered plaintext login credentials and full command history from an unencrypted Telnet session. Demonstrated both manual inspection in Wireshark (Follow TCP Stream, display filters) and automated extraction with a Python script.

**Live capture** (my home network) — Captured real traffic and found unencrypted HTTP downloads, plaintext DNS queries leaking browsing history, and noisy Windows telemetry in the background. Showed that even on a modern Windows 11 setup with HTTPS everywhere, DNS remains a blind spot.

## Tools

- Wireshark
- Python 3 with Scapy
- Windows 11

## Project layout

```
scripts/analyze_pcap.py      # automated pcap analyzer
tests/test_analyze.py        # unit tests for IAC stripping and classification
captures/                    # pcap files go here (gitignored, too large)
reports/findings_report.md   # full write-up with evidence
screenshots/                 # wireshark screenshots referenced in report
```

## How to run it

```bash
pip install scapy
python scripts/analyze_pcap.py captures/telnet-cooked.pcap
```

Download `telnet-cooked.pcap` from [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) and put it in `captures/`.

Run tests:
```bash
python -m pytest tests/test_analyze.py -v
```

## What the script detects

- Telnet keystroke reconstruction (strips IAC negotiation, recovers typed input)
- FTP username/password extraction (passwords masked in output)
- Unencrypted HTTP request logging
- DNS query enumeration
- Insecure port flagging (Telnet, FTP, SMTP, TFTP, etc.)
- MITRE ATT&CK mapping for each finding

## Findings summary

| Finding | Severity | MITRE ATT&CK |
|---------|----------|---------------|
| Telnet credentials in plaintext | Critical | T1040, T1078 |
| Full command history exposed | Critical | T1040 |
| Unencrypted HTTP data transfer | High | T1040 |
| DNS queries leak browsing history | Medium | T1016 |
| Windows telemetry domain lookups | Medium | T1016 |

Full analysis with Wireshark screenshots, compliance references (NIST, PCI DSS), and recommendations in `reports/findings_report.md`.
