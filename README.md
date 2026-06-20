# Wireshark Network Traffic Analysis

I wanted to see what's actually going over my home network in plaintext. Turns out, more than I expected.

This project has two parts. First, I analyzed a sample Telnet capture from the Wireshark wiki to pull out login credentials and a full command history, all sent without encryption. Second, I captured live traffic from my own network and found that DNS queries leak every domain I visit to anyone on the same Wi-Fi, even though all my web traffic uses HTTPS.

I also wrote a Python script that automates the whole process. Point it at any `.pcap` file and it'll flag plaintext credentials, insecure protocols, DNS leaks, and map everything to MITRE ATT&CK.

## Tools

- Wireshark 4.6.4
- Python 3 + Scapy
- Windows 11

## Layout

```
scripts/analyze_pcap.py      # automated pcap analyzer
tests/test_analyze.py        # unit tests
captures/                    # pcap files (gitignored, too large to track)
reports/findings_report.md   # full write-up with screenshots
screenshots/                 # wireshark evidence
```

## Running it

```
pip install -r requirements.txt
python scripts/analyze_pcap.py captures/telnet-cooked.pcap
```

You can grab `telnet-cooked.pcap` from [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures). Drop it in `captures/` and run the command above.

Tests:
```
python -m pytest tests/test_analyze.py -v
```

## What the script catches

- Telnet keystroke recovery (strips out IAC negotiation bytes, reconstructs what was typed)
- FTP credentials in cleartext (passwords get masked in the output)
- Unencrypted HTTP requests
- DNS query logging
- Insecure port detection
- MITRE ATT&CK IDs for each finding

## Findings

| What | Severity | MITRE |
|------|----------|-------|
| Telnet login creds in plaintext | Critical | T1040, T1078 |
| Full post-auth command history exposed | Critical | T1040 |
| DNS queries readable by anyone on LAN | Medium | T1040 |
| All web traffic properly encrypted (HTTPS) | Informational | --- |

Details, screenshots, and recommendations in [`reports/findings_report.md`](reports/findings_report.md).
