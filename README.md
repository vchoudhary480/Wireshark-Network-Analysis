# Wireshark Network Traffic Analysis

Analyzed a Telnet packet capture to demonstrate how insecure protocols leak credentials and session data. Used Wireshark for manual packet inspection and wrote a Python script to automate credential extraction and protocol analysis.

## What this project does

I took a sample Telnet capture and pulled it apart two ways — manually in Wireshark and programmatically with a Python script. The script takes any `.pcap` file, scans every packet, and flags things like plaintext credentials, unencrypted protocols, and DNS leaks.

The Telnet capture had a full login session with the username and password sent in cleartext, plus every command the user ran afterward. The script recovered all of it automatically.



## Project layout

```
scripts/analyze_pcap.py      # automated pcap analyzer
captures/                    # pcap files go here (not tracked by git)
reports/findings_report.md   # write-up of what I found
```

## How to run it

```bash
pip install scapy
python scripts/analyze_pcap.py captures/telnet-cooked.pcap
```

You can download `telnet-cooked.pcap` from [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) and drop it in the `captures/` folder.

The script also works on any other `.pcap` file — it detects Telnet keystrokes, FTP credentials, unencrypted HTTP, DNS queries, and flags insecure ports.

## Findings

| Finding | Severity |
|---------|----------|
| Telnet credentials transmitted in plaintext | Critical |
| Full command history exposed without encryption | Critical |
| No encryption at any network layer | High |

Full write-up with evidence and recommendations in `reports/findings_report.md`.

## What the script detects

- Telnet keystroke reconstruction (recovers typed input from raw packets)
- FTP username/password extraction
- Unencrypted HTTP request logging
- DNS query enumeration
- Insecure port detection (Telnet, FTP, SMTP, TFTP, etc.)
