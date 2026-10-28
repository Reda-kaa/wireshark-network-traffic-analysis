# Wireshark Network Traffic Analysis

A hands-on cybersecurity portfolio project focused on network traffic analysis, TCP/TLS inspection, and basic network anomaly detection using Wireshark and TShark.

## Project Objectives

- Analyze DNS queries and responses.
- Identify the TCP three-way handshake.
- Inspect TLS 1.3 negotiation and cipher suites.
- Explore protocol hierarchy, TCP conversations, and network endpoints.
- Detect and summarize TCP retransmissions and other TCP analysis indicators.
- Generate structured JSON and CSV reports using Python.
- Document findings with packet-level evidence and screenshots.

## Tools and Environment

- Wireshark
- TShark
- Python 3
- Windows and PowerShell
- `curl.exe` for generating HTTPS test traffic
- Wireshark display filters for DNS, TCP, and TLS

## Project Structure

```text
Wireshark Network Traffic Analysis/
├── captures/                         # Local captures; excluded from Git
├── reports/
│   ├── first-analysis.md
│   ├── detection-analysis.md
│   ├── network-detection.json
│   └── network-detection-retransmissions.csv
├── screenshots/
│   ├── 01-dns-analysis.png
│   ├── 02-tcp-handshake.png
│   ├── 03-tls13-client-hello.png
│   ├── 04-tls13-server-hello.png
│   ├── 05-protocol-hierarchy.png
│   ├── 06-conversation.png
│   └── 07-endpoints.png
├── scripts/
│   └── detect_network_anomalies.py
├── .gitignore
└── README.md
```

## Lab Results

| Analysis | Observation |
|---|---|
| DNS | Query for `example.com`, type A, and response observed |
| TCP | SYN, SYN-ACK, and ACK observed |
| TLS | TLS 1.3 negotiation inspected |
| Cipher suite | `TLS_AES_256_GCM_SHA384 (0x1302)` observed |
| Captured packets | 97,176 |
| TCP packets | 35,306 |
| TCP retransmissions | 587 |
| TCP duplicate ACKs | 226 |
| TCP resets (RST) | 131 |
| TCP conversations | 392 |
| IPv4 endpoints | 170 |

The packet statistics describe the analyzed capture, which may include background network traffic. They do not represent only the test connection.

TLS packet counts can vary depending on the TShark version, protocol dissection, and counting method. The values above should not be interpreted as counts of unique TLS connections.

## Python-Based Detection

The script `scripts/detect_network_anomalies.py` uses TShark to inspect a capture and summarize selected TCP indicators.

It generates:

- `reports/network-detection.json` — a structured summary of the analysis.
- `reports/network-detection-retransmissions.csv` — retransmission-related flow details.

### Run the analysis

From the project directory, execute:

```powershell
python .\scripts\detect_network_anomalies.py ".\captures\first-traffic-analysis.pcapng"
```

Make sure Wireshark/TShark is installed and the capture file exists at the specified path.

## Useful Wireshark Display Filters

```text
dns
tcp
tcp.stream eq 40
tcp.stream eq 40 && tls.handshake.type == 1
tcp.stream eq 40 && tls.handshake.type == 2
tcp.analysis.retransmission
tcp.analysis.duplicate_ack
tcp.flags.reset == 1
```

Replace `40` with the stream number of the connection you want to inspect.

## Reports

- [First traffic analysis](reports/first-analysis.md)
- [Detection analysis](reports/detection-analysis.md)
- [Network detection summary (JSON)](reports/network-detection.json)
- [Retransmission details (CSV)](reports/network-detection-retransmissions.csv)

## Screenshots

### DNS Analysis

![DNS analysis](screenshots/01-dns-analysis.png)

### TCP Three-Way Handshake

![TCP handshake](screenshots/02-tcp-handshake.png)

### TLS 1.3 Client Hello

![TLS Client Hello](screenshots/03-tls13-client-hello.png)

### TLS 1.3 Server Hello

![TLS Server Hello](screenshots/04-tls13-server-hello.png)

### Protocol Hierarchy

![Protocol hierarchy](screenshots/05-protocol-hierarchy.png)

### TCP Conversations

![TCP conversations](screenshots/06-conversation.png)

### Network Endpoints

![Network endpoints](screenshots/07-endpoints.png)

## Security and Privacy

Raw PCAP/PCAPNG files are intentionally excluded from version control because captures may contain IP addresses, hostnames, and other sensitive network metadata.

Review screenshots, reports, and exported data for sensitive information before publishing them.

## Limitations

- TCP retransmissions, duplicate ACKs, resets, and out-of-order packets can have legitimate causes.
- These indicators alone do not prove that an attack occurred.
- The script provides basic traffic analysis, not a complete intrusion detection or prevention system.
- Results depend on the capture contents and TShark's protocol dissection.

## Future Improvements

- Add sanitized sample captures and reproducible test cases.
- Expand the analysis to DNS anomalies and unusual connection patterns.
- Add severity levels and investigation recommendations.
- Improve report generation and document additional defensive detection examples.

## Author

Cybersecurity and Data Science portfolio project.
