# Wireshark Network Traffic Analysis

## 1. Project Overview

This project demonstrates practical network traffic analysis using Wireshark on Windows. The objective is to inspect DNS resolution, TCP connection establishment, TLS negotiation, and network protocol statistics.

## 2. Objectives

- Capture and inspect network traffic.
- Analyze DNS queries and responses.
- Identify the TCP three-way handshake.
- Inspect TLS handshake messages and negotiated parameters.
- Examine protocol hierarchy, conversations, and endpoints.
- Document observations in a reproducible technical report.

## 3. Environment and Tools

- Operating system: Windows
- Network analyzer: Wireshark
- Traffic source: Local network capture
- Test domain: `example.com`
- Test command: `curl.exe -I --connect-timeout 10 https://example.com`

## 4. DNS Analysis

A DNS query for `example.com` was observed.

- Query type: A (IPv4 address)
- DNS response: Observed

This confirms that DNS request and response traffic was present in the capture.

## 5. TCP Analysis

The TCP connection associated with stream 40 was inspected.

- Client source port: 55293
- Server destination port: 443
- SYN: Observed
- SYN-ACK: Observed
- ACK: Observed

The three-way handshake was identified in the same TCP stream, demonstrating the initial establishment of the connection.

## 6. TLS Analysis

The TLS handshake was inspected in TCP stream 40.

- Client Hello: Observed
- Server Hello: Observed
- Negotiated TLS version: TLS 1.3
- Cipher suite: `TLS_AES_256_GCM_SHA384 (0x1302)`

The negotiated cipher suite uses AES-256-GCM for authenticated encryption. SHA-384 is used as part of the TLS 1.3 key-derivation and hash mechanisms associated with this suite.

## 7. Network Statistics

The capture's Wireshark statistics showed the following values:

- Total packets: 97,176
- TCP packets: 35,306
- TLS packets: 12,095
- TCP conversations: 392
- IPv4 endpoints: 170

These statistics describe the inspected capture as a whole, not only the test connection. They may include background network activity.

## 8. Limitations

- The capture represents traffic observed during one collection session.
- Protocol statistics alone cannot establish whether an attack occurred.
- Encrypted TLS application data cannot generally be interpreted as plaintext without appropriate decryption material.
- The analysis does not establish that the entire network is secure.
- IP addresses and other potentially sensitive information should be reviewed before publication.

## 9. Conclusion

This lab demonstrates the use of Wireshark to investigate DNS traffic, identify the TCP three-way handshake, inspect TLS 1.3 negotiation, and summarize network protocol statistics.

The results provide a foundation for further defensive analysis, including traffic filtering, identification of unusual communication patterns, and evidence-based reporting.

## 10. Reproducibility

Display filters used:

- `dns`
- `tcp.stream eq 40`
- `tcp.stream eq 40 && tls.handshake.type == 1`
- `tcp.stream eq 40 && tls.handshake.type == 2`

The original capture should be kept private unless it has been reviewed and sanitized for public release.