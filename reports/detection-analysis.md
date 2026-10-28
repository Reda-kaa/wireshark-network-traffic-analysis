# TCP Retransmission Analysis

## 1. Objective

Investigate TCP retransmissions in a captured network trace using Wireshark and TShark.

## 2. Analysis Scope

- Capture file: `first-traffic-analysis.pcapng`
- TCP stream: `115`
- Local endpoint: `192.168.3.208:55369`
- Remote endpoint: `104.18.39.21:443`

## 3. Observations

### TCP connection establishment

The initial packets show a successful TCP three-way handshake:

1. SYN — frame 23618
2. SYN-ACK — frame 23619
3. ACK — frame 23620

### Retransmissions

TShark identified multiple retransmissions in stream 115.

For example, frames 30015, 30018, 30020, and 30022 share these values:

- Relative sequence number: 5320
- Acknowledgment number: 9828
- TCP payload length: 24 bytes

Another group, frames 47972, 48099, 48100, 48102, 48105, 48144, 48202, and 48650, shares:

- Relative sequence number: 8124
- Acknowledgment number: 12936
- TCP payload length: 24 bytes

The first observed transmission in this second group is frame 47927, at approximately 2705.815 seconds. The last listed retransmission is frame 48650, at approximately 2741.107 seconds.

### ACK and packet-analysis filters

The duplicate-ACK filter returned 10 packets in stream 115.

The filter for `tcp.analysis.lost_segment` or `tcp.analysis.out_of_order` returned no packets.

A query for ACKs originating from the local endpoint with `tcp.ack >= 8124` returned only frame 46643. This query does not establish whether the remote segment was ultimately received, because the capture may not contain every relevant packet or acknowledgment.

## 4. Interpretation

The capture contains repeated transmissions of TCP data that Wireshark classifies as retransmissions. Possible explanations include packet loss, delayed acknowledgments, network congestion, or capture limitations.

The available observations do not establish the root cause. They also do not, by themselves, indicate a cyberattack.

## 5. Limitations

- The analysis is limited to the packets present in this capture.
- Wireshark's TCP analysis flags are diagnostic indicators, not proof of malicious activity.
- Further investigation would require examining the surrounding packets and the capture environment.

## 6. Tools

- Wireshark
- TShark
- PowerShell

## 7. Conclusion

This investigation demonstrates how to filter a TCP stream, identify retransmissions, inspect acknowledgment numbers, and document network anomalies without overstating what the evidence proves.