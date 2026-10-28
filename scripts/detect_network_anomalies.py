
import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


def find_tshark():
    """Find TShark in PATH or the default Wireshark installation folder."""
    executable = shutil.which("tshark")
    if executable:
        return executable

    default_path = Path(
        r"C:\Program Files\Wireshark\tshark.exe"
    )
    if default_path.exists():
        return str(default_path)

    return None


def count_packets(tshark, capture, display_filter=None):
    """Count packets matching a Wireshark display filter."""
    command = [tshark, "-r", str(capture), "-T", "fields",
               "-e", "frame.number"]

    if display_filter:
        command[1:1] = ["-Y", display_filter]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def read_retransmissions(tshark, capture):
    """Extract retransmission records for later aggregation."""
    command = [
        tshark, "-r", str(capture),
        "-Y", "tcp.analysis.retransmission",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tcp.stream",
        "-e", "frame.number",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )

    rows = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            continue

        src, sport, dst, dport, stream, frame = fields
        rows.append({
            "source": f"{src}:{sport}",
            "destination": f"{dst}:{dport}",
            "stream": stream,
            "frame": frame,
        })

    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Basic network anomaly triage using TShark."
    )
    parser.add_argument("capture", help="Path to a .pcap or .pcapng file")
    parser.add_argument(
        "--output",
        default="reports/network-detection",
        help="Output file prefix (default: reports/network-detection)",
    )
    args = parser.parse_args()

    capture = Path(args.capture)
    if not capture.is_file():
        print(f"ERROR: Capture file not found: {capture}", file=sys.stderr)
        return 1

    tshark = find_tshark()
    if not tshark:
        print(
            "ERROR: TShark not found. Install Wireshark or add TShark to PATH.",
            file=sys.stderr,
        )
        return 1

    try:
        # Validate that TShark can read the capture.
        subprocess.run(
            [tshark, "-r", str(capture), "-c", "1"],
            capture_output=True,
            text=True,
            check=True,
        )

        total = count_packets(tshark, capture)
        metrics = {
            "capture_file": str(capture),
            "total_packets": total,
            "tcp_packets": count_packets(tshark, capture, "tcp"),
            "tls_packets": count_packets(tshark, capture, "tls"),
            "tcp_retransmissions": count_packets(
                tshark, capture, "tcp.analysis.retransmission"
            ),
            "tcp_duplicate_acks": count_packets(
                tshark, capture, "tcp.analysis.duplicate_ack"
            ),
            "tcp_resets": count_packets(
                tshark, capture, "tcp.flags.reset == 1"
            ),
            "tcp_lost_segment_flags": count_packets(
                tshark, capture, "tcp.analysis.lost_segment"
            ),
            "tcp_out_of_order_flags": count_packets(
                tshark, capture, "tcp.analysis.out_of_order"
            ),
        }

        retransmissions = read_retransmissions(tshark, capture)
        endpoint_counts = Counter(
            (row["source"], row["destination"])
            for row in retransmissions
        )
        stream_counts = Counter(row["stream"] for row in retransmissions)

        output_prefix = Path(args.output)
        output_prefix.parent.mkdir(parents=True, exist_ok=True)

        json_path = output_prefix.with_suffix(".json")
        csv_path = output_prefix.with_name(
            output_prefix.name + "-retransmissions.csv"
        )

        with json_path.open("w", encoding="utf-8") as file:
            json.dump(
                {
                    "metrics": metrics,
                    "top_retransmission_flows": [
                        {
                            "source": src,
                            "destination": dst,
                            "retransmission_packets": count,
                        }
                        for (src, dst), count in endpoint_counts.most_common(10)
                    ],
                    "top_retransmission_streams": [
                        {"tcp_stream": stream, "retransmission_packets": count}
                        for stream, count in stream_counts.most_common(10)
                    ],
                    "note": (
                        "These are packet counts and diagnostic indicators. "
                        "They do not prove an attack or identify the root cause."
                    ),
                },
                file,
                indent=2,
            )

        with csv_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "source", "destination", "stream", "frame"
                ],
            )
            writer.writeheader()
            writer.writerows(retransmissions)

        print("\n=== Network Traffic Detection Summary ===")
        for name, value in metrics.items():
            print(f"{name}: {value}")

        print("\nTop retransmission flows:")
        for (src, dst), count in endpoint_counts.most_common(10):
            print(f"{count:>5}  {src} -> {dst}")

        print(f"\nJSON report: {json_path}")
        print(f"Retransmission CSV: {csv_path}")
        print("Note: These indicators alone do not prove malicious activity.")
        return 0

    except subprocess.CalledProcessError as error:
        print("ERROR: TShark could not analyze the capture.", file=sys.stderr)
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
