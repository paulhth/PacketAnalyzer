#capture = pyshark.FileCapture(input_file, keep_packets=False)
#the line above is an optimization to prevent pyshark from keeping all packets in memory, which can lead to high memory usage for large pcap files. However, it may cause issues if we need to access packet details after processing them. For now, we will keep it as is and monitor memory usage during testing.

import csv
import pyshark
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

input_file = os.path.join(BASE_DIR, "data/raw_pcaps/traffic_sample.pcapng")
output_file = os.path.join(BASE_DIR, "data/datasets/basic_packet_features.csv")

print(f"Reading from: {input_file}")
print(f"Writing to: {output_file}")

capture = pyshark.FileCapture(input_file)

rows = []
count = 0

for packet in capture:
    try:
        protocol = packet.highest_layer
        length = packet.length

        src_ip = packet.ip.src if hasattr(packet, "ip") else ""
        dst_ip = packet.ip.dst if hasattr(packet, "ip") else ""

        src_port = ""
        dst_port = ""

        if hasattr(packet, "tcp"):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
        elif hasattr(packet, "udp"):
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport

        rows.append([
            protocol,
            length,
            src_ip,
            dst_ip,
            src_port,
            dst_port
        ])

        count += 1
        if count % 100 == 0:
            print(f"Processed {count} packets...")

        # Limit to first 1000 packets for testing - @TODO: Remove this limit for full dataset
        if count >= 1000:
            break

    except Exception as e:
        print(f"Skipping packet because of error: {e}")

capture.close()

with open(output_file, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "protocol",
        "length",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port"
    ])
    writer.writerows(rows)

print(f"Saved {len(rows)} rows to {output_file}")