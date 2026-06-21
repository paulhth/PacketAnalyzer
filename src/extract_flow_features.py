#citește PCAP-ul cu pyshark
#păstrează doar pachete IP + TCP/UDP
#grupează pachetele după cheia flow-ului
#actualizează statisticile flow-ului
#la final scrie un CSV cu un rând per flow

#un flow este definit de tuple-ul (src_ip, dst_ip, src_port, dst_port, transport_protocol)
#apoi pentru fiecare flow calculăm:
#- numărul total de pachete
#- numărul total de bytes
#- dimensiunea medie a pachetelor
#- dimensiunea minimă a pachetelor
#- dimensiunea maximă a pachetelor
#- durata flow-ului (timpul dintre primul și ultimul pachet)

import os
import csv
import pyshark
from collections import defaultdict
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#input_file = os.path.join(BASE_DIR, "data/raw_pcaps/traffic_sample.pcapng")
input_file = os.path.join(BASE_DIR, "data/raw_pcaps/1406.pcapng")
output_file = os.path.join(BASE_DIR, "data/datasets/flow_packet_features.csv")

print(f"Reading from: {input_file}")
print(f"Writing to: {output_file}")


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def map_label(highest_layer: str) -> str:
    """
    Etichetare simplă, similară cu logica ta actuală.
    Poate fi rafinată mai târziu.
    """
    if highest_layer in ["TLS", "QUIC"]:
        return "SECURE_WEB"
    elif highest_layer in ["DNS", "MDNS"]:
        return "NAME_RESOLUTION"
    elif highest_layer == "TCP":
        return "TRANSPORT"
    elif highest_layer == "UDP":
        return "TRANSPORT"
    return "OTHER"


# Structura internă pentru flow-uri
flows = {}

capture = pyshark.FileCapture(input_file, keep_packets=False)

packet_count = 0
skipped_count = 0

for packet in capture:
    try:
        # Acceptăm doar pachete IP
        if not hasattr(packet, "ip"):
            skipped_count += 1
            continue

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        transport_protocol = None
        src_port = None
        dst_port = None

        if hasattr(packet, "tcp"):
            transport_protocol = "TCP"
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
        elif hasattr(packet, "udp"):
            transport_protocol = "UDP"
            src_port = int(packet.udp.srcport)
            dst_port = int(packet.udp.dstport)
        else:
            skipped_count += 1
            continue

        packet_length = int(packet.length)
        packet_time = packet.sniff_timestamp  # string, ex. "1712345678.123456"
        packet_time = safe_float(packet_time)

        highest_layer = packet.highest_layer

        # Flow key unidirecțional
        flow_key = (src_ip, dst_ip, src_port, dst_port, transport_protocol)

        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "transport_protocol": transport_protocol,
                "packet_count": 0,
                "total_bytes": 0,
                "min_packet_size": packet_length,
                "max_packet_size": packet_length,
                "first_seen": packet_time,
                "last_seen": packet_time,
                "highest_layer_counts": defaultdict(int)
            }

        flow = flows[flow_key]

        flow["packet_count"] += 1
        flow["total_bytes"] += packet_length
        flow["min_packet_size"] = min(flow["min_packet_size"], packet_length)
        flow["max_packet_size"] = max(flow["max_packet_size"], packet_length)
        flow["first_seen"] = min(flow["first_seen"], packet_time)
        flow["last_seen"] = max(flow["last_seen"], packet_time)
        flow["highest_layer_counts"][highest_layer] += 1

        packet_count += 1
        if packet_count % 500 == 0:
            print(f"Processed {packet_count} packets...")

        if packet_count >= 50000:
            print("Reached test limit of 50000 packets.")
            break

    except Exception as e:
        skipped_count += 1
        print(f"Skipping packet because of error: {e}")

capture.close()

# Scriere CSV
rows = []

for flow_key, flow in flows.items():
    duration_sec = flow["last_seen"] - flow["first_seen"]

    # Evităm împărțirea la 0
    if duration_sec <= 0:
        duration_sec = 0.000001

    avg_packet_size = flow["total_bytes"] / flow["packet_count"]
    packets_per_sec = flow["packet_count"] / duration_sec
    bytes_per_sec = flow["total_bytes"] / duration_sec

    # Cel mai frecvent highest_layer din flow
    dominant_highest_layer = max(
        flow["highest_layer_counts"],
        key=flow["highest_layer_counts"].get
    )

    label = map_label(dominant_highest_layer)

    rows.append([
        flow["src_ip"],
        flow["dst_ip"],
        flow["src_port"],
        flow["dst_port"],
        flow["transport_protocol"],
        flow["packet_count"],
        flow["total_bytes"],
        round(avg_packet_size, 2),
        flow["min_packet_size"],
        flow["max_packet_size"],
        round(duration_sec, 6),
        round(packets_per_sec, 2),
        round(bytes_per_sec, 2),
        dominant_highest_layer,
        label
    ])

with open(output_file, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "transport_protocol",
        "packet_count",
        "total_bytes",
        "avg_packet_size",
        "min_packet_size",
        "max_packet_size",
        "duration_sec",
        "packets_per_sec",
        "bytes_per_sec",
        "dominant_highest_layer",
        "label"
    ])
    writer.writerows(rows)

print("\nDone.")
print(f"Processed packets: {packet_count}")
print(f"Skipped packets: {skipped_count}")
print(f"Extracted flows: {len(rows)}")
print(f"Saved flow dataset to: {output_file}")