import os
import pyshark

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
input_file = os.path.join(BASE_DIR, "data/raw_pcaps/http_trace_sample.pcapng")

print(f"Reading from: {input_file}")

capture = pyshark.FileCapture(
    input_file,
    keep_packets=False,
    decode_as={"tcp.port==8000": "http"}
)

count_port_8000 = 0

for packet in capture:
    try:
        if hasattr(packet, "tcp"):
            src_port = getattr(packet.tcp, "srcport", "")
            dst_port = getattr(packet.tcp, "dstport", "")

            if src_port == "8000" or dst_port == "8000":
                count_port_8000 += 1

                print("\n==============================")
                print(f"Packet #{count_port_8000}")
                print(f"Highest layer: {packet.highest_layer}")
                print("Layers:", [layer.layer_name for layer in packet.layers])
                print(f"Ports: {src_port} -> {dst_port}")

                if hasattr(packet, "http"):
                    print("HTTP layer detected!")
                    print("HTTP field names:", packet.http.field_names)

                    for field_name in packet.http.field_names:
                        try:
                            print(f"  {field_name}: {getattr(packet.http, field_name)}")
                        except Exception:
                            pass
                else:
                    print("No HTTP layer detected for this packet.")

                if count_port_8000 >= 10:
                    break

    except Exception as e:
        print(f"Skipping packet due to error: {e}")

capture.close()

print(f"\nTotal packets found on port 8000 (inspected up to 10): {count_port_8000}")