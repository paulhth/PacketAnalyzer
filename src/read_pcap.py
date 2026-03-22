import pyshark

capture = pyshark.FileCapture("../data/raw_pcaps/traffic_sample.pcapng")

##################################################
# Global Variables Start
##################################################
count = 0
dns_count = 0
icmp_count = 0
tls_count = 0
tcp_count = 0
total = 0
##################################################
# Global Variables End
##################################################

for packet in capture:
    try:
        total += 1
        layer = packet.highest_layer # Get the highest layer of the packet from the capture a


        if layer == "DNS":
            dns_count += 1
        elif layer == "ICMP":
            icmp_count += 1
        elif layer == "TLS":
            tls_count += 1
        elif layer == "TCP":
            tcp_count += 1

        print(
            f"Packet #{count + 1}: "
            f"highest_layer={packet.highest_layer}, "
            f"length={packet.length}"
        )
        count += 1

        if count >= 20:
            break
    except Exception as e:
        print(f"Skipping packet because of error: {e}")

print("######################--END--######################\nSummary:")
print(f"Total packets: {total}")
print(f"DNS packets: {dns_count}")
print(f"ICMP packets: {icmp_count}")
print(f"TLS packets: {tls_count}")
print(f"TCP packets: {tcp_count}")

capture.close()