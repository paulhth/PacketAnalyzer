import csv
import os
import re
import pyshark

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
input_file = os.path.join(BASE_DIR, "data/raw_pcaps/http_lo0_capture.pcapng")
output_file = os.path.join(BASE_DIR, "data/datasets/http_raw_features.csv")

os.makedirs(os.path.dirname(output_file), exist_ok=True)


def hex_payload_to_text(hex_payload: str) -> str:
    """
    Converts colon-separated hex payload (e.g. '47:45:54:20...')
    to decoded text.
    """
    try:
        raw_bytes = bytes.fromhex(hex_payload.replace(":", ""))
        return raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_host(payload_text: str) -> str:
    match = re.search(r"^Host:\s*(.+)$", payload_text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def extract_user_agent(payload_text: str) -> str:
    match = re.search(r"^User-Agent:\s*(.+)$", payload_text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def count_encoded_sequences(text: str) -> int:
    return len(re.findall(r"%[0-9A-Fa-f]{2}", text))


def count_special_chars(text: str) -> int:
    return len(re.findall(r"[^a-zA-Z0-9/_\-\.\?=&]", text))


def has_suspicious_pattern(text: str) -> int:
    patterns = [
        r"(?i)<script",
        r"\.\./",
        r"%2e%2e",
        r"(?i)javascript:",
        r"(?i)\bunion\b",
        r"(?i)\bselect\b",
        r"(?i)\bor\b\s+1=1",
    ]
    return int(any(re.search(pattern, text) for pattern in patterns))


print(f"Reading from: {input_file}")
print(f"Writing to: {output_file}")

capture = pyshark.FileCapture(input_file, keep_packets=False)

rows = []
processed_packets = 0
http_requests = 0

for packet in capture:
    processed_packets += 1

    try:
        if not hasattr(packet, "tcp"):
            continue

        src_port = str(getattr(packet.tcp, "srcport", ""))
        dst_port = str(getattr(packet.tcp, "dstport", ""))

        # We only want client -> server requests to local server on port 8000
        if dst_port != "8000":
            continue

        if not hasattr(packet.tcp, "payload"):
            continue

        payload_hex = packet.tcp.payload
        payload_text = hex_payload_to_text(payload_hex)

        if not payload_text:
            continue

        first_line = payload_text.splitlines()[0] if payload_text.splitlines() else ""

        # Simple HTTP request line detection
        # Examples: GET / HTTP/1.1, HEAD / HTTP/1.1
        request_match = re.match(
            r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+(\S+)\s+(HTTP/\d\.\d)$",
            first_line
        )

        if not request_match:
            continue

        method = request_match.group(1)
        uri = request_match.group(2)
        request_version = request_match.group(3)

        host = extract_host(payload_text)
        user_agent = extract_user_agent(payload_text)

        src_ip = packet.ip.src if hasattr(packet, "ip") else ""
        dst_ip = packet.ip.dst if hasattr(packet, "ip") else ""
        length = str(getattr(packet, "length", "0"))

        uri_length = len(uri)
        has_query = int("?" in uri)
        query_string = uri.split("?", 1)[1] if "?" in uri else ""
        query_length = len(query_string)
        num_params = query_string.count("&") + 1 if query_string else 0
        num_slashes = uri.count("/")
        num_dots = uri.count(".")
        num_special_chars = count_special_chars(uri)
        num_encoded_chars = count_encoded_sequences(uri)
        has_trace_method = int(method.upper() == "TRACE")
        has_suspicious_uri_pattern = has_suspicious_pattern(uri)

        rows.append([
            method,
            uri,
            host,
            user_agent,
            request_version,
            first_line,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            length,
            uri_length,
            has_query,
            query_length,
            num_params,
            num_slashes,
            num_dots,
            num_special_chars,
            num_encoded_chars,
            has_trace_method,
            has_suspicious_uri_pattern
        ])

        http_requests += 1

        if http_requests % 10 == 0:
            print(f"Extracted {http_requests} HTTP requests...")

    except Exception as e:
        print(f"Skipping packet due to error: {e}")

capture.close()

with open(output_file, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "method",
        "uri",
        "host",
        "user_agent",
        "request_version",
        "request_line",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "length",
        "uri_length",
        "has_query",
        "query_length",
        "num_params",
        "num_slashes",
        "num_dots",
        "num_special_chars",
        "num_encoded_chars",
        "has_trace_method",
        "has_suspicious_uri_pattern"
    ])
    writer.writerows(rows)

print(f"\nProcessed packets: {processed_packets}")
print(f"Extracted HTTP requests: {http_requests}")
print(f"Saved {len(rows)} rows to {output_file}")