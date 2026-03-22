#date brute extrase din PCAP
#date curate, coerente, gata pentru modelul ML
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_file = os.path.join(BASE_DIR, "data/datasets/basic_packet_features.csv")
output_file = os.path.join(BASE_DIR, "data/datasets/prepared_packet_features.csv")

df = pd.read_csv(input_file)

print("Initial shape:", df.shape) #shape with all packets, including those with missing or irrelevant data
print("\nInitial protocol distribution:")
print(df["protocol"].value_counts())

# Keep only useful protocols
allowed_protocols = ["TCP", "TLS", "QUIC", "DNS", "MDNS"]
df = df[df["protocol"].isin(allowed_protocols)].copy()

# Drop rows with missing important fields
df = df.dropna(subset=["protocol", "length", "src_ip", "dst_ip", "src_port", "dst_port"])

# Convert ports and length
df["src_port"] = df["src_port"].astype(int)
df["dst_port"] = df["dst_port"].astype(int)
df["length"] = df["length"].astype(int)

# Create grouped label
def map_label(protocol):
    if protocol in ["TLS", "QUIC"]:
        return "SECURE_WEB"
    elif protocol == "TCP":
        return "TRANSPORT"
    elif protocol in ["DNS", "MDNS"]:
        return "NAME_RESOLUTION"
    return "OTHER"

df["label"] = df["protocol"].apply(map_label)

print("\nPrepared shape:", df.shape) #shape with only the allowed protocols and no missing values
print("\nPrepared protocol distribution:")
print(df["protocol"].value_counts())
print("\nLabel distribution:")
print(df["label"].value_counts())

df.to_csv(output_file, index=False)
print(f"\nSaved cleaned dataset to: {output_file}")#This will save the cleaned and prepared dataset to a new CSV file, ready for analysis and modeling.