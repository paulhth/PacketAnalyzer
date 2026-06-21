#   Acest script curata si pregateste dataset-ul de flow-uri pentru antrenarea modelului de detectie a intruziunilor.
#   am scos src_ip, dst_ip, modelul ar invata IP-uri, useless 
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_file = os.path.join(BASE_DIR, "data/datasets/flow_packet_features.csv")
output_file = os.path.join(BASE_DIR, "data/datasets/prepared_flow_features.csv")

df = pd.read_csv(input_file)

# Curatam coloanele
df.columns = df.columns.str.strip()

print("Initial shape:", df.shape)

# 1. Eliminam label OTHER
df = df[df["label"] != "OTHER"]

print("After removing OTHER:", df.shape)

# # 2. Eliminam flow-uri cu durata foarte mica
# df = df[df["duration_sec"] > 0.001] => scos pt ca e problema la DNS, multe flow-uri legitime au durata foarte mica

print("After removing near-zero duration:", df.shape)

# 3. Eliminam outliers extreme (optional, dar recomandat)
# df = df[df["packet_count"] < 5000]
# df = df[df["bytes_per_sec"] < 1e7]
df = df[df["packet_count"] < 10000]
df = df[df["bytes_per_sec"] < 1e8]

print("After removing outliers:", df.shape)

# 4. Selectam features relevante
# IMPORTANT: scoatem IP-uri (nu ajuta la generalizare)
features = [
    "src_port",
    "dst_port",
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration_sec",
    "packets_per_sec",
    "bytes_per_sec"
]

X = df[features]
y = df["label"]

# Reconstruct dataframe
df_clean = X.copy()
df_clean["label"] = y

print("\nFinal dataset shape:", df_clean.shape)
print("\nLabel distribution:")
print(df_clean["label"].value_counts())

# Salvare
df_clean.to_csv(output_file, index=False)
print(f"\nSaved cleaned dataset to: {output_file}")