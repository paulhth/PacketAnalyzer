# Acest script analizează datasetul de caracteristici ale fluxurilor și oferă o 
# descriere detaliată a acestuia, inclusiv primele 10 rânduri, 
# dimensiunea datasetului, coloanele disponibile, valorile lipsă, 
# distribuția etichetelor și statistici descriptive pentru câmpurile numerice.

import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_file = os.path.join(BASE_DIR, "data/datasets/flow_packet_features.csv")

df = pd.read_csv(input_file)
df.columns = df.columns.str.strip()

print("Primele 10 randuri:")
print(df.head(10))
print()

print("Dimensiune dataset:")
print(df.shape)
print()

print("Coloane:")
print(df.columns.tolist())
print()

print("Valori lipsa pe coloane:")
print(df.isna().sum())
print()

print("Distributia etichetelor:")
print(df["label"].value_counts())
print()

print("Distributia dominant_highest_layer:")
print(df["dominant_highest_layer"].value_counts())
print()

print("Distributia transport_protocol:")
print(df["transport_protocol"].value_counts())
print()

print("Statistici pentru packet_count:")
print(df["packet_count"].describe())
print()

print("Statistici pentru total_bytes:")
print(df["total_bytes"].describe())
print()

print("Statistici pentru avg_packet_size:")
print(df["avg_packet_size"].describe())
print()

print("Statistici pentru duration_sec:")
print(df["duration_sec"].describe())
print()

print("Statistici pentru packets_per_sec:")
print(df["packets_per_sec"].describe())
print()

print("Statistici pentru bytes_per_sec:")
print(df["bytes_per_sec"].describe())
print()