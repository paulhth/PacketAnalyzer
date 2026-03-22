import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_file = os.path.join(BASE_DIR, "data/datasets/basic_packet_features.csv")

df = pd.read_csv(input_file)

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

print("Distributia protocoalelor:")
print(df["protocol"].value_counts())
print()

print("Top source ports:")
print(df["src_port"].value_counts().head(10))
print()

print("Top destination ports:")
print(df["dst_port"].value_counts().head(10))
print()

print("Statistici pentru lungimea pachetelor:")
print(df["length"].describe())