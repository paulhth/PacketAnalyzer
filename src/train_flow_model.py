import os
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
#from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_file = os.path.join(BASE_DIR, "data/datasets/prepared_flow_features.csv")

df = pd.read_csv(input_file)

df.columns = df.columns.str.strip()

# Eliminam OTHER
df = df[df["label"] != "OTHER"]

print("Dataset shape:", df.shape)
print("\nLabel distribution:")
print(df["label"].value_counts())

# =========================
# EXPERIMENT 1: CU PORTURI
# =========================

print("\n=========================")
print("EXPERIMENT 1: WITH PORTS")
print("=========================")

features_with_ports = [
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

X = df[features_with_ports]
y = df["label"]

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print("\nLabel mapping:")
for i, label in enumerate(label_encoder.classes_):
    print(f"{label} -> {i}")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

#model = DecisionTreeClassifier(random_state=42)
model = RandomForestClassifier(random_state=42, n_estimators=100)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# =========================
# EXPERIMENT 2: FARA PORTURI
# =========================

print("\n============================")
print("EXPERIMENT 2: WITHOUT PORTS")
print("============================")

features_without_ports = [
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration_sec",
    "packets_per_sec",
    "bytes_per_sec"
]

X = df[features_without_ports]
y = df["label"]

y_encoded = label_encoder.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)

#model = DecisionTreeClassifier(random_state=42)
model = RandomForestClassifier(random_state=42, n_estimators=100)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))