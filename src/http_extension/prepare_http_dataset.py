import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
input_file = os.path.join(BASE_DIR, "data/datasets/http_raw_features.csv")
output_file = os.path.join(BASE_DIR, "data/datasets/http_prepared_dataset.csv")

print(f"Reading from: {input_file}")
print(f"Writing to: {output_file}")

df = pd.read_csv(input_file)

print("\nInitial shape:", df.shape)
print("\nInitial columns:")
print(df.columns.tolist())

# Fill missing text fields
text_columns = ["method", "uri", "host", "user_agent", "request_version", "request_line", "src_ip", "dst_ip"]
for col in text_columns:
    if col in df.columns:
        df[col] = df[col].fillna("").astype(str)

# Fill and convert numeric fields
numeric_columns = [
    "src_port", "dst_port", "length", "uri_length", "has_query",
    "query_length", "num_params", "num_slashes", "num_dots",
    "num_special_chars", "num_encoded_chars",
    "has_trace_method", "has_suspicious_uri_pattern"
]

for col in numeric_columns:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

# Optional cleanup: keep only real-looking HTTP methods
allowed_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"]
df = df[df["method"].isin(allowed_methods)].copy()

def assign_http_label(row):
    reasons = []

    # Strong suspicious signals
    if row["has_trace_method"] == 1:
        reasons.append("TRACE method")

    if row["has_suspicious_uri_pattern"] == 1:
        reasons.append("Suspicious URI pattern")

    # Structural suspicious-looking heuristics
    if row["uri_length"] > 40:
        reasons.append("Long URI")

    if row["query_length"] > 25:
        reasons.append("Long query")

    if row["num_params"] >= 3:
        reasons.append("Many parameters")

    if row["num_special_chars"] >= 4:
        reasons.append("Many special chars")

    if row["num_encoded_chars"] >= 1:
        reasons.append("Encoded characters")

    if row["num_slashes"] >= 5:
        reasons.append("Deep path")

    if row["method"] in ["TRACE"]:
        reasons.append("Uncommon method")

    # Labeling rule
    if len(reasons) > 0:
        return pd.Series(["suspicious_http", "; ".join(reasons)])
    else:
        return pd.Series(["benign_http", "Normal-looking request"])

df[["label", "label_reason"]] = df.apply(assign_http_label, axis=1)

# Reorder columns for readability
preferred_order = [
    "method",
    "uri",
    "host",
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
    "has_suspicious_uri_pattern",
    "label",
    "label_reason"
]

existing_columns = [col for col in preferred_order if col in df.columns]
remaining_columns = [col for col in df.columns if col not in existing_columns]
df = df[existing_columns + remaining_columns]

print("\nPrepared shape:", df.shape)
print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nLabel reasons distribution:")
print(df["label_reason"].value_counts())

df.to_csv(output_file, index=False)
print(f"\nSaved prepared HTTP dataset to: {output_file}")