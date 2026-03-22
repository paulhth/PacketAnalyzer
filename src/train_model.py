import os
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_file = os.path.join(BASE_DIR, "data/datasets/prepared_packet_features.csv")

df = pd.read_csv(input_file)

print("Dataset shape:", df.shape)
print("\nLabel distribution:")
print(df["label"].value_counts())

# Features si target
X = df[["length", "src_port", "dst_port"]]
y = df["label"]

# Encode labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

print("\nLabel mapping:")
for index, class_name in enumerate(label_encoder.classes_):
    print(f"{class_name} -> {index}")

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

# Model
model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)

# Predictii
y_pred = model.predict(X_test)

# Evaluare
accuracy = accuracy_score(y_test, y_pred)

print(f"\nAccuracy: {accuracy:.4f}")
print("\nClassification report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

print("\nConfusion matrix:")
print(confusion_matrix(y_test, y_pred))