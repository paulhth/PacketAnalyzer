import os
import io
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# =========================================
# Config
# =========================================
st.set_page_config(
    page_title="Network Traffic Flow Classifier",
    layout="wide"
)

st.title("Network Traffic Flow Classification Dashboard")
st.write("Analiza flow-based a traficului de rețea și evaluarea modelului de clasificare.")


# =========================================
# Paths
# =========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
default_csv_path = os.path.join(BASE_DIR, "data", "datasets", "prepared_flow_features.csv")

if not os.path.exists(default_csv_path):
    # fallback dacă app.py este în src/
    alt_path = os.path.join(os.path.dirname(BASE_DIR), "data", "datasets", "prepared_flow_features.csv")
    if os.path.exists(alt_path):
        default_csv_path = alt_path


# =========================================
# Helpers
# =========================================
@st.cache_data
def load_dataset(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    return df


def plot_bar(series: pd.Series, title: str, xlabel: str, ylabel: str):
    fig, ax = plt.subplots(figsize=(8, 4))
    series.plot(kind="bar", ax=ax)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    st.pyplot(fig)


def plot_histogram(df: pd.DataFrame, column: str, bins: int = 30):
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(df[column], bins=bins)
    ax.set_title(f"Distribution of {column}")
    ax.set_xlabel(column)
    ax.set_ylabel("Frequency")
    st.pyplot(fig)


def run_experiment(df: pd.DataFrame, feature_columns: list[str], label_column: str = "label") -> dict:
    work_df = df.copy()
    work_df = work_df[work_df[label_column] != "OTHER"].copy()

    X = work_df[feature_columns]
    y = work_df[label_column]

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded
    )

    model = DecisionTreeClassifier(random_state=42)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred)

    return {
        "accuracy": acc,
        "report": report,
        "confusion_matrix": cm,
        "classes": list(label_encoder.classes_)
    }


def plot_confusion_matrix(cm, classes, title: str):
    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(cm)
    ax.set_title(title)
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_xticks(range(len(classes)))
    ax.set_yticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=45, ha="right")
    ax.set_yticklabels(classes)

    for i in range(len(classes)):
        for j in range(len(classes)):
            ax.text(j, i, cm[i, j], ha="center", va="center")

    plt.tight_layout()
    st.pyplot(fig)


# =========================================
# Sidebar
# =========================================
st.sidebar.header("Data Source")

uploaded_file = st.sidebar.file_uploader(
    "Upload prepared_flow_features.csv",
    type=["csv"]
)

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    df.columns = df.columns.str.strip()
    st.sidebar.success("Custom CSV loaded.")
else:
    if os.path.exists(default_csv_path):
        df = load_dataset(default_csv_path)
        st.sidebar.info(f"Using default dataset:\n{default_csv_path}")
    else:
        st.error("Could not find prepared_flow_features.csv. Upload the file from the sidebar.")
        st.stop()

remove_other = st.sidebar.checkbox("Remove OTHER class", value=True)

if remove_other:
    df_view = df[df["label"] != "OTHER"].copy()
else:
    df_view = df.copy()


# =========================================
# Overview
# =========================================
st.header("Dataset Overview")

col1, col2, col3 = st.columns(3)
col1.metric("Rows", len(df_view))
col2.metric("Columns", len(df_view.columns))
col3.metric("Classes", df_view["label"].nunique())

st.subheader("Preview")
st.dataframe(df_view.head(20), use_container_width=True)

st.subheader("Column Names")
st.write(df_view.columns.tolist())


# =========================================
# Label / protocol distributions
# =========================================
st.header("Distributions")

dist_col1, dist_col2 = st.columns(2)

with dist_col1:
    st.subheader("Label Distribution")
    label_counts = df_view["label"].value_counts()
    st.write(label_counts)
    plot_bar(label_counts, "Label Distribution", "Label", "Count")

with dist_col2:
    st.subheader("Transport Protocol Distribution")

    if "transport_protocol" in df_view.columns:
        protocol_counts = df_view["transport_protocol"].value_counts()
        st.write(protocol_counts)
        plot_bar(protocol_counts, "Transport Protocol Distribution", "Protocol", "Count")

    elif "protocol" in df_view.columns:
        protocol_counts = df_view["protocol"].value_counts()
        st.write(protocol_counts)
        plot_bar(protocol_counts, "Protocol Distribution", "Protocol", "Count")

    else:
        st.warning("No transport/protocol column found in dataset.")

# st.subheader("Dominant Highest Layer Distribution")
# layer_counts = df_view["dominant_highest_layer"].value_counts()
# st.write(layer_counts)
# plot_bar(layer_counts, "Dominant Highest Layer Distribution", "Layer", "Count")

st.subheader("Dominant Highest Layer Distribution")

if "dominant_highest_layer" in df_view.columns:
    layer_counts = df_view["dominant_highest_layer"].value_counts()
    st.write(layer_counts)
    plot_bar(layer_counts, "Dominant Highest Layer Distribution", "Layer", "Count")
else:
    st.info("Column 'dominant_highest_layer' is not available in the prepared dataset.")

# =========================================
# Numeric Features
# =========================================
st.header("Numeric Feature Exploration")

numeric_columns = [
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration_sec",
    "packets_per_sec",
    "bytes_per_sec"
]

selected_feature = st.selectbox("Choose a numeric feature", numeric_columns)

plot_histogram(df_view, selected_feature)

st.subheader("Descriptive Statistics")
st.dataframe(df_view[numeric_columns].describe(), use_container_width=True)


# =========================================
# ML Experiments
# =========================================
st.header("ML Experiments")

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

if st.button("Run Experiments"):
    with st.spinner("Training models and generating results..."):
        result_with_ports = run_experiment(df, features_with_ports)
        result_without_ports = run_experiment(df, features_without_ports)

    res_col1, res_col2 = st.columns(2)

    with res_col1:
        st.subheader("Experiment 1: With Ports")
        st.metric("Accuracy", f"{result_with_ports['accuracy']:.4f}")
        st.text("Classification Report")
        st.code(result_with_ports["report"])

        plot_confusion_matrix(
            result_with_ports["confusion_matrix"],
            result_with_ports["classes"],
            "Confusion Matrix - With Ports"
        )

    with res_col2:
        st.subheader("Experiment 2: Without Ports")
        st.metric("Accuracy", f"{result_without_ports['accuracy']:.4f}")
        st.text("Classification Report")
        st.code(result_without_ports["report"])

        plot_confusion_matrix(
            result_without_ports["confusion_matrix"],
            result_without_ports["classes"],
            "Confusion Matrix - Without Ports"
        )


# =========================================
# Footer
# =========================================
st.markdown("---")
st.write("This dashboard uses the prepared flow-based dataset and a Decision Tree classifier.")