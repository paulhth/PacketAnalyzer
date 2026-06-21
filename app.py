import os
from typing import Any, Optional

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


# =========================================
# Config
# =========================================
st.set_page_config(
    page_title="Network Traffic Flow Classifier",
    layout="wide",
)

st.title("Network Traffic Flow Classification Dashboard")
st.write(
    "Analiza flow-based a traficului de rețea și evaluarea unui model "
    "Random Forest pentru clasificarea traficului."
)


# =========================================
# Paths
# =========================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
default_csv_path = os.path.join(BASE_DIR, "data", "datasets", "prepared_flow_features.csv")

if not os.path.exists(default_csv_path):
    # Fallback pentru cazul în care app.py este rulat dintr-un director src/.
    alt_path = os.path.join(
        os.path.dirname(BASE_DIR),
        "data",
        "datasets",
        "prepared_flow_features.csv",
    )
    if os.path.exists(alt_path):
        default_csv_path = alt_path


# =========================================
# Feature sets
# =========================================
FEATURES_WITH_PORTS = [
    "src_port",
    "dst_port",
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration_sec",
    "packets_per_sec",
    "bytes_per_sec",
]

FEATURES_WITHOUT_PORTS = [
    "packet_count",
    "total_bytes",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "duration_sec",
    "packets_per_sec",
    "bytes_per_sec",
]

NUMERIC_COLUMNS = FEATURES_WITHOUT_PORTS


# =========================================
# Helpers
# =========================================
@st.cache_data
def load_dataset(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    return df


def get_missing_columns(df: pd.DataFrame, required_columns: list[str]) -> list[str]:
    return [column for column in required_columns if column not in df.columns]


def plot_feature_importance(model: RandomForestClassifier, feature_names: list[str]) -> None:
    importances = model.feature_importances_
    feat_imp = pd.Series(importances, index=feature_names).sort_values(ascending=False)

    st.subheader("Feature Importance")
    st.dataframe(feat_imp.rename("importance"), use_container_width=True)

    fig, ax = plt.subplots(figsize=(8, 4))
    feat_imp.plot(kind="bar", ax=ax)
    ax.set_title("Feature Importance")
    ax.set_xlabel("Feature")
    ax.set_ylabel("Importance")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)


def plot_bar(series: pd.Series, title: str, xlabel: str, ylabel: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    series.plot(kind="bar", ax=ax)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)


def plot_histogram(df: pd.DataFrame, column: str, bins: int = 30) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(df[column], bins=bins)
    ax.set_title(f"Distribution of {column}")
    ax.set_xlabel(column)
    ax.set_ylabel("Frequency")
    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)


def plot_top_flows(df: pd.DataFrame, top_n: int = 10, by: str = "total_bytes", save_path: Optional[str] = None) -> None:
    """
    Plots top-N flows by a given metric (horizontal bar chart) and optionally saves the figure.
    Expects the dataset to contain src_ip, dst_ip, src_port, dst_port, transport_protocol and the metric column.
    """
    if by not in df.columns:
        st.warning(f"Column '{by}' not found in dataset.")
        return

    # Build readable labels for flows
    def make_label(r):
        try:
            return f"{r['src_ip']}:{int(r['src_port'])} → {r['dst_ip']}:{int(r['dst_port'])} ({r.get('transport_protocol','')})"
        except Exception:
            return f"{r.get('src_ip','?')}:{r.get('src_port','?')} → {r.get('dst_ip','?')}:{r.get('dst_port','?')}"

    df = df.copy()
    df["flow_label"] = df.apply(make_label, axis=1)

    top = df.sort_values(by=by, ascending=False).head(top_n).reset_index(drop=True)

    labels = top["flow_label"].tolist()[::-1]
    values = top[by].tolist()[::-1]

    fig, ax = plt.subplots(figsize=(10, max(4, 0.5 * top_n)))
    ax.barh(range(len(values)), values, color="C0")
    ax.set_yticks(range(len(values)))
    ax.set_yticklabels(labels)
    ax.set_xlabel(by)
    ax.set_title(f"Top {top_n} flows by {by}")
    plt.tight_layout()

    if save_path:
        try:
            fig.savefig(save_path, dpi=150)
            st.success(f"Saved plot to: {save_path}")
        except Exception as e:
            st.error(f"Failed to save plot: {e}")

    st.pyplot(fig)
    plt.close(fig)


def plot_confusion_matrix(cm: Any, classes: list[str], title: str) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.imshow(cm)
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
    plt.close(fig)


def run_experiment(
    df: pd.DataFrame,
    feature_columns: list[str],
    label_column: str = "label",
) -> dict[str, Any]:
    required_columns = feature_columns + [label_column]
    missing_columns = get_missing_columns(df, required_columns)

    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

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
        stratify=y_encoded,
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    return {
        "accuracy": accuracy_score(y_test, y_pred),
        "report": classification_report(
            y_test,
            y_pred,
            target_names=label_encoder.classes_,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred),
        "classes": list(label_encoder.classes_),
        "model": model,
    }


# =========================================
# Sidebar
# =========================================
st.sidebar.header("Data Source")

uploaded_file = st.sidebar.file_uploader(
    "Upload prepared_flow_features.csv",
    type=["csv"],
)

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    df.columns = df.columns.str.strip()
    st.sidebar.success("Custom CSV loaded.")
elif os.path.exists(default_csv_path):
    df = load_dataset(default_csv_path)
    st.sidebar.info(f"Using default dataset:\n{default_csv_path}")
else:
    st.error("Could not find prepared_flow_features.csv. Upload the file from the sidebar.")
    st.stop()

if "label" not in df.columns:
    st.error("The dataset must contain a 'label' column.")
    st.stop()

remove_other = st.sidebar.checkbox("Remove OTHER class", value=True)
df_view = df[df["label"] != "OTHER"].copy() if remove_other else df.copy()


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

available_numeric_columns = [column for column in NUMERIC_COLUMNS if column in df_view.columns]

if not available_numeric_columns:
    st.warning("No expected numeric feature columns were found in the dataset.")
else:
    selected_feature = st.selectbox("Choose a numeric feature", available_numeric_columns)
    plot_histogram(df_view, selected_feature)

    st.subheader("Descriptive Statistics")
    st.dataframe(df_view[available_numeric_columns].describe(), use_container_width=True)


# =========================================
# Top Flows (new)
# =========================================
st.header("Top Flows")
tf_col1, tf_col2 = st.columns([1, 2])

with tf_col1:
    metric_option = st.selectbox("Rank flows by:", options=[c for c in ["total_bytes", "packet_count"] if c in df_view.columns])
    top_n = st.number_input("Top N", min_value=1, max_value=200, value=10, step=1)
    save_png = st.text_input("Optional: save plot to (e.g. out/top_flows.png)", value="")
    if st.button("Show Top Flows"):
        save_path = save_png.strip() or None
        plot_top_flows(df_view, top_n=top_n, by=metric_option, save_path=save_path)

with tf_col2:
    st.markdown(
        "Use this control to visualize the top flows in the dataset. The chart builds readable labels like `src:port → dst:port (PROTO)`."
    )


# =========================================
# ML Experiments
# =========================================
st.header("ML Experiments")
st.write(
    "The experiments use Random Forest with 100 estimators, a fixed random state, "
    "and an 80/20 stratified train-test split."
)

if st.button("Run Experiments"):
    try:
        with st.spinner("Training Random Forest models and generating results..."):
            result_with_ports = run_experiment(df, FEATURES_WITH_PORTS)
            result_without_ports = run_experiment(df, FEATURES_WITHOUT_PORTS)
    except ValueError as error:
        st.error(str(error))
        st.stop()

    res_col1, res_col2 = st.columns(2)

    with res_col1:
        st.subheader("Experiment 1: With Ports")
        st.metric("Accuracy", f"{result_with_ports['accuracy']:.4f}")
        st.text("Classification Report")
        st.code(result_with_ports["report"])

        plot_confusion_matrix(
            result_with_ports["confusion_matrix"],
            result_with_ports["classes"],
            "Confusion Matrix - With Ports",
        )
        plot_feature_importance(result_with_ports["model"], FEATURES_WITH_PORTS)

    with res_col2:
        st.subheader("Experiment 2: Without Ports")
        st.metric("Accuracy", f"{result_without_ports['accuracy']:.4f}")
        st.text("Classification Report")
        st.code(result_without_ports["report"])

        plot_confusion_matrix(
            result_without_ports["confusion_matrix"],
            result_without_ports["classes"],
            "Confusion Matrix - Without Ports",
        )
        plot_feature_importance(result_without_ports["model"], FEATURES_WITHOUT_PORTS)


# =========================================
# Footer
# =========================================
st.markdown("---")
st.write("This dashboard uses the prepared flow-based dataset and a Random Forest classifier.")
