import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
import warnings
warnings.filterwarnings("ignore")


DATASET_DIR = "./dataset"
MODELS_DIR = "./forensic-ai-hub/backend/models"
os.makedirs(MODELS_DIR, exist_ok=True)


# ============ LABEL MAP ============
LABEL_MAP = {
    "0": 0, "1": 1,
    "false": 0, "true": 1,
    "benign": 0, "malicious": 1,
    "legitimate": 0, "phishing": 1,
    "ham": 0, "spam": 1,
    "good": 0, "bad": 1,
    "normal": 0, "attack": 1
}


# ============ LABEL CLEANING ============

def clean_labels(series):

    # If numeric — return integers directly
    if series.dtype in ["int64", "float64"]:
        return series.fillna(-1).astype(int)

    # Convert to string
    series = series.astype(str).str.lower().str.strip()

    # Normalize 1.0 → 1
    series = series.replace({"1.0": "1", "0.0": "0"})

    # Map using global map
    mapped = series.map(LABEL_MAP)

    return mapped


# ============ URL CLEANING ============
def clean_urls(df):
    df["url"] = df["url"].astype(str)
    df = df[df["url"].str.len() > 5]
    df = df[df["url"].str.contains("[a-zA-Z]", regex=True)]
    df = df[~df["url"].isin(["nan", "none", "null", ""])]
    return df


# ============ FAST CSV LOADER + SAMPLING ============

def load_csv_sample(path, max_rows=100_000):
    try:
        # Optimize loading based on filename
        if path.endswith('.log.labeled.csv'):
            # Dataset 4 (Pipe separated)
            df = pd.read_csv(path, sep='|', engine='c')
        else:
            # Dataset 5 (Comma separated)
            df = pd.read_csv(path, sep=',', engine='c')
            
        if len(df) > max_rows:
            df = df.sample(max_rows, random_state=42)
        print(f"(+) Loaded {path} ({df.shape})")
        return df
    except Exception as e:
        print(f"(!) Skipping {path}: {e}")
        return None


# ============ FOLDER → DATASET TYPE ============

def get_dataset_type(folder):
    if folder in ["dataset1", "dataset2", "dataset3"]:
        return "PHISHING"
    if folder in ["dataset4", "dataset5"]:
        return "MALWARE"
    if folder == "dataset6":
        return "NETWORK"
    if folder == "dataset7":
        return "EMAIL"
    return None


# ============ TRAIN PHISHING MODEL ============

import json
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ... (imports remain same)

# ============ METADATA UPDATE ============
def update_metadata(model_key, accuracy):
    metadata_path = os.path.join(os.path.dirname(__file__), 'forensic-ai-hub', 'backend', 'models', 'metadata.json')
    try:
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {}
            
        if model_key not in metadata:
            metadata[model_key] = {}
            
        metadata[model_key]['accuracy'] = round(accuracy, 1)
        metadata[model_key]['last_trained'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        metadata[model_key]['status'] = 'Ready'
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"(+) Updated metadata for {model_key}: {accuracy:.1f}%")
    except Exception as e:
        print(f"(-) Failed to update metadata: {e}")

# ============ TRAIN PHISHING MODEL ============

def train_phishing(files):
    print("\n--- Training Phishing URL Model ---")

    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            df.columns = df.columns.str.lower()

            url_col = [c for c in df.columns if "url" in c]
            label_col = [c for c in df.columns if "label" in c or "target" in c]

            if not url_col or not label_col:
                continue

            url_col = url_col[0]
            label_col = label_col[0]

            df = df.rename(columns={url_col: "url", label_col: "label"})
            df = clean_urls(df)
            df["label"] = clean_labels(df["label"])
            df = df.dropna(subset=["label"])

            dfs.append(df[["url", "label"]])
        except Exception as e:
            print(f"Error reading {f}: {e}")

    if not dfs:
        print("(!) No phishing data found.")
        return

    df = pd.concat(dfs, ignore_index=True)
    print(f"Rows before sampling: {len(df)}")

    # SAMPLE to speed up training
    MAX_PHISHING_ROWS = 30000 
    if len(df) > MAX_PHISHING_ROWS:
        df = df.sample(MAX_PHISHING_ROWS, random_state=42)

    print(f"Rows after sampling: {len(df)}")

    vectorizer = CountVectorizer(analyzer="char", ngram_range=(3, 3), max_features=5000)
    X = vectorizer.fit_transform(df["url"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
    model.fit(X_train, y_train)
    
    acc = model.score(X_test, y_test) * 100
    print(f"Accuracy: {acc:.2f}%")

    joblib.dump(model, f"{MODELS_DIR}/phishing_model.pkl")
    joblib.dump(vectorizer, f"{MODELS_DIR}/phishing_vectorizer.pkl")
    print("(+) Saved phishing model.")
    update_metadata('phishing', acc)


# ============ TRAIN MALWARE MODEL ============

def train_malware(files):
    print("\n--- Training Malware Model ---")
    dfs = []

    for f in files:
        df = load_csv_sample(f, max_rows=150_000)
        if df is not None:
            dfs.append(df)

    if not dfs:
        print("(!) No malware datasets found.")
        return

    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.lower()

    label_candidates = [c for c in df.columns if "label" in c or "class" in c]
    if not label_candidates:
        print("(!) No valid label column for malware.")
        return

    label_col = label_candidates[0]

    df["label"] = clean_labels(df[label_col])
    df = df.dropna(subset=["label"])

    num_df = df.select_dtypes(include="number")
    if num_df.empty:
        print("(!) No numeric features for malware.")
        return

    X = num_df
    y = df["label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
    model.fit(X_train, y_train)
    
    acc = model.score(X_test, y_test) * 100
    print(f"Accuracy: {acc:.2f}%")

    joblib.dump(model, f"{MODELS_DIR}/malware_model.pkl")
    joblib.dump(scaler, f"{MODELS_DIR}/malware_scaler.pkl")
    print("(+) Saved malware model.")
    update_metadata('malware', acc)


# ============ TRAIN NETWORK IDS MODEL ============

def train_network(files):
    print("\n--- Training Network IDS Model ---")
    dfs = []

    for f in files:
        df = load_csv_sample(f, max_rows=200_000)
        if df is not None:
            dfs.append(df)

    if not dfs:
        print("(!) No network IDS datasets found.")
        return

    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.lower()

    # Remove leakage
    df = df.drop(columns=[c for c in ["attack_cat", "subcategory", "attack"] if c in df.columns], errors="ignore")

    if "label" not in df.columns:
        print("(!) No label column for network dataset.")
        return

    df["label"] = clean_labels(df["label"])
    df = df.dropna(subset=["label"])

    num_df = df.select_dtypes(include="number")
    X = num_df
    y = df["label"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
    model.fit(X_train, y_train)
    
    acc = model.score(X_test, y_test) * 100
    print(f"Accuracy: {acc:.2f}%")

    joblib.dump(model, f"{MODELS_DIR}/network_ids_model.pkl")
    joblib.dump(scaler, f"{MODELS_DIR}/network_ids_scaler.pkl")
    print("(+) Saved network IDS model.")
    update_metadata('network', acc)


# ============ TRAIN EMAIL MODEL ============

def train_email(files):
    print("\n--- Training Email Model ---")
    dfs = []

    for f in files:
        try:
            df = pd.read_csv(f)
            dfs.append(df)
        except:
            pass

    if not dfs:
        print("(!) No email datasets found.")
        return

    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.lower()

    text_col = [c for c in df.columns if "text" in c or "body" in c]
    label_col = [c for c in df.columns if "label" in c]

    if not text_col or not label_col:
        print("(!) Email dataset missing text/label column.")
        return

    df = df.rename(columns={text_col[0]: "text", label_col[0]: "label"})

    df["label"] = clean_labels(df["label"])
    df = df.dropna(subset=["label", "text"])

    vectorizer = TfidfVectorizer(stop_words="english", max_features=8000)
    X = vectorizer.fit_transform(df["text"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
    model.fit(X_train, y_train)
    
    acc = model.score(X_test, y_test) * 100
    print(f"Accuracy: {acc:.2f}%")

    joblib.dump(model, f"{MODELS_DIR}/email_model.pkl")
    joblib.dump(vectorizer, f"{MODELS_DIR}/email_vectorizer.pkl")
    print("(+) Saved email model.")
    update_metadata('email', acc)


# ============ MAIN ============

def main():
    print("\n=======================================")
    print("   DYNAMIC DATASET TRAINING PIPELINE   ")
    print("=======================================\n")

    datasets = {"PHISHING": [], "MALWARE": [], "NETWORK": [], "EMAIL": []}

    if os.path.exists(DATASET_DIR):
        for folder in os.listdir(DATASET_DIR):
            folder_path = os.path.join(DATASET_DIR, folder)
            if not os.path.isdir(folder_path):
                continue

            dtype = get_dataset_type(folder)
            if not dtype:
                continue

            for f in os.listdir(folder_path):
                if f.endswith(".csv"):
                    datasets[dtype].append(os.path.join(folder_path, f))

    train_phishing(datasets["PHISHING"])
    train_malware(datasets["MALWARE"])
    train_network(datasets["NETWORK"])
    train_email(datasets["EMAIL"])

    print("\n=======================================")
    print("   ALL MODELS TRAINED SUCCESSFULLY     ")
    print("=======================================\n")


if __name__ == "__main__":
    main()
