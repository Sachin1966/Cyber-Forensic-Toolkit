import os
import argparse
import pandas as pd
import joblib
import json
import warnings
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import mlflow
import mlflow.sklearn

warnings.filterwarnings("ignore")

# Configuration
DATASET_DIR = "./dataset"
MODELS_DIR = "./forensic-ai-hub/backend/models"
METADATA_PATH = os.path.join(MODELS_DIR, 'metadata.json')
os.makedirs(MODELS_DIR, exist_ok=True)

import sys

# ... Imports ...

# Logger to redirect stdout to file and console
class Logger(object):
    def __init__(self):
        self.terminal = sys.stdout
        os.makedirs("logs", exist_ok=True)
        self.log = open("logs/training.log", "a", encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush() # Ensure real-time update

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = Logger()
print(f"--- Session Started: {datetime.now()} ---")

mlflow.set_tracking_uri("file:./mlruns")


# ============ UTILS ============

LABEL_MAP = {
    "0": 0, "1": 1, "false": 0, "true": 1,
    "benign": 0, "malicious": 1, "legitimate": 0, "phishing": 1,
    "ham": 0, "spam": 1, "good": 0, "bad": 1, "normal": 0, "attack": 1
}

def clean_labels(series):
    if series.dtype in ["int64", "float64"]:
        return series.fillna(-1).astype(int)
    series = series.astype(str).str.lower().str.strip()
    series = series.replace({"1.0": "1", "0.0": "0"})
    return series.map(LABEL_MAP)

def clean_urls(df):
    df["url"] = df["url"].astype(str)
    df = df[df["url"].str.len() > 5]
    df = df[df["url"].str.contains("[a-zA-Z]", regex=True)]
    return df[~df["url"].isin(["nan", "none", "null", ""])]

def load_csv_sample(path, max_rows=100_000):
    try:
        sep = '|' if path.endswith('.log.labeled.csv') else ','
        df = pd.read_csv(path, sep=sep, engine='c')
        if len(df) > max_rows:
            df = df.sample(max_rows, random_state=42)
        print(f"(+) Loaded {path} ({df.shape})")
        return df
    except Exception as e:
        print(f"(!) Skipping {path}: {e}")
        return None

def update_metadata(model_key, metrics):
    try:
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, 'r') as f:
                metadata = json.load(f)
        else:
            metadata = {}
            
        if model_key not in metadata:
            metadata[model_key] = {}
            
        metadata[model_key].update({
            'accuracy': round(metrics['accuracy'] * 100, 1),
            'precision': round(metrics['precision'] * 100, 1),
            'recall': round(metrics['recall'] * 100, 1),
            'last_trained': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'Ready'
        })
        
        with open(METADATA_PATH, 'w') as f:
            json.dump(metadata, f, indent=2)
        # Save to metrics_latest.json for dashboard
        METRICS_JSON_PATH = os.path.join(MODELS_DIR, 'metrics_latest.json')
        if os.path.exists(METRICS_JSON_PATH):
            with open(METRICS_JSON_PATH, 'r') as f:
                all_metrics = json.load(f)
        else:
            all_metrics = {}
            
        all_metrics[model_key] = metadata[model_key]
        
        with open(METRICS_JSON_PATH, 'w') as f:
            json.dump(all_metrics, f, indent=2)

        print(f"(+) Updated metadata for {model_key}")
    except Exception as e:
        print(f"(-) Failed to update metadata: {e}")

# ============ TRAINING FUNCTIONS ============

def train_phishing(files, max_rows=30000):
    print("\n--- Training Phishing URL Model ---")
    mlflow.set_experiment("Phishing_Detection")
    
    with mlflow.start_run():
        dfs = []
        for f in files:
            try:
                df = pd.read_csv(f)
                df.columns = df.columns.str.lower()
                url_col = next((c for c in df.columns if "url" in c), None)
                label_col = next((c for c in df.columns if "label" in c or "target" in c), None)
                
                if url_col and label_col:
                    df = df.rename(columns={url_col: "url", label_col: "label"})
                    df = clean_urls(df)
                    df["label"] = clean_labels(df["label"])
                    dfs.append(df.dropna(subset=["label"])[["url", "label"]])
            except Exception as e:
                print(f"Error reading {f}: {e}")

        if not dfs: return

        df = pd.concat(dfs, ignore_index=True)
        if len(df) > max_rows: 
            df = df.sample(max_rows, random_state=42)
        
        # Features
        vectorizer = CountVectorizer(analyzer="char", ngram_range=(3, 3), max_features=5000)
        X = vectorizer.fit_transform(df["url"])
        y = df["label"]
        
        # Train
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average='weighted'),
            "recall": recall_score(y_test, y_pred, average='weighted'),
            "f1": f1_score(y_test, y_pred, average='weighted')
        }
        
        # Log
        mlflow.log_params({"n_estimators": 50, "max_features": 5000, "rows": len(df)})
        mlflow.log_metrics(metrics)
        mlflow.sklearn.log_model(model, "model")
        
        # Save Artifacts
        joblib.dump(model, f"{MODELS_DIR}/phishing_model.pkl")
        joblib.dump(vectorizer, f"{MODELS_DIR}/phishing_vectorizer.pkl")
        update_metadata('phishing', metrics)
        print(f"(+) Phishing Model Saved. Acc: {metrics['accuracy']:.2f}")

def train_malware(files, max_rows=150000):
    print("\n--- Training Malware Model ---")
    mlflow.set_experiment("Malware_Detection")
    
    with mlflow.start_run():
        dfs = [load_csv_sample(f, max_rows) for f in files if load_csv_sample(f, max_rows) is not None]
        if not dfs: return

        df = pd.concat(dfs, ignore_index=True)
        df.columns = df.columns.str.lower()
        
        label_col = next((c for c in df.columns if "label" in c or "class" in c), None)
        if not label_col: return

        df["label"] = clean_labels(df[label_col])
        df = df.dropna(subset=["label"])
        
        # Numeric Features Only
        num_df = df.select_dtypes(include="number")
        X = num_df
        y = df["label"]
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
        model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average='weighted'),
            "recall": recall_score(y_test, y_pred, average='weighted')
        }
        
        mlflow.log_params({"n_estimators": 50, "rows": len(df)})
        mlflow.log_metrics(metrics)
        mlflow.sklearn.log_model(model, "model")
        
        joblib.dump(model, f"{MODELS_DIR}/malware_model.pkl")
        joblib.dump(scaler, f"{MODELS_DIR}/malware_scaler.pkl")
        joblib.dump(X.columns, f"{MODELS_DIR}/malware_features.pkl")
        update_metadata('malware', metrics)
        print(f"(+) Malware Model Saved. Acc: {metrics['accuracy']:.2f}")

def train_network(files, max_rows=200000):
    print("\n--- Training Network IDS Model ---")
    mlflow.set_experiment("Network_IDS")
    
    with mlflow.start_run():
        dfs = [load_csv_sample(f, max_rows) for f in files if load_csv_sample(f, max_rows) is not None]
        if not dfs: return

        df = pd.concat(dfs, ignore_index=True)
        df.columns = df.columns.str.lower()
        df = df.drop(columns=[c for c in ["attack_cat", "subcategory", "attack"] if c in df.columns], errors="ignore")
        
        if "label" not in df.columns: return

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
        
        y_pred = model.predict(X_test)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average='weighted'),
            "recall": recall_score(y_test, y_pred, average='weighted')
        }
        
        mlflow.log_params({"n_estimators": 50, "rows": len(df)})
        mlflow.log_metrics(metrics)
        mlflow.sklearn.log_model(model, "model")
        
        joblib.dump(model, f"{MODELS_DIR}/network_ids_model.pkl")
        joblib.dump(scaler, f"{MODELS_DIR}/network_ids_scaler.pkl")
        joblib.dump(X.columns, f"{MODELS_DIR}/network_ids_features.pkl")
        update_metadata('network', metrics)
        print(f"(+) Network Model Saved. Acc: {metrics['accuracy']:.2f}")

def train_email(files):
    print("\n--- Training Email Model ---")
    mlflow.set_experiment("Email_Spam_Detection")
    
    with mlflow.start_run():
        dfs = []
        for f in files:
            try: dfs.append(pd.read_csv(f))
            except: pass
            
        if not dfs: return
        
        df = pd.concat(dfs, ignore_index=True)
        df.columns = df.columns.str.lower()
        
        text_col = next((c for c in df.columns if "text" in c or "body" in c), None)
        label_col = next((c for c in df.columns if "label" in c), None)
        
        if not text_col or not label_col: return
        
        df = df.rename(columns={text_col: "text", label_col: "label"})
        df["label"] = clean_labels(df["label"])
        df = df.dropna(subset=["label", "text"])
        
        vectorizer = TfidfVectorizer(stop_words="english", max_features=8000)
        X = vectorizer.fit_transform(df["text"])
        y = df["label"]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        model = RandomForestClassifier(n_estimators=50, n_jobs=-1)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average='weighted'),
            "recall": recall_score(y_test, y_pred, average='weighted')
        }
        
        mlflow.log_params({"n_estimators": 50, "max_features": 8000, "rows": len(df)})
        mlflow.log_metrics(metrics)
        mlflow.sklearn.log_model(model, "model")
        
        joblib.dump(model, f"{MODELS_DIR}/email_model.pkl")
        joblib.dump(vectorizer, f"{MODELS_DIR}/email_vectorizer.pkl")
        update_metadata('email', metrics)
        print(f"(+) Email Model Saved. Acc: {metrics['accuracy']:.2f}")

def main():
    parser = argparse.ArgumentParser(description="Forensic AI ML Pipeline")
    parser.add_argument("--model", type=str, choices=['phishing', 'malware', 'network', 'email', 'all'], default='all')
    args = parser.parse_args()
    
    datasets = {"PHISHING": [], "MALWARE": [], "NETWORK": [], "EMAIL": []}
    
    # Discovery
    if os.path.exists(DATASET_DIR):
        for folder in os.listdir(DATASET_DIR):
            folder_path = os.path.join(DATASET_DIR, folder)
            if not os.path.isdir(folder_path): continue
            
            dtype = None
            if folder in ["dataset1", "dataset2", "dataset3"]: dtype = "PHISHING"
            elif folder in ["dataset4", "dataset5"]: dtype = "MALWARE"
            elif folder == "dataset6": dtype = "NETWORK"
            elif folder == "dataset7": dtype = "EMAIL"
            
            if dtype:
                for f in os.listdir(folder_path):
                    if f.endswith(".csv"):
                        datasets[dtype].append(os.path.join(folder_path, f))

    if args.model in ['phishing', 'all']: train_phishing(datasets["PHISHING"])
    if args.model in ['malware', 'all']: train_malware(datasets["MALWARE"])
    if args.model in ['network', 'all']: train_network(datasets["NETWORK"])
    if args.model in ['email', 'all']: train_email(datasets["EMAIL"])

if __name__ == "__main__":
    main()
