import os
import json
import logging
import mlflow
import threading
import subprocess
import shutil
import psutil
from mlflow.tracking import MlflowClient
from datetime import datetime

# Configuration
# backend/mlops.py -> backend -> forensic-ai-hub -> NLP (Root)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
MLRUNS_DIR = os.path.join(ROOT_DIR, 'mlruns')
LOGS_DIR = os.path.join(ROOT_DIR, 'logs')
LOG_FILE = os.path.join(LOGS_DIR, 'training.log')
DVC_YAML = os.path.join(ROOT_DIR, 'dvc.yaml')
MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
METRICS_PATH = os.path.join(MODELS_DIR, 'metrics_latest.json')

# Ensure logs dir exists
os.makedirs(LOGS_DIR, exist_ok=True)

# Set MLflow tracking URI
mlflow.set_tracking_uri(f"file:{MLRUNS_DIR}")
client = MlflowClient()

def get_training_logs(limit=100):
    """Returns the last N lines of the training log file."""
    if not os.path.exists(LOG_FILE):
        return ["Log file not found. Waiting for training to start..."]
    
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Return tail, ensuring we handle files smaller than limit
            return [line.strip() for line in lines[-limit:]]
    except Exception as e:
        return [f"Error reading log file: {str(e)}"]

def get_metrics_summary():
    """Fetches metrics from metrics_latest.json and combines with MLflow run data."""
    dashboard_data = {
        "experiments": [],
        "system_health": get_system_health(),
        "history": [] # New field for time-series charts
    }

    # Load latest metrics from file first
    latest_metrics = {}
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r') as f:
                latest_metrics = json.load(f)
        except: pass

    try:
        experiments = client.search_experiments()
        # Collect all runs for history graph
        all_runs_history = []
        
        for exp in experiments:
            # Get last 10 runs for this experiment
            runs = client.search_runs(
                experiment_ids=[exp.experiment_id],
                max_results=10,
                order_by=["attribute.start_time DESC"]
            )
            
            exp_data = {
                "id": exp.experiment_id,
                "name": exp.name,
                "latest_run": None
            }
            
            if runs:
                # Latest run for the card
                latest = runs[0]
                exp_data["latest_run"] = {
                    "run_id": latest.info.run_id,
                    "status": latest.info.status,
                    "start_time": datetime.fromtimestamp(latest.info.start_time / 1000).strftime('%Y-%m-%d %H:%M:%S'),
                    "metrics": latest.data.metrics,
                    "params": latest.data.params
                }
                
                # Add to history
                for r in runs:
                    all_runs_history.append({
                        "name": f"{exp.name} - {datetime.fromtimestamp(r.info.start_time / 1000).strftime('%m-%d %H:%M')}",
                        "timestamp": r.info.start_time,
                        "accuracy": r.data.metrics.get("accuracy", 0) * 100, # Normalize if needed
                        "loss": r.data.metrics.get("loss", 0),
                        "model": exp.name
                    })
            
            dashboard_data["experiments"].append(exp_data)
        
        # Sort combined history by time
        dashboard_data["history"] = sorted(all_runs_history, key=lambda x: x['timestamp'])

    except Exception as e:
        print(f"Error fetching MLflow data: {e}")
    
    return dashboard_data

def get_model_registry():
    """Returns model registry data, combining file status with metadata."""
    models = []
    expected_models = ['phishing_model.pkl', 'malware_model.pkl', 'email_model.pkl', 'network_ids_model.pkl']
    
    # Load metadata for extra info
    metadata = {}
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r') as f:
                metadata = json.load(f)
        except: pass

    for m in expected_models:
        path = os.path.join(MODELS_DIR, m)
        exists = os.path.exists(path)
        last_modified = "N/A"
        size = "0 MB"
        
        # Key mapping for metadata
        key_map = {
            'phishing_model.pkl': 'phishing',
            'malware_model.pkl': 'malware',
            'email_model.pkl': 'email',
            'network_ids_model.pkl': 'network'
        }
        meta_key = key_map.get(m)
        model_meta = metadata.get(meta_key, {})

        if exists:
            last_modified = datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d %H:%M:%S')
            size_bytes = os.path.getsize(path)
            size = f"{size_bytes / (1024*1024):.2f} MB"
            
        models.append({
            "name": m.replace('_model.pkl', '').replace('_', ' ').capitalize(),
            "filename": m,
            "status": "Production" if exists else "Missing",
            "version": f"v1.0.{int(datetime.now().timestamp())}" if exists else "N/A", # Mock versioning based on time or file
            "last_updated": last_modified,
            "size": size,
            "accuracy": f"{model_meta.get('accuracy', 'N/A')}%",
            "precision": f"{model_meta.get('precision', 'N/A')}%",
            "recall": f"{model_meta.get('recall', 'N/A')}%"
        })
        
    return models

def get_system_health():
    """Returns real system metrics using psutil."""
    health = {
        "mlflow": "Healthy",
        "dvc": "Not Configured",
        "backend": "Online",
        "disk_usage": "Unknown",
        "cpu_usage": "0%",
        "ram_usage": "0%"
    }
    
    # Check DVC
    if os.path.exists(DVC_YAML):
        health['dvc'] = "Active"
    
    # Check MLflow (basic dir check)
    if not os.path.exists(MLRUNS_DIR):
         health['mlflow'] = "Not Initialized"

    try:
        health['cpu_usage'] = f"{psutil.cpu_percent(interval=0.1)}%"
        health['ram_usage'] = f"{psutil.virtual_memory().percent}%"
        health['disk_usage'] = f"{psutil.disk_usage(ROOT_DIR).percent}%"
    except:
        pass
        
    return health

def get_dvc_status():
    """Runs 'dvc status' to get repo status."""
    try:
        # Run dvc status in ROOT_DIR
        result = subprocess.run(['dvc', 'status'], cwd=ROOT_DIR, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            if not result.stdout.strip():
                return "Data and pipelines are up to date."
            return result.stdout
        else:
            return f"DVC Error: {result.stderr}"
    except Exception as e:
        return f"Failed to check DVC status: {str(e)}"

def run_training_pipeline():
    """Executes the training pipeline in a subprocess."""
    try:
        # Clear log file logic could allow appending or start fresh. 
        # Appending is safer for history, but maybe add a separator
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n\n--- STARTING RETRAINING JOB AT {datetime.now()} ---\n")

        # Command to run ml_pipeline.py
        cmd = ["python", "ml_pipeline.py", "--model", "all"]
        
        # We run it and let the script's own logger handle the file writing
        # But we also want to capture output here if we were not redirecting in Python.
        # Since ml_pipeline.py redirects stdout to logs/training.log, we can just run it.
        # We use Popen to do it asynchronously if called directly, but this function is meant to be
        # the target of a Thread.
        
        subprocess.run(cmd, cwd=ROOT_DIR, check=True)
        
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n--- TRAINING JOB COMPLETED SUCCESSFULLY AT {datetime.now()} ---\n")
            
    except subprocess.CalledProcessError as e:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
             f.write(f"\n(!) TRAINING JOB FAILED with exit code {e.returncode}\n")
    except Exception as e:
         with open(LOG_FILE, 'a', encoding='utf-8') as f:
             f.write(f"\n(!) TRAINING JOB CRASHED: {str(e)}\n")

def start_retraining_background():
    """Starts the training pipeline in a background thread."""
    thread = threading.Thread(target=run_training_pipeline)
    thread.daemon = True
    thread.start()
    return True
