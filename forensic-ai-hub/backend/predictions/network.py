import joblib
import os
from datetime import datetime
import pandas as pd

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))

model = None
scaler = None
feature_names = None

def reload_model():
    global model, scaler, feature_names
    try:
        model_path = os.path.join(MODELS_DIR, 'network_ids_model.pkl')
        scaler_path = os.path.join(MODELS_DIR, 'network_ids_scaler.pkl')
        features_path = os.path.join(MODELS_DIR, 'network_ids_features.pkl')
        
        if os.path.exists(model_path) and os.path.exists(scaler_path):
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
            if os.path.exists(features_path):
                feature_names = joblib.load(features_path)
            print("✔ Network IDS model loaded.")
            return True
        else:
            print(f"❌ Network model files missing in {MODELS_DIR}")
            return False
    except Exception as e:
        print(f"❌ Error loading Network model: {e}")
        return False

# Initial load
reload_model()

def predict_network(data):
    """
    Predict threat from network data (dict).
    Expected keys should match model features.
    """
    timestamp = datetime.now().isoformat()
    
    if not model or not scaler:
        return {
            'is_threat': False,
            'threatScore': 0,
            'timestamp': timestamp,
            'error': 'Model not loaded'
        }

    try:
        # Check input type. If dict, align to feature_names.
        if isinstance(data, dict):
             if feature_names is None:
                  return {'error': 'Features not loaded', 'threatScore': 0, 'is_threat': False, 'timestamp': timestamp}
                  
             X_aligned = pd.DataFrame(0, index=[0], columns=feature_names)
             
             # Map keys to columns (basic matching)
             common = list(set(data.keys()) & set(feature_names))
             if common:
                 X_aligned[common] = [data[k] for k in common]
             
             X_scaled = scaler.transform(X_aligned)
             pred = model.predict(X_scaled)[0]
             proba = model.predict_proba(X_scaled)[0]
             
             is_threat = bool(pred == 1)
             score = float(proba[1] * 100) if len(proba) > 1 else 0
             
             return {
                'is_threat': is_threat,
                'threatScore': score,
                'timestamp': timestamp
             }
        else:
             return {'error': 'Invalid input format', 'threatScore': 0, 'is_threat': False, 'timestamp': timestamp}
    except Exception as e:
        return {
            'is_threat': False,
            'threatScore': 0,
            'timestamp': timestamp,
            'error': str(e)
        }
