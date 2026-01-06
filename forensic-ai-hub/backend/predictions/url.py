import joblib
import os
import re
import sys
from datetime import datetime


from backend.database import log_scan, update_stats


# Absolute path to models
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))

# Load assets once

# Load assets
model = None
vectorizer = None

def reload_model():
    global model, vectorizer
    try:
        model_path = os.path.join(MODELS_DIR, 'phishing_model.pkl')
        vectorizer_path = os.path.join(MODELS_DIR, 'phishing_vectorizer.pkl')
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            # Use mmap_mode='r' to map file into memory, saving RAM
            model = joblib.load(model_path, mmap_mode='r')
            vectorizer = joblib.load(vectorizer_path, mmap_mode='r')
            print("✔ URL Phishing model loaded (mmap).")
            return True
        else:
            print(f"❌ URL model files missing in {MODELS_DIR}")
            return False
    except Exception as e:
        print(f"❌ Error loading URL model: {e}")
        return False

# Initial load
reload_model()

def extract_url_features(url):
    """Extract heuristic features for frontend display."""
    return {
        'hasIP': bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url)),
        'urlLength': len(url),
        'hasHTTPS': url.startswith('https'),
        'numDots': url.count('.'),
        'numDashes': url.count('-'),
        'hasAtSymbol': '@' in url,
        'suspiciousKeywords': [k for k in ['login', 'verify', 'account', 'update', 'secure'] if k in url.lower()]
    }

def predict_url(url):
    timestamp = datetime.now().isoformat()
    features_display = extract_url_features(url)
    
    if not model or not vectorizer:
        return {
            'url': url,
            'isPhishing': False,
            'threatScore': 0,
            'features': features_display,
            'timestamp': timestamp,
            'error': 'URL Prediction Model not loaded. Please check backend logs/models.'
        }

    try:
        # Transform and predict
        # Note: vectorizer expects an iterable of strings
        features_vec = vectorizer.transform([url])
        prediction = model.predict(features_vec)[0]
        
        try:
            proba = model.predict_proba(features_vec)[0]
            confidence = float(max(proba) * 100)
            # If malicious (1), score is confidence. If benign (0), score is 100 - confidence? 
            # Usually threat score is probability of being malicious.
            threat_score = float(proba[1] * 100) if len(proba) > 1 else (100.0 if prediction == 1 else 0.0)
        except:
            threat_score = 100.0 if prediction == 1 else 0.0

        # Handle various label types
        is_phishing = False
        pred_str = str(prediction).lower()
        if pred_str in ['1', 'bad', 'phishing', 'malware', 'malicious', 'spam']:
            is_phishing = True
            
        # Log to database
        result = {
            'scan_type': 'URL',
            'input_summary': url,
            'url': url,
            'isPhishing': is_phishing,
            'threatScore': threat_score,
            'features': features_display,
            'timestamp': timestamp
        }

        # Log to database
        # Log to database
        scan_id = log_scan('url', url, 'Phishing' if is_phishing else 'Legitimate', threat_score, is_phishing, details=result)
        update_stats('url', is_phishing)
        
        result['id'] = scan_id
            
        return result
    except Exception as e:
        print(f"❌ Prediction error: {e}")
        return {
            'url': url,
            'isPhishing': False,
            'threatScore': 0,
            'features': features_display,
            'timestamp': timestamp,
            'error': str(e)
        }
