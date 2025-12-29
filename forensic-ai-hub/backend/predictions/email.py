import joblib
import os
import sys
from datetime import datetime


from backend.database import log_scan, update_stats

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../models'))


model = None
vectorizer = None

def reload_model():
    global model, vectorizer
    try:
        model_path = os.path.join(MODELS_DIR, 'email_model.pkl')
        vectorizer_path = os.path.join(MODELS_DIR, 'email_vectorizer.pkl')
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            model = joblib.load(model_path)
            vectorizer = joblib.load(vectorizer_path)
            print("✔ Email Spam model loaded.")
            return True
        else:
            print(f"❌ Email model files missing in {MODELS_DIR}")
            return False
    except Exception as e:
        print(f"❌ Error loading Email model: {e}")
        return False

# Initial load
reload_model()

def predict_email(subject, content):
    timestamp = datetime.now().isoformat()
    full_text = f"{subject} {content}"
    
    if not model or not vectorizer:
        return {
            'subject': subject,
            'isPhishing': False,
            'isSpam': False,
            'threatScore': 0,
            'suspiciousTerms': [],
            'senderReputation': 'unknown',
            'timestamp': timestamp,
            'error': 'Email Prediction Model not loaded. Please check backend logs/models.'
        }

    try:
        features = vectorizer.transform([full_text])
        prediction = model.predict(features)[0]
        
        try:
            proba = model.predict_proba(features)[0]
            # Threat score = probability of class 1 (Spam/Phishing)
            threat_score = float(proba[1] * 100) if len(proba) > 1 else (100.0 if prediction == 1 else 0.0)
        except:
            threat_score = 100.0 if prediction == 1 else 0.0

        is_spam = False
        pred_str = str(prediction).lower()
        if pred_str in ['1', 'spam', 'phishing', 'malicious']:
            is_spam = True
            
        # Log to database
        result = {
            'scan_type': 'Email',
            'input_summary': subject,
            'subject': subject,
            'isPhishing': is_spam, # Treating spam/phishing as similar for this context
            'isSpam': is_spam,
            'threatScore': threat_score,
            'suspiciousTerms': [], # TODO: Extract terms
            'senderReputation': 'suspicious' if is_spam else 'trusted',
            'timestamp': timestamp
        }

        # Log to database
        # Log to database
        scan_id = log_scan('email', subject, 'Spam/Phishing' if is_spam else 'Legitimate', threat_score, is_spam, details=result)
        update_stats('email', is_spam)
        
        result['id'] = scan_id
            
        return result
    except Exception as e:
        print(f"❌ Email prediction error: {e}")
        return {
            'subject': subject,
            'isPhishing': False,
            'isSpam': False,
            'threatScore': 0,
            'suspiciousTerms': [],
            'senderReputation': 'unknown',
            'timestamp': timestamp,
            'error': str(e)
        }
