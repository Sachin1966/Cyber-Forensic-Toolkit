
import sys
import os
import joblib
import traceback

# Add backend to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'backend')))

print("--- Testing PCAP Analysis (Scapy) ---")
try:
    from scapy.all import rdpcap
    print("✅ Scapy imported successfully.")
except ImportError as e:
    print(f"❌ Scapy import failed: {e}")
except Exception as e:
    print(f"❌ Scapy error: {e}")

print("\n--- Testing URL Model Loading ---")
try:
    from backend.predictions.url import reload_model as reload_url, predict_url
    if reload_url():
        print("✅ URL Model loaded.")
        print(predict_url("http://google.com"))
    else:
        print("❌ URL Model failed to load.")
except Exception as e:
    print(f"❌ URL module error: {e}")
    traceback.print_exc()

print("\n--- Testing Email Model Loading ---")
try:
    from backend.predictions.email import reload_model as reload_email, predict_email
    if reload_email():
        print("✅ Email Model loaded.")
        print(predict_email("Test Subject", "Test Content"))
    else:
        print("❌ Email Model failed to load.")
except Exception as e:
    print(f"❌ Email module error: {e}")
    traceback.print_exc()

print("\n--- Testing Malware Model Loading ---")
try:
    from backend.predictions.malware import reload_model as reload_malware, predict_malware
    if reload_malware():
        print("✅ Malware Model loaded.")
    else:
        print("❌ Malware Model failed to load.")
except Exception as e:
    print(f"❌ Malware module error: {e}")
    traceback.print_exc()
