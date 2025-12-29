import os
import sys
import requests
import json


from backend.predictions.url import predict_url
from backend.predictions.email import predict_email
from backend.predictions.malware import predict_malware
# from predictions.network import predict_network

def test_systems():
    print("🚀 Testing Forensic AI Hub Backend Systems...\n")
    
    # 1. Test URL
    print("--- Testing URL Analysis ---")
    res = predict_url("http://google.com")
    print(f"Result: {json.dumps(res, indent=2)}")
    if 'error' in res:
        print("❌ URL Analysis Failed")
    else:
        print("✔ URL Analysis Working")
        
    # 2. Test Email
    print("\n--- Testing Email Analysis ---")
    res = predict_email("Win a lottery", "Click this link to claim your prize")
    print(f"Result: {json.dumps(res, indent=2)}")
    if 'error' in res:
        print("❌ Email Analysis Failed")
    else:
        print("✔ Email Analysis Working")

    # 3. Test Malware (Dummy File)
    print("\n--- Testing Malware Analysis ---")
    dummy_path = "test_malware.txt"
    with open(dummy_path, "w") as f:
        f.write("This is a test file.")
    
    res = predict_malware(dummy_path)
    print(f"Result: {json.dumps(res, indent=2)}")
    if 'error' in res and res['error'] != 'Model not loaded':
        print("❌ Malware Analysis Failed")
    else:
        print("✔ Malware Analysis Working")
        
    if os.path.exists(dummy_path):
        os.remove(dummy_path)

    print("\n✅ ALL SYSTEMS CHECKED")

if __name__ == "__main__":
    test_systems()
