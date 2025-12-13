import requests
import os
import json

BASE_URL = "http://127.0.0.1:5000"
TOKEN = None

def login():
    global TOKEN
    try:
        # Register first to be safe
        requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": "tester@example.com", "password": "password", "name": "Tester"
        })
        resp = requests.post(f"{BASE_URL}/api/auth/login", json={
            "email": "tester@example.com", "password": "password"
        })
        if resp.status_code == 200:
            TOKEN = resp.json()['access_token']
            print("[OK] Login Successful")
            return True
        else:
            print(f"[FAIL] Login Failed: {resp.text}")
            return False
    except Exception as e:
        print(f"[FAIL] Login Error: {e}")
        return False

def test_url():
    print("\n--- Testing URL ---")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    
    # Test Phishing
    resp = requests.post(f"{BASE_URL}/api/analyze/url", json={"url": "http://paypal-secure-login.com"}, headers=headers)
    print(f"Phishing URL (Expect High Risk): {resp.json().get('threatScore', 0)}")
    
    # Test Safe
    resp = requests.post(f"{BASE_URL}/api/analyze/url", json={"url": "https://google.com"}, headers=headers)
    print(f"Safe URL (Expect Low Risk): {resp.json().get('threatScore', 0)}")

def test_email():
    print("\n--- Testing Email ---")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    
    # Test Spam
    resp = requests.post(f"{BASE_URL}/api/analyze/email", json={
        "subject": "Win $1000000 now!!!", 
        "content": "Click here to claim your prize."
    }, headers=headers)
    print(f"Spam Email (Expect High Risk): {resp.json().get('threatScore', 0)}")

def test_malware():
    print("\n--- Testing Malware ---")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    
    # Create dummy file
    with open("test_malware.exe", "wb") as f:
        f.write(os.urandom(1024)) # Random bytes
        
    with open("test_malware.exe", "rb") as f:
        files = {'file': f}
        resp = requests.post(f"{BASE_URL}/api/analyze/file", files=files, headers=headers)
        print(f"Random File (Expect Low/Medium): {resp.json().get('threatScore', 0)}")
        print(f"Result: {resp.json()}")

def test_pcap():
    print("\n--- Testing PCAP ---")
    headers = {"Authorization": f"Bearer {TOKEN}"}
    
    # Create dummy file
    with open("test.pcap", "wb") as f:
        f.write(b"dummy pcap content")
        
    with open("test.pcap", "rb") as f:
        files = {'file': f}
        resp = requests.post(f"{BASE_URL}/api/analyze/pcap", files=files, headers=headers)
        print(f"PCAP (Expect Info): {resp.json()}")

if __name__ == "__main__":
    if login():
        test_url()
        test_email()
        test_malware()
        test_pcap()
