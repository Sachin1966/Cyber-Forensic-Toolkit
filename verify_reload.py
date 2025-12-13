import requests
try:
    resp = requests.post("http://127.0.0.1:5000/api/models/reload")
    print(f"Status: {resp.status_code}")
    print(f"Response: {resp.json()}")
except Exception as e:
    print(f"Error: {e}")
