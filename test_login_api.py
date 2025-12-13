import requests
import json

url = "http://127.0.0.1:5000/api/auth/login"
payload = {
    "email": "test@example.com",
    "password": "Password123"
}

try:
    print(f"Testing {url}...")
    response = requests.post(url, json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print("Keys in response:", data.keys())
        if 'access_token' in data:
            print(f"Access Token present: {data['access_token'][:20]}...")
        else:
            print("❌ Access Token MISSING!")
    else:
        print("Login failed:", response.text)

except Exception as e:
    print(f"Error: {e}")
