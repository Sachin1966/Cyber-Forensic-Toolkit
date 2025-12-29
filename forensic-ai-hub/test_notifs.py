import requests

BASE_URL = "http://127.0.0.1:5000"

def test_notifications():
    # 1. Register/Login to get token
    email = "test_user@example.com"
    password = "password123"
    
    print(f"🔑 Registering/Logging in as {email}...")
    # Try register first
    requests.post(f"{BASE_URL}/api/auth/register", json={
        "email": email, "password": password, "name": "Test User"
    })
    
    # Login
    resp = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": email, "password": password
    })
    
    if resp.status_code != 200:
        print(f"❌ Login failed: {resp.text}")
        return
        
    token = resp.json().get("access_token")
    print("✅ Got access token.")
    
    # 2. Call Notifications Endpoint
    print("📡 Calling /api/notifications...")
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/notifications", headers=headers)
    
    print(f"Status Code: {resp.status_code}")
    print(f"Response: {resp.text}")
    
    if resp.status_code == 500:
        print("❌ Confirmed 500 Error (Likely the AttributeError)")
    elif resp.status_code == 200:
        print("✅ Success! Endpoint returned 200")

if __name__ == "__main__":
    test_notifications()
