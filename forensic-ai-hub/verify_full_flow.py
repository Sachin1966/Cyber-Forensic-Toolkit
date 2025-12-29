import requests
import sqlite3
import os
import json
import time

BASE_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join("backend", "database.db")

def check_db():
    print("\n🔍 Checking Database Directly...")
    if not os.path.exists(DB_PATH):
        print("❌ Database file not found!")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Check Users
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    print(f"👥 Users count: {len(users)}")
    if len(users) > 0:
        print(f"   Last user: {dict(users[-1])}")

    # Check Scan Logs
    c.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT 1")
    last_scan = c.fetchone()
    if last_scan:
        print(f"📄 Last Scan: {dict(last_scan)}")
    else:
        print("📄 No scans found.")

    # Check Notifications
    c.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT 1")
    last_notif = c.fetchone()
    if last_notif:
        print(f"🔔 Last Notification: {dict(last_notif)}")
    else:
        print("🔔 No notifications found.")
        
    conn.close()

def run_test():
    print("🚀 Starting End-to-End Test")
    
    # 1. Login
    email = "debug_user@example.com"
    password = "password123"
    
    print(f"\n🔑 Logging in as {email}...")
    # Register purely to ensure user exists
    requests.post(f"{BASE_URL}/api/auth/register", json={
        "email": email, "password": password, "name": "Debug User"
    })
    
    sess = requests.Session()
    resp = sess.post(f"{BASE_URL}/api/auth/login", json={
        "email": email, "password": password
    })
    
    if resp.status_code != 200:
        print(f"❌ Login failed: {resp.text}")
        return
        
    token = resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    print("✅ Login successful.")

    # 2. Analyze Email (High Risk)
    print("\n📧 Sending High Risk Email Analysis...")
    email_data = {
        "subject": "URGENT: Verify your account immediately",
        "content": "Click this link immediately to verify your account or it will be suspended. http://malicious-link.com/login"
    }
    
    analyze_resp = sess.post(f"{BASE_URL}/api/analyze/email", json=email_data, headers=headers)
    print(f"Analysis Status: {analyze_resp.status_code}")
    print(f"Analysis Response: {analyze_resp.json()}")
    
    # Wait a moment for async DB ops if any (though currently synchronous)
    time.sleep(1)
    
    # 3. Check Database
    check_db()
    
    # 4. Check Notifications API
    print("\n🔔 Checking /api/notifications...")
    notif_resp = sess.get(f"{BASE_URL}/api/notifications", headers=headers)
    
    print(f"Notifications Status: {notif_resp.status_code}")
    if notif_resp.status_code == 200:
        notifs = notif_resp.json()
        print(f"Notifications Count: {len(notifs)}")
        print(f"Notifications: {json.dumps(notifs, indent=2)}")
        
        if len(notifs) > 0:
            print("✅ TEST PASSED: Notification received via API.")
        else:
            print("❌ TEST FAILED: No notifications returned by API.")
    else:
        print(f"❌ TEST FAILED: API Error {notif_resp.text}")

if __name__ == "__main__":
    import sys
    with open("verification_results.txt", "w", encoding="utf-8") as f:
        sys.stdout = f
        try:
            run_test()
        except Exception as e:
            print(f"❌ Script Error: {e}")
