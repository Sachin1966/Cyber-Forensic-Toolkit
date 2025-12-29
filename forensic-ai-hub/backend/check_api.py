import requests
import json
import sys

def check_url_api():
    url = "http://127.0.0.1:5000/api/analyze/url"
    payload = {"url": "http://google.com"}
    
    print(f"Sending POST to {url}...")
    print(f"Payload: {json.dumps(payload)}")
    
    try:
        response = requests.post(url, json=payload)
        print(f"Status Code: {response.status_code}")
        try:
            data = response.json()
            print(f"Response JSON:\n{json.dumps(data, indent=2)}")
            
            if data.get('error'):
                print("API returned an error.")
            elif data.get('prediction'):
                print("API returned a prediction.")
            else:
                print("API returned unexpected structure.")
                
        except json.JSONDecodeError:
            print(f"Could not decode JSON. Raw text:\n{response.text}")
            
    except requests.exceptions.ConnectionError:
        print("Could not connect to server. Is python app.py running?")

if __name__ == "__main__":
    check_url_api()
