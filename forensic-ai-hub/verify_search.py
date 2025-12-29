import requests

BASE_URL = "http://localhost:5000/api"

def test_search():
    print("🔍 Testing Search Functionality...")
    try:
        # Search for "url"
        res = requests.get(f"{BASE_URL}/reports?search=url")
        if res.status_code == 200:
            reports = res.json()
            print(f"✔ Search 'url' returned {len(reports)} results")
            if len(reports) > 0:
                # Check if they are actually URL reports
                matches = [r for r in reports if 'url' in r['type'].lower() or 'url' in r['name'].lower()]
                print(f"   Matches found: {len(matches)}/{len(reports)}")
                if len(matches) > 0:
                    print("   ✅ Search works for type 'url'")
                else:
                    print("   ❌ Search returned unrelated results")
            else:
                print("   ⚠ No results found for 'url' (might need to create some first)")
        else:
            print(f"❌ Search failed: {res.status_code}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_search()
