import requests
import os
import sys
import json
from datetime import datetime

BASE_URL = "http://localhost:5000/api"

def test_reports():
    print("🚀 Starting Report System Verification...")
    
    # 1. Create some test data via analysis endpoints
    print("\n1. Generating test data...")
    
    # URL Analysis
    url_data = {"url": "http://test-phishing.com/login"}
    try:
        res = requests.post(f"{BASE_URL}/analyze/url", json=url_data)
        if res.status_code == 200:
            print("✔ URL Analysis created")
        else:
            print(f"❌ URL Analysis failed: {res.text}")
    except Exception as e:
        print(f"❌ URL Analysis failed: {e}")

    # Email Analysis
    email_data = {"subject": "Urgent Update", "content": "Click this link now"}
    try:
        res = requests.post(f"{BASE_URL}/analyze/email", json=email_data)
        if res.status_code == 200:
            print("✔ Email Analysis created")
        else:
            print(f"❌ Email Analysis failed: {res.text}")
    except Exception as e:
        print(f"❌ Email Analysis failed: {e}")
        
    # 2. Test Report Listing
    print("\n2. Testing Report Listing...")
    try:
        res = requests.get(f"{BASE_URL}/reports")
        if res.status_code == 200:
            reports = res.json()
            print(f"✔ Fetched {len(reports)} reports")
            if len(reports) > 0:
                print(f"   Latest report: {reports[0]['type']} - {reports[0]['name']}")
                
                # Test Filtering
                print("\n3. Testing Filters...")
                # Filter by type
                res_type = requests.get(f"{BASE_URL}/reports?type=url")
                url_reports = res_type.json()
                print(f"✔ Filter by Type (URL): Found {len(url_reports)}")
                if all(r['type'] == 'url' for r in url_reports):
                    print("   ✔ All results are URLs")
                else:
                    print("   ❌ Filter failed: Mixed types found")
                    
                # Filter by search
                res_search = requests.get(f"{BASE_URL}/reports?search=test-phishing")
                search_reports = res_search.json()
                print(f"✔ Filter by Search ('test-phishing'): Found {len(search_reports)}")
                
                # 4. Test PDF Generation
                print("\n4. Testing PDF Generation...")
                report_id = reports[0]['id']
                print(f"   Generating PDF for Report ID: {report_id}")
                res_pdf = requests.get(f"{BASE_URL}/reports/{report_id}")
                if res_pdf.status_code == 200:
                    content_type = res_pdf.headers.get('Content-Type')
                    if 'application/pdf' in content_type:
                        print("✔ PDF generated successfully (Content-Type: application/pdf)")
                        print(f"   Size: {len(res_pdf.content)} bytes")
                        # Save it to check manually if needed
                        with open(f"test_report_{report_id}.pdf", "wb") as f:
                            f.write(res_pdf.content)
                        print(f"   Saved to test_report_{report_id}.pdf")
                    else:
                        print(f"❌ Invalid Content-Type: {content_type}")
                else:
                    print(f"❌ PDF Generation failed: {res_pdf.status_code}")
                    
            else:
                print("⚠ No reports found to test filters/PDF")
        else:
            print(f"❌ Failed to fetch reports: {res.status_code}")
    except Exception as e:
        print(f"❌ Error testing reports: {e}")

if __name__ == "__main__":
    test_reports()
