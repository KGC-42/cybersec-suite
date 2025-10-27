"""
Test script to generate a fake malware alert
"""
import requests

# Your backend URL
BACKEND_URL = "https://cybersec-backend-production.up.railway.app"

# Login first
print("🔐 Logging in...")
login_response = requests.post(
    f"{BACKEND_URL}/auth/login",
    json={"email": "kgc78423@gmail.com", "password": "your-password-here"}  # ⚠️ PUT YOUR PASSWORD
)

token = login_response.json()["access_token"]
print("✅ Logged in!")

# Send fake malware alert
print("🦠 Sending test malware alert...")
alert_payload = {
    "agent_id": 1,
    "event_type": "malware_detected",
    "severity": "high",
    "source": "clamav_scanner",  # ✅ ADDED
    "title": "Malware Detected",  # ✅ ADDED
    "description": "TEST: Malware detected in Downloads folder",
    "details": {
        "file_path": "C:\\Users\\jandg\\Downloads\\suspicious_file.exe",
        "threat_name": "Win32.Trojan.Test",
        "scan_time": "2025-10-18T22:00:00Z"
    }
}

response = requests.post(
    f"{BACKEND_URL}/api/v1/events/ingest",
    json=alert_payload,
    headers={"Authorization": f"Bearer {token}"}
)

if response.status_code in [200, 201]:
    print("✅ Alert sent successfully!")
    print("🌐 Go check the Alerts page in your dashboard!")
else:
    print(f"❌ Failed: {response.status_code}")
    print(response.text)