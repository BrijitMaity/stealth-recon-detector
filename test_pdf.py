import requests
import pyotp

import os

# 1. Login to get cookie
url_login = "http://localhost:5000/login"
totp_secret = os.environ.get("STEALTH_TOTP_SECRET", "")
admin_pass = os.environ.get("STEALTH_DASHBOARD_PASS", "")

if not totp_secret or not admin_pass:
    print("Please set STEALTH_TOTP_SECRET and STEALTH_DASHBOARD_PASS to run this test.")
    exit(1)

totp = pyotp.TOTP(totp_secret).now()
data = {
    "username": "admin",
    "password": admin_pass,
    "totp_code": totp
}
session = requests.Session()
res = session.post(url_login, data=data, allow_redirects=False)
if res.status_code != 302:
    print(f"Login failed: {res.status_code} - {res.text}")
    exit(1)

# 2. Get PDF
url_pdf = "http://localhost:5000/api/export-pdf"
res2 = session.get(url_pdf)
if res2.status_code == 200 and res2.headers.get("Content-Type") == "application/pdf":
    print("SUCCESS: PDF downloaded successfully!")
    print(f"File size: {len(res2.content)} bytes")
else:
    print(f"PDF generation failed: {res2.status_code} - {res2.text}")
