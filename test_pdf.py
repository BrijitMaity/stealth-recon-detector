import requests
import pyotp

# 1. Login to get cookie
url_login = "http://localhost:5000/login"
totp = pyotp.TOTP("JBSWY3DPEHPK3PXP").now()
data = {
    "username": "admin",
    "password": "adminpass",
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
