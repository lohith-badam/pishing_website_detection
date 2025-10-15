# Phishing Detector (Flask + Astonishing UI)

A Flask web app that predicts whether a URL is **Safe** or **Phishing**, and explains the decision with reasons, risk score, redirects, domain age, SSL info, and geolocation.

## Features
- 30 classical phishing-detection features
- Risk score (%)
- Reasons (human-readable)
- Redirect chain
- Domain age (months)
- SSL certificate summary
- IP/Geo (org, country)
- Report to Google Safe Browsing link
- REST API: `POST /api/scan { "url": "http://..." }`

## Setup
```bash
pip install -r requirements.txt
# put newmodel.pkl next to app.py
python app.py
```
Open: http://127.0.0.1:5000

## Notes
- Place your trained model file `newmodel.pkl` in the project root.
- Some features rely on external sites (WHOIS, ipinfo, checkpagerank). Network issues may affect them.
