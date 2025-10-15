from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction
from urllib.parse import urlparse
import os
import requests

warnings.filterwarnings("ignore")

app = Flask(__name__)

# Load model if available
model = None
if os.path.exists("newmodel.pkl"):
    try:
        with open("newmodel.pkl", "rb") as f:
            model = pickle.load(f)
        print("[INFO] Model loaded successfully.")
    except Exception as e:
        print(f"[WARN] Could not load model: {e}")
else:
    print("[WARN] newmodel.pkl not found. Running without ML.")

# ✅ Always safe domains (trusted sites)
whitelist = [
    "netflix.com", "youtube.com", "youtu.be", "google.com", "gmail.com",
    "github.com", "openai.com", "wikipedia.org", "microsoft.com", "apple.com",
    "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "amazon.com", "primevideo.com", "disneyplus.com", "hbo.com", "spotify.com",
    "paypal.com", "bankofamerica.com", "chase.com", "wellsfargo.com", "hsbc.com",
    "icicibank.com", "sbi.co.in", "hdfcbank.com", "axisbank.com", "kotak.com"
]

# Custom blacklist for phishing/piracy/fake sites
blacklist = [
    "movierulz", "ibomma", "tamilrockers", "filmyzilla",
    "123movies", "gomovies", "yesmovies", "fmovies", "putlocker", "solarmovie",
    "katmoviehd", "worldfree4u", "hdhub4u", "skymovieshd", "extramovies",
    "moviescounter", "9xmovies", "7starhd", "bolly4u", "desiremovies",
    "downloadhub", "vegamovies", "flixhd", "okjatt", "jiorockers", "mkvcinemas",

    # Generic phishing keywords
    "secure-login", "login-verify", "update-account", "confirm-password",
    "reset-banking", "verify-now", "id-verification", "confirm-identity",
    "security-check", "update-required", "2fa-bypass", "fake-login",
    "support-team", "alert-notification", "account-suspended"
]

def is_whitelisted(url: str, whitelist) -> bool:
    netloc = urlparse(url).netloc.lower()
    return any(netloc.endswith(domain) for domain in whitelist)

def is_blacklisted(url: str, blacklist) -> bool:
    netloc = urlparse(url).netloc.lower()
    return any(b in netloc for b in blacklist)

# Google Safe Browsing API key (replace with your key)
GOOGLE_API_KEY = "AIzaSyCHf_24yF-66L_sNQPEIx30SOnv92622oE"
SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

def check_google_safe_browsing(url):
    """Check if URL is flagged by Google Safe Browsing"""
    body = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(SAFE_BROWSING_URL, json=body, timeout=5)
        if response.status_code == 200 and response.json().get("matches"):
            return True  # Threat detected
    except Exception as e:
        print(f"[WARN] Safe Browsing check failed: {e}")
    return False

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/result", methods=["POST"])
def result():
    url = request.form.get("url")
    if not url:
        return render_template("index.html", error="Please enter a URL")

    try:
        obj = FeatureExtraction(url)
        features = obj.getFeaturesList()
        risk_score = obj.getRiskScore()

        # Default status
        status = "Unknown"
        headline = "Analysis"

        # 0. Whitelist check → Always Safe
        if is_whitelisted(url, whitelist):
            status = "Safe"
            headline = "Whitelisted domain"

        # 1. Blacklist check
        elif is_blacklisted(url, blacklist):
            status = "Phishing"
            headline = "Flagged by blacklist keywords"

        # 2. Suspicious keywords
        elif obj.AbnormalURL() == -1:
            status = "Phishing"
            headline = "Suspicious keyword detected"

        # 3. Risk score >= 2
        elif risk_score >= 2:
            status = "Phishing"
            headline = f"High risk score: {risk_score}%"

        # 4. Google Safe Browsing
        elif check_google_safe_browsing(url):
            status = "Phishing"
            headline = "Flagged by Google Safe Browsing"

        # 5. ML model (last priority)
        elif model:
            x = np.array(features).reshape(1, 30)
            y_pred = model.predict(x)[0]
            status = "Safe" if y_pred == 1 else "Phishing"
            headline = "AI-based classification"

        data = {
            "url": url,
            "status": status,
            "headline": headline,
            "features": obj.debug_feature_vector(),
            "ssl_info": obj.getSSLInfo(),
            "domain_age_months": obj.getDomainAge(),
            "location": obj.getGeoLocation(),
            "risk_score": risk_score,
            "reasons": obj.getReasons(),
            "redirects": obj.getRedirectChain(),
        }

        return render_template("index.html", data=data)

    except Exception as e:
        return render_template("index.html", error=f"Error analyzing URL: {e}")

if __name__ == "__main__":
    app.run(debug=True)
