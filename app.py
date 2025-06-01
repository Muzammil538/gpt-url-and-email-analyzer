from flask import Flask, request, jsonify
import requests
import re
import json
from functools import lru_cache

app = Flask(__name__)

# --- Config ---
GOOGLE_API_KEY = "YOUR_GOOGLE_API_KEY"
OPENROUTER_API_KEY = "YOUR_OPENROUTER_KEY"  # Get at https://openrouter.ai/keys

# --- OpenRouter Qwen3 API ---
def detect_phishing_email(email_text: str) -> bool:
    try:
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json"
            },
            data=json.dumps({
                "model": "qwen/qwen3-30b-a3b:free",
                "messages": [
                    {
                        "role": "system",
                        "content": "Analyze this email for phishing. Reply only '1' if phishing or '0' if safe:"
                    },
                    {
                        "role": "user", 
                        "content": email_text
                    }
                ],
                "temperature": 0.1  # Reduce randomness for binary classification
            }),
            timeout=10
        )
        result = response.json()["choices"][0]["message"]["content"]
        return "1" in result
    except Exception as e:
        print(f"OpenRouter error: {e}")
        return False

# --- Google Safe Browsing API (Cached) ---
@lru_cache(maxsize=1000)
def is_malicious_url(url: str) -> bool:
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "phishguard", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            }
        }
        response = requests.post(endpoint, json=payload, timeout=5).json()
        return bool(response.get("matches"))
    except Exception:
        return False

# --- Flask Routes ---
@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    email = data.get("email", "").strip()
    
    if not email:
        return jsonify({"error": "No email provided"}), 400

    urls = re.findall(r'https?://[^\s]+', email)
    is_phishing = detect_phishing_email(email)
    malicious_urls = [url for url in urls if is_malicious_url(url)]

    return jsonify({
        "phishing_email": is_phishing,
        "malicious_urls": malicious_urls
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)