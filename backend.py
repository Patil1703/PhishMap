from flask import Flask, request, jsonify
from flask_cors import CORS
import datetime as dt
import pandas as pd
import joblib
import re
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import random
import socket
import io
import os
from PIL import Image
import imagehash
import pickle
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from PIL import Image

# TensorFlow / Keras
try:
    from tensorflow.keras.applications import MobileNetV2
    from tensorflow.keras.applications.mobilenet_v2 import preprocess_input
    from tensorflow.keras.preprocessing import image as keras_image
    CNN_AVAILABLE = True
except Exception:
    CNN_AVAILABLE = False

# Whois
try:
    import whois
except Exception:
    whois = None

app = Flask(__name__)
CORS(app)

# -----------------------------
# Screenshot Capture
# -----------------------------





def capture_screenshot(url, width=1200, height=900, timeout=10):
    options = Options()
    options.add_argument("--headless")  # safer on Windows
    options.add_argument(f"--window-size={width},{height}")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")

    driver = None
    try:
        # ✅ Correct way to initialize Chrome with webdriver_manager
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)

        driver.set_page_load_timeout(timeout)
        driver.get(url)

        png = driver.get_screenshot_as_png()
        driver.quit()
        return Image.open(io.BytesIO(png)).convert("RGB")

    except Exception as e:
        print("❌ Screenshot error:", type(e).__name__, str(e))
        if driver:
            try:
                driver.quit()
            except:
                pass
        return None



# -----------------------------
# Brand DB + CNN model
# -----------------------------
BRAND_DB_FILE = "brand_db.pkl"
_brand_db = {}
if os.path.exists(BRAND_DB_FILE):
    with open(BRAND_DB_FILE, "rb") as f:
        _brand_db = pickle.load(f)

_cnn = None
if CNN_AVAILABLE:
    try:
        _cnn = MobileNetV2(weights="imagenet", include_top=False, pooling="avg")
    except Exception:
        _cnn = None

def phash_distance(h1, h2):
    i1 = int(str(h1), 16)
    i2 = int(str(h2), 16)
    return bin(i1 ^ i2).count("1")

def compute_ui_similarity(screenshot_img):
    if screenshot_img is None or not _brand_db:
        return None, 0, "No screenshot or brand DB empty"

    img_small = screenshot_img.resize((380, 380))
    s_phash = str(imagehash.phash(img_small))

    best_brand, best_score = None, -1
    explanations = []

    for brand, info in _brand_db.items():
        b_phash = info.get("phash")
        phash_sim = 0
        if b_phash:
            dist = phash_distance(s_phash, b_phash)
            phash_sim = max(0, 100 - int((dist / 64.0) * 100))

        combined_score = phash_sim

        if _cnn and info.get("embedding") is not None:
            x = keras_image.img_to_array(img_small.resize((224, 224)))
            x = np.expand_dims(x, axis=0)
            x = preprocess_input(x)
            s_emb = _cnn.predict(x)[0]
            b_emb = info["embedding"]
            cos = np.dot(s_emb, b_emb) / (np.linalg.norm(s_emb) * np.linalg.norm(b_emb) + 1e-9)
            emb_score = int((cos + 1) / 2 * 100)
            combined_score = int(0.5 * phash_sim + 0.5 * emb_score)

        if combined_score > best_score:
            best_score = combined_score
            best_brand = brand

        explanations.append(f"{brand}: {phash_sim:.0f}%")

    explanation = f"Top match: {best_brand} ({best_score}%). Details: " + ", ".join(explanations[:4])
    return best_brand, int(best_score), explanation

# -----------------------------
# Malicious Dataset
# -----------------------------
MALICIOUS_DATASET = {
    "http://lottery-winner-now.org": {
        "category": "Lottery Scam",
        "severity": "High",
        "threat": "Tricks users into fake winnings"
    },
    "http://fake-shopping-deals.net": {
        "category": "Shopping Scam",
        "severity": "High",
        "threat": "Fake e-commerce site stealing card info"
    }
}

# -----------------------------
# ML Model
# -----------------------------
MODEL_PATH = "phishing_model.pkl"
model = None
try:
    df = pd.read_csv("dataset.csv")
    X = df.drop(["Result", "index"], axis=1)
    y = df["Result"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    joblib.dump(model, MODEL_PATH)
    print("✅ Model trained and saved as phishing_model.pkl")
except Exception as e:
    print("ℹ️ Skipping ML training:", e)

# -----------------------------
# Helpers
# -----------------------------
def get_whois(domain):
    if not whois: return None
    try: return whois.whois(domain)
    except: return None

def domain_age_days(domain):
    w = get_whois(domain)
    if not w or not getattr(w, "creation_date", None):
        return None
    creation = w.creation_date
    if isinstance(creation, list): creation = creation[0]
    try: return (dt.datetime.now() - creation).days
    except: return None

# -----------------------------
# Rule-based classifier
# -----------------------------
SUSPICIOUS_TLDS = {"xyz","top","monster","gq","ml","cf","tk","ru","cn","zip"}
KEYWORD_MAP = {"Lottery Scam": ["lottery","winner","prize","claim"]}

def rule_based_classify(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    scheme = parsed.scheme.lower()
    reasons, risk = [], 0
    detected_category = None

    if domain.split(".")[-1] in SUSPICIOUS_TLDS:
        risk += 10; reasons.append("Suspicious TLD")
    if scheme != "https":
        risk += 8; reasons.append("Not using HTTPS")

    age = domain_age_days(domain)
    if age and age < 90:
        risk += 12; reasons.append(f"Very new domain ({age} days)")

    for cat, words in KEYWORD_MAP.items():
        if any(w in url.lower() for w in words):
            detected_category = cat
            risk += 20; reasons.append(f"Keyword match for {cat}")

    result = "malicious" if risk >= 75 else "suspicious" if risk >= 45 else "benign"
    severity = "High" if risk >= 75 else "Medium" if risk >= 45 else "Low"

    return {
        "result": result, "category": detected_category or "Safe/Unknown",
        "risk_score": min(100, risk), "severity": severity, "reasons": reasons
    }

# -----------------------------
# Scan Endpoint
# -----------------------------
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    base = {
        "url": url, "timestamp": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": "Safe/Unknown", "severity": "Low", "result": "benign",
        "risk_score": 0, "threat": "No issues detected",
        "explanation": ""
    }

    if not url:
        base["category"] = "Error"; base["threat"] = "Empty URL"; base["result"] = "unknown"
        return jsonify(base)

    # 1) Dataset
    if url in MALICIOUS_DATASET:
        entry = MALICIOUS_DATASET[url]
        base.update(entry); base["result"] = "malicious"; base["risk_score"] = 95
        base["explanation"] = f"Matched dataset: {entry['category']}"
        return jsonify(base)

    # 2) Rule-based
    rb = rule_based_classify(url); base.update(rb)
    base["explanation"] = "Rule-based: " + "; ".join(rb["reasons"])

    # 3) ML
    if model:
        feats = [len(url), len(urlparse(url).netloc), url.count(".")]
        try:
            pred = model.predict([feats + [0]*(model.n_features_in_-len(feats))])[0]
            if pred == 1:
                base["result"] = "malicious"; base["severity"] = "High"
                base["explanation"] += " | ML flagged phishing"
        except: pass

    # 4) UI similarity
    screenshot = capture_screenshot(url)
    if screenshot:
        ui_brand, ui_score, ui_expl = compute_ui_similarity(screenshot)
        base["ui_brand_match"] = ui_brand; base["ui_similarity_score"] = ui_score
        base["ui_explanation"] = ui_expl
        if ui_score >= 75:
            base["result"] = "malicious"; base["risk_score"] = max(base["risk_score"], 85)
            base["threat"] += f" | UI matches {ui_brand} ({ui_score}%)"
        elif ui_score >= 50:
            base["result"] = "suspicious"; base["risk_score"] = max(base["risk_score"], 60)
            base["threat"] += f" | UI partly matches {ui_brand} ({ui_score}%)"
    else:
        base["ui_explanation"] = "Screenshot failed"

    return jsonify(base)

# -----------------------------
# Alerts
# -----------------------------
@app.route("/alerts", methods=["GET"])
def alerts():
    out = []
    for u, entry in random.sample(list(MALICIOUS_DATASET.items()), k=min(2, len(MALICIOUS_DATASET))):
        out.append({
            "url": u, "category": entry["category"], "severity": entry["severity"],
            "threat": entry["threat"], "timestamp": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify(out)

if __name__ == "__main__":
    app.run(debug=True)
