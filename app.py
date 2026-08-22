from flask import Flask, send_from_directory, request, jsonify
from urllib.parse import urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import re
import io
import os
import shutil
import platform
import pytesseract
from PIL import Image

import db

# Load settings from a .env file if one exists (e.g. FLASK_DEBUG=True/False)
load_dotenv()

# =========================
# TESSERACT OCR (auto-detect, works on Windows/Linux/Mac)
# =========================

if not shutil.which("tesseract"):
    if platform.system() == "Windows":
        default_windows_path = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
        if os.path.exists(default_windows_path):
            pytesseract.pytesseract.tesseract_cmd = default_windows_path


# =========================
# FLASK APP
# =========================

app = Flask(__name__)

# Max upload size: 5 MB. Stops someone from uploading a huge file and
# slowing down / crashing the server.
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Create the database file/table (if it doesn't exist yet) as soon as the app starts.
db.init_db()

# =========================
# RATE LIMITING
# Stops one person/bot from spamming the API hundreds of times a minute.
# =========================

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)


# =========================
# WEBSITE FILES
# =========================

@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/<path:filename>")
def files(filename):
    return send_from_directory(".", filename)


# =========================
# URL ANALYZER
# =========================

@app.route("/api/check-url", methods=["POST"])
@limiter.limit("20 per minute")
def check_url():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "URL is required"
        }), 400

    url = data["url"].strip()

    # Add HTTPS if protocol is missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            return jsonify({
                "error": "Invalid URL"
            }), 400

        domain = domain.lower()

    except Exception:
        return jsonify({
            "error": "Invalid URL"
        }), 400

    # =========================
    # RISK ANALYSIS
    # =========================

    score = 0
    signals = []

    # 1. HTTPS CHECK
    if parsed.scheme != "https":
        score += 15

        signals.append({
            "type": "warning",
            "icon": "⚠️",
            "title": "No HTTPS",
            "description": "This website is not using HTTPS encryption."
        })

    # 2. IP ADDRESS CHECK
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"

    is_ip_address = bool(
        re.match(ip_pattern, domain)
    )

    if is_ip_address:
        score += 35

        signals.append({
            "type": "danger",
            "icon": "🚨",
            "title": "IP address detected",
            "description": "The link uses a direct IP address instead of a normal domain name."
        })

    # 3. SHORTENED URL CHECK
    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "cutt.ly",
        "is.gd",
        "shorturl.at"
    ]

    if any(
        domain == item or domain.endswith("." + item)
        for item in shortened_domains
    ):
        score += 25

        signals.append({
            "type": "warning",
            "icon": "🔗",
            "title": "Shortened URL detected",
            "description": "Shortened links can hide the real destination website."
        })

    # 4. BRAND IMPERSONATION CHECK
    # Scammers often put a real brand name in the domain, followed by
    # extra characters, to make it look official (e.g. usps.com-xyz.vip
    # instead of the real usps.com).
    known_brands = [
        "usps", "fedex", "dhl", "ups",
        "paypal", "amazon", "apple", "microsoft",
        "google", "facebook", "instagram", "whatsapp",
        "netflix", "bank", "hbl", "ubl", "meezan",
        "jazzcash", "easypaisa", "sbp"
    ]

    matched_brand = None

    for brand in known_brands:
        if brand in domain:
            # Allow the real domain and its normal subdomains,
            # e.g. usps.com or www.usps.com
            official_patterns = [
                brand + ".com",
                brand + ".org",
                brand + ".net"
            ]

            is_official = any(
                domain == pattern or domain.endswith("." + pattern)
                for pattern in official_patterns
            )

            if not is_official:
                matched_brand = brand
                break

    if matched_brand:
        score += 35

        signals.append({
            "type": "danger",
            "icon": "🎭",
            "title": "Possible brand impersonation",
            "description": f"The domain contains '{matched_brand}' but does not match {matched_brand}'s official website. This is a common scam trick."
        })

    # 5. SUSPICIOUS TLD CHECK
    suspicious_tlds = [
        ".vip", ".top", ".xyz", ".click", ".work",
        ".support", ".loan", ".gq", ".tk", ".ml",
        ".cf", ".ga", ".icu", ".rest", ".zip"
    ]

    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 15

        signals.append({
            "type": "warning",
            "icon": "🌐",
            "title": "Unusual domain ending",
            "description": "This domain uses an ending that's rarely used by legitimate companies and is common in scam links."
        })

    # 6. SUSPICIOUS DOMAIN WORDS
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "claim",
        "reward",
        "free",
        "gift",
        "payment",
        "signin",
        "security"
    ]

    found_words = [
        word
        for word in suspicious_words
        if word in domain
    ]

    if len(found_words) >= 2:
        score += 25

        signals.append({
            "type": "danger",
            "icon": "🔍",
            "title": "Suspicious domain pattern",
            "description": "The domain contains multiple suspicious terms commonly associated with phishing."
        })

    # 5. UNUSUAL SUBDOMAINS
    if not is_ip_address:
        parts = domain.split(".")

        if len(parts) >= 4:
            score += 10

            signals.append({
                "type": "warning",
                "icon": "⚠️",
                "title": "Unusual domain structure",
                "description": "The website uses an unusually complex subdomain structure."
            })

    # 6. VERY LONG DOMAIN
    if len(domain) > 40:
        score += 10

        signals.append({
            "type": "warning",
            "icon": "📏",
            "title": "Very long domain",
            "description": "The domain name is unusually long and should be checked carefully."
        })

    # 7. SUSPICIOUS @ SYMBOL
    if "@" in url:
        score += 25

        signals.append({
            "type": "danger",
            "icon": "🚨",
            "title": "Suspicious URL structure",
            "description": "The URL contains an @ symbol, which can sometimes disguise the actual destination."
        })

    # =========================
    # SCORE LIMIT
    # =========================

    score = min(score, 100)

    # =========================
    # RISK LEVEL
    # =========================

    if score >= 70:
        risk = "High Risk"

        message = (
            "🚨 This URL contains multiple strong warning signs. "
            "Avoid opening it or entering personal information."
        )

    elif score >= 40:
        risk = "Medium Risk"

        message = (
            "⚠️ This URL contains several suspicious signals. "
            "Verify the website independently before continuing."
        )

    elif score > 0:
        risk = "Low Risk"

        message = (
            "🔎 Some warning signs were detected. "
            "Proceed carefully and verify the website."
        )

    else:
        risk = "No Obvious Risk"

        message = (
            "✅ No obvious suspicious URL patterns were detected."
        )

    # =========================
    # SAVE TO DATABASE
    # =========================

    try:
        db.log_scan(
            scan_type="url",
            content_snippet=domain,
            score=score,
            risk_level=risk,
            signal_count=len(signals)
        )
    except Exception as error:
        print("DB LOG ERROR (check_url):", error)

    # =========================
    # RETURN URL RESULT
    # =========================

    return jsonify({
        "url": url,
        "domain": domain,
        "score": score,
        "risk": risk,
        "riskLevel": risk,
        "message": message,
        "riskMessage": message,
        "signals": signals
    })


# =========================
# SCREENSHOT OCR
# =========================

@app.route("/api/ocr", methods=["POST"])
@limiter.limit("10 per minute")
def ocr_screenshot():

    if "screenshot" not in request.files:
        return jsonify({
            "success": False,
            "error": "No screenshot uploaded"
        }), 400

    file = request.files["screenshot"]

    if file.filename == "":
        return jsonify({
            "success": False,
            "error": "No screenshot selected"
        }), 400

    allowed_extensions = {
        "png",
        "jpg",
        "jpeg"
    }

    filename = file.filename.lower()

    if "." not in filename:
        return jsonify({
            "success": False,
            "error": "Invalid image file"
        }), 400

    extension = filename.rsplit(".", 1)[1]

    if extension not in allowed_extensions:
        return jsonify({
            "success": False,
            "error": "Only PNG, JPG and JPEG images are supported"
        }), 400

    try:
        # Read uploaded image
        image_bytes = file.read()

        image = Image.open(
            io.BytesIO(image_bytes)
        )

        # Convert image to RGB
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Extract text using Tesseract
        extracted_text = pytesseract.image_to_string(
            image
        )

        extracted_text = extracted_text.strip()

        # No readable text found
        if not extracted_text:
            return jsonify({
                "success": False,
                "text": "",
                "message": "No readable text was detected in the screenshot."
            })

        # Successful OCR
        return jsonify({
            "success": True,
            "text": extracted_text,
            "message": "Text successfully extracted from screenshot."
        })

    except pytesseract.TesseractNotFoundError:
        return jsonify({
            "success": False,
            "error": "Tesseract OCR was not found. Check the installation path."
        }), 500

    except Exception as error:
        print("OCR ERROR:", error)

        return jsonify({
            "success": False,
            "error": "Unable to read the screenshot."
        }), 500


# =========================
# LOG A MESSAGE SCAN (called from the frontend after it analyzes a pasted message)
# =========================

@app.route("/api/log-scan", methods=["POST"])
@limiter.limit("30 per minute")
def log_scan():

    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        db.log_scan(
            scan_type=data.get("scanType", "message"),
            content_snippet=data.get("snippet", ""),
            score=int(data.get("score", 0)),
            risk_level=data.get("riskLevel", "Unknown"),
            signal_count=int(data.get("signalCount", 0))
        )
    except Exception as error:
        print("DB LOG ERROR (log_scan):", error)
        return jsonify({"error": "Failed to log scan"}), 500

    return jsonify({"success": True})


# =========================
# USAGE STATS (for homepage / dashboard)
# =========================

@app.route("/api/stats", methods=["GET"])
def stats():
    try:
        return jsonify(db.get_stats())
    except Exception as error:
        print("DB STATS ERROR:", error)
        return jsonify({"total_scans": 0, "high_risk_scans": 0}), 500


# =========================
# ERROR HANDLERS (clean JSON responses instead of default HTML error pages)
# =========================

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "success": False,
        "error": "File is too large. Maximum allowed size is 5MB."
    }), 413


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        "success": False,
        "error": "Too many requests. Please slow down and try again shortly."
    }), 429


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Something went wrong on our end. Please try again."
    }), 500


# =========================
# START SERVER
# =========================

if __name__ == "__main__":
    # Reads FLASK_DEBUG from a .env file. Defaults to False (safe) if not set.
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode)
