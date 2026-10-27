"""
=============================================================================
HTTPS Security Analyzer - Flask Web Application Server
=============================================================================
Course / Subject : Cryptography and Network Security (CNS)
Project Title    : HTTPS Security Analyzer: Analyzing Secure Web Communication
                   and Digital Certificates
Author           : College Student Project
=============================================================================
"""

import os
from flask import Flask, render_template, request, jsonify
from utils.ssl_analyzer import clean_url, analyze_target
from utils.security_score import calculate_security_score

app = Flask(__name__)

# Sample test domains for viva demonstration & quick exploration
SAMPLE_DOMAINS = [
    {
        "name": "Google",
        "url": "https://google.com",
        "desc": "Modern TLS 1.3 with GTS Root CA",
        "category": "standard"
    },
    {
        "name": "Cloudflare",
        "url": "https://cloudflare.com",
        "desc": "High-performance TLS 1.3 & ChaCha20/AES-GCM",
        "category": "standard"
    },
    {
        "name": "GitHub",
        "url": "https://github.com",
        "desc": "Commercial DigiCert X.509 Certificate",
        "category": "standard"
    },
    {
        "name": "Wikipedia",
        "url": "https://wikipedia.org",
        "desc": "Free Automated Let's Encrypt Authority",
        "category": "standard"
    },
    {
        "name": "Expired SSL Test",
        "url": "https://expired.badssl.com",
        "desc": "Demonstrates expired certificate detection",
        "category": "test"
    },
    {
        "name": "Self-Signed Test",
        "url": "https://self-signed.badssl.com",
        "desc": "Demonstrates untrusted root / self-signed detection",
        "category": "test"
    }
]


@app.route('/')
def index():
    """
    Renders the primary single-page dashboard.
    """
    return render_template('index.html', samples=SAMPLE_DOMAINS)


@app.route('/api/samples', methods=['GET'])
def get_samples():
    """
    Returns pre-configured sample URLs for instant testing.
    """
    return jsonify({
        "success": True,
        "samples": SAMPLE_DOMAINS
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Main API endpoint:
    Receives JSON payload with website URL, validates HTTPS format,
    performs socket and SSL connection analysis, and calculates
    the cryptographic security score.

    Flow:
    1. Parse JSON: { "url": "https://example.com" }
    2. clean_url(): Validate URL & enforce HTTPS scheme
    3. analyze_target(): Connect via socket & ssl, extract handshake & X.509 data
    4. calculate_security_score(): Score 0-100 with educational factor breakdown
    5. Return JSON to frontend
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_url = data.get('url', '').strip()

        if not raw_url:
            return jsonify({
                "success": False,
                "error": "Please enter a valid website URL (e.g. https://google.com).",
                "error_type": "INPUT_REQUIRED"
            }), 400

        # Step 1: Validate URL and enforce HTTPS
        cleaned = clean_url(raw_url)
        if not cleaned["success"]:
            return jsonify({
                "success": False,
                "error": cleaned["error"],
                "error_type": "INVALID_URL"
            }), 400

        hostname = cleaned["hostname"]
        port = cleaned["port"]

        # Step 2: Perform TLS handshake and certificate extraction
        analysis = analyze_target(hostname, port=port, timeout=7)

        if not analysis["success"]:
            return jsonify({
                "success": False,
                "hostname": hostname,
                "error": analysis.get("error", "Unable to establish secure HTTPS connection."),
                "error_type": analysis.get("error_type", "ANALYSIS_FAILED"),
                "ip_address": analysis.get("ip_address")
            }), 200

        # Step 3: Compute Cryptographic Security Score
        score_data = calculate_security_score(analysis)

        return jsonify({
            "success": True,
            "data": analysis,
            "score": score_data
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"An unexpected server error occurred: {str(e)}",
            "error_type": "SERVER_EXCEPTION"
        }), 500


if __name__ == '__main__':
    # Local development server on port 5000
    print("=" * 65)
    print(" HTTPS Security Analyzer - Web Application Server")
    print(" College Cryptography Subject Project")
    print(" Server running locally at: http://127.0.0.1:5000")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=True)
