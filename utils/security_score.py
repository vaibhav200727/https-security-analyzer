"""
=============================================================================
HTTPS Security Analyzer - Security Scoring & Educational Evaluation Module
=============================================================================
Course / Subject : Cryptography and Network Security (CNS)
Purpose          : Calculates a transparent, 100-point security score based
                   on core TLS/SSL cryptographic parameters:
                   1. HTTPS Availability (+25)
                   2. Modern TLS Version (+25)
                   3. Strong Symmetric Cipher Suite (+20)
                   4. Valid & Trusted Digital Certificate (+20)
                   5. Certificate Expiration Health (+10)
=============================================================================
"""

def calculate_security_score(analysis_result: dict) -> dict:
    """
    Computes a beginner-friendly security score out of 100 along with
    a transparent point-by-point breakdown and cryptographic explanations.

    Returns:
        dict: {
            "score": int (0-100),
            "grade": str,
            "badge_color": str,
            "summary": str,
            "breakdown": list of factor dicts,
            "recommendations": list of strings,
            "disclaimer": str
        }
    """
    if not analysis_result or not analysis_result.get("success"):
        return {
            "score": 0,
            "grade": "F",
            "badge_color": "danger",
            "summary": "Connection failed. No secure TLS session could be established.",
            "breakdown": [
                {
                    "factor": "HTTPS Available",
                    "points": 0,
                    "max_points": 25,
                    "status": "Failed",
                    "passed": False,
                    "explanation": "No HTTPS connection could be negotiated."
                }
            ],
            "recommendations": ["Ensure the server supports HTTPS on port 443."],
            "disclaimer": "This score is an educational evaluation for Cryptography study, not a penetration test."
        }

    breakdown = []
    total_score = 0
    recommendations = []

    # -------------------------------------------------------------------------
    # Factor 1: HTTPS Availability (Max: 25 points)
    # Cryptography Concept: Secures HTTP traffic over TLS/TCP on port 443.
    # -------------------------------------------------------------------------
    https_ok = analysis_result.get("https_supported", False)
    if https_ok:
        pts = 25
        status = "Pass (+25)"
        explanation = "HTTPS is actively supported on port 443, securing data transmission against plaintext eavesdropping."
        passed = True
    else:
        pts = 0
        status = "Failed (0)"
        explanation = "HTTPS is unavailable or refused on port 443."
        passed = False
        recommendations.append("Deploy TLS/SSL on the web server to secure web traffic.")

    total_score += pts
    breakdown.append({
        "factor": "HTTPS Protocol Support",
        "points": pts,
        "max_points": 25,
        "status": status,
        "passed": passed,
        "explanation": explanation
    })

    # -------------------------------------------------------------------------
    # Factor 2: TLS Protocol Version (Max: 25 points)
    # Cryptography Concept:
    # - TLS 1.3 (+25): Removes insecure ciphers, provides 1-RTT handshake,
    #   enforces forward secrecy.
    # - TLS 1.2 (+15): Secure and widely adopted, but supports legacy ciphers.
    # - TLS 1.0 / 1.1 (0): Deprecated by RFC 8996 due to known cryptographic attacks (BEAST, POODLE).
    # -------------------------------------------------------------------------
    tls_ver = analysis_result.get("tls_version", "")
    if "TLSv1.3" in tls_ver or "1.3" in tls_ver:
        pts = 25
        status = "Optimal (+25)"
        explanation = "Negotiated TLS 1.3, the latest standard with enhanced speed, mandatory forward secrecy, and obsolete ciphers eliminated."
        passed = True
    elif "TLSv1.2" in tls_ver or "1.2" in tls_ver:
        pts = 18
        status = "Acceptable (+18)"
        explanation = "Negotiated TLS 1.2. Secure, but consider upgrading to TLS 1.3 for enhanced security and faster handshakes."
        passed = True
        recommendations.append("Upgrade web server configuration to enable TLS 1.3.")
    elif "TLSv1.1" in tls_ver or "TLSv1.0" in tls_ver or "SSL" in tls_ver:
        pts = 0
        status = "Deprecated (0)"
        explanation = f"Negotiated {tls_ver}, which is deprecated and vulnerable to known cryptographic attacks."
        passed = False
        recommendations.append("Immediately disable TLS 1.0 / 1.1 and upgrade to TLS 1.2 or 1.3.")
    else:
        pts = 10
        status = "Unknown (+10)"
        explanation = f"TLS version ({tls_ver}) could not be definitively classified."
        passed = False

    total_score += pts
    breakdown.append({
        "factor": "TLS Protocol Version",
        "points": pts,
        "max_points": 25,
        "status": status,
        "passed": passed,
        "explanation": explanation
    })

    # -------------------------------------------------------------------------
    # Factor 3: Strong Cipher Suite (Max: 20 points)
    # Cryptography Concept:
    # - AEAD (Authenticated Encryption with Associated Data) like AES-GCM
    #   or ChaCha20-Poly1305 provides both Confidentiality & Integrity.
    # - 128-bit or 256-bit symmetric encryption keys resist brute-force attacks.
    # -------------------------------------------------------------------------
    cipher = analysis_result.get("cipher_info", {})
    cipher_name = cipher.get("cipher_name", "")
    bits = cipher.get("bits", 0)
    is_aead = cipher.get("is_aead", False)

    if is_aead and bits >= 256:
        pts = 20
        status = "Excellent (+20)"
        explanation = f"Negotiated strong 256-bit AEAD cipher ({cipher_name}) providing authenticated encryption and forward secrecy."
        passed = True
    elif is_aead and bits >= 128:
        pts = 18
        status = "Strong (+18)"
        explanation = f"Negotiated 128-bit AEAD cipher ({cipher_name}). High cryptographic strength with integrated integrity verification."
        passed = True
    elif bits >= 128 and ("CBC" in cipher_name or "AES" in cipher_name):
        pts = 12
        status = "Moderate (+12)"
        explanation = f"Negotiated {cipher_name} ({bits} bits). CBC mode lacks built-in AEAD integrity verification."
        passed = True
        recommendations.append("Switch to modern AEAD ciphers such as AES-GCM or ChaCha20-Poly1305.")
    elif "RC4" in cipher_name or "3DES" in cipher_name or "DES" in cipher_name:
        pts = 0
        status = "Insecure (0)"
        explanation = f"Weak/broken cipher detected ({cipher_name}). Insecure against modern cryptanalysis."
        passed = False
        recommendations.append("Disable weak legacy ciphers (RC4, 3DES, DES) immediately.")
    else:
        pts = 15
        status = "Good (+15)"
        explanation = f"Standard cipher suite negotiated ({cipher_name}, {bits} bits)."
        passed = True

    total_score += pts
    breakdown.append({
        "factor": "Symmetric Cipher Suite Strength",
        "points": pts,
        "max_points": 20,
        "status": status,
        "passed": passed,
        "explanation": explanation
    })

    # -------------------------------------------------------------------------
    # Factor 4: Digital Certificate Trust & Verification (Max: 20 points)
    # Cryptography Concept:
    # - Identity Authentication: Proves the public key belongs to the domain.
    # - Digital Signature: CA signs certificate with its private key; browser verifies
    #   with CA public key.
    # -------------------------------------------------------------------------
    is_trusted = analysis_result.get("is_trusted", False)
    cert = analysis_result.get("certificate", {})
    validity_status = cert.get("validity_status", "")

    if is_trusted and validity_status == "Valid":
        pts = 20
        status = "Trusted (+20)"
        explanation = "Certificate is issued by a recognized Certificate Authority (CA) and signature successfully verified against the root trust store."
        passed = True
    elif validity_status == "Expired":
        pts = 0
        status = "Expired (0)"
        explanation = "The digital certificate has expired. Browsers will block access due to invalid authentication."
        passed = False
        recommendations.append("Renew and deploy an updated certificate from an authorized CA.")
    elif "Untrusted" in validity_status or not is_trusted:
        pts = 0
        status = "Untrusted (0)"
        explanation = f"Certificate verification failed ({analysis_result.get('verification_error') or 'Self-signed or untrusted CA'})."
        passed = False
        recommendations.append("Replace self-signed certificate with one issued by a trusted CA (e.g., Let's Encrypt, DigiCert).")
    else:
        pts = 10
        status = "Warning (+10)"
        explanation = f"Certificate status: {validity_status}."
        passed = False

    total_score += pts
    breakdown.append({
        "factor": "Certificate Trust & Signature Verification",
        "points": pts,
        "max_points": 20,
        "status": status,
        "passed": passed,
        "explanation": explanation
    })

    # -------------------------------------------------------------------------
    # Factor 5: Certificate Expiration Health (Max: 10 points)
    # Cryptography Concept:
    # - Validity period limits key exposure window and certificate lifespan.
    # -------------------------------------------------------------------------
    days_left = cert.get("days_remaining")

    if days_left is not None:
        if days_left > 30:
            pts = 10
            status = "Healthy (+10)"
            explanation = f"Certificate is valid for {days_left} more days (sufficient operational window)."
            passed = True
        elif days_left >= 0:
            pts = 5
            status = "Expiring Soon (+5)"
            explanation = f"Warning: Certificate expires in {days_left} day(s). Urgent renewal is recommended."
            passed = False
            recommendations.append(f"Renew certificate soon; only {days_left} days remaining until expiration.")
        else:
            pts = 0
            status = "Expired (0)"
            explanation = f"Certificate expired {abs(days_left)} days ago."
            passed = False
    else:
        pts = 5
        status = "Unknown (+5)"
        explanation = "Expiration date could not be accurately calculated."
        passed = False

    total_score += pts
    breakdown.append({
        "factor": "Certificate Expiration Health",
        "points": pts,
        "max_points": 10,
        "status": status,
        "passed": passed,
        "explanation": explanation
    })

    # Ensure total is bounded between 0 and 100
    total_score = max(0, min(100, total_score))

    # Grade classification
    if total_score >= 90:
        grade = "A+"
        rating_text = "Excellent Security"
        badge_color = "success"
    elif total_score >= 75:
        grade = "B"
        rating_text = "Good Security"
        badge_color = "primary"
    elif total_score >= 55:
        grade = "C"
        rating_text = "Moderate / Warnings"
        badge_color = "warning"
    else:
        grade = "F"
        rating_text = "Insecure / High Risk"
        badge_color = "danger"

    summary = (
        f"Security Score: {total_score}/100 ({rating_text}). "
        f"This domain achieves grade {grade} based on its TLS negotiation, "
        f"symmetric cipher strength, and X.509 certificate validity."
    )

    return {
        "score": total_score,
        "grade": grade,
        "rating_text": rating_text,
        "badge_color": badge_color,
        "summary": summary,
        "breakdown": breakdown,
        "recommendations": recommendations,
        "disclaimer": "This analyzer evaluates HTTPS/TLS configuration and digital certificate properties for educational Cryptography demonstrations. It is not an invasive vulnerability scanner or penetration-testing tool."
    }
