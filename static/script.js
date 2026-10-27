/**
 * =============================================================================
 * HTTPS Security Analyzer - Interactive Client Logic
 * Course / Subject : Cryptography and Network Security (CNS)
 * =============================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    // DOM Element References
    const analyzeForm = document.getElementById('analyzeForm');
    const urlInput = document.getElementById('urlInput');
    const clearBtn = document.getElementById('clearBtn');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const btnLoader = analyzeBtn.querySelector('.btn-loader');

    const errorAlert = document.getElementById('errorAlert');
    const errorTitle = document.getElementById('errorTitle');
    const errorMessage = document.getElementById('errorMessage');
    const errorDetail = document.getElementById('errorDetail');

    const resultsSection = document.getElementById('resultsSection');
    const certificateSection = document.getElementById('certificateSection');
    const navLinkResults = document.getElementById('navLinkResults');
    const navLinkCert = document.getElementById('navLinkCert');

    const sampleChips = document.querySelectorAll('.chip');
    const btnExportJson = document.getElementById('btnExportJson');
    const toast = document.getElementById('toast');

    // Global variable to hold latest report JSON for export
    let latestReportData = null;

    // -------------------------------------------------------------------------
    // Input Helper Events
    // -------------------------------------------------------------------------
    urlInput.addEventListener('input', () => {
        clearBtn.style.display = urlInput.value.trim() ? 'block' : 'none';
        errorAlert.style.display = 'none';
    });

    clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        clearBtn.style.display = 'none';
        urlInput.focus();
    });

    // Quick Sample Chips Click
    sampleChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const sampleUrl = chip.getAttribute('data-url');
            if (sampleUrl) {
                urlInput.value = sampleUrl;
                clearBtn.style.display = 'block';
                runAnalysis(sampleUrl);
            }
        });
    });

    // Form Submit Handler
    analyzeForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const rawUrl = urlInput.value.trim();
        if (!rawUrl) {
            showError("Input Required", "Please enter a valid website URL starting with https://", "Example: https://google.com");
            return;
        }
        runAnalysis(rawUrl);
    });

    // Copy Report JSON to Clipboard
    btnExportJson.addEventListener('click', () => {
        if (!latestReportData) return;
        const jsonStr = JSON.stringify(latestReportData, null, 2);
        navigator.clipboard.writeText(jsonStr).then(() => {
            showToast("Cryptographic report JSON copied to clipboard!");
        }).catch(() => {
            showToast("Failed to copy JSON to clipboard.");
        });
    });

    // -------------------------------------------------------------------------
    // Analysis Request Dispatcher
    // -------------------------------------------------------------------------
    async function runAnalysis(targetUrl) {
        // Enforce HTTPS prefix client-side check
        let formattedUrl = targetUrl;
        if (!/^https?:\/\//i.test(formattedUrl)) {
            formattedUrl = 'https://' + formattedUrl;
            urlInput.value = formattedUrl;
        }

        if (!formattedUrl.toLowerCase().startsWith('https://')) {
            showError(
                "Insecure Scheme Detected",
                "This educational tool strictly analyzes HTTPS (port 443) connections.",
                "Plaintext HTTP does not perform TLS handshakes or use digital certificates."
            );
            return;
        }

        // Set Loading State
        setLoadingState(true);
        errorAlert.style.display = 'none';

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: formattedUrl })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                const errHead = data.error_type === "DNS_FAILURE" ? "DNS Resolution Failed" :
                                data.error_type === "TIMEOUT" ? "Connection Timeout" :
                                data.error_type === "CONNECTION_REFUSED" ? "Connection Refused (Port 443)" : "Connection Analysis Failed";

                showError(
                    errHead,
                    data.error || "Could not complete secure TLS connection to the server.",
                    `Target: ${data.hostname || formattedUrl} • Error Type: ${data.error_type || 'NETWORK_ERROR'}`
                );
                return;
            }

            // Save report data for copy / export
            latestReportData = data;

            // Render Dashboard & Details
            renderResults(data);

        } catch (err) {
            showError(
                "Network / Client Error",
                "Failed to communicate with the local Flask analyzer server.",
                err.message
            );
        } finally {
            setLoadingState(false);
        }
    }

    // -------------------------------------------------------------------------
    // UI Renderers
    // -------------------------------------------------------------------------
    function renderResults(payload) {
        const { data, score } = payload;
        const cert = data.certificate || {};
        const cipher = data.cipher_info || {};

        // 1. Target Header
        document.getElementById('resultsTargetLabel').textContent =
            `Target Domain: ${data.hostname} (Resolved IP: ${data.ip_address || 'N/A'} • Port: ${data.port})`;

        // 2. Telemetry Card
        document.getElementById('telHostname').textContent = data.hostname;
        document.getElementById('telIp').textContent = data.ip_address || 'Unavailable';
        document.getElementById('telPort').textContent = `${data.port} (HTTPS)`;

        const badgeHttps = document.getElementById('badgeHttpsStatus');
        if (data.is_trusted) {
            badgeHttps.textContent = 'Verified TLS';
            badgeHttps.className = 'badge-status';
        } else {
            badgeHttps.textContent = 'Untrusted / Warning';
            badgeHttps.className = 'badge-status tag-amber';
        }

        // Verification Warning Box
        const verifWarningBox = document.getElementById('verifWarningBox');
        const verifWarningMsg = document.getElementById('verifWarningMsg');
        if (!data.is_trusted && data.verification_error) {
            verifWarningBox.style.display = 'flex';
            verifWarningMsg.textContent = data.verification_error;
        } else {
            verifWarningBox.style.display = 'none';
        }

        // Recommendations List
        const recList = document.getElementById('recList');
        recList.innerHTML = '';
        if (score.recommendations && score.recommendations.length > 0) {
            score.recommendations.forEach(rec => {
                const li = document.createElement('li');
                li.textContent = rec;
                recList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = "Optimal cryptographic configuration. Modern TLS 1.3 and valid X.509 certificate in use.";
            recList.appendChild(li);
        }

        // 3. Security Score Gauge Card
        const scoreValEl = document.getElementById('scoreVal');
        const scoreCircleProgress = document.getElementById('scoreCircleProgress');
        const scoreGradePill = document.getElementById('scoreGradePill');
        const scoreRatingText = document.getElementById('scoreRatingText');
        const scoreSummaryText = document.getElementById('scoreSummaryText');

        const scoreNum = score.score || 0;
        scoreValEl.textContent = scoreNum;
        scoreGradePill.textContent = `Grade ${score.grade}`;
        scoreRatingText.textContent = score.rating_text;
        scoreSummaryText.textContent = score.summary;

        // Animate circular meter (perimeter = 2 * PI * 50 = 314)
        const circumference = 314;
        const offset = circumference - (circumference * scoreNum / 100);
        scoreCircleProgress.style.strokeDashoffset = offset;

        // Dynamic stroke color based on score grade
        let strokeColor = 'var(--status-green)';
        let pillClass = 'score-grade-pill';
        if (scoreNum < 55) {
            strokeColor = 'var(--status-rose)';
            pillClass += ' pts-fail';
        } else if (scoreNum < 75) {
            strokeColor = 'var(--status-amber)';
            pillClass += ' pts-warn';
        } else {
            strokeColor = 'var(--status-green)';
            pillClass += ' pts-pass';
        }
        scoreCircleProgress.style.stroke = strokeColor;
        scoreGradePill.className = pillClass;

        // Render Score Breakdown Checklist
        const breakdownList = document.getElementById('breakdownList');
        breakdownList.innerHTML = '';
        if (score.breakdown && score.breakdown.length > 0) {
            score.breakdown.forEach(item => {
                const div = document.createElement('div');
                div.className = 'breakdown-item';

                const pointClass = item.points === item.max_points ? 'pts-pass' :
                                   item.points > 0 ? 'pts-warn' : 'pts-fail';

                div.innerHTML = `
                    <div class="breakdown-info">
                        <span class="breakdown-factor">${item.factor}</span>
                        <span class="breakdown-desc">${item.explanation}</span>
                    </div>
                    <span class="breakdown-points ${pointClass}">${item.status}</span>
                `;
                breakdownList.appendChild(div);
            });
        }

        // 4. Six Key Metric Dashboard Cards
        // Card 1: HTTPS Status
        const tagHttps = document.getElementById('tagHttps');
        const valHttps = document.getElementById('valHttps');
        if (data.https_supported) {
            tagHttps.textContent = 'Active';
            tagHttps.className = 'metric-tag tag-green';
            valHttps.textContent = 'HTTPS Enabled';
        } else {
            tagHttps.textContent = 'Disabled';
            tagHttps.className = 'metric-tag tag-rose';
            valHttps.textContent = 'Insecure';
        }

        // Card 2: TLS Version
        const tagTls = document.getElementById('tagTls');
        const valTls = document.getElementById('valTls');
        const subTls = document.getElementById('subTls');
        valTls.textContent = data.tls_version || 'Unknown';
        if ((data.tls_version || '').includes('1.3')) {
            tagTls.textContent = 'TLS 1.3 (RFC 8446)';
            tagTls.className = 'metric-tag tag-cyan';
            subTls.textContent = 'Eliminates legacy algorithms, enforces forward secrecy.';
        } else if ((data.tls_version || '').includes('1.2')) {
            tagTls.textContent = 'TLS 1.2 (RFC 5246)';
            tagTls.className = 'metric-tag tag-blue';
            subTls.textContent = 'Modern and widely supported standard.';
        } else {
            tagTls.textContent = 'Legacy';
            tagTls.className = 'metric-tag tag-rose';
            subTls.textContent = 'Vulnerable legacy protocol. Upgrade required.';
        }

        // Card 3: Negotiated Cipher Suite
        const tagCipher = document.getElementById('tagCipher');
        const valCipher = document.getElementById('valCipher');
        const subCipher = document.getElementById('subCipher');
        valCipher.textContent = cipher.cipher_name || 'Standard Cipher';
        if (cipher.is_aead) {
            tagCipher.textContent = 'AEAD Verified';
            tagCipher.className = 'metric-tag tag-purple';
            subCipher.textContent = 'Combines confidentiality and message integrity.';
        } else {
            tagCipher.textContent = 'Standard';
            tagCipher.className = 'metric-tag tag-blue';
            subCipher.textContent = `${cipher.strength_rating || 'Symmetric cipher'}`;
        }

        // Card 4: Symmetric Encryption & Key Exchange
        const tagCrypto = document.getElementById('tagCrypto');
        const valCrypto = document.getElementById('valCrypto');
        const subCrypto = document.getElementById('subCrypto');
        valCrypto.textContent = cipher.encryption_algorithm || 'AES Encryption';
        subCrypto.textContent = `Key Exchange: ${cipher.key_exchange || 'ECDHE'}`;
        tagCrypto.textContent = `${cipher.bits || 256}-bit Key`;

        // Card 5: Certificate Trust Status
        const tagCert = document.getElementById('tagCert');
        const valCert = document.getElementById('valCert');
        const subCert = document.getElementById('subCert');
        const iconCertWrap = document.getElementById('iconCertWrap');

        const certStatus = cert.validity_status || 'Unknown';
        valCert.textContent = certStatus;
        if (certStatus === 'Valid') {
            tagCert.textContent = 'Trusted CA';
            tagCert.className = 'metric-tag tag-green';
            subCert.textContent = 'Signature matches local trust store.';
            iconCertWrap.className = 'metric-icon icon-green';
        } else if (certStatus === 'Expired') {
            tagCert.textContent = 'Expired';
            tagCert.className = 'metric-tag tag-rose';
            subCert.textContent = 'Certificate validity period has lapsed.';
            iconCertWrap.className = 'metric-icon icon-rose';
        } else {
            tagCert.textContent = 'Untrusted';
            tagCert.className = 'metric-tag tag-amber';
            subCert.textContent = 'Self-signed or unknown Certificate Authority.';
            iconCertWrap.className = 'metric-icon icon-amber';
        }

        // Card 6: Expiry Date & Span
        const tagDaysLeft = document.getElementById('tagDaysLeft');
        const valExpiry = document.getElementById('valExpiry');
        const subExpiry = document.getElementById('subExpiry');
        valExpiry.textContent = cert.not_after_str || cert.not_after_utc || 'N/A';
        subExpiry.textContent = `Issuer: ${cert.issuer_common_name || cert.issuer_organization || 'CA'}`;

        if (cert.days_remaining !== null && cert.days_remaining !== undefined) {
            if (cert.days_remaining > 0) {
                tagDaysLeft.textContent = `${cert.days_remaining} Days Left`;
                tagDaysLeft.className = cert.days_remaining > 30 ? 'metric-tag tag-green' : 'metric-tag tag-amber';
            } else {
                tagDaysLeft.textContent = `Expired (${Math.abs(cert.days_remaining)}d ago)`;
                tagDaysLeft.className = 'metric-tag tag-rose';
            }
        } else {
            tagDaysLeft.textContent = 'Date N/A';
        }

        // 5. Digital Certificate Deep Dive Details
        document.getElementById('certSubjectCN').textContent = cert.subject_common_name || 'N/A';
        document.getElementById('certSubjectO').textContent = cert.subject_organization || 'N/A';
        document.getElementById('certSubjectC').textContent = cert.subject_country || 'N/A';
        document.getElementById('certIssuerCN').textContent = cert.issuer_common_name || 'N/A';
        document.getElementById('certIssuerO').textContent = cert.issuer_organization || 'N/A';
        document.getElementById('certIssuerC').textContent = cert.issuer_country || 'N/A';
        document.getElementById('certNotBefore').textContent = cert.not_before_str || 'N/A';
        document.getElementById('certNotAfter').textContent = cert.not_after_str || 'N/A';
        document.getElementById('certSerialHex').textContent = cert.serial_number_hex || 'N/A';

        document.getElementById('certSigAlgo').textContent = cert.signature_algorithm || 'sha256WithRSAEncryption';
        document.getElementById('certPubKey').textContent = cert.public_key_description || `${cert.public_key_type || 'RSA'} (${cert.public_key_size || 2048} bits)`;
        document.getElementById('certFpSha256').textContent = cert.fingerprint_sha256 || 'N/A';
        document.getElementById('certFpSha1').textContent = cert.fingerprint_sha1 || 'N/A';

        // SANs
        const sansTagsEl = document.getElementById('certSansTags');
        sansTagsEl.innerHTML = '';
        const sans = cert.sans || [];
        if (sans.length > 0) {
            sans.forEach(san => {
                const span = document.createElement('span');
                span.className = 'san-tag';
                span.textContent = san;
                sansTagsEl.appendChild(span);
            });
        } else {
            const span = document.createElement('span');
            span.className = 'san-tag';
            span.textContent = cert.subject_common_name || 'None listed';
            sansTagsEl.appendChild(span);
        }

        // 6. Certificate Trust Chain Visualization
        renderTrustChain(data.chain, cert, data.hostname);

        // Show sections & smooth scroll
        resultsSection.style.display = 'block';
        certificateSection.style.display = 'block';
        navLinkResults.style.display = 'inline-block';
        navLinkCert.style.display = 'inline-block';

        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    function renderTrustChain(chain, cert, hostname) {
        if (!chain || chain.length === 0) return;

        const chainRootName = document.getElementById('chainRootName');
        const chainRootRole = document.getElementById('chainRootRole');
        const chainRootSig = document.getElementById('chainRootSig');

        const chainInterName = document.getElementById('chainInterName');
        const chainInterRole = document.getElementById('chainInterRole');
        const chainInterSig = document.getElementById('chainInterSig');

        const chainLeafName = document.getElementById('chainLeafName');
        const chainLeafRole = document.getElementById('chainLeafRole');
        const chainLeafSig = document.getElementById('chainLeafSig');

        if (chain.length >= 3) {
            // Leaf Cert
            chainLeafName.textContent = chain[0].subject;
            chainLeafRole.textContent = `End-Entity Certificate for ${hostname}. Binds the server's public key.`;
            chainLeafSig.textContent = `Signed by: ${chain[0].issuer} (${chain[0].sig_algo})`;

            // Intermediate CA
            chainInterName.textContent = chain[1].subject;
            chainInterRole.textContent = `Intermediate Certificate Authority. Protects the Root CA private key.`;
            chainInterSig.textContent = `Signed by: ${chain[1].issuer} (${chain[1].sig_algo})`;

            // Root CA
            chainRootName.textContent = chain[chain.length - 1].subject;
            chainRootRole.textContent = `Root Certificate Authority (Trust Anchor pre-installed in OS trust store).`;
            chainRootSig.textContent = `Self-Signed Trust Anchor (${chain[chain.length - 1].sig_algo})`;
        } else if (chain.length === 2) {
            chainLeafName.textContent = chain[0].subject;
            chainLeafRole.textContent = `End-Entity Certificate for ${hostname}.`;
            chainLeafSig.textContent = `Signed by: ${chain[0].issuer}`;

            chainInterName.textContent = chain[1].subject;
            chainInterRole.textContent = `Direct Root/Intermediate Issuer.`;
            chainInterSig.textContent = `Signed by: ${chain[1].issuer}`;

            chainRootName.textContent = chain[1].issuer;
            chainRootRole.textContent = `Root Trust Anchor.`;
            chainRootSig.textContent = `Self-Signed Root`;
        } else if (chain.length === 1) {
            // Self-Signed
            chainLeafName.textContent = chain[0].subject;
            chainLeafRole.textContent = `Self-signed certificate (No external CA validation).`;
            chainLeafSig.textContent = `Issuer: ${chain[0].issuer} (Untrusted)`;

            chainInterName.textContent = `None (Direct Self-Signature)`;
            chainInterRole.textContent = `Server signed its own certificate.`;
            chainInterSig.textContent = `No Intermediate CA`;

            chainRootName.textContent = `Self-Signed Host (Untrusted Root)`;
            chainRootRole.textContent = `Not present in browser trust store. Causes security alert.`;
            chainRootSig.textContent = `Untrusted Signature`;
        }
    }

    // -------------------------------------------------------------------------
    // Helper Functions
    // -------------------------------------------------------------------------
    function setLoadingState(isLoading) {
        analyzeBtn.disabled = isLoading;
        if (isLoading) {
            btnText.style.display = 'none';
            btnLoader.style.display = 'inline-flex';
        } else {
            btnText.style.display = 'inline-flex';
            btnLoader.style.display = 'none';
        }
    }

    function showError(title, message, detail = '') {
        errorTitle.textContent = title;
        errorMessage.textContent = message;
        if (detail) {
            errorDetail.textContent = detail;
            errorDetail.style.display = 'block';
        } else {
            errorDetail.style.display = 'none';
        }
        errorAlert.style.display = 'flex';
        errorAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    function showToast(message) {
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => {
            toast.classList.remove('show');
        }, 3200);
    }

    // Optional: trigger initial analysis on load if URL is provided
    if (urlInput.value.trim()) {
        clearBtn.style.display = 'block';
    }
});
