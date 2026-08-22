document.addEventListener("DOMContentLoaded", () => {

    // =========================
    // LOAD LIVE STATS (from the database, shown in the About section)
    // =========================

    async function loadStats() {

        const totalEl =
            document.getElementById("stat-total-scans");

        const highRiskEl =
            document.getElementById("stat-high-risk");

        if (!totalEl || !highRiskEl) return;

        try {

            const response = await fetch("/api/stats");
            const data = await response.json();

            totalEl.textContent =
                data.total_scans ?? 0;

            highRiskEl.textContent =
                data.high_risk_scans ?? 0;

        } catch (error) {

            console.error("Failed to load stats:", error);

            totalEl.textContent = "0";
            highRiskEl.textContent = "0";

        }

    }

    loadStats();


    const messageInput =
        document.getElementById("message");

    const characterCount =
        document.getElementById("character-count");

    const screenshotInput =
        document.getElementById("screenshot");

    const uploadArea =
        document.querySelector(".upload-area");

    const analyzeButton =
        document.getElementById("analyze-btn");


    // =========================
    // CHARACTER COUNTER
    // =========================

    messageInput.addEventListener("input", () => {

        const count =
            messageInput.value.length;

        characterCount.textContent =
            `${count} characters`;

    });


    // =========================
    // SCREENSHOT UPLOAD
    // =========================

    screenshotInput.addEventListener("change", () => {

        const file =
            screenshotInput.files[0];

        if (!file) return;

        const allowedTypes = [
            "image/png",
            "image/jpeg",
            "image/jpg"
        ];

        if (!allowedTypes.includes(file.type)) {

            alert(
                "Please upload a PNG or JPG image."
            );

            screenshotInput.value = "";

            return;
        }

        const uploadTitle =
            uploadArea.querySelector("h3");

        const uploadDescription =
            uploadArea.querySelector("p");

        uploadTitle.textContent =
            "Screenshot selected ✓";

        uploadDescription.textContent =
            file.name;

    });


    // =========================
    // MESSAGE ANALYZER
    // =========================

    function analyzeMessage(message) {

        const text =
            message.toLowerCase();

        let score = 0;

        const signals = [];


        // URGENCY

        const urgencyWords = [
            "urgent",
            "immediately",
            "act now",
            "limited time",
            "expires",
            "within 24 hours",
            "last chance",
            "hurry",
            "quickly",
            "today only",
            "deadline",
            "right now",
            // Roman Urdu / Urdu
            "jaldi",
            "abhi",
            "foran",
            "turant",
            "aakhri mauka",
            "aakhri chance",
            "24 ghanton",
            "waqt khatam"
        ];

        if (
            urgencyWords.some(word =>
                text.includes(word)
            )
        ) {

            score += 20;

            signals.push({
                icon: "⚠️",
                title: "Urgency detected",
                description:
                    "The message creates pressure by asking you to act quickly."
            });

        }


        // MONEY / PRIZE

        const moneyWords = [
            "you won",
            "winner",
            "prize",
            "cash prize",
            "free money",
            "reward",
            "lottery",
            "jackpot",
            "rupees",
            "cash",
            "bonus",
            "gift card",
            // Roman Urdu / Urdu
            "aap jeet gaye",
            "aap ne jeeta",
            "mubarak ho",
            "inaam",
            "lucky draw",
            "qurandaz",
            "muft",
            "free tohfa"
        ];

        if (
            moneyWords.some(word =>
                text.includes(word)
            )
        ) {

            score += 25;

            signals.push({
                icon: "💰",
                title: "Financial bait",
                description:
                    "The message uses money, rewards or prizes to attract attention."
            });

        }


        // SENSITIVE INFORMATION

        const sensitiveWords = [
            "password",
            "otp",
            "verification code",
            "security code",
            "pin",
            "bank account",
            "credit card",
            "debit card",
            "cnic",
            "account number",
            "card number",
            // Roman Urdu / Urdu
            "jazzcash pin",
            "easypaisa pin",
            "apna pin",
            "code bhejain",
            "code share",
            "shanakhti card",
            "account ki tafseelat"
        ];

        if (
            sensitiveWords.some(word =>
                text.includes(word)
            )
        ) {

            score += 30;

            signals.push({
                icon: "🔐",
                title:
                    "Sensitive information request",
                description:
                    "The message may be asking for sensitive personal or financial information."
            });

        }


        // ACCOUNT THREAT

        const accountThreats = [
            "account suspended",
            "account blocked",
            "account restricted",
            "account will be closed",
            "unusual activity",
            "suspicious activity",
            "security alert",
            "unauthorized activity",
            // Roman Urdu / Urdu
            "account band",
            "account block",
            "account suspend",
            "ghair mamuli activity",
            "shak parwana",
            "account bandish"
        ];

        if (
            accountThreats.some(word =>
                text.includes(word)
            )
        ) {

            score += 25;

            signals.push({
                icon: "🔒",
                title:
                    "Account threat detected",
                description:
                    "The message uses fear about your account to encourage action."
            });

        }


        // VERIFICATION REQUEST

        const verificationWords = [
            "verify your account",
            "verify your identity",
            "confirm your identity",
            "verification required",
            "update your account",
            "confirm your account",
            // Roman Urdu / Urdu
            "tasdeeq karain",
            "verify karain",
            "apna account update karen",
            "shanakht ki tasdeeq"
        ];

        if (
            verificationWords.some(word =>
                text.includes(word)
            )
        ) {

            score += 20;

            signals.push({
                icon: "🪪",
                title:
                    "Verification request",
                description:
                    "The message asks you to verify your identity or account."
            });

        }


        // COMMON SCAM PHRASES

        const scamPhrases = [
            "click here to claim",
            "claim now",
            "click the link",
            "send money",
            "pay a fee",
            "you have been selected",
            "you have been chosen",
            "claim your reward",
            "receive your prize",
            // Roman Urdu / Urdu
            "link par click karen",
            "click karen",
            "paisay bhejain",
            "fee jama karwayen",
            "aap ka number select hua hai",
            "aap ka number chuna gaya",
            "abhi claim karen"
        ];

        if (
            scamPhrases.some(phrase =>
                text.includes(phrase)
            )
        ) {

            score += 20;

            signals.push({
                icon: "🚨",
                title:
                    "Suspicious phrase detected",
                description:
                    "The message contains language commonly associated with scams."
            });

        }


        score = Math.min(score, 100);


        let riskLevel;
        let riskMessage;

        if (score >= 70) {

            riskLevel = "High Risk";

            riskMessage =
                "🚨 Multiple strong warning signs were detected. Avoid clicking links or sharing personal information.";

        }

        else if (score >= 40) {

            riskLevel = "Medium Risk";

            riskMessage =
                "⚠️ Several suspicious signals were detected. Verify the sender before taking action.";

        }

        else if (score > 0) {

            riskLevel = "Low Risk";

            riskMessage =
                "🔎 Some warning signs were detected. Proceed carefully.";

        }

        else {

            riskLevel = "No Obvious Risk";

            riskMessage =
                "✅ No common suspicious patterns were detected.";

        }


        return {
            score,
            riskLevel,
            riskMessage,
            signals
        };

    }


    // =========================
    // ANALYZE BUTTON
    // =========================

    analyzeButton.addEventListener(
        "click",
        async () => {

            let message =
                messageInput.value.trim();

            const screenshot =
                screenshotInput.files[0];


            if (!message && !screenshot) {

                alert(
                    "Please paste a message or upload a screenshot first."
                );

                return;

            }


            analyzeButton.innerHTML =
                "⏳ Analyzing...";

            analyzeButton.disabled = true;


            try {

                // =========================
                // SCREENSHOT OCR
                // =========================

                if (screenshot && !message) {

                    const formData =
                        new FormData();

                    formData.append(
                        "screenshot",
                        screenshot
                    );

                    const ocrResponse =
                        await fetch(
                            "/api/ocr",
                            {
                                method: "POST",
                                body: formData
                            }
                        );

                    const ocrResult =
                        await ocrResponse.json();

                    if (!ocrResponse.ok) {

                        throw new Error(
                            ocrResult.error ||
                            "OCR failed"
                        );

                    }

                    if (!ocrResult.success) {

                        alert(
                            ocrResult.message ||
                            "No text found in screenshot."
                        );

                        return;

                    }

                    // Put extracted text into textarea

                    message =
                        ocrResult.text;

                    messageInput.value =
                        message;

                    characterCount.textContent =
                        `${message.length} characters`;

                }


                // =========================
                // FIND ALL URLS (fixed: was only checking the first URL before)
                // =========================

                const urlPattern =
                    /https?:\/\/[^\s]+|www\.[^\s]+/gi;

                const rawUrls =
                    message.match(urlPattern) || [];

                // Clean trailing punctuation from each URL and remove duplicates
                const urls = [
                    ...new Set(
                        rawUrls.map(u =>
                            u.replace(/[.,!?;]+$/, "")
                        )
                    )
                ];


                // =========================
                // TEXT ANALYSIS (always run, even if links are present)
                // =========================

                const textResult =
                    analyzeMessage(message);


                // =========================
                // URL ANALYSIS (check every link found, not just the first)
                // =========================

                let urlResults = [];

                if (urls.length > 0) {

                    const urlChecks = urls.map(
                        async (singleUrl) => {

                            const response =
                                await fetch(
                                    "/api/check-url",
                                    {
                                        method: "POST",

                                        headers: {
                                            "Content-Type":
                                                "application/json"
                                        },

                                        body: JSON.stringify({
                                            url: singleUrl
                                        })
                                    }
                                );

                            const result =
                                await response.json();

                            if (!response.ok) {
                                return null;
                            }

                            return result;

                        }
                    );

                    urlResults =
                        (await Promise.all(urlChecks))
                            .filter(r => r !== null);

                }


                // =========================
                // COMBINE TEXT + ALL URL RESULTS
                // =========================

                const combined =
                    combineResults(textResult, urlResults);

                displayResult(combined);

                // Log this scan to the backend/database (fire-and-forget,
                // doesn't block the UI or the result the user sees)
                logScanToServer(message, urls, combined);

            }

            catch (error) {

                console.error(error);

                alert(
                    error.message ||
                    "Something went wrong while analyzing."
                );

            }

            finally {

                analyzeButton.innerHTML =
                    "🔍 Analyze Message";

                analyzeButton.disabled =
                    false;

            }

        }
    );


    // =========================
    // COMBINE TEXT ANALYSIS + MULTIPLE URL RESULTS INTO ONE REPORT
    // =========================

    function combineResults(textResult, urlResults) {

        let allSignals = [
            ...textResult.signals
        ];

        // Track the worst (highest) URL score separately from the
        // text score, so we can combine them below instead of just
        // picking whichever single score is bigger.
        let highestUrlScore = 0;

        urlResults.forEach((urlResult, index) => {

            const domainLabel =
                urlResult.domain
                    ? ` (${urlResult.domain})`
                    : "";

            urlResult.signals.forEach(signal => {

                allSignals.push({
                    icon: signal.icon,
                    title: `${signal.title}${domainLabel}`,
                    description: signal.description
                });

            });

            if (urlResult.score > highestUrlScore) {
                highestUrlScore = urlResult.score;
            }

        });

        // Combine text-based warning signs (urgency, prize bait, etc.)
        // with link-based warning signs (brand impersonation, bad TLD,
        // etc.) instead of only keeping the single worst score. A
        // message that is both urgent AND links to an impersonated
        // brand is more dangerous than either signal alone.
        let highestScore =
            textResult.score + highestUrlScore;

        highestScore = Math.min(highestScore, 100);


        let riskLevel;
        let riskMessage;

        if (highestScore >= 70) {

            riskLevel = "High Risk";

            riskMessage =
                "🚨 Multiple strong warning signs were detected. Avoid clicking links or sharing personal information.";

        }

        else if (highestScore >= 40) {

            riskLevel = "Medium Risk";

            riskMessage =
                "⚠️ Several suspicious signals were detected. Verify the sender before taking action.";

        }

        else if (highestScore > 0) {

            riskLevel = "Low Risk";

            riskMessage =
                "🔎 Some warning signs were detected. Proceed carefully.";

        }

        else {

            riskLevel = "No Obvious Risk";

            riskMessage =
                "✅ No common suspicious patterns were detected.";

        }


        if (urlResults.length > 1) {

            riskMessage +=
                ` (${urlResults.length} links were found and checked.)`;

        }


        return {
            score: highestScore,
            riskLevel,
            riskMessage,
            signals: allSignals
        };

    }


    // =========================
    // LOG SCAN TO SERVER/DATABASE
    // =========================

    function logScanToServer(message, urls, combinedResult) {

        // Only store a short snippet, never the full message,
        // to avoid saving sensitive info (OTPs, card numbers, etc.)
        const snippet =
            urls.length > 0
                ? urls[0]
                : message.slice(0, 120);

        fetch("/api/log-scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                scanType: urls.length > 0 ? "url" : "message",
                snippet: snippet,
                score: combinedResult.score,
                riskLevel: combinedResult.riskLevel,
                signalCount: combinedResult.signals.length
            })
        })
        .then(() => loadStats())
        .catch(error => {
            // Logging failure should never interrupt the user's experience
            console.error("Scan logging failed:", error);
        });

    }


    // =========================
    // DISPLAY RESULT
    // =========================

    function displayResult(result) {

        const existingResult =
            document.getElementById(
                "demo-result"
            );

        if (existingResult) {

            existingResult.remove();

        }


        const resultBox =
            document.createElement("div");

        resultBox.id =
            "demo-result";


        let signalHTML = "";


        if (result.signals.length === 0) {

            signalHTML = `
                <div class="signal">
                    <span>✅</span>
                    <div>
                        <strong>
                            No major warning signs detected
                        </strong>
                        <p>
                            No common suspicious patterns were detected.
                        </p>
                    </div>
                </div>
            `;

        }

        else {

            result.signals.forEach(signal => {

                signalHTML += `
                    <div class="signal">
                        <span>
                            ${signal.icon}
                        </span>

                        <div>
                            <strong>
                                ${signal.title}
                            </strong>

                            <p>
                                ${signal.description}
                            </p>
                        </div>
                    </div>
                `;

            });

        }


        resultBox.innerHTML = `

            <div class="demo-result-card">

                <div class="result-header">

                    <div>

                        <span class="result-label">
                            ANALYSIS RESULT
                        </span>

                        <h2>
                            ${result.riskLevel}
                        </h2>

                    </div>


                    <div class="result-score">

                        <strong>
                            ${result.score}
                        </strong>

                        <span>
                            /100
                        </span>

                    </div>

                </div>


                <div class="risk-message">
                    ${result.riskMessage}
                </div>


                <div class="signals">
                    ${signalHTML}
                </div>


                <div class="safety-tip">

                    <strong>
                        🛡️ Safety Tip
                    </strong>

                    <p>
                        Never share passwords, OTPs, PINs,
                        CNIC or banking information through
                        suspicious messages.
                    </p>

                </div>

            </div>
        `;


        const analyzerBox =
            document.querySelector(
                ".analyzer-box"
            );

        analyzerBox.appendChild(
            resultBox
        );


        resultBox.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });

    }

});
