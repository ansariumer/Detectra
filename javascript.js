
// ==========================================
// DETECTRY - SCAM LENS
// URL ANALYSIS ENGINE
// ==========================================


// 1. GET HTML ELEMENTS

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const resultSection = document.getElementById("result");
const errorMessage = document.getElementById("errorMessage");

const scanButton = document.getElementById("scanButton");


// 2. SCAN FORM EVENT

scanForm.addEventListener("submit", function(event) {

    event.preventDefault();

    errorMessage.textContent = "";
    resultSection.classList.add("hidden");

    // Get entered text and remove outer spaces
    let userInput = urlInput.value.trim();

    // Empty input check
    if (userInput === "") {
        errorMessage.textContent =
            "Please enter a website URL first!";
        return;
    }

    // Reject spaces inside URL
    if (/\s/.test(userInput)) {
        errorMessage.textContent =
            "URL cannot contain spaces inside it.";
        return;
    }

    // Add HTTPS if protocol is missing
    let cleanURL = userInput;

    if (!/^https?:\/\//i.test(cleanURL)) {
        cleanURL = "https://" + cleanURL;
    }

    // Validate URL
    let parsedURL;

    try {

        parsedURL = new URL(cleanURL);

        if (
            !["http:", "https:"].includes(parsedURL.protocol) ||
            !parsedURL.hostname
        ) {
            throw new Error("Invalid URL");
        }

    } catch {

        errorMessage.textContent =
            "Invalid URL! Please enter a correct website address.";

        return;
    }

    // Start scanning
    scanButton.disabled = true;
    scanButton.textContent = "Analyzing...";

    // Run analysis
    analyzeURL(parsedURL);

    scanButton.disabled = false;
    scanButton.innerHTML = "⌕ Scan Website";

});


// ==========================================
// 3. URL ANALYSIS FUNCTION
// ==========================================

function analyzeURL(url) {

    let score = 0;
    let threats = [];

    let domain = url.hostname.toLowerCase();
    let fullURL = url.href.toLowerCase();

    // Function to add threat points
    function addThreat(points, message) {

        score += points;

        threats.push({
            points: points,
            message: message
        });

    }


    // CHECK 1: HTTP INSTEAD OF HTTPS

    if (url.protocol === "http:") {

        addThreat(
            10,
            "Website uses HTTP instead of HTTPS."
        );

    }


    // CHECK 2: IP ADDRESS DETECTION

    let ipPattern =
        /^(\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(domain)) {

        let validIP = domain.split(".")
            .every(part => Number(part) <= 255);

        if (validIP) {
            addThreat(
                20,
                "Website uses an IP address instead of a domain name."
            );
        }

    }


    // CHECK 3: SUSPICIOUS KEYWORDS

    const suspiciousWords = [
        "login",
        "verify",
        "account",
        "password",
        "banking",
        "free-prize",
        "claim",
        "winner",
        "urgent",
        "update-payment",
        "confirm",
        "wallet",
        "suspend",
        "gift",
        "bonus"
    ];

    let matchedWords = suspiciousWords.filter(word =>
        fullURL.includes(word)
    );

    if (matchedWords.length > 0) {

        addThreat(
            Math.min(matchedWords.length * 5, 20),
            "Suspicious keywords detected: " +
            matchedWords.join(", ")
        );

    }


    // CHECK 4: TOO MANY SUBDOMAINS

    let domainParts = domain.split(".");

    if (domainParts.length > 4) {

        addThreat(
            10,
            "Unusually high number of subdomains detected."
        );

    }


    // CHECK 5: URL SHORTENER DETECTION

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "rebrand.ly"
    ];

    if (shorteners.includes(domain)) {

        addThreat(
            15,
            "URL shortening service detected. Final destination is hidden."
        );

    }


    // CHECK 6: UNUSUALLY LONG URL

    if (fullURL.length > 100) {

        addThreat(
            10,
            "URL is unusually long."
        );

    }


    // CHECK 7: SUSPICIOUS @ SYMBOL / CREDENTIALS

    if (url.username || url.password) {

        addThreat(
            15,
            "URL contains embedded login credentials or an @ structure."
        );

    }


    // CHECK 8: PUNYCODE / INTERNATIONALIZED DOMAIN

    if (domain.includes("xn--")) {

        addThreat(
            15,
            "Internationalized or encoded domain detected. Check for lookalike characters."
        );

    }


    // CHECK 9: SUSPICIOUS TLD

    const suspiciousTLDs = [
        "zip",
        "mov",
        "click",
        "top",
        "work",
        "country"
    ];

    let tld = domainParts[domainParts.length - 1];

    if (suspiciousTLDs.includes(tld)) {

        addThreat(
            10,
            "Domain uses a TLD sometimes associated with suspicious links: ." + tld
        );

    }


    // CHECK 10: EXCESSIVE HYPHENS IN DOMAIN

    let hyphenCount =
        (domain.match(/-/g) || []).length;

    if (hyphenCount >= 3) {

        addThreat(
            10,
            "Domain contains an unusually high number of hyphens."
        );

    }


    // CHECK 11: POSSIBLE BRAND LOOKALIKE

    const knownBrands = [
        "google",
        "amazon",
        "paypal",
        "microsoft",
        "facebook",
        "instagram",
        "netflix",
        "apple"
    ];

    const domainWithoutTLD =
        domainParts.slice(0, -1).join(".");

    const suspiciousBrandWords = [
        "secure",
        "verify",
        "login",
        "support",
        "account",
        "official",
        "update"
    ];

    let brandLookalike = knownBrands.some(brand => {

        let brandMentioned =
            domainWithoutTLD.includes(brand);

        let extraWords =
            suspiciousBrandWords.some(word =>
                domainWithoutTLD.includes(word)
            );

        // Flag brand-related domains with additional
        // suspicious words. This is only a heuristic.
        return brandMentioned && extraWords;

    });

    if (brandLookalike) {

        addThreat(
            15,
            "Possible brand impersonation pattern detected."
        );

    }


    // ==========================================
    // 4. CALCULATE FINAL SCAM SCORE
    // ==========================================

    score = Math.min(score, 100);


    // ==========================================
    // 5. DETERMINE RISK LEVEL
    // ==========================================

    let riskLevel;
    let riskDescription;
    let riskColor;

    if (score <= 20) {

        riskLevel = "Low Risk";
        riskDescription =
            "Few suspicious patterns detected. This does not guarantee safety.";
        riskColor = "#22c55e";

    }

    else if (score <= 50) {

        riskLevel = "Medium Risk";
        riskDescription =
            "Some suspicious patterns found. Verify the website before proceeding.";
        riskColor = "#facc15";

    }

    else if (score <= 75) {

        riskLevel = "High Risk";
        riskDescription =
            "Several suspicious patterns detected. Avoid sharing personal information.";
        riskColor = "#f97316";

    }

    else {

        riskLevel = "Critical Risk";
        riskDescription =
            "Many suspicious patterns detected. Avoid interacting with this URL.";
        riskColor = "#ef4444";

    }


    // ==========================================
    // 6. DISPLAY RESULTS
    // ==========================================

    displayResults(
        url.href,
        score,
        riskLevel,
        riskDescription,
        riskColor,
        threats
    );

}


// ==========================================
// 7. DISPLAY RESULT ON WEBSITE
// ==========================================

function displayResults(
    scannedURL,
    score,
    riskLevel,
    description,
    color,
    threats
) {

    resultSection.classList.remove("hidden");

    // Display URL
    document.getElementById("scannedURL")
        .textContent = scannedURL;

    // Display score
    document.getElementById("score")
        .textContent = score;

    // Display risk
    const riskElement = document.getElementById("risk");

    riskElement.textContent = riskLevel;
    riskElement.style.color = color;

    document.getElementById("riskDescription")
        .textContent = description;


    // Update score circle
    const circle = document.getElementById("scoreCircle");

    circle.style.background =
        `conic-gradient(${color} ${score * 3.6}deg, #26364d 0deg)`;


    // Update progress bar
    document.getElementById("progressBar").style.width =
        score + "%";

    document.getElementById("progressBar").style.background =
        color;

    document.getElementById("scoreText")
        .textContent = score + "%";


    // Display number of threats
    document.getElementById("threatCount")
        .textContent = threats.length;


    // Display threat list safely
    const threatList = document.getElementById("threats");

    threatList.replaceChildren();

    if (threats.length === 0) {

        const li = document.createElement("li");

        li.className = "safe-item";

        li.textContent =
            "✓ No suspicious URL patterns detected.";

        threatList.appendChild(li);

    } else {

        threats.forEach(threat => {

            const li = document.createElement("li");

            li.textContent =
                "⚠ " + threat.message +
                " (+" + threat.points + " points)";

            threatList.appendChild(li);

        });

    }


    // Recommendation
    const recommendationIcon =
        document.getElementById("recommendationIcon");

    const recommendationTitle =
        document.getElementById("recommendationTitle");

    const recommendationText =
        document.getElementById("recommendationText");


    if (score <= 20) {

        recommendationIcon.textContent = "🛡️";

        recommendationTitle.textContent =
            "Stay Alert!";

        recommendationText.textContent =
            "No major warning patterns were found. Still verify the website before entering sensitive information.";

    }

    else if (score <= 50) {

        recommendationIcon.textContent = "⚠️";

        recommendationTitle.textContent =
            "Proceed With Caution";

        recommendationText.textContent =
            "Some warning signs were detected. Avoid clicking unknown links or sharing sensitive details.";

    }

    else {

        recommendationIcon.textContent = "🚨";

        recommendationTitle.textContent =
            "Potentially Dangerous Link";

        recommendationText.textContent =
            "Multiple warning signs were detected. Do not enter passwords, banking details or personal information.";

    }


    // Save scan to history
    addToHistory(scannedURL, score, riskLevel, color);

    // Scroll to result
    resultSection.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

}


// ==========================================
// 8. SCAN HISTORY
// ==========================================

function addToHistory(url, score, risk, color) {

    const historyList =
        document.getElementById("historyList");

    // Remove empty message
    const emptyMessage =
        historyList.querySelector(".empty-history");

    if (emptyMessage) {
        emptyMessage.remove();
    }

    const item = document.createElement("div");

    item.className = "history-item";

    const urlText = document.createElement("span");
    urlText.className = "history-url";
    urlText.textContent = url;

    const status = document.createElement("span");
    status.className = "history-status";
    status.textContent = score + "/100 • " + risk;
    status.style.color = color;

    item.append(urlText, status);

    historyList.prepend(item);

    // Keep only last 5 scans
    while (historyList.children.length > 5) {
        historyList.lastElementChild.remove();
    }

}


// ==========================================
// 9. CLEAR HISTORY
// ==========================================

document.getElementById("clearHistory")
    .addEventListener("click", function() {

        const historyList =
            document.getElementById("historyList");

        historyList.replaceChildren();

        const emptyMessage =
            document.createElement("p");

        emptyMessage.className = "empty-history";

        emptyMessage.textContent =
            "No scans performed yet.";

        historyList.appendChild(emptyMessage);

    });

