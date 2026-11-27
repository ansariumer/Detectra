
// ============================================
// DETECTRY - SCAM LENS
// Client-side URL Risk Analysis
// ============================================


// ============================================
// 1. GET HTML ELEMENTS
// ============================================

const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");

const errorMessage = document.getElementById("errorMessage");
const result = document.getElementById("result");

const score = document.getElementById("score");
const risk = document.getElementById("risk");
const riskDescription = document.getElementById("riskDescription");

const scoreCircle = document.getElementById("scoreCircle");
const scannedURL = document.getElementById("scannedURL");

const scoreText = document.getElementById("scoreText");
const progressBar = document.getElementById("progressBar");

const threatCount = document.getElementById("threatCount");
const threats = document.getElementById("threats");

const recommendationIcon =
    document.getElementById("recommendationIcon");

const recommendationTitle =
    document.getElementById("recommendationTitle");

const recommendationText =
    document.getElementById("recommendationText");

const historyList = document.getElementById("historyList");
const clearHistoryButton = document.getElementById("clearHistory");


// ============================================
// 2. DETECTION DATA
// ============================================

// Suspicious keywords
const suspiciousKeywords = [
    "login",
    "verify",
    "secure",
    "free-gift",
    "claim-prize",
    "bank-update",
    "password-reset",
    "account-suspended",
    "urgent",
    "winner",
    "wallet-connect",
    "confirm-identity"
];


// Known URL shortening services
const shorteners = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rb.gy"
];


// ============================================
// 3. HANDLE FORM SUBMISSION
// ============================================

scanForm.addEventListener("submit", function(event) {

    // Prevent page refresh
    event.preventDefault();

    // Clear previous error
    errorMessage.textContent = "";

    // Hide previous result
    result.classList.add("hidden");

    // Get input and remove surrounding spaces
    let enteredURL = urlInput.value.trim();

    // Check empty input
    if (enteredURL === "") {
        showError("Please enter a website URL.");
        return;
    }

    // Reject whitespace inside the URL
    if (/\s/.test(enteredURL)) {
        showError("URL cannot contain spaces.");
        return;
    }

    // Reject unsupported URL formats
    if (!/^https?:\/\//i.test(enteredURL)) {
        enteredURL = "https://" + enteredURL;
    }

    // Validate URL
    let parsedURL;

    try {

        parsedURL = new URL(enteredURL);

        // Allow only HTTP and HTTPS
        if (
            parsedURL.protocol !== "http:" &&
            parsedURL.protocol !== "https:"
        ) {
            showError("Only HTTP and HTTPS links are supported.");
            return;
        }

        // Check hostname
        const hostname = parsedURL.hostname;

        if (
            !hostname ||
            !hostname.includes(".") ||
            hostname.startsWith(".")
        ) {
            showError("Please enter a valid website domain.");
            return;
        }

        // Check domain labels
        const labels = hostname.split(".");

        const invalidDomain = labels.some(label =>
            label.length === 0 ||
            label.length > 63 ||
            label.startsWith("-") ||
            label.endsWith("-")
        );

        if (invalidDomain) {
            showError("Invalid domain format.");
            return;
        }

    } catch (error) {

        showError("Invalid URL. Please enter a valid website link.");
        return;

    }

    // Analyse URL
    scanButton.disabled = true;
    scanButton.textContent = "Analysing...";

    try {
        analyseURL(parsedURL, enteredURL);
    } catch (error) {
        console.error("Scanning error:", error);
        showError("Something went wrong while analysing this URL.");
    } finally {
        scanButton.disabled = false;
        scanButton.innerHTML = "<span>⌕</span> Scan Website";
    }

});


// ============================================
// 4. URL ANALYSIS
// ============================================

function analyseURL(url, originalURL) {

    let riskScore = 0;

    let detectedThreats = [];

    const hostname = url.hostname.toLowerCase();

    const fullURL = originalURL.toLowerCase();


    // CHECK 1: SUSPICIOUS KEYWORDS

    const foundKeywords = suspiciousKeywords.filter(keyword =>
        fullURL.includes(keyword)
    );

    if (foundKeywords.length > 0) {

        riskScore += 15;

        detectedThreats.push(
            "Suspicious keywords detected: " +
            foundKeywords.join(", ")
        );

    }


    // CHECK 2: IP ADDRESS INSTEAD OF DOMAIN

    const ipPattern =
        /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {

        const validIP = hostname.split(".").every(part =>
            Number(part) <= 255
        );

        if (validIP) {

            riskScore += 25;

            detectedThreats.push(
                "Website uses an IP address instead of a domain name."
            );

        }

    }


    // CHECK 3: EXCESSIVELY LONG URL

    if (originalURL.length > 100) {

        riskScore += 10;

        detectedThreats.push(
            "URL is unusually long and may hide its destination."
        );

    }


    // CHECK 4: TOO MANY SUBDOMAINS

    const domainParts = hostname.split(".");

    const subdomains = domainParts.slice(0, -2);

    const actualSubdomains = subdomains.filter(
        part => part !== "www"
    );

    if (actualSubdomains.length > 2) {

        riskScore += 15;

        detectedThreats.push(
            "URL contains an unusually large number of subdomains."
        );

    }


    // CHECK 5: HTTP INSTEAD OF HTTPS

    if (url.protocol === "http:") {

        riskScore += 10;

        detectedThreats.push(
            "Website does not use HTTPS encryption."
        );

    }


    // CHECK 6: @ SYMBOL / USER INFORMATION

    if (url.username !== "" || url.password !== "") {

        riskScore += 20;

        detectedThreats.push(
            "URL contains user information before the hostname."
        );

    }


    // CHECK 7: PUNYCODE DOMAIN

    if (hostname.includes("xn--")) {

        riskScore += 20;

        detectedThreats.push(
            "Domain uses Punycode encoding and may imitate another website."
        );

    }


    // CHECK 8: URL SHORTENER

    if (shorteners.includes(hostname)) {

        riskScore += 10;

        detectedThreats.push(
            "URL uses a shortening service that hides its final destination."
        );

    }


    // ========================================
    // 5. CALCULATE FINAL SCORE
    // ========================================

    // Maximum score = 100
    riskScore = Math.min(riskScore, 100);


    let riskLevel;
    let description;
    let advice;
    let icon;
    let color;


    if (riskScore >= 60) {

        riskLevel = "High Risk";

        description =
            "Multiple suspicious indicators were detected.";

        advice =
            "Avoid opening this link or entering personal information. Verify the website through its official source.";

        icon = "🚨";

        color = "#ef4444";

    } else if (riskScore >= 30) {

        riskLevel = "Medium Risk";

        description =
            "Some suspicious characteristics were detected.";

        advice =
            "Be cautious. Verify the website address before interacting with it.";

        icon = "⚠️";

        color = "#f59e0b";

    } else {

        riskLevel = "Low Risk";

        description =
            "Few suspicious indicators were detected.";

        advice =
            "No major warning signs were found in our checks. Still, verify the website before sharing sensitive information.";

        icon = "🛡️";

        color = "#22c55e";

    }


    // Display results
    displayResults(
        originalURL,
        riskScore,
        riskLevel,
        description,
        detectedThreats,
        advice,
        icon,
        color
    );

}


// ============================================
// 6. DISPLAY SCAN RESULTS
// ============================================

function displayResults(
    url,
    scoreValue,
    riskLevel,
    description,
    detectedThreats,
    advice,
    icon,
    color
) {

    // Display scanned URL
    scannedURL.textContent = url;

    // Display score
    score.textContent = scoreValue;

    scoreText.textContent = scoreValue + "%";

    // Display risk category
    risk.textContent = riskLevel;

    risk.style.color = color;

    // Display description
    riskDescription.textContent = description;


    // Update score circle
    const degrees = scoreValue * 3.6;

    scoreCircle.style.background =
        `conic-gradient(${color} ${degrees}deg, #26364d ${degrees}deg)`;


    // Update progress bar
    progressBar.style.width = scoreValue + "%";

    progressBar.style.background = color;


    // Display detected threat count
    threatCount.textContent = detectedThreats.length;


    // Clear previous threats
    threats.innerHTML = "";


    // Display threats
    if (detectedThreats.length === 0) {

        const item = document.createElement("li");

        item.classList.add("safe-item");

        item.textContent =
            "No suspicious indicators detected.";

        threats.appendChild(item);

    } else {

        detectedThreats.forEach(threat => {

            const item = document.createElement("li");

            item.textContent = threat;

            threats.appendChild(item);

        });

    }


    // Display recommendation
    recommendationIcon.textContent = icon;

    recommendationTitle.textContent = riskLevel + " - Recommendation";

    recommendationText.textContent = advice;


    // Show results section
    result.classList.remove("hidden");


    // Save scan in history
    saveToHistory(url, scoreValue, riskLevel, color);

}


// ============================================
// 7. ERROR HANDLING
// ============================================

function showError(message) {

    errorMessage.textContent = message;

}


// ============================================
// 8. SCAN HISTORY
// ============================================

// Get saved history from browser
function getHistory() {

    try {

        return JSON.parse(
            localStorage.getItem("scamLensHistory")
        ) || [];

    } catch (error) {

        return [];

    }

}


// Save new scan
function saveToHistory(url, scoreValue, riskLevel, color) {

    let history = getHistory();

    const scan = {

        url: url,

        score: scoreValue,

        risk: riskLevel,

        color: color,

        time: new Date().toLocaleString()

    };


    // Add latest scan at the beginning
    history.unshift(scan);


    // Keep only latest 5 scans
    history = history.slice(0, 5);


    // Save in browser storage
    try {

        localStorage.setItem(
            "scamLensHistory",
            JSON.stringify(history)
        );

    } catch (error) {

        console.error("Could not save scan history:", error);

    }


    // Update history display
    displayHistory();

}


// ============================================
// 9. DISPLAY HISTORY
// ============================================

function displayHistory() {

    const history = getHistory();

    historyList.innerHTML = "";


    // Empty history
    if (history.length === 0) {

        const emptyMessage = document.createElement("p");

        emptyMessage.className = "empty-history";

        emptyMessage.textContent = "No scans performed yet.";

        historyList.appendChild(emptyMessage);

        return;

    }


    // Display each scan
    history.forEach(scan => {

        const item = document.createElement("div");

        item.className = "history-item";


        const urlElement = document.createElement("div");

        urlElement.className = "history-url";

        urlElement.textContent = scan.url;


        const statusElement = document.createElement("div");

        statusElement.className = "history-status";

        statusElement.textContent =
            scan.risk + " (" + scan.score + "/100)";

        statusElement.style.color = scan.color;


        item.appendChild(urlElement);

        item.appendChild(statusElement);

        historyList.appendChild(item);

    });

}


// ============================================
// 10. CLEAR HISTORY
// ============================================

clearHistoryButton.addEventListener("click", function() {

    localStorage.removeItem("scamLensHistory");

    displayHistory();

});


// ============================================
// 11. LOAD HISTORY WHEN WEBSITE OPENS
// ============================================

displayHistory();
