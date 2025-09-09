/* -----------------------------
   Config
------------------------------ */
window.BACKEND_URL = "http://127.0.0.1:5000/scan";
window.USE_BACKEND = true;

/* -----------------------------
   Helpers
------------------------------ */
function $(id) {
  return document.getElementById(id);
}

function normalizeUrl(u) {
  try {
    const parsed = new URL(u);
    return parsed.protocol + "//" + parsed.hostname + parsed.pathname.replace(/\/$/, "");
  } catch {
    return u.trim();
  }
}

function severityClass(sev) {
  sev = (sev || "").toLowerCase();
  if (sev.includes("critical")) return "severity-critical";
  if (sev.includes("high")) return "severity-high";
  if (sev.includes("medium")) return "severity-medium";
  return "severity-low";
}

/**
 * Normalize backend response into a compact object for UI
 */
function normalizeBackendResult(input, data) {
  const ts = data.timestamp || new Date().toLocaleString();
  return {
    url: input,
    status: (data.result || "unknown").toUpperCase(),
    category: data.category || "Safe/Unknown",
    severity: data.severity || "Low",
    risk_score: typeof data.risk_score === "number" ? data.risk_score : 0,
    threat: data.threat || data.explanation || "No issues detected",
    time: ts,
    ui_brand_match: data.ui_brand_match || "N/A",
    ui_similarity_score: data.ui_similarity_score || 0,
    ui_explanation: data.ui_explanation || ""
  };
}

/**
 * Display results on Scanner UI
 */
function displayAndSave(row) {
  if ($("resultContainer")) $("resultContainer").style.display = "block";
  if ($("status")) $("status").innerText = `${row.status} (${row.category})`;

  // Severity + Risk
  if ($("domainAge")) {
    $("domainAge").innerHTML = `<span class="sev-label ${severityClass(row.severity)}">
      ${row.severity}</span> | Risk: ${row.risk_score}/100`;
  }

  // Threat explanation
  if ($("ipAddress")) $("ipAddress").innerText = row.threat;

  // NEW: UI Similarity details
  if ($("uiDetails")) {
    $("uiDetails").innerHTML = `
      <strong>UI Brand Match:</strong> ${row.ui_brand_match} <br>
      <strong>UI Similarity Score:</strong> ${row.ui_similarity_score}% <br>
      <em>${row.ui_explanation}</em>
    `;
  }

  // Save history
  try {
    const key = "scanHistory";
    const history = JSON.parse(localStorage.getItem(key)) || [];
    history.push(row);
    localStorage.setItem(key, JSON.stringify(history.slice(-200)));
  } catch (e) {
    console.error("Failed to save history:", e);
  }
}

/* -----------------------------
   Scan flow
------------------------------ */
async function scanInput() {
  const inputEl = $("urlInput");
  if (!inputEl) {
    alert("Input box not found.");
    return;
  }

  const input = (inputEl.value || "").trim();
  if (!input) {
    alert("⚠️ Please enter a URL or App link.");
    return;
  }

  const normInput = normalizeUrl(input);
  const timestamp = new Date().toLocaleString();

  if (!window.USE_BACKEND) {
    displayAndSave({
      url: input,
      status: "UNKNOWN",
      category: "Safe/Unknown",
      severity: "Low",
      risk_score: 0,
      threat: "Backend disabled.",
      time: timestamp,
      ui_brand_match: "N/A",
      ui_similarity_score: 0,
      ui_explanation: "Not checked"
    });
    return;
  }

  try {
    const res = await fetch(window.BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input })
    });
    if (!res.ok) throw new Error("Backend error " + res.status);

    const data = await res.json();
    const rowData = normalizeBackendResult(input, data);
    displayAndSave(rowData);
  } catch (err) {
    console.error("Scan failed:", err);
    displayAndSave({
      url: input,
      status: "ERROR",
      category: "Error",
      severity: "--",
      risk_score: 0,
      threat: "❌ Could not connect to backend",
      time: timestamp,
      ui_brand_match: "N/A",
      ui_similarity_score: 0,
      ui_explanation: "Backend error"
    });
  }
}
