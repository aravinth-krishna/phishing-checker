const API = "http://127.0.0.1:8000/predict";
const inMemoryCache = new Map();
let storedSuspicious = new Set();

function loadStoredCache() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["suspicious_cache"], (res) => {
      const arr = res.suspicious_cache || [];
      storedSuspicious = new Set(arr);
      resolve();
    });
  });
}

function saveToStoredCache(url) {
  if (storedSuspicious.has(url)) return Promise.resolve();
  storedSuspicious.add(url);
  const arr = Array.from(storedSuspicious);
  return new Promise((resolve) => {
    chrome.storage.local.set({ suspicious_cache: arr }, () => resolve());
  });
}

function extractFeaturesFromUrl(url) {
  try {
    const u = url.toLowerCase();
    return {
      NumDots: (u.match(/\./g) || []).length,
      SubdomainLevel: u.split(".").length - 2,
      PathLevel: u.split("/").length - 3,
      UrlLength: u.length,
      NumDash: (u.match(/-/g) || []).length,
      NumDashInHostname: (new URL(url).hostname.match(/-/g) || []).length,
      AtSymbol: u.includes("@") ? 1 : 0,
      NumNumericChars: (u.match(/\d/g) || []).length,
      NoHttps: u.startsWith("https://") ? 0 : 1,
      IpAddress: /\d+\.\d+\.\d+\.\d+/.test(u) ? 1 : 0,
    };
  } catch (e) {
    // invalid URL
    return null;
  }
}

function heuristicFlag(url) {
  try {
    const u = url.toLowerCase();
    const hostname = new URL(url).hostname;
    const suspiciousWords = [
      "login",
      "signin",
      "verify",
      "secure",
      "update",
      "confirm",
      "account",
      "otp",
      "password",
      "bank",
      "wallet",
      "unlock",
      "auth",
      "subscription",
      "recovery",
    ];

    const hasKeyword = suspiciousWords.some((w) => u.includes(w));
    const isIp = /\b\d{1,3}(\.\d{1,3}){3}\b/.test(hostname);
    const isLong = u.length > 80;
    const noHttps = !u.startsWith("https://");
    const puny = hostname.startsWith("xn--") || /xn--/.test(hostname);
    const atSign = u.includes("@");

    let score = 0;
    if (OPTIONS.highlightLogin && hasKeyword) score += 0.4;
    if (OPTIONS.highlightLong && isLong) score += 0.15;

    if (isIp) score += 0.25;
    if (noHttps) score += 0.1;
    if (puny) score += 0.2;
    if (atSign) score += 0.2;

    if (score > 1) score = 1;

    return {
      label:
        score >= 0.7 ? "phishing" : score >= 0.3 ? "suspicious" : "legitimate",
      score,
    };
  } catch (e) {
    return { label: "unknown", score: 0 };
  }
}

async function checkUrl(url) {
  const heur = heuristicFlag(url);
  if (heur.label !== "legitimate") {
    inMemoryCache.set(url, heur);
    if (heur.label === "phishing") saveToStoredCache(url);
    return heur;
  }

  if (inMemoryCache.has(url)) return inMemoryCache.get(url);

  if (storedSuspicious.has(url)) {
    const result = { label: "phishing", score: 1 };
    inMemoryCache.set(url, result);
    return result;
  }

  const features = extractFeaturesFromUrl(url);
  if (!features) {
    const res = { label: "unknown", score: 0 };
    inMemoryCache.set(url, res);
    return res;
  }

  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features }),
    });
    const data = await res.json();
    inMemoryCache.set(url, data);

    if (data.label === "phishing") {
      await saveToStoredCache(url);
    }
    return data;
  } catch (err) {
    const unknown = { label: "unknown", score: 0 };
    inMemoryCache.set(url, unknown);
    return unknown;
  }
}

function blockNavigationIfSuspicious(anchorEl, url) {
  anchorEl.title = anchorEl.title || "";
  anchorEl.title += `\nChecked by Phishing Checker`;

  anchorEl.addEventListener(
    "click",
    (e) => {
      const href = anchorEl.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopPropagation();
        alert(`🚨 Blocked potential phishing link!\n${href}`);
      }
    },
    true
  );

  anchorEl.addEventListener(
    "auxclick",
    (e) => {
      const href = anchorEl.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopPropagation();
        alert(`🚨 Blocked potential phishing link!\n${href}`);
      }
    },
    true
  );
}

function injectBlockerScript() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("inject.js");
  (document.head || document.documentElement).appendChild(script);
}

function exposeBlockedUrlsToPage() {
  const arr = Array.from(storedSuspicious);
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("setBlockedUrls.js");
  script.dataset.urls = JSON.stringify(arr);
  (document.head || document.documentElement).appendChild(script);
}

let OPTIONS = {
  highlightNav: true,
  highlightLong: true,
  highlightLogin: true,
};

function loadOptions() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["options"], (res) => {
      OPTIONS = {
        highlightNav: res.options?.highlightNav ?? true,
        highlightLong: res.options?.highlightLong ?? true,
        highlightLogin: res.options?.highlightLogin ?? true,
      };
      resolve();
    });
  });
}

function buildHoverTooltipData(url, heur) {
  const parsed = new URL(url);
  const domain = parsed.hostname;

  return {
    domain,
    score: heur.score ?? "N/A",
    https: parsed.protocol === "https:" ? "Yes" : "No",

    sevText:
      heur.label === "phishing"
        ? "High Risk — Possible Phishing"
        : heur.label === "suspicious"
        ? "Medium Risk — Suspicious"
        : "Safe Link",

    barClass:
      heur.label === "phishing"
        ? "severity-phishing"
        : heur.label === "suspicious"
        ? "severity-suspicious"
        : "severity-safe",
  };
}

// Modern Custom Tooltip (replaces ugly title tooltip)
let tooltip = null;

function showTooltip(link, data, x, y) {
  if (!tooltip) {
    tooltip = document.createElement("div");
    tooltip.className = "phish-tooltip";
    document.body.appendChild(tooltip);
  }

  tooltip.innerHTML = `
    <div class="severity-bar ${data.barClass}"></div>
    <div class="title">${data.sevText}</div>

    <div class="row"><b>Domain:</b> ${data.domain}</div>
    <div class="row"><b>HTTPS:</b> ${data.https}</div>
    <div class="row"><b>Score:</b> ${data.score}</div>
  `;

  const tooltipWidth = 260;
  const tooltipHeight = 120;

  let left = x + 16;
  let top = y + 16;

  if (left + tooltipWidth > window.innerWidth) {
    left = x - tooltipWidth - 16;
  }

  if (top + tooltipHeight > window.innerHeight) {
    top = y - tooltipHeight - 16;
  }

  tooltip.style.left = left + "px";
  tooltip.style.top = top + "px";

  tooltip.classList.add("visible");
}

function hideTooltip() {
  if (tooltip) tooltip.classList.remove("visible");
}

document
  .querySelectorAll("a.phishing-warning, a.phishing-safe, a.phishing-mixed")
  .forEach((a) => {
    a.classList.remove("phishing-warning", "phishing-safe", "phishing-mixed");
  });

async function scanLinks() {
  await loadStoredCache();
  exposeBlockedUrlsToPage();

  let links = Array.from(document.querySelectorAll("a[href]"));

  await loadOptions();

  if (OPTIONS.highlightNav) {
    links = links.filter((a) => {
      return !(
        a.closest("nav") ||
        a.closest("header") ||
        a.closest("footer") ||
        a.classList.contains("nav-link") ||
        a.parentElement?.tagName === "NAV"
      );
    });
  }

  let total = 0,
    safe = 0,
    suspicious = 0;

  document.addEventListener(
    "click",
    (e) => {
      const a = e.target.closest && e.target.closest("a[href]");
      if (!a) return;
      const href = a.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        alert("🚨 Blocked potential phishing link!\\n" + href);
      }
    },
    true
  );

  document.addEventListener(
    "auxclick",
    (e) => {
      const a = e.target.closest && e.target.closest("a[href]");
      if (!a) return;
      const href = a.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        alert("🚨 Blocked potential phishing link!\\n" + href);
      }
    },
    true
  );

  injectBlockerScript();

  for (const link of links) {
    total++;
    const href = link.href;
    const result = await checkUrl(href);
    const data = buildHoverTooltipData(href, result);

    link.removeAttribute("title");

    link.addEventListener("mousemove", (e) =>
      showTooltip(link, data, e.clientX, e.clientY)
    );

    link.addEventListener("mouseleave", hideTooltip);

    if (result.label === "phishing") {
      link.classList.add("phishing-warning");
      suspicious++;
      saveToStoredCache(href);
    } else if (result.label === "suspicious") {
      link.classList.add("phishing-mixed");
      suspicious++;
    } else {
      link.classList.add("phishing-safe");
      safe++;
    }
  }

  chrome.storage.local.set({ scan_stats: { total, safe, suspicious } }, () => {
    chrome.runtime.sendMessage({ type: "stats", total, safe, suspicious });
  });
}

chrome.storage.local.get(["enabled"], (res) => {
  if (res.enabled) scanLinks();
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "rescan") {
    chrome.storage.local.get(["enabled"], (res) => {
      if (res.enabled) scanLinks();
    });
  }
});
