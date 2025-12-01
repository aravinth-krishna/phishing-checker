chrome.runtime.onInstalled.addListener(() => {
  console.log("Phishing Link Checker Extension Installed");
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "manualCheck") {
    checkCertificate(msg.url).then((certInfo) => {
      sendResponse(certInfo);
    });
    return true;
  }
});

async function checkCertificate(url) {
  try {
    const isHttps = url.startsWith("https://");

    if (!isHttps) {
      return {
        label: "suspicious",
        reason: "Not using HTTPS",
        score: 0.7,
      };
    }

    return {
      label: "legitimate",
      reason: "HTTPS enabled (SSL assumed valid)",
      score: 0.0,
    };
  } catch (err) {
    return {
      label: "suspicious",
      reason: "SSL check failed",
      score: 0.6,
    };
  }
}

async function getDomainHealth(domain) {
  try {
    const res = await fetch(
      `https://api.domainsdb.info/v1/domain-info?domain=${domain}`
    );
    const data = await res.json();

    return {
      traffic: data.traffic_rank || 0,
      blacklist: data.is_blacklisted || false,
      risk: data.risk_score || 0,
    };
  } catch (e) {
    return { traffic: 0, blacklist: false, risk: 0 };
  }
}
