document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("toggleBtn");
  const totalEl = document.getElementById("total");
  const safeEl = document.getElementById("safe");
  const suspiciousEl = document.getElementById("suspicious");

  const highlightNav = document.getElementById("highlightNav");
  const highlightLong = document.getElementById("highlightLong");
  const highlightLogin = document.getElementById("highlightLogin");

  const clearCacheBtn = document.getElementById("clearCacheBtn");
  const manualInput = document.getElementById("manualUrl");
  const manualBtn = document.getElementById("checkUrlBtn");
  const manualResult = document.getElementById("manualResult");

  // 🔥 NEW: always reload current tab so content.js is guaranteed alive
  function reloadActiveTab(callback) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs[0]) return;
      chrome.tabs.reload(tabs[0].id, callback || (() => {}));
    });
  }

  function safeSendMessageToActiveTab(msg) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0]) return;
      chrome.tabs.sendMessage(tabs[0].id, msg, () => {});
    });
  }

  // Load stats
  chrome.storage.local.get(["scan_stats"], (res) => {
    if (res.scan_stats) {
      totalEl.innerText = res.scan_stats.total;
      safeEl.innerText = res.scan_stats.safe;
      suspiciousEl.innerText = res.scan_stats.suspicious;
    }
  });

  // Load enabled + options
  chrome.storage.local.get(["enabled", "options"], (result) => {
    const enabled = result.enabled || false;
    updateButton(enabled);

    const opts = result.options || {};
    highlightNav.checked = opts.highlightNav ?? true;
    highlightLong.checked = opts.highlightLong ?? true;
    highlightLogin.checked = opts.highlightLogin ?? true;
  });

  // ------------------------------------------------------
  // 🔥 ENABLE/DISABLE → reload page to guarantee content.js present
  // ------------------------------------------------------
  toggleBtn.addEventListener("click", () => {
    chrome.storage.local.get(["enabled"], (result) => {
      const newStatus = !result.enabled;

      chrome.storage.local.set({ enabled: newStatus }, () => {
        updateButton(newStatus);

        // 👉 force page reload, then rescan
        reloadActiveTab(() => {
          safeSendMessageToActiveTab({ type: "rescan" });
        });
      });
    });
  });

  // ------------------------------------------------------
  // 🔥 Option checkboxes → reload page
  // ------------------------------------------------------
  [highlightNav, highlightLong, highlightLogin].forEach((opt) => {
    opt.addEventListener("change", () => {
      chrome.storage.local.set({
        options: {
          highlightNav: highlightNav.checked,
          highlightLong: highlightLong.checked,
          highlightLogin: highlightLogin.checked,
        },
      });

      reloadActiveTab(() => {
        safeSendMessageToActiveTab({ type: "rescan" });
      });
    });
  });

  // ------------------------------------------------------
  // 🔥 Clear cache → reload page
  // ------------------------------------------------------
  clearCacheBtn.addEventListener("click", () => {
    chrome.storage.local.remove("suspicious_cache", () => {
      reloadActiveTab(() => {
        safeSendMessageToActiveTab({ type: "rescan" });
      });
    });
  });

  // Manual check
  manualBtn.addEventListener("click", () => {
    const url = manualInput.value.trim();
    if (!url) return;

    chrome.runtime.sendMessage({ type: "manualCheck", url }, (response) => {
      if (!response) {
        manualResult.innerText = "Unable to check.";
        manualResult.style.color = "black";
        return;
      }

      const { label } = response;

      if (label === "phishing") {
        manualResult.style.color = "red";
        manualResult.innerText = "🚨 Dangerous";
      } else if (label === "suspicious") {
        manualResult.style.color = "orange";
        manualResult.innerText = "⚠️ Mixed Risk";
      } else {
        manualResult.style.color = "green";
        manualResult.innerText = "✅ Safe";
      }
    });
  });

  // Stats from content script
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "stats") {
      totalEl.innerText = msg.total;
      safeEl.innerText = msg.safe;
      suspiciousEl.innerText = msg.suspicious;
    }
  });

  function updateButton(enabled) {
    if (enabled) {
      toggleBtn.innerText = "Disable Scanning";
      toggleBtn.className = "enabled";
    } else {
      toggleBtn.innerText = "Enable Scanning";
      toggleBtn.className = "disabled";
    }
  }
});
