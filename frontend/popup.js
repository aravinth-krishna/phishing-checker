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

  // Helpers: safe messaging
  function getActiveTab(callback) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0]) return callback(null);
      callback(tabs[0]);
    });
  }

  function trySendMessageToTab(tabId, msg, attempts = 6, delayMs = 300) {
    if (!tabId) return;
    let tries = 0;
    const attempt = () => {
      tries++;
      chrome.tabs.sendMessage(tabId, msg, (resp) => {
        // if there's an error (no receiver), retry until attempts exhausted
        if (chrome.runtime.lastError) {
          if (tries < attempts) {
            setTimeout(attempt, delayMs);
          } else {
            // silent fail: no content script on page or not allowed (e.g. chrome://)
            console.debug(
              "popup → content message skipped (no receiver):",
              chrome.runtime.lastError.message
            );
          }
        } else {
          // success
        }
      });
    };
    attempt();
  }

  function reloadActiveTabAndThen(fnAfterReload, waitMs = 450) {
    getActiveTab((tab) => {
      if (!tab) return;
      try {
        chrome.tabs.reload(tab.id, () => {
          setTimeout(() => {
            if (typeof fnAfterReload === "function") fnAfterReload(tab.id);
          }, waitMs);
        });
      } catch (e) {
        // fallback: still attempt callback
        setTimeout(() => {
          if (typeof fnAfterReload === "function") fnAfterReload(tab.id);
        }, waitMs);
      }
    });
  }

  // Load UI state
  chrome.storage.local.get(["scan_stats"], (res) => {
    if (res.scan_stats) {
      totalEl.innerText = res.scan_stats.total ?? 0;
      safeEl.innerText = res.scan_stats.safe ?? 0;
      suspiciousEl.innerText = res.scan_stats.suspicious ?? 0;
    }
  });

  chrome.storage.local.get(["enabled", "options"], (result) => {
    const enabled = result.enabled ?? false;
    updateButton(enabled);

    const opts = result.options || {};
    highlightNav.checked = opts.highlightNav ?? true;
    highlightLong.checked = opts.highlightLong ?? true;
    highlightLogin.checked = opts.highlightLogin ?? true;
  });

  toggleBtn.addEventListener("click", () => {
    chrome.storage.local.get(["enabled"], (result) => {
      const newStatus = !result.enabled;

      chrome.storage.local.set({ enabled: newStatus }, () => {
        updateButton(newStatus);

        if (!newStatus) {
          chrome.storage.local.set(
            { scan_stats: { total: 0, safe: 0, suspicious: 0 } },
            () => {
              totalEl.innerText = 0;
              safeEl.innerText = 0;
              suspiciousEl.innerText = 0;
            }
          );

          getActiveTab((tab) => {
            if (tab && tab.id) chrome.tabs.reload(tab.id);
          });
        }

        if (newStatus) {
          reloadActiveTabAndThen((tabId) => {
            trySendMessageToTab(tabId, { type: "rescan" });
          });
        }
      });
    });
  });

  // Option checkboxes
  [highlightNav, highlightLong, highlightLogin].forEach((opt) => {
    opt.addEventListener("change", () => {
      chrome.storage.local.set({
        options: {
          highlightNav: highlightNav.checked,
          highlightLong: highlightLong.checked,
          highlightLogin: highlightLogin.checked,
        },
      });

      reloadActiveTabAndThen((tabId) => {
        trySendMessageToTab(tabId, { type: "rescan" });
      });

      location.reload();
    });
  });

  // Clear suspicious cache
  clearCacheBtn.addEventListener("click", () => {
    chrome.storage.local.remove("suspicious_cache", () => {
      // Reload page so all highlights are removed
      getActiveTab((tab) => {
        if (tab && tab.id) chrome.tabs.reload(tab.id);
      });
    });
  });

  // Manual check (background)
  manualBtn.addEventListener("click", () => {
    const url = manualInput.value.trim();
    if (!url) return;

    // send to service worker (background.js)
    chrome.runtime.sendMessage({ type: "manualCheck", url }, (response) => {
      if (chrome.runtime.lastError) {
        console.debug("manualCheck failed:", chrome.runtime.lastError.message);
        manualResult.innerText = "Unable to check.";
        manualResult.style.color = "black";
        return;
      }

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

  // Receive live stats from content script
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "stats") {
      totalEl.innerText = msg.total ?? 0;
      safeEl.innerText = msg.safe ?? 0;
      suspiciousEl.innerText = msg.suspicious ?? 0;
    }
  });

  // UI helper
  function updateButton(enabled) {
    if (enabled) {
      toggleBtn.className = "main-toggle enabled";
      toggleBtn.innerText = "Disable Scanning";
    } else {
      toggleBtn.className = "main-toggle disabled";
      toggleBtn.innerText = "Enable Scanning";
    }
  }
});
