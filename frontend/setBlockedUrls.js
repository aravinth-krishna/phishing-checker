(function () {
  try {
    const urls = JSON.parse(document.currentScript.dataset.urls || "[]");
    window.__PHISHING_CHECKER_BLOCKED_URLS = new Set(urls);
  } catch (e) {
    window.__PHISHING_CHECKER_BLOCKED_URLS = new Set();
  }
})();
