(function () {
  const originalOpen = window.open;
  window.open = function (url, ...args) {
    try {
      if (window.__PHISHING_CHECKER_BLOCKED_URLS?.has(url)) {
        alert("🚨 Blocked potential phishing link!\n" + url);
        return null;
      }
    } catch (e) {}
    return originalOpen.call(window, url, ...args);
  };

  const origPush = history.pushState;
  history.pushState = function (state, title, url) {
    try {
      if (window.__PHISHING_CHECKER_BLOCKED_URLS?.has(String(url))) {
        alert("🚨 Blocked potential phishing link!\n" + url);
        return;
      }
    } catch (e) {}
    return origPush.apply(this, arguments);
  };

  const origReplace = history.replaceState;
  history.replaceState = function (state, title, url) {
    try {
      if (window.__PHISHING_CHECKER_BLOCKED_URLS?.has(String(url))) {
        alert("🚨 Blocked potential phishing link!\n" + url);
        return;
      }
    } catch (e) {}
    return origReplace.apply(this, arguments);
  };
})();
