/**
 * background.js — PhishGuard Service Worker (Manifest V3)
 *
 * Responsabilités :
 *  - Recevoir les messages PHISHING_DETECTED du content script
 *  - Afficher une notification système native
 *  - Exposer l'état du service au popup
 */

// ── Notification native sur lien CRITICAL ─────────────────────────────────────
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "PHISHING_DETECTED") {
    const flagSummary = (message.flags || []).slice(0, 3).join(" · ");

    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icons/icon32.png",
      title:    "⛔ PhishGuard — Lien CRITICAL détecté",
      message:  `Score : ${message.score}/100\n${flagSummary}`,
      priority: 2,
    });
  }

  // Réponse au popup (health check)
  if (message.type === "POPUP_HEALTH") {
    fetch("http://127.0.0.1:5050/api/health")
      .then(r => r.json())
      .then(data => sendResponse({ online: true, status: data.status }))
      .catch(()  => sendResponse({ online: false }));
    return true; // signale une réponse asynchrone
  }
});
