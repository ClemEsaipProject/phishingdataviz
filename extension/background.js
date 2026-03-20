/**
 * background.js — PhishGuard Service Worker (Manifest V3)
 *
 * Responsabilités :
 *  - Recevoir les messages PHISHING_DETECTED du content script
 *  - Afficher une notification système native
 *  - Exposer l'état du service au popup
 *  - Menu contextuel sur les liens (clic droit → Analyser avec PhishGuard)
 */

// ── Menu contextuel (clic droit sur un lien) ───────────────────────────────
// removeAll() avant create() pour éviter l'erreur "duplicate id" au rechargement
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id:       "phishguard-analyze",
      title:    "Analyser avec PhishGuard",
      contexts: ["link"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== "phishguard-analyze") return;
  const url = info.linkUrl;
  if (!url) return;

  fetch("http://127.0.0.1:5050/api/analyze", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ url }),
  })
    .then(r => r.json())
    .then(data => {
      const level = data.risk_level || "INCONNU";
      const score = data.risk_score ?? "?";
      const flags = (data.flags || []).slice(0, 3).join(" · ") || "Aucun signal";
      const icon  = level === "CRITICAL" ? "⛔"
                  : level === "HIGH"     ? "⚠️"
                  : level === "MEDIUM"   ? "🟡"
                  : level === "LOW"      ? "🔵"
                  :                        "✅";
      chrome.notifications.create({
        type:     "basic",
        iconUrl:  "icons/icon32.png",
        title:    `${icon} PhishGuard — ${level}`,
        message:  `Score : ${score}/100\n${flags}`,
        priority: level === "CRITICAL" ? 2 : 1,
      });
    })
    .catch(() => {
      chrome.notifications.create({
        type:    "basic",
        iconUrl: "icons/icon32.png",
        title:   "PhishGuard — Hors ligne",
        message: "Le backend Flask n'est pas joignable (port 5050).",
      });
    });
});

/**
 * Tous les fetch() vers l'API locale passent par ce service worker.
 *
 * Pourquoi : les content scripts sur des pages HTTPS (Gmail, Outlook…)
 * sont bloqués par la politique "mixed content" du navigateur quand ils
 * tentent un fetch() vers http://localhost. Le service worker n'est pas
 * soumis à cette restriction — il sert de relais transparent.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {

  // ── Relais d'analyse URL (contourne le mixed-content HTTPS → HTTP) ──────────
  if (message.type === "ANALYZE_URL") {
    fetch("http://127.0.0.1:5050/api/analyze", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: message.url }),
    })
      .then(r => r.json())
      .then(data => sendResponse({ ok: true, data }))
      .catch(()  => sendResponse({ ok: false }));
    return true;  // indique une réponse asynchrone à Chrome
  }

  // ── Notification native sur lien CRITICAL ───────────────────────────────────
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

  // ── Health check pour le popup ───────────────────────────────────────────────
  if (message.type === "POPUP_HEALTH") {
    fetch("http://127.0.0.1:5050/api/health")
      .then(r => r.json())
      .then(data => sendResponse({ online: true, status: data.status }))
      .catch(()  => sendResponse({ online: false }));
    return true;
  }
});
