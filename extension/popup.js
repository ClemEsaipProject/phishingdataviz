/**
 * popup.js — PhishGuard Popup
 *
 * 1. Vérifie que le backend Flask est en ligne via le service worker
 * 2. Interroge le content script de l'onglet actif pour les stats de la page
 */

const dot        = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");

// ── Health check backend ───────────────────────────────────────────────────────
chrome.runtime.sendMessage({ type: "POPUP_HEALTH" }, response => {
  if (response?.online) {
    dot.className      = "online";
    statusText.textContent = "Backend en ligne · analyse active";
  } else {
    dot.className      = "offline";
    statusText.textContent = "Backend hors ligne — lancez python api.py";
  }
});

// ── Stats depuis le content script de l'onglet actif ─────────────────────────
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  if (!tab?.id) return;

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      // Compte les ancres par niveau (attribut posé par content.js)
      const all    = document.querySelectorAll("a[data-phishguard]");
      const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, SAFE: 0 };
      all.forEach(a => {
        const lvl = a.getAttribute("data-phishguard");
        if (lvl in counts) counts[lvl]++;
      });
      return { total: all.length, counts };
    },
  }, results => {
    if (!results?.[0]?.result) return;
    const { total, counts } = results[0].result;

    document.getElementById("count-total").textContent    = total;
    document.getElementById("count-critical").textContent = counts.CRITICAL;
    document.getElementById("count-high").textContent     = counts.HIGH;
    document.getElementById("count-medium").textContent   = counts.MEDIUM;
    document.getElementById("count-low").textContent      = counts.LOW;
    document.getElementById("count-safe").textContent     = counts.SAFE;
  });
});
