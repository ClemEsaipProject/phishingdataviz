/**
 * content.js — PhishGuard Content Script
 *
 * Scanne tous les liens <a> du DOM courant et les colorie selon leur niveau de risque.
 * Compatible : navigateur standard · Gmail · Outlook Web
 *
 * Stratégie :
 *  - Cache par session (Map) → chaque domaine unique n'est analysé qu'une fois
 *  - File d'attente + concurrence limitée → pas de flood sur l'API locale
 *  - MutationObserver avec debounce → support des SPA (Gmail, Outlook)
 */

const API_BASE        = "http://127.0.0.1:5050";
const MAX_CONCURRENT  = 3;    // requêtes simultanées max vers l'API
const DEBOUNCE_MS     = 600;  // délai MutationObserver (ms)

// ── Cache session : url → résultat API ────────────────────────────────────────
const urlCache = new Map();

// ── Styles visuels par niveau ──────────────────────────────────────────────────
const RISK_STYLE = {
  CRITICAL: { color: "#fff",    bg: "#cc0000", border: "2px solid #8b0000", weight: "bold"   },
  HIGH:     { color: "#fff",    bg: "#e65c00", border: "2px solid #b34700", weight: "bold"   },
  MEDIUM:   { color: "#1a1a00", bg: "#e6c200", border: "2px solid #b39600", weight: "normal" },
  LOW:      { color: "#003366", bg: "#b3d9ff", border: "2px solid #0066cc", weight: "normal" },
  SAFE:     null,
};

// ── Sélecteurs DOM selon la plateforme ────────────────────────────────────────
function getSelector() {
  const host = window.location.hostname;
  if (host.includes("mail.google.com"))
    return ".a3s.aiL a, .ii.gt a";
  if (host.includes("outlook.live") || host.includes("outlook.office"))
    return ".ReadMsgBody a, .ExternalClass a, [data-is-focusable='true'] a";
  return "a[href]";
}

// ── Appel API (avec cache) ────────────────────────────────────────────────────
async function fetchAnalysis(url) {
  if (urlCache.has(url)) return urlCache.get(url);

  try {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    urlCache.set(url, data);
    return data;
  } catch {
    // API hors ligne → mode silencieux (aucune modification visuelle)
    return null;
  }
}

// ── Application du style sur un <a> ──────────────────────────────────────────
function applyStyle(anchor, result) {
  const style = RISK_STYLE[result.risk_level];
  if (!style) return;   // SAFE → pas de modification

  anchor.style.color           = style.color;
  anchor.style.backgroundColor = style.bg;
  anchor.style.border          = style.border;
  anchor.style.borderRadius    = "3px";
  anchor.style.padding         = "1px 4px";
  anchor.style.textDecoration  = "none";
  anchor.style.fontWeight      = style.weight;

  // Badge inline
  const badge       = document.createElement("sup");
  badge.textContent = ` ⚠${result.risk_level}`;
  badge.style.cssText = `
    font-size: 0.65em;
    font-weight: bold;
    color: ${style.color};
    margin-left: 3px;
  `;
  anchor.appendChild(badge);

  // Tooltip détaillé
  const lines = [
    `[PhishGuard] Score : ${result.risk_score}/100`,
    `Niveau : ${result.risk_level}`,
    ...(result.flags || []),
  ];
  anchor.title = lines.join("\n");

  // Notifier le service worker si CRITICAL
  if (result.risk_level === "CRITICAL") {
    chrome.runtime.sendMessage({
      type:  "PHISHING_DETECTED",
      url:   result.url,
      score: result.risk_score,
      flags: result.flags,
    });
  }

  anchor.setAttribute("data-phishguard", result.risk_level);
}

// ── File d'attente à concurrence limitée ──────────────────────────────────────
let activeRequests = 0;
const queue        = [];

async function processQueue() {
  while (queue.length > 0 && activeRequests < MAX_CONCURRENT) {
    const { anchor, url } = queue.shift();
    activeRequests++;
    fetchAnalysis(url)
      .then(result => { if (result) applyStyle(anchor, result); })
      .finally(() => { activeRequests--; processQueue(); });
  }
}

function enqueue(anchor, url) {
  queue.push({ anchor, url });
  processQueue();
}

// ── Scan du DOM ───────────────────────────────────────────────────────────────
function scanLinks() {
  document.querySelectorAll(getSelector()).forEach(anchor => {
    if (anchor.getAttribute("data-phishguard")) return;   // déjà traité
    const href = anchor.href;
    if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

    anchor.setAttribute("data-phishguard", "pending");
    enqueue(anchor, href);
  });
}

// ── MutationObserver (SPA / Gmail / Outlook) ─────────────────────────────────
let debounceTimer = null;
const observer    = new MutationObserver(mutations => {
  const hasNewLinks = mutations.some(m =>
    [...m.addedNodes].some(n =>
      n.nodeType === 1 && (n.tagName === "A" || n.querySelector?.("a"))
    )
  );
  if (!hasNewLinks) return;
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(scanLinks, DEBOUNCE_MS);
});

observer.observe(document.body, { childList: true, subtree: true });

// ── Lancement initial ─────────────────────────────────────────────────────────
scanLinks();
