/**
 * content.js — PhishGuard Content Script
 *
 * Stratégie CSS-first :
 *  - Une feuille de style est injectée dans <head> une seule fois.
 *  - Les règles ciblent a[data-phishguard="LEVEL"] avec !important
 *    et couvrent :link, :visited, :hover pour écraser TOUS les styles du site.
 *  - Le badge ⚠ est rendu via ::after → aucune manipulation DOM supplémentaire.
 *  - Le script JS ne pose que l'attribut data-phishguard sur la balise <a>.
 *
 * Compatible : navigateur standard · Gmail · Outlook Web · toute SPA
 */

const MAX_CONCURRENT = 3;
const DEBOUNCE_MS    = 600;

// ── Injection CSS (une seule fois par page) ───────────────────────────────────
function injectStyles() {
  if (document.getElementById("phishguard-styles")) return;

  const style = document.createElement("style");
  style.id    = "phishguard-styles";

  // Chaque niveau cible :link, :visited, :hover pour écraser
  // la couleur mauve "visité" du navigateur et les styles du site.
  style.textContent = `
    /* ── CRITICAL ── */
    a[data-phishguard="CRITICAL"],
    a[data-phishguard="CRITICAL"]:link,
    a[data-phishguard="CRITICAL"]:visited,
    a[data-phishguard="CRITICAL"]:hover {
      color:            #ffffff !important;
      background-color: #cc0000 !important;
      border:           2px solid #8b0000 !important;
      border-radius:    3px !important;
      padding:          1px 5px !important;
      text-decoration:  none !important;
      font-weight:      bold !important;
    }
    a[data-phishguard="CRITICAL"]::after {
      content:        " ⚠ CRITICAL";
      font-size:      0.65em;
      font-weight:    bold;
      color:          #ffcccc;
      vertical-align: super;
      margin-left:    2px;
    }

    /* ── HIGH ── */
    a[data-phishguard="HIGH"],
    a[data-phishguard="HIGH"]:link,
    a[data-phishguard="HIGH"]:visited,
    a[data-phishguard="HIGH"]:hover {
      color:            #ffffff !important;
      background-color: #e65c00 !important;
      border:           2px solid #b34700 !important;
      border-radius:    3px !important;
      padding:          1px 5px !important;
      text-decoration:  none !important;
      font-weight:      bold !important;
    }
    a[data-phishguard="HIGH"]::after {
      content:        " ⚠ HIGH";
      font-size:      0.65em;
      font-weight:    bold;
      color:          #ffe0cc;
      vertical-align: super;
      margin-left:    2px;
    }

    /* ── MEDIUM ── */
    a[data-phishguard="MEDIUM"],
    a[data-phishguard="MEDIUM"]:link,
    a[data-phishguard="MEDIUM"]:visited,
    a[data-phishguard="MEDIUM"]:hover {
      color:            #1a1a00 !important;
      background-color: #e6c200 !important;
      border:           2px solid #b39600 !important;
      border-radius:    3px !important;
      padding:          1px 5px !important;
      text-decoration:  none !important;
    }
    a[data-phishguard="MEDIUM"]::after {
      content:        " ⚠ MEDIUM";
      font-size:      0.65em;
      font-weight:    bold;
      color:          #4d3d00;
      vertical-align: super;
      margin-left:    2px;
    }

    /* ── LOW ── */
    a[data-phishguard="LOW"],
    a[data-phishguard="LOW"]:link,
    a[data-phishguard="LOW"]:visited,
    a[data-phishguard="LOW"]:hover {
      color:            #003366 !important;
      background-color: #b3d9ff !important;
      border:           2px solid #0066cc !important;
      border-radius:    3px !important;
      padding:          1px 5px !important;
      text-decoration:  none !important;
    }
    a[data-phishguard="LOW"]::after {
      content:        " ⚠ LOW";
      font-size:      0.65em;
      font-weight:    bold;
      color:          #003366;
      vertical-align: super;
      margin-left:    2px;
    }
  `;

  // Insérer en premier dans <head> pour que les styles du site
  // puissent le surcharger si nécessaire (on le couvre avec !important)
  document.head.prepend(style);
}

// ── Cache session : url → résultat API ────────────────────────────────────────
const urlCache = new Map();

/**
 * Analyse une URL via le service worker (background.js).
 *
 * Le content script ne fait plus de fetch() direct : sur les pages HTTPS
 * (Gmail, Outlook…) le navigateur bloque les requêtes vers http://localhost
 * ("mixed content"). Le service worker n'est pas soumis à cette restriction
 * et sert de relais transparent.
 */
async function fetchAnalysis(url) {
  if (urlCache.has(url)) return urlCache.get(url);
  if (!chrome.runtime?.id) return null;  // extension context invalidated (after reload)

  try {
    const response = await chrome.runtime.sendMessage({ type: "ANALYZE_URL", url });
    if (!response?.ok) return null;   // backend hors ligne ou extension déchargée
    urlCache.set(url, response.data);
    return response.data;
  } catch {
    return null;   // service worker inactif ou extension rechargée
  }
}

// ── Application du résultat sur <a> (CSS-only) ────────────────────────────────
function applyResult(anchor, result) {
  const level = result.risk_level;
  if (level === "SAFE") {
    anchor.setAttribute("data-phishguard", "SAFE");
    return;
  }

  // Seul l'attribut change — le CSS fait tout le reste
  anchor.setAttribute("data-phishguard", level);

  // Tooltip natif (title) pour les détails au survol
  anchor.title = [
    `[PhishGuard] Score : ${result.risk_score}/100`,
    `Niveau : ${level}`,
    ...(result.flags || []),
  ].join("\n");

  // Notification système pour les liens CRITICAL
  if (level === "CRITICAL") {
    chrome.runtime.sendMessage({
      type:  "PHISHING_DETECTED",
      url:   result.url,
      score: result.risk_score,
      flags: result.flags,
    });
  }
}

// ── File d'attente (concurrence limitée) ──────────────────────────────────────
let activeRequests = 0;
const queue        = [];

function processQueue() {
  while (queue.length > 0 && activeRequests < MAX_CONCURRENT) {
    const { anchor, url } = queue.shift();
    activeRequests++;
    fetchAnalysis(url)
      .then(result => { if (result) applyResult(anchor, result); })
      .catch(() => {})
      .finally(() => { activeRequests--; processQueue(); });
  }
}

function enqueue(anchor, url) {
  queue.push({ anchor, url });
  processQueue();
}

// ── Sélecteurs selon la plateforme ────────────────────────────────────────────
function getSelector() {
  const host = window.location.hostname;

  // Gmail : les sélecteurs de classe (.a3s.aiL) changent entre versions.
  // On utilise a[href] global — le MutationObserver cible de toute façon
  // uniquement les nouveaux nœuds injectés par Gmail lors de l'ouverture
  // d'un email, ce qui évite de rescanner toute la page à chaque fois.
  if (host.includes("mail.google.com"))
    return "a[href]";

  // Outlook Web : même stratégie — sélecteur large, debounce MutationObserver.
  if (host.includes("outlook.live") || host.includes("outlook.office"))
    return "a[href]";

  return "a[href]";
}

// ── Scan du DOM ───────────────────────────────────────────────────────────────
function scanLinks() {
  document.querySelectorAll(getSelector()).forEach(anchor => {
    if (anchor.getAttribute("data-phishguard")) return;  // déjà traité
    const href = anchor.href;
    if (!href || href.startsWith("#") || href.startsWith("javascript:")) return;

    anchor.setAttribute("data-phishguard", "pending");
    enqueue(anchor, href);
  });
}

// ── MutationObserver avec debounce (SPA / Gmail / Outlook) ───────────────────
let debounceTimer = null;
const observer    = new MutationObserver(mutations => {
  // Ignorer les mutations causées par notre propre injection de style
  const hasNewLinks = mutations.some(m =>
    [...m.addedNodes].some(n =>
      n.nodeType === 1
      && n.id !== "phishguard-styles"
      && (n.tagName === "A" || n.querySelector?.("a"))
    )
  );
  if (!hasNewLinks) return;
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(scanLinks, DEBOUNCE_MS);
});

// ── Initialisation ────────────────────────────────────────────────────────────
injectStyles();
observer.observe(document.body, { childList: true, subtree: true });
scanLinks();
