/* ═══════════════════════════════════════════════════
   ENTROPY — Password Strength Analyzer
   All analysis runs locally. Zero network calls.
═══════════════════════════════════════════════════ */

// ── Common passwords (top ~200 compressed) ──────────
const COMMON_PASSWORDS = new Set([
  "password","123456","12345678","qwerty","abc123","monkey","1234567",
  "letmein","trustno1","dragon","baseball","iloveyou","master","sunshine",
  "ashley","bailey","passw0rd","shadow","123123","654321","superman",
  "qazwsx","michael","football","password1","password123","1234567890",
  "welcome","admin","login","hello","qwerty123","password2","123456789",
  "111111","1111111","12345","000000","pass","test","1q2w3e","qwertyuiop",
  "q1w2e3r4","1qaz2wsx","zxcvbnm","asdfghjkl","qazwsxedc","pokemon",
  "charlie","donald","diamond","princess","jessica","0987654321","696969",
  "batman","summer","winter","spring","autumn","flower","ranger","access",
  "thunder","matrix","starwars","soccer","hockey","harley","ranger",
  "hunter","hunter2","google","myspace","ginger","cheese","robert",
  "thomas","andrew","daniel","george","jordan","harley","rangers","dakota",
]);

// ── Keyboard patterns ───────────────────────────────
const KEYBOARD_PATTERNS = [
  "qwerty","qwertyuiop","asdfgh","asdfghjkl","zxcvbn","zxcvbnm",
  "1qaz","2wsx","3edc","4rfv","5tgb","6yhn","7ujm",
  "qazwsx","1q2w3e","1q2w3e4r","qweasdzxc","qweasd",
  "12345","123456","1234567","12345678","123456789","1234567890",
  "09876","098765","0987654","09876543","098765432","0987654321",
  "abcdef","abcdefgh","abcdefghij",
];

// ── Repeated pattern detector ───────────────────────
function hasRepeatedSequence(pw) {
  // detect aaa, abcabc, ababab style repetitions
  if (/(.)\1{2,}/.test(pw)) return true;
  for (let len = 2; len <= Math.floor(pw.length / 2); len++) {
    const chunk = pw.slice(0, len);
    const re = new RegExp(`(${chunk.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}){2,}`,'i');
    if (re.test(pw)) return true;
  }
  return false;
}

// ── Entropy calculation ─────────────────────────────
function calcPool(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw))   pool += 26;
  if (/[A-Z]/.test(pw))   pool += 26;
  if (/[0-9]/.test(pw))   pool += 10;
  if (/[ !"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(pw)) pool += 33;
  return pool;
}

function calcEntropy(pw) {
  if (!pw) return 0;
  const pool = calcPool(pw);
  return Math.round(Math.log2(Math.pow(pool, pw.length)) * 10) / 10;
}

// ── Crack time estimate ─────────────────────────────
// Assume fast offline attack: 10 billion guesses/sec
function crackTime(entropy) {
  const guesses = Math.pow(2, entropy);
  const seconds = guesses / 10e9;
  if (seconds < 1)           return "instant";
  if (seconds < 60)          return `${Math.round(seconds)}s`;
  if (seconds < 3600)        return `${Math.round(seconds/60)}min`;
  if (seconds < 86400)       return `${Math.round(seconds/3600)}hrs`;
  if (seconds < 2592000)     return `${Math.round(seconds/86400)}days`;
  if (seconds < 31536000)    return `${Math.round(seconds/2592000)}mo`;
  if (seconds < 3153600000)  return `${Math.round(seconds/31536000)}yrs`;
  return "centuries";
}

// ── Strength score (0–100) ──────────────────────────
function strengthScore(pw, entropy, warnings) {
  let score = Math.min(entropy, 100);
  score -= warnings.length * 12;
  return Math.max(0, Math.min(100, Math.round(score)));
}

// ── Strength label + color class ───────────────────
function strengthMeta(score) {
  if (score < 20) return { label: "Very Weak",  cls: "strength-bad",  color: "var(--bad)",  pct: 10 };
  if (score < 40) return { label: "Weak",        cls: "strength-poor", color: "var(--poor)", pct: 28 };
  if (score < 60) return { label: "Fair",        cls: "strength-ok",   color: "var(--ok)",   pct: 52 };
  if (score < 80) return { label: "Strong",      cls: "strength-good", color: "var(--good)", pct: 75 };
  return             { label: "Very Strong",  cls: "strength-great",color: "var(--great)", pct: 100 };
}

// ── Pattern warnings ────────────────────────────────
function detectWarnings(pw) {
  const warnings = [];
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(lower))
    warnings.push("⚠ This is a known common password");
  for (const pat of KEYBOARD_PATTERNS) {
    if (lower.includes(pat)) {
      warnings.push(`⚠ Contains keyboard pattern: "${pat}"`);
      break;
    }
  }
  if (hasRepeatedSequence(pw))
    warnings.push("⚠ Contains repeated sequences or characters");
  if (/^\d+$/.test(pw))
    warnings.push("⚠ All numbers — trivially brute-forced");
  if (/^[a-zA-Z]+$/.test(pw))
    warnings.push("⚠ Letters only — missing numbers and symbols");
  if (pw.length < 8)
    warnings.push("⚠ Critically short");
  return warnings;
}

// ── Suggestions ─────────────────────────────────────
function buildSuggestions(pw, entropy, checks) {
  const tips = [];
  if (!checks.chkLength)  tips.push("Make it at least <strong>12 characters</strong> long.");
  if (!checks.chkUpper)   tips.push("Add some <strong>uppercase letters</strong>.");
  if (!checks.chkSymbol)  tips.push("Include <strong>special characters</strong> like !@#$%.");
  if (!checks.chkNumber)  tips.push("Mix in a few <strong>numbers</strong>.");
  if (entropy < 60)       tips.push("Consider a random <strong>passphrase</strong>: four random words strung together are highly memorable and very strong.");
  return tips.length
    ? "<strong>Suggestions:</strong> " + tips.join(" ")
    : pw.length > 0
      ? "<strong>Excellent!</strong> This password scores well across all criteria."
      : "";
}

// ═══════════════════════════════════════════════════
//  DOM logic
// ═══════════════════════════════════════════════════

const input      = document.getElementById("passwordInput");
const toggleBtn  = document.getElementById("toggleVisibility");
const eyeIcon    = document.getElementById("eyeIcon");
const meterFill  = document.getElementById("meterFill");
const meterLabel = document.getElementById("meterLabel");
const warningsEl = document.getElementById("warnings");
const suggestEl  = document.getElementById("suggestions");

// Stat cards
const statEntropy = document.getElementById("statEntropy").querySelector(".stat-value");
const statCrack   = document.getElementById("statCrack").querySelector(".stat-value");
const statLength  = document.getElementById("statLength").querySelector(".stat-value");
const statPool    = document.getElementById("statPool").querySelector(".stat-value");

// Check items
const checkMap = {
  chkLength:    { el: document.getElementById("chkLength"),    test: pw => pw.length >= 12 },
  chkUpper:     { el: document.getElementById("chkUpper"),     test: pw => /[A-Z]/.test(pw) },
  chkLower:     { el: document.getElementById("chkLower"),     test: pw => /[a-z]/.test(pw) },
  chkNumber:    { el: document.getElementById("chkNumber"),    test: pw => /[0-9]/.test(pw) },
  chkSymbol:    { el: document.getElementById("chkSymbol"),    test: pw => /[^a-zA-Z0-9]/.test(pw) },
  chkNoCommon:  { el: document.getElementById("chkNoCommon"),  test: pw => !COMMON_PASSWORDS.has(pw.toLowerCase()) },
  chkNoPattern: { el: document.getElementById("chkNoPattern"), test: pw => !KEYBOARD_PATTERNS.some(p => pw.toLowerCase().includes(p)) },
  chkNoRepeat:  { el: document.getElementById("chkNoRepeat"),  test: pw => !hasRepeatedSequence(pw) },
};

// Clear all strength classes
const checker = document.querySelector(".checker");
const ALL_STRENGTH = ["strength-bad","strength-poor","strength-ok","strength-good","strength-great"];

function analyze(pw) {
  // Clear
  ALL_STRENGTH.forEach(c => checker.classList.remove(c));

  if (!pw) {
    meterFill.style.width = "0%";
    meterFill.style.background = "var(--muted)";
    meterLabel.textContent = "—";
    meterLabel.style.color = "var(--muted)";
    statEntropy.textContent = "—";
    statCrack.textContent   = "—";
    statLength.textContent  = "—";
    statPool.textContent    = "—";
    Object.values(checkMap).forEach(({el}) => { el.className = "check-item"; });
    warningsEl.innerHTML = "";
    suggestEl.innerHTML  = "";
    return;
  }

  const entropy  = calcEntropy(pw);
  const pool     = calcPool(pw);
  const warnings = detectWarnings(pw);

  // Run checks
  const checks = {};
  for (const [key, {el, test}] of Object.entries(checkMap)) {
    const pass = test(pw);
    checks[key] = pass;
    el.className = "check-item " + (pass ? "pass" : "fail");
  }

  const score  = strengthScore(pw, entropy, warnings);
  const meta   = strengthMeta(score);

  // Meter
  meterFill.style.width      = meta.pct + "%";
  meterFill.style.background = meta.color;
  meterLabel.textContent     = meta.label;
  meterLabel.style.color     = meta.color;
  checker.classList.add(meta.cls);

  // Stats
  statEntropy.textContent = entropy + " bits";
  statEntropy.style.color = meta.color;
  statCrack.textContent   = crackTime(entropy);
  statCrack.style.color   = meta.color;
  statLength.textContent  = pw.length;
  statLength.style.color  = pw.length >= 12 ? "var(--good)" : "var(--bad)";
  statPool.textContent    = pool;
  statPool.style.color    = pool >= 70 ? "var(--good)" : pool >= 36 ? "var(--ok)" : "var(--bad)";

  // Warnings
  warningsEl.innerHTML = warnings
    .map(w => `<div class="warning-tag">${w}</div>`)
    .join("");

  // Suggestions
  suggestEl.innerHTML = buildSuggestions(pw, entropy, checks);
}

// ── Event listeners ─────────────────────────────────
input.addEventListener("input", () => analyze(input.value));

toggleBtn.addEventListener("click", () => {
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  eyeIcon.textContent = isPassword ? "🙈" : "👁";
});

// Focus input on load
window.addEventListener("DOMContentLoaded", () => input.focus());
