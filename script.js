/* Password Strength Checker
   - Entropy estimate (bits) based on charset size + length, with simple penalties
   - Pattern checks: common passwords, sequences, repeats, keyboard walks, dates, leetspeak-ish, etc.
   - Crack-time estimates (rough)
*/

const elPw = document.getElementById("pw");
const elToggle = document.getElementById("toggle");
const elMeterFill = document.getElementById("meterFill");
const elChecks = document.getElementById("checks");
const elScorePill = document.getElementById("scorePill");
const elEntropyPill = document.getElementById("entropyPill");
const elGuessPill = document.getElementById("guessPill");
const elCrack = document.getElementById("crack");

// Small in-file common list (you can expand it)
const COMMON = new Set([
  "password","123456","123456789","12345678","qwerty","abc123","111111","letmein","iloveyou","admin",
  "welcome","monkey","dragon","football","baseball","login","princess","sunshine","master","shadow",
  "passw0rd","password1","qwerty123","zaq12wsx","1q2w3e4r","000000","654321","superman","batman",
  "trustno1","starwars","freedom","hello","whatever"
]);

const KEYBOARD_WALKS = [
  "qwertyuiop", "asdfghjkl", "zxcvbnm",
  "1234567890", "0987654321"
];

const update = () => {
  const pw = elPw.value || "";
  const analysis = analyzePassword(pw);

  renderChecks(analysis.checks);
  renderCrackTimes(analysis);

  // Meter + pills
  elMeterFill.style.width = `${analysis.score}%`;
  elScorePill.textContent = `Score: ${analysis.score}/100 (${analysis.label})`;
  elEntropyPill.textContent = `Entropy: ${analysis.entropyBits.toFixed(1)} bits`;
  elGuessPill.textContent = `Guess space: ~${formatBigInt(analysis.guessSpace)} guesses`;
};

elPw.addEventListener("input", update);

elToggle.addEventListener("click", () => {
  const isPw = elPw.type === "password";
  elPw.type = isPw ? "text" : "password";
  elToggle.textContent = isPw ? "Hide" : "Show";
  elToggle.setAttribute("aria-label", isPw ? "Hide password" : "Show password");
});

update();

/* ---------------- Core analysis ---------------- */

function analyzePassword(pw) {
  const checks = [];

  if (pw.length === 0) {
    return {
      entropyBits: 0,
      guessSpace: 0n,
      score: 0,
      label: "—",
      checks: [{
        level: "warn",
        title: "Type a password to begin",
        detail: "This tool evaluates locally in your browser."
      }],
      crackTimes: []
    };
  }

  // Character set sizing
  const charset = estimateCharsetSize(pw);
  let baseEntropy = pw.length * log2(charset);

  // Pattern checks and penalties
  const lower = pw.toLowerCase();
  const normalized = normalizeLeet(lower);

  // 1) Too short
  if (pw.length < 8) {
    checks.push(bad("Too short", "Use at least 12–16+ characters when possible."));
    baseEntropy -= 10;
  } else if (pw.length < 12) {
    checks.push(warn("Moderate length", "Consider 12–16+ characters (or a passphrase)."));
  } else {
    checks.push(ok("Good length", "Longer passwords are significantly harder to crack."));
  }

  // 2) Character variety
  const variety = characterVariety(pw);
  if (variety.classesUsed <= 1) {
    checks.push(bad("Low character variety", "Mixing character types helps, but length matters more."));
    baseEntropy -= 8;
  } else if (variety.classesUsed === 2) {
    checks.push(warn("Some variety", "Consider adding more variety or increasing length."));
  } else {
    checks.push(ok("Good variety", `Uses ${variety.classesUsed} character classes.`));
  }

  // 3) Common password / dictionary-ish
  const isCommon = COMMON.has(lower) || COMMON.has(normalized);
  if (isCommon) {
    checks.push(bad("Common password", "This appears in common-password lists."));
    baseEntropy -= 30;
  } else if (looksDictionaryLike(normalized)) {
    checks.push(warn("Looks dictionary-like", "Avoid single common words (even with simple substitutions)."));
    baseEntropy -= 8;
  } else {
    checks.push(ok("Not obviously common", "No direct match in the built-in common list."));
  }

  // 4) Sequences (abcd, 1234)
  const seq = hasSequence(lower, 4);
  if (seq) {
    checks.push(bad("Contains a sequence", `Found a simple sequence (“${seq}”).`));
    baseEntropy -= 12;
  } else {
    checks.push(ok("No simple sequences", "Didn’t detect common straight sequences."));
  }

  // 5) Repeats (aaaa, abab, etc.)
  const rep = repeatedPatterns(lower);
  if (rep) {
    checks.push(warn("Repeating pattern", `Found repeating chunk (“${rep}”).`));
    baseEntropy -= 8;
  } else {
    checks.push(ok("No obvious repeats", "Didn’t detect simple repeating chunks."));
  }

  // 6) Keyboard walks (qwerty/asdf/12345)
  const walk = keyboardWalk(lower);
  if (walk) {
    checks.push(bad("Keyboard pattern", `Looks like a keyboard walk (“${walk}”).`));
    baseEntropy -= 15;
  } else {
    checks.push(ok("No keyboard walk", "Didn’t detect qwerty/asdf style runs."));
  }

  // 7) Dates / years
  const dateHit = containsDateOrYear(lower);
  if (dateHit) {
    checks.push(warn("Contains a date/year", `Found “${dateHit}”. Dates are commonly guessed.`));
    baseEntropy -= 6;
  } else {
    checks.push(ok("No obvious date/year", "Didn’t detect a common year or date format."));
  }

  // 8) Too many of the same char
  const mono = highSingleCharShare(pw);
  if (mono) {
    checks.push(warn("Low diversity of characters", mono));
    baseEntropy -= 6;
  } else {
    checks.push(ok("Good character diversity", "No single character dominates."));
  }

  // Clamp entropy to [0, ...]
  const entropyBits = Math.max(0, baseEntropy);

  // Guess space ~ 2^entropy. Use BigInt with cap for display.
  const guessSpace = entropyToGuessSpace(entropyBits);

  // Score mapping (tunable)
  const score = entropyToScore(entropyBits, pw.length, variety.classesUsed, isCommon);

  const label =
    score < 25 ? "Very weak" :
    score < 45 ? "Weak" :
    score < 65 ? "Okay" :
    score < 80 ? "Strong" : "Very strong";

  const crackTimes = estimateCrackTimes(entropyBits);

  return { entropyBits, guessSpace, score, label, checks, crackTimes };
}

function estimateCharsetSize(pw) {
  let hasLower = /[a-z]/.test(pw);
  let hasUpper = /[A-Z]/.test(pw);
  let hasDigit = /\d/.test(pw);
  let hasSymbol = /[^a-zA-Z0-9]/.test(pw);

  // Rough sizes
  let size = 0;
  if (hasLower) size += 26;
  if (hasUpper) size += 26;
  if (hasDigit) size += 10;
  if (hasSymbol) size += 33; // printable-ish symbols

  // If empty for some reason, fallback
  return Math.max(1, size);
}

function characterVariety(pw) {
  const classes = [
    /[a-z]/.test(pw),
    /[A-Z]/.test(pw),
    /\d/.test(pw),
    /[^a-zA-Z0-9]/.test(pw),
  ];
  return { classesUsed: classes.filter(Boolean).length };
}

function normalizeLeet(s) {
  // Simple leet normalization commonly used in guesses
  return s
    .replace(/@/g, "a")
    .replace(/\$/g, "s")
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/!/g, "i")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t");
}

function looksDictionaryLike(s) {
  // Heuristic: mostly letters and length between 4-20 and no separators
  if (!/^[a-z]+$/.test(s)) return false;
  if (s.length < 4 || s.length > 20) return false;

  // Common suffixes/prefixes that appear in guess patterns
  const commonAffixes = ["ing","er","ers","ed","s","es","y","ly"];
  // If it ends with a very common affix, still "dictionary-like"
  return commonAffixes.some(a => s.endsWith(a)) || true;
}

function hasSequence(s, minLen = 4) {
  // detect ascending sequences in letters or digits
  const sequences = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789"
  ];

  for (const seq of sequences) {
    for (let i = 0; i <= seq.length - minLen; i++) {
      const chunk = seq.slice(i, i + minLen);
      if (s.includes(chunk)) return chunk;
    }
    // descending
    const rev = seq.split("").reverse().join("");
    for (let i = 0; i <= rev.length - minLen; i++) {
      const chunk = rev.slice(i, i + minLen);
      if (s.includes(chunk)) return chunk;
    }
  }

  return null;
}

function repeatedPatterns(s) {
  // detect repeating substrings like "ababab" or "xyzxyz"
  // Try chunk sizes 1..4
  for (let size = 1; size <= 4; size++) {
    for (let start = 0; start + size * 3 <= s.length; start++) {
      const chunk = s.slice(start, start + size);
      if (chunk.length < size) continue;

      let count = 1;
      let idx = start + size;
      while (s.slice(idx, idx + size) === chunk) {
        count++;
        idx += size;
      }
      if (count >= 3 && chunk.trim() !== "") {
        return chunk.repeat(Math.min(3, count));
      }
    }
  }
  // also detect 4+ same char in a row
  const m = s.match(/(.)\1{3,}/);
  if (m) return m[0];
  return null;
}

function keyboardWalk(s) {
  for (const row of KEYBOARD_WALKS) {
    // check forward and reverse in length 4+
    for (let L = 4; L <= Math.min(8, row.length); L++) {
      for (let i = 0; i <= row.length - L; i++) {
        const chunk = row.slice(i, i + L);
        if (s.includes(chunk)) return chunk;
        const rev = chunk.split("").reverse().join("");
        if (s.includes(rev)) return rev;
      }
    }
  }
  // diagonals like 1q2w3e4r
  if (/(?:1q2w|2w3e|3e4r|q1w2e3r4)/.test(s)) return "1q2w…";
  return null;
}

function containsDateOrYear(s) {
  // year 19xx or 20xx
  const year = s.match(/\b(19\d{2}|20\d{2})\b/);
  if (year) return year[0];

  // dd/mm/yyyy, mm/dd/yy, yyyy-mm-dd, etc (very rough)
  const date = s.match(/\b(\d{1,2}[\/\-\.]\d{1,2}([\/\-\.]\d{2,4})?)\b/);
  if (date) return date[0];

  return null;
}

function highSingleCharShare(pw) {
  if (pw.length < 8) return null;
  const freq = new Map();
  for (const ch of pw) freq.set(ch, (freq.get(ch) || 0) + 1);
  const max = Math.max(...freq.values());
  const share = max / pw.length;
  if (share >= 0.4) {
    return `One character makes up ${(share * 100).toFixed(0)}% of the password.`;
  }
  return null;
}

/* ---------------- Entropy / scoring ---------------- */

function log2(x) {
  return Math.log(x) / Math.log(2);
}

function entropyToGuessSpace(bits) {
  // guesses ~ 2^bits, but BigInt exponentiation needs integer exponent.
  // We'll approximate by splitting integer + fractional.
  const intBits = Math.floor(bits);
  const frac = bits - intBits;

  // Cap exponent to keep BigInt reasonable in UI (still huge)
  const cap = 4096; // beyond this, it's already astronomically large
  const safeBits = Math.min(intBits, cap);
  let base = 1n << BigInt(safeBits);

  // Multiply by 2^frac (approx) using float factor, then to BigInt
  const factor = Math.pow(2, frac);
  const approx = BigInt(Math.floor(Number.MAX_SAFE_INTEGER)); // fallback in case
  // Convert carefully: if base is too large for Number, we keep BigInt only for integer part.
  // We'll just return base for huge values; fractional doesn't matter.
  if (safeBits >= 52) return base;

  // For smaller, we can scale
  const scaled = BigInt(Math.floor(Number(base) * factor));
  return scaled > 0n ? scaled : base || 1n;
}

function entropyToScore(bits, length, classesUsed, isCommon) {
  // Base score from bits (roughly: 0..100 around 0..80 bits)
  let s = Math.round((bits / 80) * 100);

  // Length bonuses / penalties
  if (length >= 16) s += 8;
  if (length >= 20) s += 6;
  if (length < 10) s -= 8;

  // Variety small nudge
  if (classesUsed >= 3) s += 4;
  if (classesUsed === 1) s -= 6;

  // Common password hammer
  if (isCommon) s = Math.min(s, 15);

  return clamp(s, 0, 100);
}

function clamp(n, a, b) {
  return Math.max(a, Math.min(b, n));
}

function estimateCrackTimes(entropyBits) {
  // guesses = 2^bits. time = guesses / rate
  // Offline rates vary wildly. Provide a few scenarios:
  const rates = [
    { label: "10K guesses/sec (slow)", r: 1e4 },
    { label: "100M guesses/sec (fast GPU)", r: 1e8 },
    { label: "10B guesses/sec (very fast)", r: 1e10 },
  ];

  const guesses = Math.pow(2, Math.min(entropyBits, 120)); // float cap
  // For >120 bits, time is effectively "astronomical" for our display
  const capped = entropyBits > 120;

  return rates.map(({label, r}) => {
    if (capped) return { label, seconds: Infinity };
    const sec = guesses / r;
    return { label, seconds: sec };
  });
}

/* ---------------- Rendering ---------------- */

function renderChecks(checks) {
  elChecks.innerHTML = "";
  for (const c of checks) {
    const li = document.createElement("li");
    li.className = "check";

    const badge = document.createElement("div");
    badge.className = `badge ${c.level}`;
    badge.textContent = c.level === "ok" ? "✓" : (c.level === "warn" ? "!" : "×");

    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = c.title;
    const detail = document.createElement("span");
    detail.textContent = c.detail;

    text.appendChild(title);
    text.appendChild(detail);

    li.appendChild(badge);
    li.appendChild(text);
    elChecks.appendChild(li);
  }
}

function renderCrackTimes(analysis) {
  elCrack.innerHTML = "";
  for (const row of analysis.crackTimes) {
    const div = document.createElement("div");
    div.className = "crackRow";
    const k = document.createElement("div");
    k.className = "k";
    k.textContent = row.label;

    const v = document.createElement("div");
    v.className = "v";
    v.textContent = formatDuration(row.seconds);

    div.appendChild(k);
    div.appendChild(v);
    elCrack.appendChild(div);
  }
}

/* ---------------- Helpers ---------------- */

function ok(title, detail) { return { level: "ok", title, detail }; }
function warn(title, detail) { return { level: "warn", title, detail }; }
function bad(title, detail) { return { level: "bad", title, detail }; }

function formatBigInt(n) {
  if (typeof n !== "bigint") return String(n);
  if (n === 0n) return "0";
  const s = n.toString();
  if (s.length <= 4) return s;
  // 1.23e+45 style
  const head = s.slice(0, 3);
  const exp = s.length - 1;
  return `${head[0]}.${head.slice(1)}e+${exp}`;
}

function formatDuration(seconds) {
  if (!isFinite(seconds)) return "astronomical";
  if (seconds < 1) return "< 1 second";

  const units = [
    ["year", 365 * 24 * 3600],
    ["day", 24 * 3600],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1]
  ];

  let s = seconds;
  for (const [name, size] of units) {
    if (s >= size) {
      const v = Math.floor(s / size);
      return `${v.toLocaleString()} ${name}${v === 1 ? "" : "s"}`;
    }
  }
  return `${Math.round(seconds)} seconds`;
}
