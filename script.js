const passwordInput = document.getElementById('passwordInput');
const strengthBar = document.getElementById('strengthBar');
const feedback = document.getElementById('feedback');
const entropyVal = document.getElementById('entropyVal');
const patternWarning = document.getElementById('patternWarning');
const toggleVis = document.getElementById('toggleVis');

// Toggle Password Visibility
toggleVis.onclick = () => {
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
};

passwordInput.addEventListener('input', () => {
    const val = passwordInput.value;
    if (!val) {
        resetUI();
        return;
    }

    const entropy = calculateEntropy(val);
    const patternFound = checkPatterns(val);
    
    updateUI(entropy, patternFound);
});

function calculateEntropy(pwd) {
    let poolSize = 0;
    if (/[a-z]/.test(pwd)) poolSize += 26;
    if (/[A-Z]/.test(pwd)) poolSize += 26;
    if (/[0-9]/.test(pwd)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) poolSize += 32;

    // Entropy formula: L * log2(PoolSize)
    return poolSize > 0 ? Math.floor(pwd.length * Math.log2(poolSize)) : 0;
}

function checkPatterns(pwd) {
    const common = [/123/, /qwerty/i, /asdf/i, /password/i, /(.)\1{2,}/];
    return common.some(pattern => pattern.test(pwd));
}

function updateUI(entropy, hasPattern) {
    entropyVal.innerText = entropy;
    patternWarning.innerText = hasPattern ? "⚠️ Common pattern detected!" : "";

    let score = entropy;
    if (hasPattern) score -= 20; // Penalty for common patterns

    if (score < 30) {
        setBar(25, '#ff8a80', 'Weak ☁️');
    } else if (score < 60) {
        setBar(50, '#ffd54f', 'Better 🌤️');
    } else if (score < 80) {
        setBar(75, '#ce93d8', 'Strong! 🌸');
    } else {
        setBar(100, '#81c784', 'Unstoppable! ✨');
    }
}

function setBar(width, color, text) {
    strengthBar.style.width = width + '%';
    strengthBar.style.background = color;
    feedback.innerText = text;
    feedback.style.color = color;
}

function resetUI() {
    strengthBar.style.width = '0%';
    feedback.innerText = 'Waiting for input...';
    feedback.style.color = '#888';
    entropyVal.innerText = '0';
    patternWarning.innerText = '';
}
