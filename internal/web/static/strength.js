// Live password-strength indicator + confirmation-match check for the
// password-reset / first-password-setup page. The scoring here must mirror
// internal/auth.Strength() (and passwordBits) exactly -- same brute-force
// formula, same repetition/sequence pattern penalties, same score
// thresholds -- so the bar never promises a password will be accepted when
// the server would actually reject it. If you change one, change the other.
(function () {
  "use strict";

  var LABELS = ["very weak", "weak", "fair", "good", "strong"];
  // Colors come from the shared CSS custom properties (see style.css)
  // rather than a second hardcoded copy here, so the palette only has one
  // place to change.
  var COLOR_VARS = ["--meter-weak", "--meter-fair", "--meter-fair", "--meter-good", "--meter-strong"];
  function strengthColor(score) {
    return getComputedStyle(document.documentElement).getPropertyValue(COLOR_VARS[score]).trim();
  }
  var SEQUENCE_GUESS_BITS = 6.0;
  var MIN_SEQUENCE_RUN = 4;

  function log2(x) {
    return Math.log(x) / Math.log(2);
  }

  function charPool(chars) {
    var hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
    for (var i = 0; i < chars.length; i++) {
      var c = chars[i];
      if (c >= "a" && c <= "z") hasLower = true;
      else if (c >= "A" && c <= "Z") hasUpper = true;
      else if (c >= "0" && c <= "9") hasDigit = true;
      else hasSymbol = true;
    }
    var pool = 0;
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigit) pool += 10;
    if (hasSymbol) pool += 33;
    return pool;
  }

  // Shortest unit whose repetition exactly tiles chars, e.g. ["a","b","a","b"] -> {unit: ["a","b"], count: 2}.
  function detectRepeat(chars) {
    var n = chars.length;
    for (var p = 1; p <= Math.floor(n / 2); p++) {
      if (n % p !== 0) continue;
      var tiles = true;
      for (var i = p; i < n; i++) {
        if (chars[i] !== chars[i - p]) { tiles = false; break; }
      }
      if (tiles) return { unit: chars.slice(0, p), count: n / p };
    }
    return { unit: null, count: 0 };
  }

  function normalize(c) {
    return c >= "A" && c <= "Z" ? c.toLowerCase() : c;
  }

  // Longest run of consecutive ascending/descending character codes, e.g. 4 for "1234" or "abcd".
  function longestSequenceRun(chars) {
    if (chars.length === 0) return 0;
    var best = 1, cur = 1, dir = 0;
    for (var i = 1; i < chars.length; i++) {
      var d = normalize(chars[i]).charCodeAt(0) - normalize(chars[i - 1]).charCodeAt(0);
      if (d === 1 || d === -1) {
        cur = (cur > 1 && d !== dir) ? 2 : cur + 1;
        dir = d;
      } else {
        cur = 1;
        dir = 0;
      }
      if (cur > best) best = cur;
    }
    return best;
  }

  // Mirrors internal/auth.passwordBits exactly: brute force, repetition, and
  // sequence-run attack estimates, taking the cheapest (minimum) of the three.
  function passwordBits(password) {
    if (!password) return 0;
    var chars = password.split("");
    var pool = charPool(chars);
    if (pool === 0) return 0;

    var bits = chars.length * log2(pool);

    var repeat = detectRepeat(chars);
    if (repeat.count >= 2) {
      var unitPool = charPool(repeat.unit);
      if (unitPool > 0) {
        var repeatBits = repeat.unit.length * log2(unitPool) + log2(repeat.count);
        bits = Math.min(bits, repeatBits);
      }
    }

    var run = longestSequenceRun(chars);
    if (run >= MIN_SEQUENCE_RUN) {
      var seqBits = (chars.length - run) * log2(pool) + SEQUENCE_GUESS_BITS;
      bits = Math.min(bits, seqBits);
    }

    return bits;
  }

  function strength(password) {
    var bits = passwordBits(password);
    if (bits < 28) return 0;
    if (bits < 36) return 1;
    if (bits < 60) return 2;
    if (bits < 80) return 3;
    return 4;
  }

  document.addEventListener("DOMContentLoaded", function () {
    var passwordInput = document.getElementById("password");
    var confirmInput = document.getElementById("password_confirm");
    var bar = document.getElementById("strength-bar");
    var label = document.getElementById("strength-label");
    var mismatch = document.getElementById("confirm-mismatch");
    var script = document.querySelector('script[src$="/strength.js"]');
    var minStrength = script ? parseInt(script.getAttribute("data-min-strength"), 10) || 0 : 0;
    if (!passwordInput || !bar || !label) return;

    function updateBar() {
      var score = strength(passwordInput.value);
      var pct = passwordInput.value ? (score + 1) * 20 : 0;
      bar.style.width = pct + "%";
      bar.style.background = strengthColor(score);
      if (!passwordInput.value) {
        label.textContent = " ";
      } else {
        label.textContent = LABELS[score] + (score < minStrength ? " (below required minimum)" : "");
      }
    }

    function updateMismatch() {
      if (!confirmInput || !mismatch) return;
      var mismatched = confirmInput.value.length > 0 && confirmInput.value !== passwordInput.value;
      mismatch.hidden = !mismatched;
    }

    passwordInput.addEventListener("input", function () {
      updateBar();
      updateMismatch();
    });
    if (confirmInput) {
      confirmInput.addEventListener("input", updateMismatch);
    }
    updateBar();
  });
})();
