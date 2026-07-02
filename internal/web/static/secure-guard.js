// Refuses to submit any form containing a password field when the page
// wasn't loaded in a secure context, and shows why. window.isSecureContext
// is the browser's own definition of "safe to send secrets": true for
// https:, and also true for http://localhost (so local dev without TLS
// still works) -- so this doesn't need to parse the URL itself.
//
// This is a last-resort client-side guard, not a substitute for actually
// running TLS (see the server-side warnings logged at startup, and the
// README's TLS section) -- a determined attacker who already controls the
// network can also tamper with this script. It exists to stop the common,
// non-adversarial case: someone lands on a plain-HTTP URL (stale bookmark,
// misconfigured proxy, typo'd link) and would otherwise type their
// password in without noticing.
(function () {
  "use strict";
  if (window.isSecureContext) return;

  function showBanner() {
    // main.card (login/reset pages) if present, otherwise fall back to
    // inserting right after the page's own <h1> (admin pages, which don't
    // wrap content in a "card" element).
    var container = document.querySelector("main.card") || document.body;
    if (!container || container.querySelector(".insecure-banner")) return;
    var p = document.createElement("p");
    p.className = "error insecure-banner";
    p.textContent = "This page was loaded over an insecure connection (plain HTTP). Passwords will not be submitted until this is fixed.";
    var h1 = container.querySelector("h1");
    if (h1 && h1.parentNode === container) {
      h1.insertAdjacentElement("afterend", p);
    } else {
      container.insertBefore(p, container.firstChild);
    }
  }

  document.addEventListener("DOMContentLoaded", showBanner);

  document.addEventListener(
    "submit",
    function (e) {
      var form = e.target;
      if (form.querySelector && form.querySelector('input[type="password"]')) {
        e.preventDefault();
        showBanner();
      }
    },
    true
  );
})();
