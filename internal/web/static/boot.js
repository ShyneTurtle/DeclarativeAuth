// Logs the build version and page load time to the console once the page
// has finished loading. Reads the version from <body data-version>, which
// both layout templates set from the server's embedded build version.
(function () {
  // Date.now() fallback in case the Performance API is entirely
  // unavailable (very old browsers) -- captured at script-parse time,
  // which is close enough to navigation start for a rough fallback
  // number; the primary path below doesn't use this at all.
  var fallbackStart = Date.now();

  function report() {
    var version = document.body.getAttribute("data-version") || "dev";
    var loadMs;
    if (window.performance && typeof performance.now === "function") {
      // performance.now() is time elapsed since the navigation's time
      // origin -- i.e. it already covers DNS/connect/TLS/request/response
      // and DOM processing, the same start point Navigation Timing's own
      // entries use. Reading it here, at "load", is deliberately preferred
      // over reading a PerformanceNavigationTiming entry's own
      // loadEventEnd: that field isn't guaranteed to be finalized yet
      // while one of the "load" event's own listeners (this one) is still
      // running, per the Navigation Timing spec -- which reliably under-
      // reported the total, network time included, if read that way.
      loadMs = Math.round(performance.now());
    } else {
      loadMs = Date.now() - fallbackStart;
    }
    console.info("DeclarativeAuth " + version + " - page loaded in " + loadMs + "ms");
  }

  if (document.readyState === "complete") {
    report();
  } else {
    window.addEventListener("load", report);
  }
})();
