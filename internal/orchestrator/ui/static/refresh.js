// FANGS dashboard auto-refresh.
//
// Vanilla JS, no framework. Any element with a `data-refresh-url`
// attribute gets re-fetched + innerHTML-swapped on an interval. The
// element's initial server-side content is identical to what the
// fragment endpoint returns, so the first paint is correct and
// subsequent intervals just keep it fresh.
//
// Use:
//   <section data-refresh-url="/ui/_fragments/overview-stats"
//            data-refresh-interval="5000">
//     ...initial render (also what /ui/_fragments/overview-stats returns)...
//   </section>
//
// Interval defaults to 5000ms.

(function () {
  function refresh(el) {
    var url = el.dataset.refreshUrl;
    // Optional CSS selector — when set, fetch the URL, parse it, and
    // extract the matching element's innerHTML. Lets us point at the
    // same page the user is already viewing and just swap a slice of
    // it, without server-side fragment routes.
    var extract = el.dataset.refreshExtract;
    fetch(url, {credentials: "same-origin"})
      .then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then(function (html) {
        if (extract) {
          var src = new DOMParser()
            .parseFromString(html, "text/html")
            .querySelector(extract);
          if (src) el.innerHTML = src.innerHTML;
        } else {
          el.innerHTML = html;
        }
      })
      .catch(function (err) {
        // Network blip — leave existing content alone. Console only.
        if (window.console && console.warn) {
          console.warn("refresh failed for", url, err);
        }
      });
  }

  function start() {
    var nodes = document.querySelectorAll("[data-refresh-url]");
    nodes.forEach(function (el) {
      var interval = parseInt(el.dataset.refreshInterval || "5000", 10);
      if (!isFinite(interval) || interval < 1000) interval = 5000;
      setInterval(function () { refresh(el); }, interval);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();

// ---------------------------------------------------------------------
// Dynamic in-place navigation for filter pills.
//
// Mark a container with `data-dynamic-nav="<css-selector>"` (typically
// the same selector pointing at itself) to enable SPA-style updates
// for descendant chips. Click on any link with class "chip" inside →
// fetch the URL, extract <css-selector> from the response, swap
// innerHTML in place, pushState the URL so back/forward + reload work.
//
// Falls back to full navigation when the extract target is missing
// (defensive — if the link points elsewhere, behave like a normal
// browser).
(function () {
  // snapshotOpenDetails records which <details> are currently open,
  // keyed by the data-pid attribute on the nearest ancestor with one
  // (the proc-row wrapper). Lets us restore manually-expanded process
  // rows after a filter-induced innerHTML swap.
  function snapshotOpenDetails(container) {
    var openPIDs = new Set();
    container.querySelectorAll("[data-pid] details[open]").forEach(function (d) {
      var row = d.closest("[data-pid]");
      if (row) openPIDs.add(row.dataset.pid);
    });
    return openPIDs;
  }

  function restoreOpenDetails(container, openPIDs) {
    if (!openPIDs || !openPIDs.size) return;
    container.querySelectorAll("[data-pid]").forEach(function (row) {
      if (openPIDs.has(row.dataset.pid)) {
        var d = row.querySelector("details");
        if (d) d.open = true;
      }
    });
  }

  function inPlace(container, url) {
    var selector = container.dataset.dynamicNav;
    if (!selector) return false;
    var openPIDs = snapshotOpenDetails(container);
    return fetch(url, {credentials: "same-origin"})
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
      .then(function (html) {
        var src = new DOMParser()
          .parseFromString(html, "text/html")
          .querySelector(selector);
        if (!src) {
          // Selector missing from response — fall back to full nav.
          window.location.href = url;
          return;
        }
        container.innerHTML = src.innerHTML;
        restoreOpenDetails(container, openPIDs);
        if (window.location.href !== url) {
          history.pushState({dynamicNav: selector}, "", url);
        }
      })
      .catch(function (err) {
        if (window.console && console.warn) console.warn("dynamic nav failed", err);
        window.location.href = url;
      });
  }

  document.addEventListener("click", function (e) {
    if (e.ctrlKey || e.metaKey || e.shiftKey || e.button !== 0) return;
    var link = e.target.closest("a.chip");
    if (!link) return;
    var container = link.closest("[data-dynamic-nav]");
    if (!container) return;
    var url = link.href;
    // Only intercept same-origin links.
    if (new URL(url, window.location.href).origin !== window.location.origin) return;
    e.preventDefault();
    inPlace(container, url);
  });

  // Back/forward — re-fetch + re-swap so URL ↔ content stays in sync.
  window.addEventListener("popstate", function () {
    document.querySelectorAll("[data-dynamic-nav]").forEach(function (container) {
      inPlace(container, window.location.href);
    });
  });
})();
