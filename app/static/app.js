// Thetha front-end. No inline scripts (CSP), and all bot text is rendered with
// textContent, never innerHTML, so it can't inject markup (XSS).
(function () {
  "use strict";

  // ---------- Quick exit: button or Esc twice ----------
  function quickExit() {
    try { navigator.sendBeacon("/quick-exit"); } catch (e) { /* ignore */ }
    var log = document.getElementById("log");
    if (log) log.textContent = "";
    // replace() keeps this page out of the back-button history
    window.location.replace("https://www.google.com/search?q=weather+today");
  }
  var lastEsc = 0;
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    var now = Date.now();
    if (now - lastEsc < 800) quickExit();
    lastEsc = now;
  });
  document.addEventListener("DOMContentLoaded", function () {
    var qe = document.getElementById("quick-exit");
    if (qe) qe.addEventListener("click", quickExit);

    document.querySelectorAll("form.confirm-delete").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        if (!window.confirm("Delete permanently? This cannot be undone.")) e.preventDefault();
      });
    });

    initChat();
  });

  // ---------- Chat ----------
  function initChat() {
    var form = document.getElementById("chat-form");
    if (!form) return;
    var log = document.getElementById("log");
    var input = document.getElementById("message");
    var province = document.getElementById("province");
    var csrf = document.querySelector('meta[name="csrf-token"]').content;

    function el(tag, cls, text) {
      var n = document.createElement(tag);
      if (cls) n.className = cls;
      if (text !== undefined) n.textContent = text;
      return n;
    }
    function scroll() { log.scrollTop = log.scrollHeight; }
    function clearChips() { log.querySelectorAll(".chips").forEach(function (c) { c.remove(); }); }

    function chips(list) {
      if (!list || !list.length) return;
      var box = el("div", "chips");
      list.forEach(function (label) {
        var b = el("button", "chip", label);
        b.type = "button";
        box.appendChild(b);
      });
      log.appendChild(box);
    }

    function renderReply(r) {
      var m = el("div", "msg bot" + (r.risk_level ? " risk-" + r.risk_level : ""), r.text);
      if (r.resources && r.resources.length) {
        var ul = el("ul", "res");
        r.resources.forEach(function (h) {
          var li = el("li");
          li.appendChild(el("strong", null, h.name + ": "));
          var digits = h.number.replace(/[^\d*#+]/g, "");
          var a = el("a", null, h.number);
          a.href = "tel:" + encodeURIComponent(digits);
          li.appendChild(a);
          if (h.note) li.appendChild(el("span", "muted", " · " + h.note));
          ul.appendChild(li);
        });
        m.appendChild(ul);
      }
      if (r.link && typeof r.link.href === "string" && r.link.href.charAt(0) === "/") {
        var a = el("a", "button", r.link.label);
        a.href = r.link.href;
        m.appendChild(a);
      }
      log.appendChild(m);
      chips(r.quick_replies);
      scroll();
    }

    function send(text) {
      text = text.trim();
      if (!text) return;
      clearChips();
      log.appendChild(el("div", "msg user", text));
      scroll();
      input.value = "";
      var typing = el("div", "msg bot typing", "…");
      log.appendChild(typing);
      fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ message: text, province: province.value || null }),
        credentials: "same-origin"
      }).then(function (res) {
        return res.json().then(function (body) { return { ok: res.ok, body: body }; });
      }).then(function (r) {
        typing.remove();
        if (!r.ok) {
          renderReply({ text: r.body.error || "Something went wrong. If you are in danger, call 10111.", quick_replies: [] });
        } else {
          renderReply(r.body);
        }
      }).catch(function () {
        typing.remove();
        renderReply({ text: "I can't connect right now. If you are in danger call 10111 or 112, or dial *120*7867#.", quick_replies: [] });
      });
    }

    form.addEventListener("submit", function (e) { e.preventDefault(); send(input.value); });
    log.addEventListener("click", function (e) {
      if (e.target.classList.contains("chip")) send(e.target.textContent);
    });
    input.focus();
  }
})();
