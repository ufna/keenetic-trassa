// The trassa page: rule editing, "why", daemon status and version history.
// Data is inserted only via textContent: names from DNS and the rules text never become markup.
"use strict";

(function () {
  var $ = function (id) { return document.getElementById(id); };
  var rulesEl = $("rules");
  var saved = "";           // rules text in effect
  var marks = {};           // line number → "err" or "wrn"
  var confirmAction = null; // what to run on the "Apply with warnings" button
  var enabled = null;       // trassa is turned on, from the last state; null until it arrives
  var startingUntil = 0;    // after turning on, "not running" means "starting" until this time
  var pollTimer = null;
  var HISTORY_ROWS = 6;     // versions shown without scrolling
  var OBS_ROWS = 8;         // DNS answers shown without scrolling
  var signedIn = false;

  var KIND = {
    page: "Edited on this page",
    rollback: "Restored an earlier version",
    outside: "Changed outside this page"
  };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function pad2(n) { return String(n).padStart(2, "0"); }
  function clock(d) { return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds()); }
  function day(d) { return pad2(d.getDate()) + "." + pad2(d.getMonth() + 1) + " " + pad2(d.getHours()) + ":" + pad2(d.getMinutes()); }

  // api sends a request to trassa and returns the parsed response. A 401 response means there is no session.
  async function api(method, path, body) {
    var opt = { method: method, headers: { "X-Trassa": "1" }, credentials: "same-origin" };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    var r;
    try {
      r = await fetch(path, opt);
    } catch (e) {
      throw new Error("the router is not responding: " + e.message);
    }
    var data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (r.status === 401 && path !== "/api/login") showLogin();
    if (!r.ok) {
      var err = new Error((data && data.error) || ("error " + r.status));
      err.status = r.status;
      throw err;
    }
    return data;
  }

  /* ---- Editor ---- */
  function drawGutter() {
    var n = rulesEl.value.split("\n").length;
    var frag = document.createDocumentFragment();
    for (var i = 1; i <= n; i++) frag.appendChild(el("div", marks[i] || "", String(i)));
    $("gutter").replaceChildren(frag);
    $("gutter").scrollTop = rulesEl.scrollTop;
  }

  function setStatus(text, kind) {
    var s = $("status");
    s.textContent = text;
    s.className = "status-line" + (kind ? " " + kind : "");
  }

  function dirty() { return rulesEl.value !== saved; }

  function clearProblems() {
    marks = {};
    $("problems").replaceChildren();
    $("confirm").hidden = true;
    drawGutter();
  }

  function showProblems(ps) {
    marks = {};
    var ul = $("problems");
    ul.replaceChildren();
    ps.forEach(function (p) {
      var kind = p.severity === "error" ? "err" : "wrn";
      if (p.line) marks[p.line] = marks[p.line] === "err" ? "err" : kind;
      var li = el("li", kind);
      li.appendChild(el("span", "where", p.line ? "line " + p.line : "file"));
      li.appendChild(el("span", "", (kind === "err" ? "error: " : "warning: ") + p.msg));
      ul.appendChild(li);
    });
    drawGutter();
  }

  function counts(r) { return "rules: " + r.rules + ", exits: " + r.exits + ", expectations: " + r.tests; }
  function errorsIn(ps) { return ps.filter(function (p) { return p.severity === "error"; }).length; }

  async function check() {
    try {
      var r = await api("POST", "/api/check", { text: rulesEl.value });
      showProblems(r.problems);
      var errs = errorsIn(r.problems), warns = r.problems.length - errs;
      if (errs) setStatus("Errors: " + errs + " — these rules cannot be applied", "bad");
      else if (warns) setStatus("No errors, warnings: " + warns + "; " + counts(r), "warn");
      else setStatus("No errors; " + counts(r), "ok");
    } catch (e) { if (e.status !== 401) setStatus(e.message, "bad"); }
  }

  // showResult shows the outcome of a save or a version restore; again repeats the action with confirmation.
  function showResult(r, again) {
    showProblems(r.problems);
    $("confirm").hidden = true;
    var errs = errorsIn(r.problems);
    if (errs) { setStatus("Errors: " + errs + " — rules not saved; the previous ones remain in effect", "bad"); return; }
    if (r.needConfirm) {
      $("confirm-text").textContent = "Warnings: " + r.problems.length +
        ". The rules work, but most likely do not do what was intended. Apply anyway?";
      confirmAction = again;
      $("confirm").hidden = false;
      setStatus("Confirmation needed", "warn");
      return;
    }
    if (r.unchanged) { setStatus("No changes: this text is already saved on the router", ""); return; }
    if (!r.saved) { setStatus("The daemon rejected the rules; the previous ones remain in effect: " + r.message, "bad"); return; }
    var msg = {
      "running": ["Saved and applied; " + counts(r), "ok"],
      "partly": ["Saved, but address sets and routes are not built yet — the daemon will retry. " + r.message, "warn"],
      "not-running": ["Saved. The daemon is not running — the rules will take effect when it starts", "warn"],
      "unknown": ["Saved, but the daemon did not reply in time — check the status at the top of the page", "warn"]
    }[r.applied] || [r.message, ""];
    setStatus(msg[0], msg[1]);
  }

  async function save(confirm) {
    var text = rulesEl.value;
    $("save").disabled = true;
    setStatus("Saving…", "");
    try {
      var r = await api("POST", "/api/save", { text: text, confirm: confirm });
      if (r.saved || r.unchanged) saved = text;
      showResult(r, function () { save(true); });
      loadHistory();
      loadState();
    } catch (e) {
      if (e.status !== 401) setStatus(e.message, "bad");
    } finally {
      $("save").disabled = false;
    }
  }

  // loadRules fetches the rules in effect from the router. force replaces even an unsaved edit: after
  // a version restore, when the person has already agreed to lose it.
  async function loadRules(force) {
    var r = await api("GET", "/api/rules");
    var a = force ? { editor: r.text, saved: r.text, note: "" } : TrassaLogic.adopt(rulesEl.value, saved, r.text);
    saved = a.saved;
    rulesEl.value = a.editor;
    clearProblems();
    if (a.note) setStatus(a.note, "warn");
  }

  /* ---- History ---- */
  async function loadHistory() {
    var list;
    try { list = await api("GET", "/api/history"); } catch (e) { return; }
    var ol = $("history");
    ol.replaceChildren();
    if (!list.length) {
      ol.appendChild(el("li", "note", "No versions yet: the first one appears on the first save."));
      return;
    }
    list.forEach(function (v) {
      var li = el("li", v.current ? "current" : "");
      li.appendChild(el("span", "when", day(new Date(v.time))));
      var what = el("span", "what", KIND[v.kind] || v.kind);
      what.appendChild(el("small", "", "rules: " + v.rules + ", expectations: " + v.tests));
      li.appendChild(what);
      var acts = el("span", "acts");
      var open = el("button", "linkbtn", "Open");
      open.type = "button";
      open.addEventListener("click", function () { openVersion(v); });
      acts.appendChild(open);
      if (v.current) {
        acts.appendChild(el("span", "tag", "in effect"));
      } else {
        var back = el("button", "linkbtn", "Restore");
        back.type = "button";
        back.addEventListener("click", function () {
          if (!back.dataset.armed) {
            back.dataset.armed = "1";
            back.textContent = "Restore? Click again";
            // The confirmation lasts a few seconds: a stray click later restores nothing.
            setTimeout(function () { delete back.dataset.armed; back.textContent = "Restore"; }, 5000);
            return;
          }
          rollback(v, false);
        });
        acts.appendChild(back);
      }
      li.appendChild(acts);
      ol.appendChild(li);
    });
    fitRows(ol, ol.children, HISTORY_ROWS);
  }

  // putVersion puts a version's text into the editor; that does not put it into effect.
  async function putVersion(v) {
    var r = await api("GET", "/api/version?id=" + encodeURIComponent(v.id));
    rulesEl.value = r.text;
    clearProblems();
  }

  async function openVersion(v) {
    if (dirty() && !window.confirm("The editor has an unsaved edit. Replace it with the text of this version?")) return;
    try {
      await putVersion(v);
      setStatus("The editor shows the version from " + day(new Date(v.time)) + ". It is not in effect yet: save to apply it", "warn");
    } catch (e) { if (e.status !== 401) setStatus(e.message, "bad"); }
  }

  async function rollback(v, confirm) {
    if (!confirm && dirty() && !window.confirm("The editor has an unsaved edit — restoring a version will discard it. Continue?")) {
      loadHistory();
      return;
    }
    setStatus("Restoring the version from " + day(new Date(v.time)) + "…", "");
    try {
      var r = await api("POST", "/api/rollback", { id: v.id, confirm: confirm });
      // Line marks refer to the version's text, so that text belongs in the editor.
      if (r.saved) await loadRules(true);
      else if (!r.unchanged) await putVersion(v);
      showResult(r, function () { rollback(v, true); });
      loadHistory();
      loadState();
    } catch (e) { if (e.status !== 401) setStatus(e.message, "bad"); }
  }

  /* ---- Why ---- */
  async function why(ev) {
    ev.preventDefault();
    var q = $("why-q").value.trim();
    var box = $("why-answer");
    if (!q) return;
    box.replaceChildren(el("span", "note", "Asking…"));
    try {
      var r = await api("POST", "/api/why", { subject: q });
      var lines = r.text.replace(/\n$/, "").split("\n");
      var head = lines.shift();
      var v = el("div", "verdict");
      var arrow = head.lastIndexOf(" → ");
      if (arrow > 0) {
        var act = head.slice(arrow + 3);
        v.appendChild(el("span", "", head.slice(0, arrow)));
        v.appendChild(el("span", "", "→"));
        v.appendChild(el("span", "badge " + (act === "direct" ? "direct" : "tunnel"), act));
      } else {
        v.textContent = head;
      }
      box.replaceChildren(v);
      if (lines.length) box.appendChild(el("pre", "rule-text", lines.join("\n")));
      if (r.source === "file") box.appendChild(el("p", "note", "The daemon is not answering: this answer comes from the rules file alone, without DNS data."));
    } catch (e) {
      if (e.status !== 401) box.replaceChildren(el("span", "note bad", e.message));
    }
  }

  /* ---- Status ---- */
  function chip(text, dot) {
    var c = el("span", "chip");
    if (dot) c.appendChild(el("span", "dot " + dot));
    c.appendChild(document.createTextNode(text));
    return c;
  }

  function duration(ms) {
    var m = Math.max(0, Math.floor(ms / 60000)), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d) return d + "d " + (h % 24) + "h";
    if (h) return h + "h " + (m % 60) + "m";
    return m + "m";
  }

  function renderState(s) {
    var d = s.daemon, chips = $("chips"), banner = $("banner");
    chips.replaceChildren();
    if (s.enabled !== enabled) {
      enabled = s.enabled;
      renderPower();
    }
    if (!s.enabled) {
      banner.textContent = "trassa is turned off: the daemon is stopped and the router routes all traffic as without trassa. " +
        "You can still edit and save rules: they take effect when trassa is turned on." +
        (d ? " The daemon is still stopping." : "");
      banner.hidden = false;
      renderCounters(null);
      renderTunnels(s.tunnels, null);
      renderObs(null);
      return;
    }
    if (d) startingUntil = 0;
    if (!d && s.daemonState === "not-running" && Date.now() < startingUntil) {
      chips.appendChild(chip("starting", "off"));
      banner.textContent = "trassa is turned on: the daemon is starting, this takes a few seconds.";
      banner.hidden = false;
    } else if (!d) {
      var kind = {
        "not-running": ["daemon not running", "The trassa daemon is not running. You can still edit and save rules: " +
          "they will take effect when it starts. No counters or DNS answers until then."],
        "no-reply": ["daemon busy", "The trassa daemon did not reply in time — it may be rebuilding its address sets. " +
          "The page will refresh in a few seconds."]
      }[s.daemonState] || ["daemon error", "The trassa daemon answered with an error."];
      chips.appendChild(chip(kind[0], "bad"));
      banner.textContent = kind[1] + " (" + s.daemonError + ")";
      banner.hidden = false;
    } else {
      banner.hidden = true;
      chips.appendChild(chip(d.mode === "route" ? "routing mode" : "observe mode", "ok"));
      if (d.mode === "route") {
        d.exits.forEach(function (x) {
          if (!x.known) chips.appendChild(chip(x.name + ": not known yet", "off"));
          else if (x.via) chips.appendChild(chip(x.name + " → " + x.via, "ok"));
          else chips.appendChild(chip(x.name + ": no live tunnels", "bad"));
        });
      }
      chips.appendChild(chip("up " + duration(new Date(s.now) - new Date(d.started))));
    }
    renderCounters(d);
    renderTunnels(s.tunnels, d);
    renderObs(d);
  }

  function renderCounters(d) {
    var c = $("counters");
    c.replaceChildren();
    if (!d) return;
    var st = d.stats;
    [
      ["DNS answers with addresses", st.answers], ["matched rules", st.claimed], ["addresses in sets", d.addrs],
      ["set changes", st.changes], ["apply errors", st.applyErrors, true], ["malformed packets", st.malformed, true]
    ].forEach(function (p) {
      var s = el("span", p[2] ? (p[1] ? "bad" : "zero") : "");
      s.appendChild(document.createTextNode(p[0] + " "));
      s.appendChild(el("b", "", String(p[1])));
      c.appendChild(s);
    });
  }

  function renderTunnels(list, d) {
    var box = $("tunnels");
    box.replaceChildren();
    if (!list.length) { box.appendChild(el("p", "note", "No exits — or the rules file has errors.")); return; }
    var via = {};
    if (d) d.exits.forEach(function (x) { via[x.name] = x.via; });
    var groups = {};
    list.forEach(function (t) {
      if (!groups[t.exit]) {
        var g = el("div", "exit");
        var head = el("div", "exit-head");
        head.appendChild(el("span", "badge tunnel", t.exit));
        if (d && d.mode === "route") head.appendChild(document.createTextNode(via[t.exit] ? "via " + via[t.exit] : "no live tunnels"));
        g.appendChild(head);
        groups[t.exit] = el("ul", "ifaces");
        g.appendChild(groups[t.exit]);
        box.appendChild(g);
      }
      var li = el("li", via[t.exit] === t.name ? "active" : "");
      li.appendChild(el("span", "dot " + (t.error ? "bad" : t.up ? "ok" : "off")));
      // The name as written in the rules, then whatever else identifies it: the description
      // and the firmware name (tunnel-a · Wireguard2 or Wireguard2 · tunnel-a).
      var label = [t.name];
      [t.description, t.id].forEach(function (x) { if (x && label.indexOf(x) < 0) label.push(x); });
      li.appendChild(el("span", "name", label.join(" · ")));
      li.appendChild(el("span", "meta", t.error || (t.up ? "connected" : "not connected")));
      groups[t.exit].appendChild(li);
    });
  }

  function renderObs(d) {
    var rows = d ? d.recent : [];
    var tb = $("obs");
    tb.replaceChildren();
    $("obs-empty").hidden = rows.length > 0;
    rows.forEach(function (o) {
      var tr = el("tr");
      tr.appendChild(el("td", "t", clock(new Date(o.at))));
      // The device address goes under the name: a long IPv6 address in its own column would squeeze the name.
      var name = el("td", "name", o.name);
      name.appendChild(el("span", "dev", o.client));
      tr.appendChild(name);
      var td = el("td", "path");
      td.appendChild(el("span", "badge " + (o.action === "direct" ? "direct" : "tunnel"), o.action));
      td.appendChild(el("span", "dev", o.line ? "line " + o.line : "default"));
      tr.appendChild(td);
      tb.appendChild(tr);
    });
    fitRows($("obs-wrap"), tb.children, OBS_ROWS);
  }

  // fitRows lets box show at most n rows and scroll the rest. Row heights differ and change with
  // the screen width, so the height is taken from the n-th row itself.
  function fitRows(box, rows, n) {
    if (rows.length <= n) {
      box.style.maxHeight = "";
      return;
    }
    var bottom = rows[n - 1].getBoundingClientRect().bottom;
    box.style.maxHeight = Math.ceil(bottom - box.getBoundingClientRect().top + box.scrollTop) + "px";
  }

  function fitLists() {
    fitRows($("history"), $("history").children, HISTORY_ROWS);
    fitRows($("obs-wrap"), $("obs").children, OBS_ROWS);
  }

  /* ---- Turning trassa on and off ---- */
  // showSwitch puts the switch in position on: true, false, or null while the state is unknown.
  function showSwitch(on) {
    var b = $("power");
    b.setAttribute("aria-checked", on ? "true" : "false");
    b.setAttribute("aria-label", on ? "trassa is turned on" : "trassa is turned off");
    $("power-text").textContent = on === null ? "" : on ? "On" : "Off";
    b.disabled = on === null;
  }

  function renderPower() { showSwitch(enabled); }

  // power flips the switch at once and then asks the router; if the router refuses, it flips back.
  async function power() {
    var b = $("power"), want = !enabled;
    showSwitch(want);
    b.disabled = true;
    try {
      var r = await api("POST", "/api/power", { on: want });
      enabled = r.enabled;
      startingUntil = enabled ? Date.now() + 30000 : 0;
      await loadState();
    } catch (e) {
      $("banner").textContent = "trassa not turned " + (want ? "on" : "off") + ": " + e.message;
      $("banner").hidden = false;
    } finally {
      renderPower();
    }
  }

  async function loadState() {
    try {
      renderState(await api("GET", "/api/state"));
    } catch (e) {
      if (e.status === undefined) { $("banner").textContent = e.message; $("banner").hidden = false; }
    }
  }

  /* ---- Sign-in ---- */
  function showLogin() {
    signedIn = false;
    clearInterval(pollTimer);
    $("login").hidden = false;
    $("login-pass").focus();
  }

  async function login(ev) {
    ev.preventDefault();
    var user = $("login-user").value.trim(), pass = $("login-pass").value, st = $("login-status");
    st.textContent = "Checking…";
    st.className = "status-line";
    $("login-go").disabled = true;
    try {
      var ch = await api("GET", "/api/login");
      var resp = TrassaHash.response(user, pass, ch.realm, ch.challenge);
      await api("POST", "/api/login", { id: ch.id, login: user, response: resp });
      $("login-pass").value = "";
      $("login").hidden = true;
      st.textContent = "";
      start();
    } catch (e) {
      st.textContent = e.message;
      st.className = "status-line bad";
    } finally {
      $("login-go").disabled = false;
    }
  }

  async function logout() {
    try { await api("POST", "/api/logout"); } catch (e) { /* the session is closed anyway */ }
    showLogin();
  }

  function wait(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function reveal() { document.body.classList.remove("loading"); }

  async function start() {
    try {
      await loadRules(false);
    } catch (e) {
      // Not signed in: the sign-in form covers the page, and the page appears after signing in.
      if (e.status !== 401) {
        setStatus(e.message, "bad");
        reveal();
      }
      return;
    }
    signedIn = true;
    // The page appears once, with everything in place: parts filling in one by one make it jump.
    // A slow router holds it back for three seconds at most.
    await Promise.race([Promise.all([loadHistory(), loadState()]), wait(3000)]);
    reveal();
    clearInterval(pollTimer);
    pollTimer = setInterval(function () { if (!document.hidden && signedIn) loadState(); }, 5000);
  }

  rulesEl.addEventListener("input", function () {
    clearProblems();
    setStatus(dirty() ? "Unsaved changes" : "", "");
  });
  rulesEl.addEventListener("scroll", function () { $("gutter").scrollTop = rulesEl.scrollTop; });
  $("check").addEventListener("click", check);
  $("save").addEventListener("click", function () { save(false); });
  $("power").addEventListener("click", power);
  $("revert").addEventListener("click", function () {
    rulesEl.value = saved;
    clearProblems();
    setStatus("Edit discarded", "");
  });
  $("confirm-yes").addEventListener("click", function () {
    $("confirm").hidden = true;
    if (confirmAction) confirmAction();
  });
  $("confirm-no").addEventListener("click", function () { $("confirm").hidden = true; rulesEl.focus(); });
  $("why-form").addEventListener("submit", why);
  $("login-form").addEventListener("submit", login);
  $("logout").addEventListener("click", logout);
  window.addEventListener("resize", fitLists);
  window.addEventListener("beforeunload", function (ev) {
    if (dirty()) { ev.preventDefault(); ev.returnValue = ""; }
  });
  drawGutter();
  start();
})();
