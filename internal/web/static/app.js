// Страница trassa: правка правил, «почему», состояние демона и история версий.
// Данные вставляются только через textContent: имена из DNS и текст правил не становятся разметкой.
"use strict";

(function () {
  var $ = function (id) { return document.getElementById(id); };
  var rulesEl = $("rules");
  var saved = "";           // действующий текст правил
  var marks = {};           // номер строки → "err" или "wrn"
  var confirmAction = null; // что выполнить по кнопке «Применить с предупреждениями»
  var pollTimer = null;
  var signedIn = false;

  var KIND = {
    page: "Правка со страницы",
    rollback: "Возврат прежней версии",
    outside: "Изменено не со страницы"
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

  // api отправляет запрос к trassa и возвращает разобранный ответ. Ответ 401 — сеанса нет.
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
      throw new Error("роутер не отвечает: " + e.message);
    }
    var data = null;
    try { data = await r.json(); } catch (e) { data = null; }
    if (r.status === 401 && path !== "/api/login") showLogin();
    if (!r.ok) {
      var err = new Error((data && data.error) || ("ошибка " + r.status));
      err.status = r.status;
      throw err;
    }
    return data;
  }

  /* ---- Редактор ---- */
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
      li.appendChild(el("span", "where", p.line ? "строка " + p.line : "файл"));
      li.appendChild(el("span", "", (kind === "err" ? "ошибка: " : "предупреждение: ") + p.msg));
      ul.appendChild(li);
    });
    drawGutter();
  }

  function counts(r) { return "правил " + r.rules + ", выходов " + r.exits + ", ожиданий " + r.tests; }
  function errorsIn(ps) { return ps.filter(function (p) { return p.severity === "error"; }).length; }

  async function check() {
    try {
      var r = await api("POST", "/api/check", { text: rulesEl.value });
      showProblems(r.problems);
      var errs = errorsIn(r.problems), warns = r.problems.length - errs;
      if (errs) setStatus("Ошибок: " + errs + " — такие правила не применить", "bad");
      else if (warns) setStatus("Ошибок нет, предупреждений: " + warns + "; " + counts(r), "warn");
      else setStatus("Ошибок нет: " + counts(r), "ok");
    } catch (e) { if (e.status !== 401) setStatus(e.message, "bad"); }
  }

  // showResult показывает исход сохранения или возврата версии; again повторяет действие с подтверждением.
  function showResult(r, again) {
    showProblems(r.problems);
    $("confirm").hidden = true;
    var errs = errorsIn(r.problems);
    if (errs) { setStatus("Ошибок: " + errs + " — правила не сохранены, действуют прежние", "bad"); return; }
    if (r.needConfirm) {
      $("confirm-text").textContent = "Предупреждений: " + r.problems.length +
        ". Правила рабочие, но, скорее всего, делают не то, что задумано. Применить всё равно?";
      confirmAction = again;
      $("confirm").hidden = false;
      setStatus("Нужно подтверждение", "warn");
      return;
    }
    if (r.unchanged) { setStatus("Изменений нет: этот текст уже действует", ""); return; }
    if (!r.saved) { setStatus("Демон не принял правила, действуют прежние: " + r.message, "bad"); return; }
    var msg = {
      "running": ["Сохранено и применено: " + counts(r), "ok"],
      "partly": ["Сохранено, но списки и маршруты ещё не построены — демон повторит попытку. " + r.message, "warn"],
      "not-running": ["Сохранено. Демон не запущен — правила вступят в силу при его запуске", "warn"],
      "unknown": ["Сохранено, но демон не ответил вовремя — проверьте состояние вверху страницы", "warn"]
    }[r.applied] || [r.message, ""];
    setStatus(msg[0], msg[1]);
  }

  async function save(confirm) {
    var text = rulesEl.value;
    $("save").disabled = true;
    setStatus("Сохраняю…", "");
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

  async function loadRules() {
    var r = await api("GET", "/api/rules");
    saved = r.text;
    rulesEl.value = r.text;
    clearProblems();
  }

  /* ---- История ---- */
  async function loadHistory() {
    var list;
    try { list = await api("GET", "/api/history"); } catch (e) { return; }
    var ol = $("history");
    ol.replaceChildren();
    if (!list.length) {
      ol.appendChild(el("li", "note", "Версий пока нет: первая появится при первом сохранении."));
      return;
    }
    list.forEach(function (v) {
      var li = el("li", v.current ? "current" : "");
      li.appendChild(el("span", "when", day(new Date(v.time))));
      var what = el("span", "what", KIND[v.kind] || v.kind);
      what.appendChild(el("small", "", "правил " + v.rules + ", ожиданий " + v.tests));
      li.appendChild(what);
      var acts = el("span", "acts");
      var open = el("button", "linkbtn", "Открыть");
      open.type = "button";
      open.addEventListener("click", function () { openVersion(v); });
      acts.appendChild(open);
      if (v.current) {
        acts.appendChild(el("span", "tag", "действует"));
      } else {
        var back = el("button", "linkbtn", "Вернуть");
        back.type = "button";
        back.addEventListener("click", function () {
          if (!back.dataset.armed) { back.dataset.armed = "1"; back.textContent = "Точно вернуть?"; return; }
          rollback(v, false);
        });
        acts.appendChild(back);
      }
      li.appendChild(acts);
      ol.appendChild(li);
    });
  }

  // putVersion кладёт текст версии в редактор; действующим он от этого не становится.
  async function putVersion(v) {
    var r = await api("GET", "/api/version?id=" + encodeURIComponent(v.id));
    rulesEl.value = r.text;
    clearProblems();
  }

  async function openVersion(v) {
    if (dirty() && !window.confirm("В редакторе несохранённая правка. Заменить её текстом версии?")) return;
    try {
      await putVersion(v);
      setStatus("В редакторе версия от " + day(new Date(v.time)) + ". Она ещё не действует: чтобы применить, сохраните", "warn");
    } catch (e) { if (e.status !== 401) setStatus(e.message, "bad"); }
  }

  async function rollback(v, confirm) {
    if (!confirm && dirty() && !window.confirm("В редакторе несохранённая правка — при возврате версии она пропадёт. Продолжить?")) {
      loadHistory();
      return;
    }
    setStatus("Возвращаю версию от " + day(new Date(v.time)) + "…", "");
    try {
      var r = await api("POST", "/api/rollback", { id: v.id, confirm: confirm });
      // Пометки строк относятся к тексту версии — он и должен быть в редакторе.
      if (r.saved) await loadRules();
      else if (!r.unchanged) await putVersion(v);
      showResult(r, function () { rollback(v, true); });
      loadHistory();
      loadState();
    } catch (e) { if (e.status !== 401) setStatus(e.message, "bad"); }
  }

  /* ---- Почему ---- */
  async function why(ev) {
    ev.preventDefault();
    var q = $("why-q").value.trim();
    var box = $("why-answer");
    if (!q) return;
    box.replaceChildren(el("span", "note", "Спрашиваю…"));
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
      if (r.source === "file") box.appendChild(el("p", "note", "Демон не отвечает: ответ только по файлу правил, без сведений из DNS."));
    } catch (e) {
      if (e.status !== 401) box.replaceChildren(el("span", "note bad", e.message));
    }
  }

  /* ---- Состояние ---- */
  function chip(text, dot) {
    var c = el("span", "chip");
    if (dot) c.appendChild(el("span", "dot " + dot));
    c.appendChild(document.createTextNode(text));
    return c;
  }

  function duration(ms) {
    var m = Math.max(0, Math.floor(ms / 60000)), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d) return d + " д " + (h % 24) + " ч";
    if (h) return h + " ч " + (m % 60) + " мин";
    return m + " мин";
  }

  function renderState(s) {
    var d = s.daemon, chips = $("chips"), banner = $("banner");
    chips.replaceChildren();
    if (!d) {
      chips.appendChild(chip("демон не отвечает", "bad"));
      banner.textContent = "Демон trassa не отвечает (" + s.daemonError + "). Правила можно править и сохранять: " +
        "они вступят в силу при его запуске. Счётчиков и DNS-ответов пока нет.";
      banner.hidden = false;
    } else {
      banner.hidden = true;
      chips.appendChild(chip(d.mode === "route" ? "маршрутизация" : "наблюдение", "ok"));
      if (d.mode === "route") {
        d.exits.forEach(function (x) {
          if (!x.known) chips.appendChild(chip(x.name + ": ещё неизвестно", "off"));
          else if (x.via) chips.appendChild(chip(x.name + " → " + x.via, "ok"));
          else chips.appendChild(chip(x.name + ": нет живых туннелей", "bad"));
        });
      }
      chips.appendChild(chip("работает " + duration(new Date(s.now) - new Date(d.started))));
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
      ["DNS-ответов с адресами", st.answers], ["под правила", st.claimed], ["адресов в списках", d.addrs],
      ["изменений списков", st.changes], ["ошибок применения", st.applyErrors, true], ["повреждённых пакетов", st.malformed, true]
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
    if (!list.length) { box.appendChild(el("p", "note", "Выходов нет — или в файле правил ошибки.")); return; }
    var via = {};
    if (d) d.exits.forEach(function (x) { via[x.name] = x.via; });
    var groups = {};
    list.forEach(function (t) {
      if (!groups[t.exit]) {
        var g = el("div", "exit");
        var head = el("div", "exit-head");
        head.appendChild(el("span", "badge tunnel", t.exit));
        if (d && d.mode === "route") head.appendChild(document.createTextNode(via[t.exit] ? "идёт через " + via[t.exit] : "живых туннелей нет"));
        g.appendChild(head);
        groups[t.exit] = el("ul", "ifaces");
        g.appendChild(groups[t.exit]);
        box.appendChild(g);
      }
      var li = el("li", via[t.exit] === t.name ? "active" : "");
      li.appendChild(el("span", "dot " + (t.error ? "bad" : t.up ? "ok" : "off")));
      li.appendChild(el("span", "name", t.name + (t.description ? " · " + t.description : "")));
      li.appendChild(el("span", "meta", t.error || (t.up ? "подключён" : "не подключён")));
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
      // Адрес устройства — под именем: длинный адрес IPv6 в своей колонке сжимал бы имя.
      var name = el("td", "name", o.name);
      name.appendChild(el("span", "dev", o.client));
      tr.appendChild(name);
      var td = el("td", "path");
      td.appendChild(el("span", "badge " + (o.action === "direct" ? "direct" : "tunnel"), o.action));
      td.appendChild(el("span", "dev", o.line ? "стр. " + o.line : "default"));
      tr.appendChild(td);
      tb.appendChild(tr);
    });
  }

  async function loadState() {
    try {
      renderState(await api("GET", "/api/state"));
    } catch (e) {
      if (e.status === undefined) { $("banner").textContent = e.message; $("banner").hidden = false; }
    }
  }

  /* ---- Вход ---- */
  function showLogin() {
    signedIn = false;
    clearInterval(pollTimer);
    $("login").hidden = false;
    $("login-pass").focus();
  }

  async function login(ev) {
    ev.preventDefault();
    var user = $("login-user").value.trim(), pass = $("login-pass").value, st = $("login-status");
    st.textContent = "Проверяю…";
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
    try { await api("POST", "/api/logout"); } catch (e) { /* сеанс и так закрыт */ }
    showLogin();
  }

  async function start() {
    try {
      await loadRules();
    } catch (e) {
      if (e.status !== 401) setStatus(e.message, "bad");
      return;
    }
    signedIn = true;
    loadHistory();
    loadState();
    clearInterval(pollTimer);
    pollTimer = setInterval(function () { if (!document.hidden && signedIn) loadState(); }, 5000);
  }

  rulesEl.addEventListener("input", function () {
    clearProblems();
    setStatus(dirty() ? "Есть несохранённые изменения" : "", "");
  });
  rulesEl.addEventListener("scroll", function () { $("gutter").scrollTop = rulesEl.scrollTop; });
  $("check").addEventListener("click", check);
  $("save").addEventListener("click", function () { save(false); });
  $("revert").addEventListener("click", function () {
    rulesEl.value = saved;
    clearProblems();
    setStatus("Правка отменена", "");
  });
  $("confirm-yes").addEventListener("click", function () {
    $("confirm").hidden = true;
    if (confirmAction) confirmAction();
  });
  $("confirm-no").addEventListener("click", function () { $("confirm").hidden = true; rulesEl.focus(); });
  $("why-form").addEventListener("submit", why);
  $("login-form").addEventListener("submit", login);
  $("logout").addEventListener("click", logout);
  window.addEventListener("beforeunload", function (ev) {
    if (signedIn && dirty()) { ev.preventDefault(); ev.returnValue = ""; }
  });
  drawGutter();
  start();
})();
