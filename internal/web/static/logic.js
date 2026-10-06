// Page decisions that do not depend on the markup: a test checks them through node.
"use strict";

// Second-level zones under a country domain: example.co.uk is a domain of its own, co.uk is not.
var secondLevel = ["ac", "co", "com", "edu", "go", "gov", "ne", "net", "or", "org"];

// Domains under which anyone registers a site of their own: a rule for one of them would cover
// strangers' sites too, so they are never offered as parents.
var sharedSuffixes = ["appspot.com", "azurewebsites.net", "blogspot.com", "cloudfront.net", "firebaseapp.com",
  "github.io", "herokuapp.com", "msk.ru", "narod.ru", "netlify.app", "pages.dev", "spb.ru", "ucoz.ru",
  "vercel.app", "web.app", "workers.dev"];

var TrassaLogic = {
  // parents lists the domains a name belongs to, nearest first, down to the one registered:
  // "a.b.example.com" → ["b.example.com", "example.com"]. A rule for a domain also covers its
  // subdomains, so these are the broader choices for a rule.
  parents: function (name) {
    var labels = name.split(".");
    var base = 2;
    if (labels.length >= 3 && labels[labels.length - 1].length === 2 &&
        secondLevel.indexOf(labels[labels.length - 2]) >= 0) {
      base = 3;
    }
    for (var k = 0; k < sharedSuffixes.length; k++) {
      if (name.endsWith("." + sharedSuffixes[k])) base = sharedSuffixes[k].split(".").length + 1;
    }
    var out = [];
    for (var i = 1; labels.length - i >= base; i++) {
      out.push(labels.slice(i).join("."));
    }
    return out;
  },

  // ruleLine writes a rule: name, exit, strict (only for a tunnel), and for which devices:
  // scope "all", "only" (the list) or "except" (every device but the list).
  ruleLine: function (r) {
    var line = r.name + " -> " + r.exit;
    if (r.strict && r.exit !== "direct" && r.exit !== "none") line += " strict";
    if (r.scope === "only") line += " for " + r.list;
    if (r.scope === "except") line += " for !" + r.list;
    return line;
  },

  // appendRule puts a rule line at the end of the rules text.
  appendRule: function (text, line) {
    var t = text.replace(/\s+$/, "");
    return (t === "" ? "" : t + "\n") + line + "\n";
  },

  // ascii writes a name typed in another alphabet the way DNS answers carry it (punycode): "сайт.рф"
  // becomes "xn--80aswg.xn--p1ai". A part of a label cannot be converted and stays as it is.
  ascii: function (q) {
    if (!/[^\x00-\x7f]/.test(q)) return q;
    try { return new URL("http://" + q).hostname; } catch (e) { return q; }
  },

  // mergeAnswers puts a response of /api/answers into the page's list, newest first. have is what
  // the page had: {epoch, last}. Answers the page already has are skipped (two requests may
  // overlap), and the page's number never goes back (a late response). A response of another
  // daemon (it restarted) is not merged: reset asks the page to fetch the whole list.
  mergeAnswers: function (list, resp, have, max) {
    if (resp.full) return { answers: resp.answers.slice(0, max), last: resp.last, epoch: resp.epoch, reset: false };
    if (have.epoch && resp.epoch !== have.epoch) return { answers: list, last: 0, epoch: resp.epoch, reset: true };
    var fresh = resp.answers.filter(function (a) { return a.seq > have.last; });
    return { answers: fresh.concat(list).slice(0, max), last: Math.max(have.last, resp.last), epoch: resp.epoch, reset: false };
  },

  // deviceLabel names a device in the filter: by its name, else by its address.
  deviceLabel: function (o) { return o.device || o.client; },

  // deviceOptions lists the devices among the answers for the filter, once each, sorted by label.
  // Devices that share a name are told apart by their addresses.
  deviceOptions: function (answers) {
    var seen = {}, list = [], count = {};
    answers.forEach(function (o) {
      if (seen[o.client]) return;
      seen[o.client] = true;
      var label = TrassaLogic.deviceLabel(o);
      count[label] = (count[label] || 0) + 1;
      list.push({ value: o.client, label: label });
    });
    list.forEach(function (d) { if (count[d.label] > 1) d.label += " · " + d.value; });
    return list.sort(function (a, b) { return a.label.localeCompare(b.label); });
  },

  // filter keeps the DNS answers whose name contains q (any case) and that went to client
  // ("" means any).
  filter: function (rows, q, client) {
    q = TrassaLogic.ascii(q.trim().toLowerCase());
    return rows.filter(function (r) {
      return (!q || r.name.toLowerCase().indexOf(q) >= 0) && (!client || r.client === client);
    });
  },

  // adopt decides what to show in the editor when the rules in effect arrive from the router.
  // An unsaved edit is not lost: after signing in again or reloading the page, the editor keeps
  // what the person typed. Returns {editor, saved, note}.
  adopt: function (editor, saved, server) {
    if (editor === saved || editor === server) return { editor: server, saved: server, note: "" };
    if (server === saved) return { editor: editor, saved: server, note: "Your unsaved edit is kept in the editor." };
    return {
      editor: editor, saved: server,
      note: "The rules on the router changed while you were away. Your edit is kept in the editor; " +
        "“Discard edit” shows the rules in effect."
    };
  }
};
