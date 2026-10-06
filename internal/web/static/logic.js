// Page decisions that do not depend on the markup: a test checks them through node.
"use strict";

// Second-level zones under a country domain: example.co.uk is a domain of its own, co.uk is not.
var secondLevel = ["ac", "co", "com", "edu", "go", "gov", "ne", "net", "or", "org"];

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

  // filter keeps the DNS answers whose name contains q (any case) and that went to client
  // ("" means any).
  filter: function (rows, q, client) {
    q = q.trim().toLowerCase();
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
