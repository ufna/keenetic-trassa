// Page decisions that do not depend on the markup: a test checks them through node.
"use strict";

var TrassaLogic = {
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
