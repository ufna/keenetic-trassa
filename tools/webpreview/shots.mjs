// The README's screenshots: the webpreview page in headless Chrome, through the DevTools Protocol.
//
//	go run ./tools/webpreview -rules tools/webpreview/demo.conf &
//	node tools/webpreview/shots.mjs <directory>
//
// It writes PNG files at twice the page's size; docs/assets/readme has them as WebP:
//	magick page.png -resize 2200x -quality 82 page.webp (editor, why, add: -quality 84)
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const out = process.argv[2];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "trassa-shots-"));
const W = 1320, H = 940, SCALE = 2;

const chrome = spawn("google-chrome-stable", ["--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
  "--remote-debugging-port=9333", `--user-data-dir=${profile}`, `--window-size=${W},${H}`, "about:blank"], { stdio: "ignore" });
try {
  let page;
  for (let i = 0; i < 30 && !page; i++) {
    await sleep(300);
    try { page = (await (await fetch("http://127.0.0.1:9333/json")).json()).find((t) => t.type === "page"); } catch {}
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let seq = 0;
  const pending = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  const send = (method, params = {}) => new Promise((r) => { const id = ++seq; pending.set(id, r); ws.send(JSON.stringify({ id, method, params })); });
  const js = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails));
    return r.result?.result?.value;
  };
  const shot = async (name, sel, pad = 12) => {
    let clip;
    if (sel) {
      clip = await js(`(() => { const r = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect();
        return { x: r.x + scrollX - ${pad}, y: r.y + scrollY - ${pad}, width: r.width + ${2 * pad}, height: r.height + ${2 * pad}, scale: 1 }; })()`);
    }
    const r = await send("Page.captureScreenshot", { format: "png", ...(clip ? { clip, captureBeyondViewport: true } : {}) });
    fs.writeFileSync(`${out}/${name}.png`, Buffer.from(r.result.data, "base64"));
    console.log("shot", name, clip ? `${Math.round(clip.width)}x${Math.round(clip.height)}` : "viewport");
  };
  const load = async () => {
    await send("Page.navigate", { url: "http://127.0.0.1:8091/" });
    await sleep(3500);
  };
  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: SCALE, mobile: false });

  // The whole page, with an answer in "Why".
  await load();
  await js(`document.getElementById("why-q").value = "www.youtube.com"; document.getElementById("why-form").requestSubmit();`);
  await sleep(1200);
  await shot("page");
  await shot("why", 'section[aria-labelledby="h-why"]', 0);

  // The editor with an error, after Check.
  await js(`(() => { const t = document.getElementById("rules");
    t.value = t.value.replace("instagram.com cdninstagram.com              -> vpn\\n",
      "instagram.com cdninstagram.com              -> vpn\\nreddit.com                                  -> proxy\\n");
    t.dispatchEvent(new Event("input", { bubbles: true })); document.getElementById("check").click(); })()`);
  await sleep(1500);
  await shot("editor", 'section[aria-labelledby="h-rules"]', 0);

  // The window that makes a rule from a name in the DNS answers.
  await load();
  await js(`[...document.querySelectorAll("#obs .name-link")].find((b) => b.textContent === "connectivitycheck.gstatic.com").click()`);
  await sleep(800);
  await shot("add", "#add-form", 28);
} finally {
  chrome.kill();
  await sleep(500);
  fs.rmSync(profile, { recursive: true, force: true });
}
