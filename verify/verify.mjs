import { createRequire } from "node:module";
const require = createRequire("D:/project/git-primer/node_modules/");
const { chromium } = require("playwright-core");
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { join, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const root = dirname(fileURLToPath(import.meta.url)) + "/..";
const shots = dirname(fileURLToPath(import.meta.url)) + "/shots";
await mkdir(shots, { recursive: true });
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".woff2": "font/woff2", ".webp": "image/webp", ".gif": "image/gif" };
const server = createServer(async (req, res) => {
  try {
    const p = req.url === "/" ? "/index.html" : req.url.split("?")[0];
    const body = await readFile(join(root, p));
    res.writeHead(200, { "content-type": MIME[extname(p)] || "application/octet-stream" });
    res.end(body);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = "http://127.0.0.1:" + server.address().port + "/";
const browser = await chromium.launch({ channel: "msedge", headless: true });
const page = await browser.newPage({ viewport: { width: 1200, height: 900 }, deviceScaleFactor: 2 });
const errors = [];
page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
page.on("console", (m) => { if (m.type() === "error") errors.push("console: " + m.text()); });
await page.goto(base, { waitUntil: "networkidle" });
await page.waitForTimeout(600);
const t = (sel) => page.$eval(sel, (n) => n.textContent.trim());
const term = (sel) => page.$eval(sel, (n) => n.textContent);
const ok = [], bad = [];
const check = (name, cond) => cond ? ok.push(name) : bad.push(name);

/* d1 威胁模型对照台：全点完 → 拦2/限4/明说不防2 */
await page.evaluate(() => { for (let i = 0; i < 8; i++) d1.pick(i); });
check("d1 block=2", (await t("#d1-block")) === "2");
check("d1 cap=4", (await t("#d1-cap")) === "4");
check("d1 dis=2", (await t("#d1-dis")) === "2");
await page.evaluate(() => d1.pick(5));
check("d1 verdict cites docstring", (await term("#d1-term")).includes("not filesystem or network isolation"));

/* d2 分层闸门：六段代码 */
await page.click("#d2 button:has-text('9,000 字符')");
check("d2 long pre-Popen", (await t("#d2-born")).startsWith("否"));
await page.click("#d2 button:has-text('import socket')");
check("d2 import pre-Popen", (await term("#d2-term")).includes("Blocked module import: socket"));
await page.click("#d2 button:has-text('sleep(30)')");
check("d2 timeout killed", (await t("#d2-ms")).includes("1.0s"));
await page.click("#d2 button:has-text('两百万个 x')");
check("d2 output capped 6000", (await term("#d2-term")).includes("6,000 字符"));
await page.click("#d2 button:has-text('bytearray 600MB')");
check("d2 memory MemoryError", (await term("#d2-term")).includes("MemoryError"));
await page.click("#d2 button:has-text('正常算个数')");
check("d2 ok prints 1024", (await term("#d2-term")).includes("1024"));

/* d3 import 判定器：顺序点六病例 */
for (let i = 0; i < 6; i++) await page.evaluate((k) => d3.pick(k), i);
check("d3 judged 6", (await t("#d3-n")) === "6 / 6");
check("d3 blocked 4", (await t("#d3-block")) === "4");
check("d3 overkill 1", (await t("#d3-over")) === "1");
check("d3 socketing allowed", (await term("#d3-term")).includes("socketing 不是 socket"));

/* d4 进程树围栏 */
await page.click("#d4 button:has-text('笼内进程')");
check("d4 spawned 2 kids", (await t("#d4-kids")) === "2 / 2");
await page.click("#d4 button:has-text('只 kill 根')");
check("d4 kill root → 2 orphans", (await t("#d4-orphan")).startsWith("2"));
check("d4 kids survive root kill", (await t("#d4-kids")) === "2 / 2");
await page.click("#d4 button:has-text('job.close()')");
check("d4 job reaps orphans", (await t("#d4-orphan")).startsWith("0"));
check("d4 job flag shown", (await term("#d4-tree")).includes("KILL_ON_JOB_CLOSE"));

/* d5 环境泄漏对照 */
await page.evaluate(() => { el("d5-wl").checked = false; d5.paint(); });
check("d5 off → 6 secrets leak", (await t("#d5-leak")).includes("5 个裸奔"));
await page.evaluate(() => { el("d5-wl").checked = true; d5.paint(); });
check("d5 on → 0 leak", (await t("#d5-leak")).startsWith("0"));
check("d5 home redirected", (await t("#d5-home")).includes("run-xxxx"));

/* d6 产物回传 */
await page.click("#d6 button:has-text('手写 PNG')");
check("d6 png collected", (await t("#d6-n")) === "1");
check("d6 magic intact", (await t("#d6-magic")).includes("PNG 完好"));
await page.click("#d6 button:has-text('3MB')");
check("d6 big skipped", (await t("#d6-skip")) === "1");
await page.click("#d6 button:has-text('data.csv')");
check("d6 csv not in whitelist", (await t("#d6-skip")) === "2" && (await t("#d6-n")) === "1");

/* 速查卡 + 互动数 */
check("cheat 12 cards", (await page.$$eval(".cheat .cc", (n) => n.length)) === 12);
check("six interactive tags", (await page.$$eval(".demo-tag", (n) => n.length)) === 6);

/* 截图 */
for (const [id, name] of [["#d1","d1"],["#d3","d3"],["#d4","d4"],["#d6","d6"],[".finale","finale"]]) {
  await page.$eval(id, (n) => n.scrollIntoView({ block: "center" }));
  await page.waitForTimeout(250);
  await page.screenshot({ path: shots + "/" + name + ".png" });
}

/* 移动端 390px */
const mp = await browser.newPage({ viewport: { width: 390, height: 844 } });
await mp.goto(base, { waitUntil: "networkidle" });
await mp.waitForTimeout(400);
const overflow = await mp.evaluate(() => {
  const out = [];
  document.querySelectorAll(".demo, .tbl-wrap, .term, .cheat, svg").forEach((n) => {
    const r = n.getBoundingClientRect();
    if (r.right > 391 && r.width > 20) out.push(n.className + " → " + Math.round(r.right));
  });
  return out.slice(0, 8);
});
check("mobile no overflow", overflow.length === 0);
if (overflow.length) console.log("OVERFLOW:", overflow);

console.log("PASS:", ok.length, "→", ok.join(" | "));
if (bad.length) console.log("FAIL:", bad.join(" | "));
console.log("ERRORS:", errors.length ? errors.join("\n") : "none");
await browser.close();
process.exit(bad.length || errors.length ? 1 : 0);
