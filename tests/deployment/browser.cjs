"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const {chromium} = require("playwright");

(async () => {
  const [mode, origin, directory] = process.argv.slice(2);
  const browser = await chromium.launch({args: ["--no-proxy-server",
    "--host-resolver-rules=MAP deployment.test 172.30.83.1"]});
  const records = [];
  const pending = [];
  const restored = mode === "fresh" ? null : JSON.parse(fs.readFileSync(directory + "/browser-state.json"));
  // A signed pass alone could hide broken session snapshot restoration.
  if (restored) restored.cookies = restored.cookies.filter(cookie => cookie.name !== "ankah_pass");
  const context = await browser.newContext({ignoreHTTPSErrors: true,
    ...(restored ? {storageState: restored} : {})});
  context.on("response", response => {
    const task = (async () => {
      const row = {url: response.url(), status: response.status(), headers: response.headers()};
      records.push(row);
      console.log(JSON.stringify({url: row.url, status: row.status}));
      let timer;
      const body = await Promise.race([response.body().catch(() => Buffer.alloc(0)),
        new Promise(resolve => { timer = setTimeout(() => resolve(Buffer.from("[body unavailable]")), 3000); })]);
      clearTimeout(timer);
      row.body = body.toString().slice(0, 1024);
    })();
    pending.push(task);
  });
  try {
    const page = await context.newPage();
    const path = "/original?deployment=check%2Fpath&keep=two";
    const final = page.waitForResponse(r => r.url() === origin + path && r.status() === 200,
      {timeout: 90000});
    final.catch(() => {});
    await page.goto(origin + path, {waitUntil: "domcontentloaded", timeout: 90000});
    const response = await final;
    assert.equal((await response.json()).path, path);
    const returning = await page.goto(origin + path);
    assert.equal(returning.status(), 200);
    await Promise.allSettled(pending);
    if (mode === "fresh") {
      assert(records.some(r => r.status === 428), "fresh browser never challenged");
      assert(records.some(r => /\/ankah\/answer\//.test(r.url) && r.status === 200),
        "browser proof not accepted");
    } else {
      assert(!records.some(r => r.status === 428), "solved session lost on restart");
    }
    if (mode === "fresh") {
      await page.goto(origin + "/ankah-admin/");
      await page.locator("#login-mode").click();
      const token = fs.readFileSync(directory + "/deploy/compose/credentials/dashboard.token", "utf8").trim();
      await page.locator("#token").fill(token);
      await page.locator("#token-login button[type=submit]").click();
      await page.locator("#main").waitFor({state: "visible"});
      await page.goto(origin + path); // Stop dashboard polling before restart checks.
    }
    await context.storageState({path: directory + "/browser-state.json"});
    console.log(JSON.stringify({mode, final: response.status(), path}));
  } finally {
    await context.close();
    await Promise.allSettled(pending);
    fs.writeFileSync(directory + "/browser-" + mode + ".json", JSON.stringify(records, null, 2));
    await browser.close();
  }
})().catch(error => { console.error(error); process.exit(1); });
