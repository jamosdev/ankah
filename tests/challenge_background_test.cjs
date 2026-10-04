"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {spawn} = require("node:child_process");
const {createInterface} = require("node:readline");
const {chromium} = require("playwright");

// The Python fixture and browser may run in separate local containers.
const [executable, assets, outputPath, ...fixtureOptions] = process.argv.slice(2);
if (!outputPath) throw new Error("Usage: challenge_background_test.cjs EXECUTABLE ASSETS OUTPUT [fixture options]");
const output = path.resolve(outputPath);
fs.mkdirSync(output, {recursive: true});
const runner = process.env.ANKAH_FIXTURE_RUNNER ? JSON.parse(process.env.ANKAH_FIXTURE_RUNNER) :
  ["python3", path.join(__dirname, "browser_fixture.py")];
let metadata;
const origin = (host) => `https://${host}:${metadata.port}`;
const results = [];

async function freshFixture(name) {
  const child = spawn(runner[0], [...runner.slice(1), executable, assets, "-", ...fixtureOptions]);
  child.stdin.on("error", () => {}); // An early fixture exit is reported through its status/stderr.
  let stderr = "";
  child.stderr.on("data", (data) => { stderr += data; });
  const exited = new Promise((resolve) => child.on("close", (code) => resolve(code)));
  const lines = createInterface({input: child.stdout});
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Fixture startup timeout")), 20000);
    child.once("error", reject);
    lines.once("line", (line) => {
      clearTimeout(timeout);
      try { resolve(JSON.parse(line)); } catch (error) { reject(error); }
    });
    exited.then((code) => { clearTimeout(timeout); reject(new Error(`Fixture exited ${code}: ${stderr}`)); });
  });
  async function stop() {
    child.stdin.end();
    const timeout = setTimeout(() => child.kill("SIGTERM"), 20000);
    const code = await exited;
    clearTimeout(timeout);
    lines.close();
    fs.writeFileSync(path.join(output, name + "-fixture.log"), stderr);
    assert.equal(code, 0, stderr);
  }
  try { return {metadata: await ready, stop}; }
  catch (error) { await stop().catch(() => {}); throw error; }
}

async function main() {
  const browser = await chromium.launch({executablePath: process.env.BROWSER || undefined,
    args: ["--no-proxy-server", "--host-resolver-rules=MAP *.test " +
           (process.env.ANKAH_FIXTURE_ADDRESS || "127.0.0.1")]});
  const version = await browser.version();
  const scenarios = [
    {name: "landing", host: "submit.test", target: "/", hold: true},
    {name: "primary-test", host: "status.test", hold: true},
    {name: "secondary-test", host: "submit.test", hold: true},
    {name: "static-only-mobile", host: "other.test", hold: true, mobile: true},
    {name: "phone", host: "submit.test", phone: true, mobile: true},
    {name: "reduced-motion", host: "submit.test", hold: true, reduced: true},
    {name: "normal-return", host: "submit.test"},
    ...["script-failed", "script-stalled", "config-failed", "config-stalled", "config-invalid"]
      .map((fault) => ({name: fault, host: "submit.test", fault})),
  ];
  if (!fixtureOptions.includes("--no-dashboard")) scenarios.push({name: "dashboard-control", host: "status.test", dashboard: true});
  try {
    for (const scenario of scenarios) {
      const fixture = await freshFixture(scenario.name);
      metadata = fixture.metadata;
      const context = await browser.newContext({ignoreHTTPSErrors: true,
        viewport: scenario.mobile ? {width: 390, height: 844} : {width: 1200, height: 800},
        isMobile: !!scenario.mobile, hasTouch: !!scenario.mobile,
        reducedMotion: scenario.reduced ? "reduce" : "no-preference"});
      const page = await context.newPage();
      const errors = [], csp = [], requests = [], rejected = [];
      let release = () => {};
      page.on("pageerror", (error) => errors.push(String(error)));
      page.on("console", (message) => {
        if (/content.security.policy|violates.*directive/i.test(message.text())) csp.push(message.text());
      });
      page.on("request", (request) => { if (/particle/.test(request.url())) requests.push(request.url()); });
      page.on("response", (response) => {
        if (response.status() >= 400) rejected.push({status: response.status(),
          url: response.url(), headers: response.headers()});
      });
      if (scenario.hold) await context.addInitScript(() => {
        HTMLFormElement.prototype.submit = function () { window.finishHeld = true; };
      });
      if (scenario.fault) {
        const resource = scenario.fault.startsWith("script") ? "particles.min.js" : "particlejs.json";
        const stalled = new Promise((resolve) => { release = resolve; });
        await context.route("**/" + resource, async (route) => {
          if (scenario.fault.endsWith("stalled")) await stalled;
          if (scenario.fault.endsWith("invalid")) {
            await route.fulfill({status: 200, contentType: "application/json", body: "{"});
          } else {
            await route.abort().catch(() => {});
          }
        });
      }
      try {
        let target = scenario.target || "/ankah/unlock";
        if (scenario.dashboard) target = "/ankah-admin/";
        if (scenario.phone) {
          // Create an unsolved original page through Chromium's fixture DNS.
          // Its controller is withheld only while obtaining the QR session.
          await context.route("**/challenge.js", (route) => route.abort());
          const response = await page.goto(origin(scenario.host) + target,
            {waitUntil: "domcontentloaded"});
          assert.equal(response.status(), 428);
          const sid = await page.locator("body").getAttribute("data-session");
          await context.unroute("**/challenge.js");
          await context.clearCookies();
          target = "/ankah/solve/" + sid;
        }
        await page.goto(origin(scenario.host) + target, {waitUntil: "domcontentloaded"});
        let state;
        if (scenario.fault || scenario.name === "normal-return") {
          await page.waitForURL(origin(scenario.host) + "/", {waitUntil: "domcontentloaded", timeout: 10000});
          assert.equal(await page.locator("body").getAttribute("data-challenge"), null);
          state = {returned: true};
        } else if (scenario.reduced) {
          await page.waitForFunction(() => window.finishHeld, null, {timeout: 10000});
          assert.equal(await page.locator("canvas").count(), 0);
          assert.deepEqual(requests, []);
          state = {reducedMotion: true, particleRequests: 0};
        } else {
          await page.waitForFunction(() => window.pJSDom?.[0]?.pJS.particles.array.length > 0,
                                    null, {timeout: 10000});
          state = await page.evaluate(() => {
            const p = window.pJSDom[0].pJS;
            const pixels = p.canvas.ctx.getImageData(0, 0, p.canvas.w, p.canvas.h).data;
            return {count: p.particles.array.length, configuredCount: p.particles.number.value,
              speed: p.particles.move.speed, color: p.particles.color.value,
              painted: pixels.some((value, i) => i % 4 === 3 && value > 0),
              hover: p.interactivity.events.onhover.enable, detectOn: p.interactivity.detect_on,
              width: p.canvas.w, height: p.canvas.h,
              positions: p.particles.array.map(({x, y}) => [x, y]),
              overflow: document.documentElement.scrollWidth > innerWidth};
          });
          assert(state.painted && !state.overflow, JSON.stringify(state));
          await page.waitForFunction((before) => window.pJSDom[0].pJS.particles.array.some(
            (particle, i) => particle.x !== before[i]?.[0] || particle.y !== before[i]?.[1]),
            state.positions, {timeout: 5000});
          delete state.positions;
          if (!scenario.dashboard) {
            assert.equal(state.configuredCount, 137);
            assert.equal(state.speed, 6);
            assert.equal(state.color, "#ffffff");
            assert.equal(state.hover, true);
            assert.equal(state.detectOn, "window");
            assert(requests.every((url) => url.startsWith(origin(scenario.host) + "/ankah/assets/")));
            assert(requests.some((url) => url.endsWith("/particles.min.js")));
            assert(requests.some((url) => url.endsWith("/particlejs.json")));
          }
          if (scenario.hold) {
            await page.waitForFunction(() => window.finishHeld, null, {timeout: 10000});
            const button = page.locator("#finish button");
            const box = await button.boundingBox();
            assert(await page.evaluate(({x, y}) => !!document.elementFromPoint(x, y)?.closest("#finish button"),
              {x: box.x + box.width / 2, y: box.y + box.height / 2}));
            await button.focus();
            assert(await button.evaluate((element) => element === document.activeElement));
          }
          if (scenario.phone) {
            await page.waitForFunction(() => document.getElementById("progress").textContent ===
              document.querySelector('[data-name="challenge_passed_mobile"]').textContent,
              null, {timeout: 10000});
            state.phoneSolved = true;
          }
          if (!scenario.mobile && !scenario.dashboard) {
            await page.mouse.move(10, 10);
            await page.waitForFunction(() => window.pJSDom[0].pJS.interactivity.status === "mousemove");
          }
        }
        assert.deepEqual(errors, []);
        assert.deepEqual(csp, []);
        await page.screenshot({path: path.join(output, scenario.name + ".png"), fullPage: true});
        if (scenario.hold && !scenario.reduced) {
          await page.locator("#finish button").click();
          await page.waitForURL(origin(scenario.host) + "/", {waitUntil: "domcontentloaded", timeout: 10000});
          state.buttonReturned = true;
        }
        results.push({name: scenario.name, result: "PASS", ...metadata, ...state,
                      particleRequests: requests, errors, csp});
      } catch (error) {
        await page.screenshot({path: path.join(output, scenario.name + "-failure.png"), fullPage: true}).catch(() => {});
        results.push({name: scenario.name, result: "FAIL", ...metadata,
                      error: String(error), url: page.url(), body: (await page.locator("body").innerText()).slice(0, 512),
                      errors, csp, requests, rejected});
        throw error;
      } finally {
        release();
        await context.close();
        await fixture.stop();
      }
    }
  } finally {
    fs.writeFileSync(path.join(output, "result.json"), JSON.stringify({browser: version, results}, null, 2));
    await browser.close();
  }
  console.log(`${results.length} browser scenarios passed`);
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
