"use strict";
const http = require("node:http");
const net = require("node:net");
const {performance} = require("node:perf_hooks");
const {createInterface} = require("node:readline");

const sleep = ms => new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));
const emit = row => process.stdout.write(JSON.stringify(row) + "\n");
const now = () => performance.timeOrigin + performance.now();

const expectedPi = new Map();
function validPayload(text, n) {
  try {
    const body = JSON.parse(text);
    if (!expectedPi.has(n)) {
      let total = 0;
      for (let i = 0; i < n; i++) total += 4 / (1 + ((i + .5) / n) ** 2);
      expectedPi.set(n, total / n);
    }
    return body.backend === "django" && body.n === n && Number.isFinite(body.pi) &&
      Math.abs(body.pi - expectedPi.get(n)) < 1e-9;
  } catch (_) { return false; }
}

// Every scheduled arrival produces a record, even when concurrency or the
// generator's event loop cannot keep up. Completion never moves the schedule.
async function schedule({start, duration, rate, concurrency, lateMs = 250, visit, missed,
                         clock = now, wait = sleep}) {
  const active = new Set();
  const count = Math.floor(duration * rate);
  for (let seq = 0; seq < count; seq++) {
    const due = start + seq * 1000 / rate;
    await wait(due - clock());
    if (clock() - due > lateMs || active.size >= concurrency) {
      missed(seq, due, active.size >= concurrency ? "concurrency" : "schedule_lag");
      continue;
    }
    const task = Promise.resolve().then(() => visit(seq, due));
    active.add(task);
    task.finally(() => active.delete(task));
  }
  await Promise.all(active);
}

function request(url, headers, timeoutMs) {
  return new Promise(resolve => {
    let done = false;
    const finish = row => { if (!done) { done = true; clearTimeout(timer); resolve(row); } };
    const req = http.get(url, {agent: false, headers: {...headers, Connection: "close"}}, response => {
      let text = "", size = 0;
      response.on("data", chunk => {
        size += chunk.length;
        if (text.length < 65536) text += chunk.toString();
      });
      response.on("end", () => finish({status: response.statusCode, headers: response.headers,
        body: text.slice(0, 1024), text, bytes: size}));
      response.on("error", error => finish({error: error.code || error.message}));
    });
    req.on("error", error => finish({error: error.code || error.message}));
    const timer = setTimeout(() => {
      finish({error: "timeout"});
      req.destroy();
    }, timeoutMs);
  });
}

async function tcpReady(origin, record) {
  const target = new URL(origin);
  const deadline = now() + 20000;
  while (true) {
    const result = await new Promise(resolve => {
      const socket = net.connect({host: target.hostname, port: target.port || 80});
      socket.setTimeout(500);
      socket.once("connect", () => { socket.destroy(); resolve("connected"); });
      socket.once("error", error => resolve(error.code));
      socket.once("timeout", () => { socket.destroy(); resolve("timeout"); });
    });
    record({type: "tcp_readiness", phase: "setup", time_ms: now(), result});
    if (result === "connected") return;
    if (now() >= deadline) throw new Error("TCP readiness deadline");
    await sleep(100);
  }
}

async function browserVisit(browser, existing, cfg, actor, phase, id, due, record, initialState) {
  const deadline = due + cfg.timeout_ms;
  let context = existing, page, firstChallenge = null, proofAccepted = null;
  let last = {}, outcome = "error", error = null, challenges = 0;
  const pending = [];
  let wireHandler, failedHandler, requestHandler;
  const remaining = () => Math.max(1, deadline - now());
  try {
    if (!context) context = await browser.newContext(initialState ? {storageState: initialState} : {});
    page = await context.newPage();
    await page.setExtraHTTPHeaders({"X-Availability-Id": id});
    wireHandler = response => {
      const at = now();
      if (response.status() === 428 && new URL(response.url()).pathname === "/pi") {
        firstChallenge ??= at;
        challenges++;
      }
      if (/\/ankah\/(answer\/|open\?)/.test(response.url()) && response.status() === 200)
        proofAccepted = at;
      const task = (async () => {
        const row = {type: "wire", actor, phase, id, time_ms: at, url: response.url(),
          status: response.status(), headers: response.headers()};
        if (row.status >= 400) row.body = (await response.body().catch(() => Buffer.alloc(0))).toString().slice(0, 1024);
        record(row);
      })();
      pending.push(task);
      task.catch(() => {});
    };
    failedHandler = req => record({type: "wire", actor, phase, id, time_ms: now(),
      url: req.url(), error: req.failure()?.errorText || "request_failed"});
    requestHandler = req => record({type: "wire_request", actor, phase, id, time_ms: now(),
      url: req.url(), method: req.method(), headers: req.headers()});
    // A fresh context also captures the worker's WebAssembly fetch.
    const source = existing ? page : context;
    source.on("response", wireHandler);
    source.on("requestfailed", failedHandler);
    source.on("request", requestHandler);
    const url = cfg.origin + "/pi?n=" + cfg.n + "&visit=" + id;
    const final = page.waitForResponse(r => r.url() === url && r.status() !== 428,
      {timeout: remaining()});
    final.catch(() => {});
    await page.goto(url, {waitUntil: "domcontentloaded", timeout: remaining()});
    const response = await final;
    const text = await response.text();
    last = {status: response.status(), headers: await response.allHeaders(), body: text.slice(0, 1024)};
    outcome = response.status() === 200 && validPayload(text, cfg.n) ? "success" :
      response.status() >= 400 ? "rejected" : "invalid_payload";
    if (now() > deadline) outcome = "timeout";
  } catch (err) {
    error = String(err).slice(0, 1024);
    outcome = now() >= deadline || err.name === "TimeoutError" ? "timeout" : "error";
  } finally {
    const ended = now();
    if (page) {
      const source = existing ? page : context;
      await page.close().catch(() => {});
      if (!existing) await context.close().catch(() => {});
      source.off("response", wireHandler);
      source.off("requestfailed", failedHandler);
      source.off("request", requestHandler);
    } else if (!existing && context) await context.close().catch(() => {});
    await Promise.allSettled(pending);
    const row = {type: "visit", actor, phase, id, due_ms: due, ended_ms: ended,
      latency_ms: ended - due, outcome, challenges, proof_accepted: proofAccepted !== null,
      challenge_ms: firstChallenge !== null && proofAccepted !== null ? proofAccepted - firstChallenge : null,
      challenge_wait_ms: firstChallenge !== null ? (proofAccepted ?? ended) - firstChallenge : null,
      error, ...last};
    record(row);
    return row;
  }
}

async function main() {
  const lines = createInterface({input: process.stdin});
  const inbox = [], waiters = [];
  lines.on("line", line => {
    const value = JSON.parse(line);
    if (waiters.length) waiters.shift()(value); else inbox.push(value);
  });
  const read = () => inbox.length ? Promise.resolve(inbox.shift()) : new Promise(resolve => waiters.push(resolve));
  const cfg = await read(), role = process.argv[2];
  let browser, returning, returningState, cookies = "", userAgent = "availability-unsolved";
  if (role === "visitors" || cfg.attack === "solved") {
    const {chromium} = require("playwright");
    browser = await chromium.launch({args: ["--no-proxy-server"]});
  }
  try {
    await tcpReady(cfg.origin, emit);
    if (role === "visitors" || cfg.attack === "solved") {
      returning = await browser.newContext();
      const prep = await browserVisit(browser, returning, cfg,
        role === "visitors" ? "returning" : "attacker", "setup", "setup_" + role, now(), emit);
      if (prep.outcome !== "success") throw new Error("Preparation failed: " + JSON.stringify(prep));
      if (cfg.arm !== "direct" && !prep.proof_accepted) throw new Error("Preparation did not accept proof");
      cookies = (await returning.cookies(cfg.origin)).map(c => c.name + "=" + c.value).join("; ");
      returningState = await returning.storageState();
      const page = await returning.newPage();
      userAgent = await page.evaluate(() => navigator.userAgent);
      await page.close();
    }
    emit({type: "ready", role, browser: browser ? browser.version() : null});
    const {start_ms: start} = await read();
    emit({type: "boundary", boundary: "start", scheduled_ms: start, time_ms: now()});
    const schedules = role === "visitors" ? ["new", "returning"] : cfg.attack === "none" ? [] : ["attacker"];
    await Promise.all(schedules.map(actor => schedule({start, duration: cfg.duration_s,
      rate: actor === "attacker" ? cfg.attack_rps : cfg.visitor_rps,
      concurrency: actor === "attacker" ? 2048 : 64,
      missed: (seq, due, reason) => emit({type: "visit", phase: "measured", actor,
        id: actor + "_" + seq, due_ms: due, ended_ms: now(), outcome: "generator_miss", reason}),
      visit: async (seq, due) => {
        const id = actor + "_" + seq;
        if (actor !== "attacker") {
          await browserVisit(browser, null, cfg, actor, "measured", id, due, emit,
            actor === "returning" ? returningState : undefined);
        } else {
          emit({type: "wire_request", phase: "measured", actor, id, time_ms: now(),
            url: cfg.origin + "/pi?n=" + cfg.n + "&visit=" + id, method: "GET"});
          const result = await request(cfg.origin + "/pi?n=" + cfg.n + "&visit=" + id,
            {"X-Availability-Id": id, "User-Agent": userAgent, Cookie: cookies}, cfg.attack_timeout_ms);
          const ended = now(), text = result.text;
          delete result.text;
          emit({type: "wire", phase: "measured", actor, id, time_ms: due, ...result});
          emit({type: "visit", phase: "measured", actor, id, due_ms: due, ended_ms: ended,
            latency_ms: ended - due, outcome: result.error ? result.error === "timeout" ? "timeout" : "error" :
              result.status === 200 && validPayload(text, cfg.n) ? "success" :
                result.status === 428 ? "challenged" : result.status >= 400 ? "rejected" : "invalid_payload",
            ...result});
        }
      },
    })));
    await sleep(start + cfg.duration_s * 1000 - now());
    emit({type: "boundary", boundary: "drained", time_ms: now()});
  } finally {
    if (browser) await browser.close();
    lines.close();
    process.stdin.destroy();
  }
}

module.exports = {validPayload, schedule, request, browserVisit};
if (require.main === module) main().catch(error => {
  emit({type: "fatal", error: String(error.stack)});
  process.exitCode = 1;
  process.stdin.destroy();
});
