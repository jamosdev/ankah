"use strict";
const assert = require("node:assert/strict");
const http = require("node:http");
const {test} = require("node:test");
const {performance} = require("node:perf_hooks");
const {validPayload, schedule, request} = require("./client.cjs");

test("success requires the application payload and requested work", () => {
  assert(validPayload('{"backend":"django","n":1,"pi":3.2}', 1));
  assert(!validPayload("<body>challenge</body>", 1));
  assert(!validPayload('{"backend":"django","n":2,"pi":3.2}', 1));
  assert(!validPayload('{"backend":"other","n":1,"pi":3.2}', 1));
  assert(!validPayload('{"backend":"django","n":1,"pi":0}', 1));
});

test("full concurrency records missed arrivals instead of throttling the schedule", async () => {
  const rows = [], missed = [];
  let clock = 0, release;
  const held = new Promise(resolve => { release = resolve; });
  await schedule({start: 0, duration: .04, rate: 100, concurrency: 1,
    clock: () => clock, wait: async delay => { clock += Math.max(0, delay); },
    visit: async seq => { rows.push(seq); await held; },
    missed: (seq, due, reason) => { missed.push({seq, due, reason}); if (seq === 3) release(); }});
  assert.deepEqual(rows, [0]);
  assert.equal(missed.length, 3);
  assert(missed.every(row => row.reason === "concurrency"));
});

test("overdue arrivals are accounted even without active requests", async () => {
  const missed = [];
  await schedule({start: performance.timeOrigin + performance.now() - 1000,
    duration: .03, rate: 100, concurrency: 1, lateMs: 10,
    visit: () => assert.fail("overdue arrival was issued"), missed: seq => missed.push(seq)});
  assert.deepEqual(missed, [0, 1, 2]);
});

test("transport retains bounded diagnostics and enforces absolute deadline", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/hold") return;
    res.writeHead(429, {"Retry-After": "1"});
    res.end("Rate limit exceeded\n".repeat(1000));
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try {
    const origin = "http://127.0.0.1:" + server.address().port;
    const result = await request(origin, {}, 1000);
    assert.equal(result.status, 429);
    assert.equal(result.headers["retry-after"], "1");
    assert.equal(result.body.length, 1024);
    assert.equal((await request(origin + "/hold", {}, 20)).error, "timeout");
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
