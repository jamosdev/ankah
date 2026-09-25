"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");

const wasm = fs.readFileSync(process.argv[2]);
const workerSource = fs.readFileSync(process.argv[3], "utf8");
const nonce = "0".repeat(32);

function expected(start, count, bits) {
  for (let counter = start; counter < start + count; counter++) {
    const hash = crypto.createHash("sha256").update(`${nonce}:${counter}`).digest();
    if (hash.readUInt32BE(0) >>> (32 - bits) === 0) return counter;
  }
  return -1;
}

async function main() {
  const {instance} = await WebAssembly.instantiate(wasm);
  const {memory, nonce_buffer, search_batch} = instance.exports;
  const offset = nonce_buffer();
  for (let i = 0; i < 32; i++) new Uint8Array(memory.buffer)[offset + i] = nonce.charCodeAt(i);
  for (const [start, count, bits] of [[0, 1000, 8], [9000, 10000, 9],
                                       [30000, 10000, 18], [0, 64, 24]]) {
    assert.equal(search_batch(start, count, bits), expected(start, count, bits));
  }
  assert.equal(search_batch(0, 1, 7), -1);
  assert.equal(search_batch(0, 16385, 18), -1);
  assert.equal(search_batch(0xffffffff, 1, 18), -1);

  const messages = [];
  let tick = 0;
  const self = {postMessage(message) { messages.push(message); }};
  const context = {
    self, Uint8Array, Number, Math, Error, Promise, setTimeout,
    performance: {now() { tick += 150; return tick; }},
    fetch: async () => ({ok: true, clone() { return this; }, arrayBuffer: async () => wasm}),
    WebAssembly: {
      instantiateStreaming: async () => WebAssembly.instantiate(wasm),
      instantiate: async () => WebAssembly.instantiate(wasm),
    },
  };
  vm.runInNewContext(workerSource, context);
  await self.onmessage({data: {nonce, bits: 18, wasm: "/browser_pow.wasm"}});
  assert.equal(messages[0].type, "ready");
  assert(messages.some((item) => item.type === "progress"));
  assert.equal(messages.at(-1).type, "solution");
  assert.equal(messages.at(-1).counter, 36440);

  messages.length = 0;
  context.fetch = async () => ({ok: false});
  await self.onmessage({data: {nonce, bits: 18, wasm: "/missing"}});
  assert.equal(messages.at(-1).type, "error");

  let submitted = false;
  let posted = "";
  const progress = {textContent: ""};
  const challengeText = {
    challenge_progress: "{0} guesses · {1}/s · {2}% chance of success by now",
    challenge_passed_continuing: "Challenge passed. Continuing...",
    challenge_passed_mobile: "Challenge passed. Click Finished on the original page.",
  };
  const page = {
    documentElement: {lang: "en"},
    body: {dataset: {challenge: `${nonce}.0.8.x`, session: "abc", worker: "/worker.js",
                     wasm: "/solver.wasm"}},
    querySelectorAll() {
      return Object.entries(challengeText).map(([name, textContent]) =>
        ({dataset: {name}, textContent}));
    },
    getElementById(id) {
      if (id === "progress") return progress;
      if (id === "finish") return {submit() { submitted = true; }};
      return null;
    },
  };
  const controller = fs.readFileSync(require("node:path").join(__dirname, "../challenge.js"), "utf8");
  vm.runInNewContext(controller, {
    document: page, TextEncoder, Uint8Array, Number, Math, Error, Promise, setTimeout, clearTimeout,
    performance: {now: () => Date.now()},
    Worker: class { constructor() { throw new Error("Worker unavailable"); } },
    WebAssembly,
    crypto: crypto.webcrypto,
    fetch: async (url) => { posted = url; return {ok: true}; },
  });
  for (let i = 0; i < 100 && !submitted; i++) await new Promise((resolve) => setTimeout(resolve, 10));
  assert(submitted, progress.textContent);
  assert.match(posted, /^\/ankah\/answer\/abc\?answer=\d+$/);

  submitted = false;
  posted = "";
  let terminated = false;
  class SuccessfulWorker {
    postMessage() {
      queueMicrotask(() => {
        this.onmessage({data: {type: "ready"}});
        this.onmessage({data: {type: "solution", counter: expected(0, 1000, 8),
                               guesses: expected(0, 1000, 8) + 1}});
      });
    }
    terminate() { terminated = true; }
  }
  vm.runInNewContext(controller, {
    document: page, TextEncoder, Uint8Array, Number, Math, Error, Promise, setTimeout, clearTimeout,
    performance: {now: () => Date.now()}, Worker: SuccessfulWorker, WebAssembly,
    crypto: {subtle: {digest() { throw new Error("Unexpected fallback"); }}},
    fetch: async (url) => { posted = url; return {ok: true}; },
  });
  for (let i = 0; i < 100 && !submitted; i++) await new Promise((resolve) => setTimeout(resolve, 10));
  assert(submitted && terminated, progress.textContent);
  assert.match(posted, /^\/ankah\/answer\/abc\?answer=\d+$/);
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
