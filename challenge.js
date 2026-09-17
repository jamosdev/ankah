/* Solve off the page thread when the browser supports the bundled module. */
(() => {
  "use strict";
  const challenge = document.body.dataset.challenge;
  const progress = document.getElementById("progress");
  const session = document.body.dataset.session;
  const mobile = document.body.dataset.mobile === "1";
  const panel = document.getElementById("phone-panel");
  const [nonce, , bitText] = challenge.split(".");
  const bits = Number(bitText);
  const encoder = new TextEncoder();
  let guesses = 0;
  const started = performance.now();

  if (panel) {
    panel.hidden = true;
    setTimeout(() => { panel.hidden = false; }, 10000);
  }

  function update() {
    const elapsed = Math.max((performance.now() - started) / 1000, 0.001);
    const rate = Math.round(guesses / elapsed);
    const chance = 100 * (1 - Math.exp(-guesses / (2 ** bits)));
    progress.textContent =
      `${guesses.toLocaleString()} guesses · ${rate.toLocaleString()}/s · ` +
      `${chance.toFixed(1)}% chance of success by now`;
  }

  function passes(hash) {
    const full = Math.floor(bits / 8);
    for (let i = 0; i < full; i++) if (hash[i] !== 0) return false;
    const remainder = bits % 8;
    return remainder === 0 || (hash[full] >>> (8 - remainder)) === 0;
  }

  async function solveWithWebCrypto() {
    if (!crypto.subtle) throw new Error("This browser cannot solve the challenge");
    guesses = 0;
    for (let counter = 0; counter < Number.MAX_SAFE_INTEGER; counter++) {
      const data = encoder.encode(`${nonce}:${counter}`);
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
      guesses++;
      if ((guesses & 255) === 0) update();
      if (passes(hash)) {
        update();
        return counter;
      }
    }
    throw new Error("Challenge search exhausted");
  }

  function solveWithWorker() {
    return new Promise((resolve, reject) => {
      const worker = new Worker(document.body.dataset.worker);
      let settled = false;
      const fail = (reason) => {
        if (settled) return;
        settled = true;
        clearTimeout(startup);
        worker.terminate();
        reject(reason);
      };
      const startup = setTimeout(() => fail(new Error("Solver startup timed out")), 5000);
      worker.onerror = () => fail(new Error("Solver worker failed"));
      worker.onmessage = ({data}) => {
        if (settled) return;
        if (data.type === "ready") {
          clearTimeout(startup);
        } else if (data.type === "progress" && Number.isSafeInteger(data.guesses)) {
          guesses = data.guesses;
          update();
        } else if (data.type === "solution" && Number.isSafeInteger(data.counter) &&
                   data.counter >= 0 && data.counter < 0xffffffff) {
          guesses = data.guesses;
          update();
          settled = true;
          clearTimeout(startup);
          worker.terminate();
          resolve(data.counter);
        } else if (data.type === "error") {
          fail(new Error(data.message || "Solver worker failed"));
        }
      };
      worker.postMessage({nonce, bits, wasm: document.body.dataset.wasm});
    });
  }

  async function solve() {
    if (!/^[0-9a-f]{32}$/.test(nonce) || !Number.isInteger(bits) ||
        bits < 8 || bits > 24) throw new Error("Invalid challenge");
    let counter;
    if (document.body.dataset.worker && document.body.dataset.wasm &&
        typeof Worker !== "undefined" && typeof WebAssembly !== "undefined") {
      try {
        counter = await solveWithWorker();
      } catch (_) {
        counter = await solveWithWebCrypto();
      }
    } else {
      counter = await solveWithWebCrypto();
    }
    progress.textContent = "Challenge passed. Continuing...";
    const endpoint = session
      ? `/ankah/answer/${session}?answer=${counter}`
      : `/ankah/open?challenge=${encodeURIComponent(challenge)}&answer=${counter}`;
    const response = await fetch(endpoint,
      {method: "POST", credentials: "same-origin", cache: "no-store"});
    if (!response.ok) throw new Error("The answer was rejected");
    if (mobile) {
      progress.textContent = "Challenge passed. Click Finished on the original page.";
    } else {
      document.getElementById("finish").submit();
    }
  }

  solve().catch((error) => {
    progress.textContent = error.message;
    if (panel) panel.hidden = false;
  });
})();
