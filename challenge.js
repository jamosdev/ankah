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
  const locale = document.documentElement.lang || "en";
  const languageText = new Map([...document.querySelectorAll("#challenge-text [data-name]")]
    .map((node) => [node.dataset.name, node.textContent]));
  const number = new Intl.NumberFormat(locale);
  const decimal = new Intl.NumberFormat(locale, {minimumFractionDigits: 1, maximumFractionDigits: 1});
  const text = (name, ...values) => {
    const result = languageText.get(name);
    if (!result) throw new Error("missing challenge text: " + name);
    return result.replace(/\{(\d+)\}/g, (_, index) => String(values[Number(index)]));
  };
  const failure = (name) => Object.assign(new Error(text(name)), {localized: true});
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
    progress.textContent = text("challenge_progress",
      number.format(guesses), number.format(rate), decimal.format(chance));
  }

  function passes(hash) {
    const full = Math.floor(bits / 8);
    for (let i = 0; i < full; i++) if (hash[i] !== 0) return false;
    const remainder = bits % 8;
    return remainder === 0 || (hash[full] >>> (8 - remainder)) === 0;
  }

  async function solveWithWebCrypto() {
    if (!crypto.subtle) throw failure("challenge_browser_unsupported");
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
    throw failure("challenge_search_exhausted");
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
      const startup = setTimeout(() => fail(failure("challenge_startup_timeout")), 5000);
      worker.onerror = () => fail(failure("challenge_worker_failed"));
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
          fail(failure(languageText.has(data.code) ?
            data.code : "challenge_worker_failed"));
        }
      };
      worker.postMessage({nonce, bits, wasm: document.body.dataset.wasm});
    });
  }

  async function solve() {
    if (!/^[0-9a-f]{32}$/.test(nonce) || !Number.isInteger(bits) ||
        bits < 8 || bits > 24) throw failure("challenge_invalid");
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
    progress.textContent = text("challenge_passed_continuing");
    const endpoint = session
      ? `/ankah/answer/${session}?answer=${counter}`
      : `/ankah/open?challenge=${encodeURIComponent(challenge)}&answer=${counter}`;
    const response = await fetch(endpoint,
      {method: "POST", credentials: "same-origin", cache: "no-store"});
    if (!response.ok) throw failure("challenge_answer_rejected");
    if (mobile) {
      progress.textContent = text("challenge_passed_mobile");
    } else {
      document.getElementById("finish").submit();
    }
  }

  solve().catch((error) => {
    progress.textContent = error.localized ? error.message : text("challenge_failed");
    if (panel) panel.hidden = false;
  });
})();
