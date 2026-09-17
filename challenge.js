/* Browser fallback solver. A WebAssembly worker will use the same wire format. */
(() => {
  "use strict";
  const challenge = document.body.dataset.challenge;
  const progress = document.getElementById("progress");
  const session = document.body.dataset.session;
  const mobile = document.body.dataset.mobile === "1";
  const panel = document.getElementById("phone-panel");
  if (panel) {
    panel.hidden = true;
    setTimeout(() => { panel.hidden = false; }, 10000);
  }
  const parts = challenge.split(".");
  const nonce = parts[0];
  const bits = Number(parts[2]);
  const encoder = new TextEncoder();
  let guesses = 0;
  let started = performance.now();

  function passes(hash) {
    const full = Math.floor(bits / 8);
    for (let i = 0; i < full; i++) {
      if (hash[i] !== 0) return false;
    }
    const remainder = bits % 8;
    return remainder === 0 || (hash[full] >>> (8 - remainder)) === 0;
  }

  function update() {
    const elapsed = Math.max((performance.now() - started) / 1000, 0.001);
    const rate = Math.round(guesses / elapsed);
    const chance = 100 * (1 - Math.exp(-guesses / (2 ** bits)));
    progress.textContent =
      `${guesses.toLocaleString()} guesses · ${rate.toLocaleString()}/s · ` +
      `${chance.toFixed(1)}% chance of success by now`;
  }

  async function solve() {
    if (!Number.isInteger(bits) || bits < 8 || bits > 24 || !crypto.subtle) {
      throw new Error("This browser cannot solve the challenge");
    }
    for (let counter = 0; counter < Number.MAX_SAFE_INTEGER; counter++) {
      const data = encoder.encode(`${nonce}:${counter}`);
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
      guesses++;
      if ((guesses & 255) === 0) update();
      if (passes(hash)) {
        update();
        progress.textContent = "Challenge passed. Continuing...";
        const endpoint = session
          ? `/ankah/answer/${session}?answer=${counter}`
          : `/ankah/open?challenge=${encodeURIComponent(challenge)}&answer=${counter}`;
        const response = await fetch(
          endpoint,
          { method: "POST", credentials: "same-origin", cache: "no-store" }
        );
        if (!response.ok) throw new Error("The answer was rejected");
        if (mobile) {
          progress.textContent = "Challenge passed. Click Finished on the original page.";
        } else {
          document.getElementById("finish").submit();
        }
        return;
      }
    }
    throw new Error("Challenge search exhausted");
  }

  solve().catch((error) => {
    progress.textContent = error.message;
    if (panel) panel.hidden = false;
  });
})();
