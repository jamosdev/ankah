"use strict";

self.onmessage = async ({data}) => {
  try {
    const {nonce, bits, wasm} = data;
    if (!/^[0-9a-f]{32}$/.test(nonce) || !Number.isInteger(bits) ||
        bits < 8 || bits > 24) throw new Error("Invalid challenge");
    const response = await fetch(wasm, {cache: "force-cache"});
    if (!response.ok) throw new Error("Solver unavailable");
    let loaded;
    if (WebAssembly.instantiateStreaming) {
      try {
        loaded = await WebAssembly.instantiateStreaming(response.clone());
      } catch (_) {
        loaded = await WebAssembly.instantiate(await response.arrayBuffer());
      }
    } else {
      loaded = await WebAssembly.instantiate(await response.arrayBuffer());
    }
    const {memory, nonce_buffer, search_batch} = loaded.instance.exports;
    if (!memory || !nonce_buffer || !search_batch) throw new Error("Invalid solver");
    const offset = nonce_buffer();
    if (offset + 32 > memory.buffer.byteLength) throw new Error("Invalid solver memory");
    const input = new Uint8Array(memory.buffer, offset, 32);
    for (let i = 0; i < 32; i++) input[i] = nonce.charCodeAt(i);
    self.postMessage({type: "ready"});
    let lastUpdate = performance.now();
    for (let start = 0; start < 0xffffffff;) {
      const count = Math.min(16384, 0xffffffff - start);
      const answer = search_batch(start, count, bits);
      if (answer !== -1) {
        self.postMessage({type: "solution", counter: answer >>> 0, guesses: (answer >>> 0) + 1});
        return;
      }
      start += count;
      const now = performance.now();
      if (now - lastUpdate >= 100) {
        self.postMessage({type: "progress", guesses: start});
        lastUpdate = now;
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    throw new Error("Solver range exhausted");
  } catch (error) {
    self.postMessage({type: "error", message: error.message});
  }
};
