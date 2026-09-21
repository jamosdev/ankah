"use strict";

(function () {
  const HOUR = 3600;
  const DAY = 86400;
  const POLL_MS = 1000;
  const LIVE_SAMPLES = 300;
  const RANGES = {
    live: { words: "over the last few minutes", note: "Rates between polls, last five minutes." },
    "24h": { unit: HOUR, count: 24, words: "over the last 24 hours",
             note: "Hourly averages, last 24 hours." },
    "7d": { unit: HOUR, count: 168, words: "over the last 7 days",
            note: "Hourly averages, last 7 days." },
    "30d": { unit: DAY, count: 30, words: "over the last 30 days",
             note: "Daily averages, last 30 days." },
    all: { unit: DAY, count: Infinity, words: "since the statistics epoch",
           note: "Daily averages since the statistics epoch." },
  };
  const HEAT_DAYS = { live: 2, "24h": 2, "7d": 7, "30d": 30, all: 30 };
  const RAMPS = {
    dark: ["#0d366b", "#104281", "#184f95", "#1c5cab", "#256abf", "#2a78d6", "#3987e5",
           "#5598e7", "#6da7ec", "#86b6ef", "#9ec5f4", "#b7d3f6", "#cde2fb"],
    light: ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5",
            "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b"],
  };
  const STATES = {
    reading: "Reading request",
    responding: "Responding",
    sending: "Sending file",
    uploading: "Receiving body",
    connecting: "Connecting upstream",
    forwarding: "Forwarding",
    tunnel: "WebSocket tunnel",
  };

  const $ = (id) => document.getElementById(id);

  function stored(area, key) {
    try {
      return window[area].getItem(key);
    } catch (error) {
      return null;
    }
  }

  function store(area, key, value) {
    try {
      if (value === null) window[area].removeItem(key);
      else window[area].setItem(key, value);
    } catch (error) {
      // Storage only remembers conveniences; the page works without it.
    }
  }

  const si = d3.format(".3~s");
  const grouped = d3.format(",");
  const percent = d3.format(".1%");
  const clockFormat = d3.timeFormat("%H:%M:%S");
  const hourFormat = d3.timeFormat("%a %-d %b, %H:%M");
  const dayFormat = d3.timeFormat("%a %-d %b");
  const utcDayFormat = d3.utcFormat("%a %-d %b UTC");
  const dateFormat = d3.timeFormat("%-d %b %Y, %H:%M");
  const tickFormats = [d3.timeFormat("%H:%M:%S"), d3.timeFormat("%H:%M"), d3.timeFormat("%a %-d"),
                       d3.timeFormat("%b"), d3.timeFormat("%Y")];

  /* Axis ticks in 24 hour time, naming the coarsest unit that changed. */
  function timeTick(date) {
    if (date.getSeconds()) return tickFormats[0](date);
    if (date.getMinutes() || date.getHours()) return tickFormats[1](date);
    if (date.getDate() !== 1) return tickFormats[2](date);
    return date.getMonth() ? tickFormats[3](date) : tickFormats[4](date);
  }

  function bytes(value) {
    if (value >= 1000) return `${si(value)}B`;
    if (value > 0 && value < 10) return `${d3.format(".2~f")(value)} B`;
    return `${Math.round(value)} B`;
  }

  function perSecond(value) {
    return `${bytes(value)}/s`;
  }

  function count(value) {
    return value < 10000 ? grouped(Math.round(value)) : si(value);
  }

  function rate(value) {
    if (value === 0) return "0";
    return value < 10 ? d3.format(".2~r")(value) : count(value);
  }

  function milliseconds(value) {
    return value < 10 ? `${d3.format(".1~f")(value)} ms` : `${grouped(Math.round(value))} ms`;
  }

  function age(ms) {
    const seconds = Math.max(0, Math.floor(ms / 1000));
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
    const hours = Math.floor(minutes / 60);
    if (hours < 48) return `${hours}h ${minutes % 60}m`;
    return `${Math.floor(hours / 24)}d ${hours % 24}h`;
  }

  const state = {
    token: null,
    schema: null,
    field: {},
    live: null,
    samples: [],
    hours: new Map(),
    days: new Map(),
    ringFirstDay: null,
    evicted: null,
    evictedDays: 0,
    fullHistory: false,
    epoch: null,
    range: "live",
    mask: stored("localStorage", "ankah-mask") === "1",
    timer: null,
    polling: false,
    historyPending: null,
  };
  const F = (name) => state.field[name];

  class Unauthorized extends Error {}

  async function api(path, method) {
    const response = await fetch(path, {
      method: method || "GET",
      headers: { Authorization: `Bearer ${state.token}` },
      cache: "no-store",
    });
    if (response.status === 401) throw new Unauthorized("unauthorized");
    if (!response.ok) throw new Error(`${path} answered ${response.status}`);
    return response.json();
  }

  function setStatus(text, error) {
    const status = $("status");
    status.textContent = text;
    status.classList.toggle("is-error", error);
  }

  function readToken() {
    const match = /(?:^|&)token=([0-9a-f]{64})(?:&|$)/.exec(location.hash.slice(1));
    if (match) {
      store("sessionStorage", "ankah-token", match[1]);
      history.replaceState(null, "", location.pathname + location.search);
      return match[1];
    }
    return stored("sessionStorage", "ankah-token");
  }

  function showLogin(message) {
    state.token = null;
    store("sessionStorage", "ankah-token", null);
    clearTimeout(state.timer);
    $("main").hidden = true;
    $("login").hidden = false;
    $("login-message").textContent = message;
    setStatus("Waiting for a token", false);
    $("token").focus();
  }

  function handleError(error) {
    if (error instanceof Unauthorized) {
      showLogin("The token was not accepted. Check the dashboard token file.");
      return;
    }
    setStatus("Connection lost, retrying", true);
  }

  async function loadSchema() {
    const schema = await api("/stats/schema");
    if (schema.v !== 1) throw new Error("unsupported statistics version");
    state.schema = schema;
    state.field = {};
    schema.fields.forEach((name, index) => {
      state.field[name] = index;
    });
  }

  async function loadHistory(full) {
    const days = full ? state.schema.day_capacity : 32;
    const history = await api(`/stats/history?hours=${state.schema.hour_capacity}&days=${days}`);
    state.hours = new Map();
    state.days = new Map();
    history.hours.rows.forEach((row, i) => state.hours.set(history.hours.first + i, row));
    history.days.rows.forEach((row, i) => state.days.set(history.days.first + i, row));
    state.epoch = history.epoch;
    state.evicted = history.evicted;
    state.evictedDays = history.evicted_days;
    state.ringFirstDay = full ? history.days.first : null;
    state.fullHistory = full;
  }

  function markLoading(loading) {
    for (const plot of document.querySelectorAll(".plot")) plot.classList.toggle("is-loading", loading);
  }

  function requestHistory() {
    if (state.historyPending) return;
    markLoading(true);
    state.historyPending = loadHistory(state.range === "all" || state.fullHistory)
      .catch(handleError)
      .finally(() => {
        state.historyPending = null;
        markLoading(false);
        render();
      });
  }

  /* Adds a live packet's completed buckets. Returns false when the page missed
   * buckets between polls and needs the history again. */
  function merge(map, series, size) {
    let highest = -Infinity;
    for (const index of map.keys()) if (index > highest) highest = index;
    series.rows.forEach((row, i) => map.set(series.first + i, row));
    if (!series.rows.length) return true;
    const expected = highest === -Infinity ? Math.floor(state.epoch / size) : highest + 1;
    return series.first <= expected;
  }

  function ingest(live) {
    if (live.v !== 1) throw new Error("unsupported statistics version");
    const previous = state.samples[state.samples.length - 1];
    const countersWentBack = previous && live.cumulative.some((value, field) =>
      state.schema.kinds[field] === "sum" && value < previous.c[field]);
    const clockWentBack = previous && live.sample_ms < previous.t;
    if (state.epoch !== null &&
        (live.epoch !== state.epoch || countersWentBack || clockWentBack)) {
      // A reset or a restart: every retained number belongs to the old epoch.
      state.samples = [];
      state.hours = new Map();
      state.days = new Map();
      state.ringFirstDay = null;
      state.evicted = null;
      state.evictedDays = 0;
      state.epoch = live.epoch;
      requestHistory();
    }
    state.epoch = live.epoch;
    const last = state.samples[state.samples.length - 1];
    if (!last || live.sample_ms > last.t) {
      state.samples.push({ t: live.sample_ms, at: Date.now(), c: live.cumulative, g: live.gauges });
      if (state.samples.length > LIVE_SAMPLES) state.samples.shift();
    }
    const hoursWhole = merge(state.hours, live.recent_hours, HOUR);
    const daysWhole = merge(state.days, live.recent_days, DAY);
    const newDay = state.live && live.day_index !== state.live.day_index;
    state.live = live;
    if (!hoursWhole || !daysWhole || (newDay && state.fullHistory)) requestHistory();
  }

  async function poll() {
    clearTimeout(state.timer);
    if (!state.token || state.polling) return;
    if (document.hidden) {
      setStatus("Paused while this tab is hidden", false);
      return;
    }
    state.polling = true;
    try {
      ingest(await api("/stats/live"));
      render();
      setStatus(`Live, updated ${clockFormat(new Date())}`, false);
    } catch (error) {
      state.polling = false;
      if (error instanceof Unauthorized) {
        handleError(error);
        return;
      }
      setStatus("Connection lost, retrying", true);
    }
    state.polling = false;
    state.timer = setTimeout(poll, POLL_MS);
  }

  async function start() {
    $("login").hidden = true;
    setStatus("Connecting", false);
    try {
      await loadSchema();
      await loadHistory(state.range === "all");
      $("main").hidden = false;
      poll();
    } catch (error) {
      handleError(error);
      if (!(error instanceof Unauthorized)) state.timer = setTimeout(start, 2000);
    }
  }

  /* One point per poll interval in live mode, or per bucket otherwise, oldest
   * first. `amounts` holds per field totals for the point. */
  function points() {
    const live = state.live;
    if (state.range === "live") {
      const list = [];
      for (let i = 1; i < state.samples.length; i += 1) {
        const a = state.samples[i - 1];
        const b = state.samples[i];
        const seconds = (b.t - a.t) / 1000;
        if (seconds <= 0) continue;
        list.push({ time: new Date(b.at), seconds, amounts: b.c.map((value, f) => value - a.c[f]),
                    connections: b.g.connections, label: clockFormat(new Date(b.at)) });
      }
      return list;
    }
    const spec = RANGES[state.range];
    const map = spec.unit === HOUR ? state.hours : state.days;
    const current = spec.unit === HOUR ? live.hour_index : live.day_index;
    const epochIndex = Math.floor(live.epoch / spec.unit);
    // Evicted days are represented by the summary band, not walked one by one.
    const retainedFirst = state.ringFirstDay === null ?
      current - state.schema.day_capacity : state.ringFirstDay;
    const first = spec.count === Infinity ? Math.max(epochIndex, retainedFirst) :
      Math.max(epochIndex, current - spec.count + 1);
    const list = [];
    for (let index = first; index <= current; index += 1) {
      const partial = index === current;
      const row = partial ? (spec.unit === HOUR ? live.current_hour : live.current_day) : map.get(index);
      if (!row) continue;
      const start = Math.max(index * spec.unit, live.epoch);
      const end = partial ? Math.max(live.now, start + 1) : (index + 1) * spec.unit;
      const begins = new Date(start * 1000);
      // Daily buckets are UTC days, so they are named as UTC dates.
      const label = (spec.unit === HOUR ? hourFormat(begins) : utcDayFormat(begins)) +
                    (partial ? ", so far" : "");
      list.push({ time: new Date(((start + end) / 2) * 1000), seconds: end - start, amounts: row,
                  connections: row[F("peak_connections")], label, index, start, end, partial,
                  unit: spec.unit });
    }
    return list;
  }

  /* Too many buckets for the plot width are merged into bins of whole buckets,
   * aligned to absolute bucket index so bins do not shift between polls. Sums add
   * and peaks take the maximum, so a bin's average rate is exact. */
  function binned(list, limit) {
    if (state.range === "live" || list.length <= limit) return list;
    const size = Math.ceil(list.length / limit);
    const kinds = state.schema.kinds;
    const bins = [];
    for (const point of list) {
      const key = Math.floor(point.index / size);
      const bin = bins[bins.length - 1];
      if (!bin || bin.key !== key) {
        bins.push({ key, first: point, last: point, seconds: point.seconds,
                    amounts: point.amounts.slice(), connections: point.connections });
        continue;
      }
      bin.last = point;
      bin.seconds += point.seconds;
      bin.connections = Math.max(bin.connections, point.connections);
      point.amounts.forEach((value, f) => {
        bin.amounts[f] = kinds[f] === "max" ? Math.max(bin.amounts[f], value) : bin.amounts[f] + value;
      });
    }
    return bins.map((bin) => {
      const name = (seconds) => (bin.first.unit === HOUR ? hourFormat : utcDayFormat)(new Date(seconds * 1000));
      const last = bin.last.index * bin.first.unit;
      return { time: new Date(((bin.first.start + bin.last.end) / 2) * 1000), seconds: bin.seconds,
               amounts: bin.amounts, connections: bin.connections,
               label: `${name(bin.first.start)} to ${name(Math.max(bin.first.start, last))}` +
                      (bin.last.partial ? ", so far" : "") };
    });
  }

  /* The merged record for days older than the daily history, drawn as a flat
   * average so it never reads as data at daily resolution. */
  function evictedBand() {
    if (state.range !== "all" || !state.evictedDays || state.ringFirstDay === null) return null;
    const start = state.live.epoch;
    const end = state.ringFirstDay * DAY;
    if (end <= start) return null;
    return { start: new Date(start * 1000), end: new Date(end * 1000), seconds: end - start,
             amounts: state.evicted, label: `Average before ${utcDayFormat(new Date(end * 1000))}` };
  }

  function totals(list, band) {
    const sums = state.schema.fields.map(() => 0);
    let seconds = 0;
    let peak = 0;
    const add = (amounts, span) => {
      seconds += span;
      amounts.forEach((value, f) => {
        if (state.schema.kinds[f] === "sum") sums[f] += value;
      });
    };
    for (const point of list) {
      add(point.amounts, point.seconds);
      peak = Math.max(peak, point.connections);
    }
    if (band) {
      add(band.amounts, band.seconds);
      peak = Math.max(peak, band.amounts[F("peak_connections")]);
    }
    return { sums, seconds, peak };
  }

  function render() {
    if (!state.live || !state.schema || $("main").hidden) return;
    const list = points();
    const band = evictedBand();
    const sum = totals(list, band);
    const width = chart("chart-throughput").plot.clientWidth || 600;
    const shown = binned(list, Math.max(24, Math.floor(width / 3)));
    renderHero(sum);
    renderMeters();
    renderTiles(shown, sum);
    renderThroughput(shown, band);
    renderConnections(shown, band);
    renderHeatmap();
    renderOpenConnections();
    const live = state.live;
    $("epoch-note").textContent = `Statistics since ${dateFormat(new Date(live.epoch * 1000))}, ` +
                                  `${age((live.now - live.epoch) * 1000)} ago.`;
  }

  function renderHero(sum) {
    const recent = state.samples.slice(-6);
    const value = $("hero-value");
    if (recent.length < 2) {
      value.textContent = "Measuring";
    } else {
      const a = recent[0];
      const b = recent[recent.length - 1];
      const out = b.c[F("client_bytes_out")] - a.c[F("client_bytes_out")];
      value.textContent = perSecond(out / ((b.t - a.t) / 1000));
    }
    const out = sum.sums[F("client_bytes_out")];
    const upstream = sum.sums[F("upstream_bytes_in")];
    const words = RANGES[state.range].words;
    $("hero-note").textContent = out > 0 ?
      `${percent(Math.max(0, Math.min(1, (out - upstream) / out)))} served by Ankah itself ${words}` :
      `Nothing sent to clients ${words}`;
  }

  function meter(id, value, limit, format, extra) {
    const root = $(id);
    const share = limit > 0 ? Math.min(1, value / limit) : 0;
    root.querySelector(".meter-value").textContent =
      limit > 0 ? `${format(value)} of ${format(limit)}` : "Disabled";
    root.querySelector(".fill").style.width = `${(share * 100).toFixed(1)}%`;
    root.classList.toggle("is-warning", share >= 0.7 && share < 0.9);
    root.classList.toggle("is-critical", share >= 0.9);
    root.querySelector(".meter-note").textContent =
      share >= 0.9 ? "At or near the limit" : share >= 0.7 ? "Approaching the limit" : extra || "";
  }

  function renderMeters() {
    const gauges = state.live.gauges;
    const limits = state.schema.limits;
    meter("meter-connections", gauges.connections, limits.connections, count,
          limits.tls_connections ? `${count(gauges.tls_connections)} TLS sockets open` : "");
    meter("meter-pending", gauges.pending_bytes, limits.pending_bytes, bytes,
          `${count(gauges.saved_posts)} saved, ${count(gauges.sessions)} challenge sessions`);
    meter("meter-cache", gauges.cache_bytes, limits.cache_bytes, bytes, "");
  }

  function spark(svgNode, values) {
    const svg = d3.select(svgNode);
    svg.selectAll("*").remove();
    const series = values.slice(-24);
    const usable = series.filter((value) => value !== null && Number.isFinite(value));
    if (usable.length < 2) return;
    const width = svgNode.getBoundingClientRect().width || 200;
    const height = 32;
    const x = d3.scaleLinear().domain([0, series.length - 1]).range([4, width - 4]);
    const y = d3.scaleLinear().domain([0, d3.max(usable) || 1]).range([height - 4, 4]);
    const defined = (value) => value !== null && Number.isFinite(value);
    svg.attr("viewBox", `0 0 ${width} ${height}`);
    svg.append("path").attr("d", d3.line().defined(defined).x((_, i) => x(i)).y((v) => y(v))(series));
    let last = series.length - 1;
    while (last > 0 && !defined(series[last])) last -= 1;
    svg.append("circle").attr("cx", x(last)).attr("cy", y(series[last])).attr("r", 3);
  }

  function tile(id, label, value, values) {
    const root = $(id);
    if (label) root.querySelector(".label").textContent = label;
    root.querySelector(".tile-value").textContent = value;
    spark(root.querySelector(".spark"), values);
  }

  function renderTiles(list, sum) {
    const live = state.range === "live";
    const ratio = (point, top, bottom) => {
      const below = point.amounts[F(bottom)];
      return below ? top(point) / below : null;
    };
    tile("tile-connections", live ? "Connections" : "Peak connections",
         count(live ? state.live.gauges.connections : sum.peak), list.map((p) => p.connections));
    tile("tile-requests", null, sum.seconds > 0 ? rate(sum.sums[F("requests")] / sum.seconds) : "0",
         list.map((p) => p.amounts[F("requests")] / p.seconds));
    const issued = sum.sums[F("challenges_issued")];
    const passed = (amounts) => amounts[F("challenges_solved")] + amounts[F("passes_issued")];
    tile("tile-challenges", null, issued ? percent(Math.min(1, passed(sum.sums) / issued)) : "None issued",
         list.map((p) => {
           const value = ratio(p, (point) => passed(point.amounts), "challenges_issued");
           return value === null ? null : Math.min(1, value);
         }));
    const responses = sum.sums[F("upstream_responses")];
    tile("tile-latency", null,
         responses ? milliseconds(sum.sums[F("upstream_latency_ms_total")] / responses) : "No responses",
         list.map((p) => ratio(p, (point) => point.amounts[F("upstream_latency_ms_total")],
                               "upstream_responses")));
  }

  /* Chart plumbing shared by the line charts and the heatmap. */
  const charts = {};

  function chart(id) {
    if (charts[id]) return charts[id];
    const card = $(id);
    const plot = card.querySelector(".plot");
    const svgNode = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svgNode.setAttribute("tabindex", "0");
    svgNode.setAttribute("role", "img");
    const tooltip = document.createElement("div");
    tooltip.className = "tooltip";
    tooltip.hidden = true;
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.hidden = true;
    plot.append(svgNode, tooltip, empty);
    const view = { card, plot, svgNode, svg: d3.select(svgNode), tooltip, empty,
                   table: false, focused: false, move: null, key: null, clear: null };
    const toggle = card.querySelector(".table-toggle");
    toggle.addEventListener("click", () => {
      view.table = !view.table;
      toggle.setAttribute("aria-pressed", String(view.table));
      plot.hidden = view.table;
      card.querySelector(".table-wrap").hidden = !view.table;
      const scale = card.querySelector(".scale");
      if (scale) scale.hidden = view.table;
      render();
    });
    svgNode.addEventListener("pointermove", (event) => {
      if (view.move) view.move(d3.pointer(event, svgNode));
    });
    svgNode.addEventListener("pointerleave", () => {
      if (!view.focused) hideTip(view);
    });
    svgNode.addEventListener("focus", () => {
      view.focused = true;
      if (view.key) view.key("Focus");
    });
    svgNode.addEventListener("blur", () => {
      view.focused = false;
      hideTip(view);
    });
    svgNode.addEventListener("keydown", (event) => {
      if (view.key && view.key(event.key)) event.preventDefault();
    });
    charts[id] = view;
    return view;
  }

  function hideTip(view) {
    view.tooltip.hidden = true;
    if (view.clear) view.clear();
  }

  function fillTip(view, when, rows, x) {
    const tip = view.tooltip;
    const head = document.createElement("div");
    head.className = "when";
    head.textContent = when;
    tip.replaceChildren(head);
    for (const row of rows) {
      const line = document.createElement("div");
      line.className = "row";
      if (row.key) {
        const key = document.createElement("span");
        key.className = `key ${row.key}`;
        line.append(key);
      }
      const value = document.createElement("strong");
      value.textContent = row.value;
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = row.name;
      line.append(value, name);
      tip.append(line);
    }
    tip.hidden = false;
    const width = view.plot.clientWidth;
    const left = x + 14 + tip.offsetWidth > width ? x - 14 - tip.offsetWidth : x + 14;
    tip.style.left = `${Math.max(0, left)}px`;
    tip.style.top = "8px";
  }

  function fillTable(view, headers, rows) {
    if (!view.table) return;
    const table = document.createElement("table");
    const head = table.createTHead().insertRow();
    headers.forEach((text, i) => {
      const cell = document.createElement("th");
      cell.textContent = text;
      if (i) cell.className = "number";
      head.append(cell);
    });
    const body = table.createTBody();
    for (const row of rows) {
      const line = body.insertRow();
      row.forEach((text, i) => {
        const cell = line.insertCell();
        cell.textContent = text;
        if (i) cell.className = "number";
      });
    }
    view.card.querySelector(".table-wrap").replaceChildren(table);
  }

  function legend(view, items) {
    const root = view.card.querySelector(".legend");
    root.replaceChildren();
    if (items.length < 2) return;
    for (const item of items) {
      const entry = document.createElement("span");
      const key = document.createElement("span");
      key.className = `key ${item.key}`;
      entry.append(key, document.createTextNode(item.name));
      root.append(entry);
    }
  }

  function showEmpty(view, message) {
    view.svg.selectAll("*").remove();
    view.svgNode.style.display = "none";
    view.empty.hidden = false;
    view.empty.textContent = message;
    view.move = view.key = view.clear = null;
    view.tooltip.hidden = true;
  }

  /* Series share one time axis; values may be null for gaps. */
  function lineChart(view, spec) {
    const { svg, svgNode } = view;
    if (spec.times.length < 2 && !spec.band) {
      showEmpty(view, "Not enough data yet. Points appear as polls and buckets complete.");
      return;
    }
    view.empty.hidden = true;
    svgNode.style.display = "";
    svgNode.setAttribute("aria-label", spec.label);
    svg.selectAll("*").remove();
    const width = Math.max(view.plot.clientWidth, 280);
    const height = 240;
    const margin = { top: 16, right: 76, bottom: 28, left: 64 };
    svg.attr("viewBox", `0 0 ${width} ${height}`).attr("height", height);
    const times = spec.times;
    const start = spec.band ? spec.band.start : times[0];
    const end = times.length ? times[times.length - 1] : spec.band.end;
    const x = d3.scaleTime().domain([start, end]).range([margin.left, width - margin.right]);
    const values = spec.series.flatMap((s) => s.values).concat(spec.band ? spec.band.values : []);
    const top = d3.max(values.filter((v) => v !== null && Number.isFinite(v))) || 1;
    const y = d3.scaleLinear().domain([0, top]).nice(4).range([height - margin.bottom, margin.top]);
    const ticks = spec.integer ? y.ticks(4).filter(Number.isInteger) : y.ticks(4);

    const grid = svg.append("g");
    for (const tick of ticks) {
      const at = Math.round(y(tick)) + 0.5;
      grid.append("line").attr("class", tick === 0 ? "baseline" : "grid-line")
        .attr("x1", margin.left).attr("x2", width - margin.right).attr("y1", at).attr("y2", at);
    }
    svg.append("g").attr("class", "axis").attr("transform", `translate(0,${height - margin.bottom})`)
      .call(d3.axisBottom(x).ticks(Math.max(2, Math.floor(width / 120))).tickFormat(timeTick)
        .tickSize(0).tickPadding(8));
    svg.append("g").attr("class", "axis").attr("transform", `translate(${margin.left},0)`)
      .call(d3.axisLeft(y).tickValues(ticks).tickFormat(spec.tick).tickSize(0).tickPadding(8));

    if (spec.band) {
      const x0 = x(spec.band.start);
      const x1 = x(spec.band.end);
      const high = d3.max(spec.band.values);
      svg.append("rect").attr("class", "band-fill").attr("x", x0).attr("y", y(high))
        .attr("width", Math.max(0, x1 - x0)).attr("height", Math.max(0, y(0) - y(high)));
      for (const value of spec.band.values) {
        svg.append("line").attr("class", "band-line").attr("x1", x0).attr("x2", x1)
          .attr("y1", y(value)).attr("y2", y(value));
      }
      svg.append("text").attr("class", "band-label").attr("x", x0 + 6).attr("y", y(high) - 8)
        .text(spec.band.label);
    }

    const defined = (d) => d[1] !== null && Number.isFinite(d[1]);
    for (const series of spec.series) {
      const data = times.map((time, i) => [time, series.values[i]]);
      if (spec.series.length === 1) {
        svg.append("path").attr("class", `area ${series.key}`).attr("d", d3.area().defined(defined)
          .x((d) => x(d[0])).y0(y(0)).y1((d) => y(d[1])).curve(d3.curveMonotoneX)(data));
      }
      svg.append("path").attr("class", `line ${series.key}`).attr("d", d3.line().defined(defined)
        .x((d) => x(d[0])).y((d) => y(d[1])).curve(d3.curveMonotoneX)(data));
    }

    // Endpoint values, dropped when two ends would collide.
    const ends = spec.series.map((series) => {
      let i = series.values.length - 1;
      while (i >= 0 && !defined([0, series.values[i]])) i -= 1;
      return i >= 0 ? { series, time: times[i], value: series.values[i] } : null;
    }).filter(Boolean);
    const crowded = ends.length === 2 && Math.abs(y(ends[0].value) - y(ends[1].value)) < 16;
    for (const item of ends) {
      svg.append("circle").attr("class", `dot ${item.series.key}`)
        .attr("cx", x(item.time)).attr("cy", y(item.value)).attr("r", 4);
      if (!crowded) {
        svg.append("text").attr("class", "end-label").attr("x", x(item.time) + 9)
          .attr("y", y(item.value) + 4).text(spec.format(item.value));
      }
    }

    const crosshair = svg.append("line").attr("class", "crosshair")
      .attr("y1", margin.top).attr("y2", height - margin.bottom).style("display", "none");
    const markers = spec.series.map((series) =>
      svg.append("circle").attr("class", `dot ${series.key}`).attr("r", 4).style("display", "none"));
    const nearest = d3.bisector((d) => d).center;

    function show(index) {
      if (!times.length) return;
      const i = Math.max(0, Math.min(times.length - 1, index));
      view.index = i;
      view.time = times[i];
      const cx = x(times[i]);
      crosshair.attr("x1", cx).attr("x2", cx).style("display", null);
      spec.series.forEach((series, s) => {
        const value = series.values[i];
        if (value === null || !Number.isFinite(value)) markers[s].style("display", "none");
        else markers[s].attr("cx", cx).attr("cy", y(value)).style("display", null);
      });
      fillTip(view, spec.when(i), spec.series.map((series) => ({
        key: spec.series.length > 1 ? series.key : null,
        name: series.name,
        value: series.values[i] === null ? "No data" : spec.format(series.values[i]),
      })), cx);
    }

    view.clear = () => {
      view.time = null;
      crosshair.style("display", "none");
      for (const marker of markers) marker.style("display", "none");
    };
    view.move = ([px]) => show(nearest(times, x.invert(px)));
    view.key = (key) => {
      const last = times.length - 1;
      const current = view.time ? nearest(times, view.time) : last;
      if (key === "Focus") show(current);
      else if (key === "ArrowLeft") show(current - 1);
      else if (key === "ArrowRight") show(current + 1);
      else if (key === "Home") show(0);
      else if (key === "End") show(last);
      else if (key === "Escape") hideTip(view);
      else return false;
      return true;
    };
    if (view.time) show(nearest(times, view.time));
  }

  function renderThroughput(list, band) {
    const view = chart("chart-throughput");
    const out = list.map((p) => p.amounts[F("client_bytes_out")] / p.seconds);
    const upstream = list.map((p) => p.amounts[F("upstream_bytes_in")] / p.seconds);
    const items = [{ key: "series-1", name: "To clients" }, { key: "series-2", name: "From the application" }];
    legend(view, band ? items.concat({ key: "band", name: "Average before daily history" }) : items);
    lineChart(view, {
      label: "Throughput to clients and from the application",
      times: list.map((p) => p.time),
      series: [{ key: "series-1", name: "to clients", values: out },
               { key: "series-2", name: "from the application", values: upstream }],
      band: band && { start: band.start, end: band.end, label: band.label,
                      values: [band.amounts[F("client_bytes_out")] / band.seconds,
                               band.amounts[F("upstream_bytes_in")] / band.seconds] },
      format: perSecond,
      tick: (v) => (v === 0 ? "0" : perSecond(v)),
      when: (i) => list[i].label,
    });
    const rows = list.map((p, i) => [p.label, perSecond(out[i]), perSecond(upstream[i])]);
    if (band) {
      rows.unshift([band.label, perSecond(band.amounts[F("client_bytes_out")] / band.seconds),
                    perSecond(band.amounts[F("upstream_bytes_in")] / band.seconds)]);
    }
    fillTable(view, ["Time", "To clients", "From the application"], rows);
  }

  function renderConnections(list, band) {
    const view = chart("chart-connections");
    const live = state.range === "live";
    $("connections-title").textContent = live ? "Connections" : "Peak connections";
    legend(view, band ? [{ key: "series-1", name: "Peak connections" },
                         { key: "band", name: "Peak before daily history" }] : []);
    const values = list.map((p) => p.connections);
    lineChart(view, {
      label: live ? "Open connections" : "Peak connections per period",
      times: list.map((p) => p.time),
      series: [{ key: "series-1", name: live ? "open" : "peak", values }],
      band: band && { start: band.start, end: band.end, label: band.label.replace("Average", "Peak"),
                      values: [band.amounts[F("peak_connections")]] },
      format: count,
      tick: (v) => count(v),
      integer: true,
      when: (i) => list[i].label,
    });
    fillTable(view, ["Time", live ? "Open" : "Peak"], list.map((p) => [p.label, count(p.connections)]));
  }

  function theme() {
    const chosen = document.documentElement.dataset.theme;
    if (chosen) return chosen;
    return matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function renderHeatmap() {
    const view = chart("chart-heatmap");
    const live = state.live;
    const dayCount = HEAT_DAYS[state.range];
    const today = new Date(live.now * 1000);
    today.setHours(0, 0, 0, 0);
    const days = [];
    for (let i = dayCount - 1; i >= 0; i -= 1) {
      const day = new Date(today);
      day.setDate(day.getDate() - i);
      days.push(day);
    }
    const dayKey = (date) => `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`;
    const rows = new Map(days.map((day, i) => [dayKey(day), i]));
    const field = F("client_bytes_out");
    // Two UTC hours share a local hour when clocks go back, so cells add up.
    const cells = new Map();
    const add = (index, values, partial) => {
      const begins = new Date(index * HOUR * 1000);
      const row = rows.get(dayKey(begins));
      if (row === undefined) return;
      const column = begins.getHours();
      const key = row * 24 + column;
      const cell = cells.get(key) || { row, column, value: 0, begins, partial: false };
      cell.value += values[field];
      cell.partial = cell.partial || partial;
      cells.set(key, cell);
    };
    state.hours.forEach((values, index) => add(index, values, false));
    add(live.hour_index, live.current_hour, true);

    const list = [...cells.values()].sort((a, b) => a.begins - b.begins);
    const describe = (cell) => `${hourFormat(cell.begins)}${cell.partial ? ", so far" : ""}`;
    fillTable(view, ["Hour starting", "Bytes to clients"], list.map((cell) => [describe(cell), bytes(cell.value)]));
    if (!list.length) {
      showEmpty(view, "No hourly data yet.");
      view.card.querySelector(".scale").replaceChildren();
      return;
    }
    const { svg, svgNode } = view;
    view.empty.hidden = true;
    svgNode.style.display = "";
    svgNode.setAttribute("aria-label", "Bytes sent to clients in each hour, by day");
    svg.selectAll("*").remove();
    const width = Math.max(view.plot.clientWidth, 280);
    const narrow = width < 520;
    const rowLabel = narrow ? d3.timeFormat("%a %-d") : dayFormat;
    const margin = { top: 4, right: 4, bottom: 24, left: narrow ? 52 : 92 };
    const cellWidth = (width - margin.left - margin.right) / 24;
    const rowHeight = Math.max(12, Math.min(26, cellWidth * 0.75));
    const height = margin.top + rowHeight * days.length + margin.bottom;
    svg.attr("viewBox", `0 0 ${width} ${height}`).attr("height", height);
    const max = d3.max(list, (cell) => cell.value) || 0;
    const ramp = RAMPS[theme()];
    const color = max > 0 ?
      d3.scaleLinear().domain(ramp.map((_, i) => (max * i) / (ramp.length - 1))).range(ramp).clamp(true) :
      () => ramp[0];
    const cx = (column) => margin.left + column * cellWidth;
    const cy = (row) => margin.top + row * rowHeight;

    for (let row = 0; row < days.length; row += 1) {
      svg.append("text").attr("class", "axis-label").attr("x", margin.left - 8)
        .attr("y", cy(row) + rowHeight / 2 + 4).attr("text-anchor", "end").text(rowLabel(days[row]));
      for (let column = 0; column < 24; column += 1) {
        if (cells.has(row * 24 + column)) continue;
        svg.append("rect").attr("class", "cell cell-empty").attr("x", cx(column) + 1).attr("y", cy(row) + 1)
          .attr("width", Math.max(1, cellWidth - 2)).attr("height", Math.max(1, rowHeight - 2)).attr("rx", 2);
      }
    }
    const every = cellWidth * 3 >= 44 ? 3 : 6;
    for (let column = 0; column < 24; column += every) {
      svg.append("text").attr("class", "axis-label").attr("x", cx(column) + 1)
        .attr("y", height - 8).text(`${String(column).padStart(2, "0")}:00`);
    }
    for (const cell of list) {
      svg.append("rect").attr("class", "cell").attr("fill", color(cell.value))
        .attr("x", cx(cell.column) + 1).attr("y", cy(cell.row) + 1)
        .attr("width", Math.max(1, cellWidth - 2)).attr("height", Math.max(1, rowHeight - 2)).attr("rx", 2);
    }
    const outline = svg.append("rect").attr("class", "cell is-active").attr("fill", "none")
      .attr("width", Math.max(1, cellWidth - 2)).attr("height", Math.max(1, rowHeight - 2)).attr("rx", 2)
      .style("display", "none");

    function show(row, column) {
      const r = Math.max(0, Math.min(days.length - 1, row));
      const c = Math.max(0, Math.min(23, column));
      view.cell = [r, c];
      outline.attr("x", cx(c) + 1).attr("y", cy(r) + 1).style("display", null);
      const cell = cells.get(r * 24 + c);
      const begins = new Date(days[r]);
      begins.setHours(c);
      fillTip(view, cell ? describe(cell) : hourFormat(begins), [{
        key: null, name: "to clients", value: cell ? bytes(cell.value) : "No data",
      }], cx(c) + cellWidth);
    }
    view.clear = () => {
      view.cell = null;
      outline.style("display", "none");
    };
    view.move = ([px, py]) => {
      const column = Math.floor((px - margin.left) / cellWidth);
      const row = Math.floor((py - margin.top) / rowHeight);
      if (column < 0 || column > 23 || row < 0 || row >= days.length) hideTip(view);
      else show(row, column);
    };
    view.key = (key) => {
      const [row, column] = view.cell || [days.length - 1, new Date(live.now * 1000).getHours()];
      if (key === "Focus") show(row, column);
      else if (key === "ArrowLeft") show(row, column - 1);
      else if (key === "ArrowRight") show(row, column + 1);
      else if (key === "ArrowUp") show(row - 1, column);
      else if (key === "ArrowDown") show(row + 1, column);
      else if (key === "Escape") hideTip(view);
      else return false;
      return true;
    };
    if (view.cell) show(view.cell[0], view.cell[1]);

    const scale = view.card.querySelector(".scale");
    const low = document.createElement("span");
    low.className = "note";
    low.textContent = "0";
    const high = document.createElement("span");
    high.className = "note";
    high.textContent = bytes(max);
    const steps = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    steps.setAttribute("viewBox", `0 0 ${ramp.length * 12} 10`);
    steps.setAttribute("aria-hidden", "true");
    steps.setAttribute("preserveAspectRatio", "none");
    ramp.forEach((fill, i) => {
      const step = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      step.setAttribute("x", String(i * 12));
      step.setAttribute("width", "12");
      step.setAttribute("height", "10");
      step.setAttribute("fill", fill);
      steps.append(step);
    });
    scale.replaceChildren(low, steps, high);
  }

  function masked(ip) {
    if (!state.mask || ip === "?") return ip;
    const tail = ip.slice(ip.lastIndexOf(":") + 1);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(tail)) {
      const parts = tail.split(".");
      return `${parts[0]}.${parts[1]}.x.x`;
    }
    const groups = ip.split(":").filter(Boolean);
    return `${groups.slice(0, 2).join(":")}:x::`;
  }

  function renderOpenConnections() {
    const body = $("connections-body");
    body.replaceChildren();
    const top = state.live.top;
    if (!top.length) {
      const cell = body.insertRow().insertCell();
      cell.colSpan = 5;
      cell.className = "note";
      cell.textContent = "No open connections";
    }
    for (const item of top) {
      const row = body.insertRow();
      const values = [masked(item.ip), STATES[item.state] || item.state, age(item.age_ms),
                      bytes(item.in), bytes(item.out)];
      values.forEach((text, i) => {
        const cell = row.insertCell();
        cell.textContent = text;
        if (i > 1) cell.className = "number";
      });
    }
    const other = state.live.top_other;
    $("connections-note").textContent = other.count ?
      `${count(other.count)} more open connections moved ${bytes(other.in)} in and ${bytes(other.out)} out.` : "";
  }

  let particleConfig = null;

  async function startParticles() {
    if (typeof window.particlesJS !== "function" ||
        matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (!particleConfig) {
      try {
        const response = await fetch("/dashboard/particlejs.json");
        particleConfig = await response.json();
      } catch (error) {
        return;
      }
    }
    const config = JSON.parse(JSON.stringify(particleConfig));
    const ink = theme() === "dark" ? "#c3cad6" : "#6b6a65";
    config.particles.number.value = 60;
    config.particles.color.value = ink;
    config.particles.opacity.value = 0.22;
    config.particles.line_linked.color = ink;
    config.particles.line_linked.opacity = 0.1;
    config.particles.move.speed = 1.2;
    config.interactivity.events.onhover.enable = false;
    config.interactivity.events.onclick.enable = false;
    const running = window.pJSDom || [];
    window.pJSDom = [];
    for (const item of running) item.pJS.fn.vendors.destroypJS();
    window.pJSDom = [];
    window.particlesJS("particles", config);
  }

  function applyTheme(chosen) {
    if (chosen) document.documentElement.dataset.theme = chosen;
    else delete document.documentElement.dataset.theme;
    $("theme").textContent = theme() === "dark" ? "Light theme" : "Dark theme";
    startParticles();
    render();
  }

  $("theme").addEventListener("click", () => {
    const next = theme() === "dark" ? "light" : "dark";
    store("localStorage", "ankah-theme", next);
    applyTheme(next);
  });
  matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
    if (!document.documentElement.dataset.theme) applyTheme(null);
  });

  $("mask").setAttribute("aria-pressed", String(state.mask));
  $("mask").addEventListener("click", () => {
    state.mask = !state.mask;
    $("mask").setAttribute("aria-pressed", String(state.mask));
    store("localStorage", "ankah-mask", state.mask ? "1" : "0");
    render();
  });

  for (const button of document.querySelectorAll("[data-range]")) {
    button.addEventListener("click", () => {
      state.range = button.dataset.range;
      for (const other of document.querySelectorAll("[data-range]")) {
        other.setAttribute("aria-pressed", String(other === button));
      }
      $("range-note").textContent = RANGES[state.range].note;
      for (const view of Object.values(charts)) {
        view.time = null;
        view.cell = null;
        hideTip(view);
      }
      if (state.range === "all" && !state.fullHistory) requestHistory();
      else render();
    });
  }

  let resetTimer = null;
  $("reset").addEventListener("click", async () => {
    const button = $("reset");
    if (!button.classList.contains("is-armed")) {
      button.classList.add("is-armed");
      button.textContent = "Confirm reset";
      resetTimer = setTimeout(() => {
        button.classList.remove("is-armed");
        button.textContent = "Reset statistics";
      }, 4000);
      return;
    }
    clearTimeout(resetTimer);
    button.classList.remove("is-armed");
    button.textContent = "Reset statistics";
    try {
      const result = await api("/stats/reset", "POST");
      const warning = $("persistence-warning");
      warning.hidden = result.persistence !== "failed";
      warning.textContent = result.persistence === "failed"
        ? "Statistics were reset in memory, but the snapshot could not be updated. Older data may return after a restart."
        : "";
      state.samples = [];
      await loadHistory(state.fullHistory);
      poll();
    } catch (error) {
      handleError(error);
    }
  });

  $("login").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = $("token").value.trim();
    $("token").value = "";
    if (!/^[0-9a-f]{64}$/.test(value)) {
      $("login-message").textContent = "The token is 64 lowercase hexadecimal characters.";
      return;
    }
    state.token = value;
    store("sessionStorage", "ankah-token", value);
    start();
  });

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.token && state.schema) poll();
  });
  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(render, 150);
  });

  $("range-note").textContent = RANGES[state.range].note;
  applyTheme(stored("localStorage", "ankah-theme"));
  state.token = readToken();
  if (state.token) start();
  else showLogin("Enter the token from the dashboard token file.");
})();
