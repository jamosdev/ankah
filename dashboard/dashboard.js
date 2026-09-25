// SPDX-License-Identifier: LGPL-3.0-only

"use strict";

(function () {
  const HOUR = 3600;
  const DAY = 86400;
  const POLL_MS = 1000;
  const LIVE_SAMPLES = 300;
  const locale = document.documentElement.lang || "en";
  const languageText = new Map([...document.querySelectorAll("#language-text [data-name]")]
    .map((node) => [node.dataset.name, node.textContent]));
  const text = (name, ...values) => {
    const result = languageText.get(name);
    if (!result) throw new Error(`missing dashboard text: ${name}`);
    return result.replace(/\{(\d+)\}/g, (placeholder, rawIndex) => {
      const index = Number(rawIndex);
      if (index >= values.length) throw new Error(`missing value for ${name}: ${placeholder}`);
      return String(values[index]);
    });
  };
  const RANGES = {
    live: { words: text("range_live_words"), note: text("range_live_note") },
    "24h": { unit: HOUR, count: 24, words: text("range_24h_words"),
             note: text("range_24h_note") },
    "7d": { unit: HOUR, count: 168, words: text("range_7d_words"),
            note: text("range_7d_note") },
    "30d": { unit: DAY, count: 30, words: text("range_30d_words"),
             note: text("range_30d_note") },
    all: { unit: DAY, count: Infinity, words: text("range_all_words"),
           note: text("range_all_note") },
  };
  const HEAT_DAYS = { live: 2, "24h": 2, "7d": 7, "30d": 30, all: 30 };
  const RAMPS = {
    dark: ["#0d366b", "#104281", "#184f95", "#1c5cab", "#256abf", "#2a78d6", "#3987e5",
           "#5598e7", "#6da7ec", "#86b6ef", "#9ec5f4", "#b7d3f6", "#cde2fb"],
    light: ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5",
            "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b"],
  };
  const STATES = {
    reading: text("reading_request"),
    responding: text("responding"),
    sending: text("sending_file"),
    uploading: text("receiving_body"),
    connecting: text("connecting_upstream"),
    forwarding: text("forwarding"),
    tunnel: text("websocket_tunnel"),
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

  const compact = new Intl.NumberFormat(locale,
    {notation: "compact", maximumSignificantDigits: 3}).format;
  const grouped = new Intl.NumberFormat(locale, {maximumFractionDigits: 0}).format;
  const decimalTwo = new Intl.NumberFormat(locale, {maximumFractionDigits: 2}).format;
  const decimalOne = new Intl.NumberFormat(locale, {maximumFractionDigits: 1}).format;
  const significantTwo = new Intl.NumberFormat(locale, {maximumSignificantDigits: 2}).format;
  const percent = new Intl.NumberFormat(locale,
    {style: "percent", minimumFractionDigits: 1, maximumFractionDigits: 1}).format;
  const date = (options) => new Intl.DateTimeFormat(locale, options).format;
  const clockFormat = date({hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23"});
  const hourFormat = date({weekday: "short", day: "numeric", month: "short",
                           hour: "2-digit", minute: "2-digit", hourCycle: "h23"});
  const dayFormat = date({weekday: "short", day: "numeric", month: "short"});
  const utcDay = date({weekday: "short", day: "numeric", month: "short", timeZone: "UTC"});
  const utcDayFormat = (value) => utcDay(value) + " UTC";
  const dateFormat = date({day: "numeric", month: "short", year: "numeric",
                           hour: "2-digit", minute: "2-digit", hourCycle: "h23"});
  const tickFormats = [clockFormat,
    date({hour: "2-digit", minute: "2-digit", hourCycle: "h23"}),
    date({weekday: "short", day: "numeric"}),
    date({month: "short"}), date({year: "numeric"})];

  /* Axis ticks in 24 hour time, naming the coarsest unit that changed. */
  function timeTick(date) {
    if (date.getSeconds()) return tickFormats[0](date);
    if (date.getMinutes() || date.getHours()) return tickFormats[1](date);
    if (date.getDate() !== 1) return tickFormats[2](date);
    return date.getMonth() ? tickFormats[3](date) : tickFormats[4](date);
  }

  function bytes(value) {
    if (value >= 1000) return `${compact(value)} B`;
    if (value > 0 && value < 10) return `${decimalTwo(value)} B`;
    return `${grouped(Math.round(value))} B`;
  }

  function perSecond(value) {
    return `${bytes(value)}/s`;
  }

  function count(value) {
    return value < 10000 ? grouped(Math.round(value)) : compact(value);
  }

  function rate(value) {
    if (value === 0) return "0";
    return value < 10 ? significantTwo(value) : count(value);
  }

  function milliseconds(value) {
    return value < 10 ? `${decimalOne(value)} ms` : `${grouped(Math.round(value))} ms`;
  }

  function age(ms) {
    const seconds = Math.max(0, Math.floor(ms / 1000));
    if (seconds < 60) return text("age_seconds", grouped(seconds));
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return text("age_minutes", grouped(minutes), grouped(seconds % 60));
    const hours = Math.floor(minutes / 60);
    if (hours < 48) return text("age_hours", grouped(hours), grouped(minutes % 60));
    return text("age_days", grouped(Math.floor(hours / 24)), grouped(hours % 24));
  }

  const state = {
    token: null,
    bearer: false,
    setupPending: false,
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
      store("sessionStorage", "ankah-bearer", "1");
      history.replaceState(null, "", location.pathname + location.search);
      return match[1];
    }
    return stored("sessionStorage", "ankah-token");
  }

  function showLogin(message) {
    state.token = null;
    state.bearer = false;
    state.setupPending = false;
    store("sessionStorage", "ankah-token", null);
    store("sessionStorage", "ankah-bearer", null);
    clearTimeout(state.timer);
    $("export").hidden = true;
    $("setup").hidden = true;
    $("signout").hidden = true;
    $("main").hidden = true;
    $("login").hidden = false;
    $("token-login").hidden = true;
    $("login-mode").hidden = false;
    $("login-mode").textContent = text("use_dashboard_token");
    $("token-login").querySelector("p").textContent = text("enter_token");
    $("login-message").textContent = message;
    setStatus(text("waiting_token"), false);
    $("code").focus();
  }

  function handleError(error) {
    if (error instanceof Unauthorized) {
      const bearer = state.bearer;
      showLogin(text("enter_code"));
      if (bearer) {
        $("login-mode").click();
        $("token-login").querySelector("p").textContent = text("token_rejected");
      }
      return;
    }
    setStatus(text("connection_lost"), true);
  }

  async function loadSchema() {
    const schema = await api("stats/schema");
    if (schema.v !== 3) throw new Error("unsupported statistics version");
    state.schema = schema;
    state.field = {};
    schema.fields.forEach((name, index) => {
      state.field[name] = index;
    });
  }

  async function loadHistory(full) {
    const days = full ? state.schema.day_capacity : 32;
    const history = await api(`stats/history?hours=${state.schema.hour_capacity}&days=${days}`);
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
    if (live.v !== 3) throw new Error("unsupported statistics version");
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
      setStatus(text("paused"), false);
      return;
    }
    state.polling = true;
    try {
      ingest(await api("stats/live"));
      render();
      setStatus(text("live_updated", clockFormat(new Date())), false);
    } catch (error) {
      state.polling = false;
      if (error instanceof Unauthorized) {
        handleError(error);
        return;
      }
      setStatus(text("connection_lost"), true);
    }
    state.polling = false;
    state.timer = setTimeout(poll, POLL_MS);
  }

  async function start() {
    $("login").hidden = true;
    $("token-login").hidden = true;
    $("login-mode").hidden = true;
    setStatus(text("connecting"), false);
    try {
      await loadSchema();
      await loadHistory(state.range === "all");
      $("export").hidden = false;
      $("setup").hidden = !state.bearer;
      $("signout").hidden = false;
      $("main").hidden = false;
      poll();
      if (state.setupPending) {
        state.setupPending = false;
        $("setup").click();
      }
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
                    connections: b.g.connections,
                    throttleConnections: b.g.throttle_connections,
                    throttleQueue: b.g.throttle_queue,
                    label: clockFormat(new Date(b.at)) });
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
                    (partial ? text("so_far") : "");
      list.push({ time: new Date(((start + end) / 2) * 1000), seconds: end - start, amounts: row,
                  connections: row[F("peak_connections")], label, index, start, end, partial,
                  throttleConnections: row[F("peak_throttle_connections")],
                  throttleQueue: row[F("peak_throttle_queue")],
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
                    amounts: point.amounts.slice(), connections: point.connections,
                    throttleConnections: point.throttleConnections,
                    throttleQueue: point.throttleQueue });
        continue;
      }
      bin.last = point;
      bin.seconds += point.seconds;
      bin.connections = Math.max(bin.connections, point.connections);
      bin.throttleConnections = Math.max(bin.throttleConnections, point.throttleConnections);
      bin.throttleQueue = Math.max(bin.throttleQueue, point.throttleQueue);
      point.amounts.forEach((value, f) => {
        bin.amounts[f] = kinds[f] === "max" ? Math.max(bin.amounts[f], value) : bin.amounts[f] + value;
      });
    }
    return bins.map((bin) => {
      const name = (seconds) => (bin.first.unit === HOUR ? hourFormat : utcDayFormat)(new Date(seconds * 1000));
      const last = bin.last.index * bin.first.unit;
      return { time: new Date(((bin.first.start + bin.last.end) / 2) * 1000), seconds: bin.seconds,
               amounts: bin.amounts, connections: bin.connections,
               throttleConnections: bin.throttleConnections,
               throttleQueue: bin.throttleQueue,
               label: text("range_between", name(bin.first.start),
                           name(Math.max(bin.first.start, last))) +
                      (bin.last.partial ? text("so_far") : "") };
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
             amounts: state.evicted,
             label: text("average_before", utcDayFormat(new Date(end * 1000))) };
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
    renderThrottle(shown, band);
    renderHeatmap();
    renderOpenConnections();
    const live = state.live;
    $("epoch-note").textContent = text("statistics_since",
      dateFormat(new Date(live.epoch * 1000)), age((live.now - live.epoch) * 1000));
  }

  function renderHero(sum) {
    const recent = state.samples.slice(-6);
    const value = $("hero-value");
    if (recent.length < 2) {
      value.textContent = text("measuring");
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
      text("served_itself", percent(Math.max(0, Math.min(1, (out - upstream) / out))), words) :
      text("nothing_sent", words);
  }

  function meter(id, value, limit, format, extra) {
    const root = $(id);
    const share = limit > 0 ? Math.min(1, value / limit) : 0;
    root.querySelector(".meter-value").textContent =
      limit > 0 ? text("of", format(value), format(limit)) : text("disabled");
    root.querySelector(".fill").style.width = `${(share * 100).toFixed(1)}%`;
    root.classList.toggle("is-warning", share >= 0.7 && share < 0.9);
    root.classList.toggle("is-critical", share >= 0.9);
    root.querySelector(".meter-note").textContent =
      share >= 0.9 ? text("at_limit") : share >= 0.7 ? text("approaching_limit") : extra || "";
  }

  function renderMeters() {
    const gauges = state.live.gauges;
    const limits = state.schema.limits;
    meter("meter-connections", gauges.connections, limits.connections, count,
          limits.tls_connections ? text("tls_open", count(gauges.tls_connections)) : "");
    meter("meter-pending", gauges.pending_bytes, limits.pending_bytes, bytes,
          text("saved_sessions", count(gauges.saved_posts), count(gauges.sessions)));
    meter("meter-cache", gauges.cache_bytes, limits.cache_bytes, bytes, "");
    meter("meter-throttle-connections", gauges.throttle_connections,
          limits.throttle_connections, count, "");
    meter("meter-throttle-queue", gauges.throttle_queue,
          limits.throttle_queue, count, "");
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
    tile("tile-connections", live ? text("connections") : text("peak_connections"),
         count(live ? state.live.gauges.connections : sum.peak), list.map((p) => p.connections));
    tile("tile-requests", null, sum.seconds > 0 ? rate(sum.sums[F("requests")] / sum.seconds) : "0",
         list.map((p) => p.amounts[F("requests")] / p.seconds));
    const issued = sum.sums[F("challenges_issued")];
    const passed = (amounts) => amounts[F("challenges_solved")] + amounts[F("passes_issued")];
    tile("tile-challenges", null,
         issued ? percent(Math.min(1, passed(sum.sums) / issued)) : text("none_issued"),
         list.map((p) => {
           const value = ratio(p, (point) => passed(point.amounts), "challenges_issued");
           return value === null ? null : Math.min(1, value);
         }));
    const responses = sum.sums[F("upstream_responses")];
    tile("tile-latency", null,
         responses ? milliseconds(sum.sums[F("upstream_latency_ms_total")] / responses) :
                     text("no_responses"),
         list.map((p) => ratio(p, (point) => point.amounts[F("upstream_latency_ms_total")],
                               "upstream_responses")));
    tile("tile-throttle", null,
         sum.seconds > 0 ? perSecond(sum.sums[F("throttled_static_bytes")] / sum.seconds) : "0",
         list.map((p) => p.amounts[F("throttled_static_bytes")] / p.seconds));
    const queued = sum.sums[F("throttle_queued_requests")];
    tile("tile-queue-wait", null,
         queued ? milliseconds(sum.sums[F("throttle_wait_ms_total")] / queued) : text("no_waits"),
         list.map((p) => ratio(p, (point) => point.amounts[F("throttle_wait_ms_total")],
                               "throttle_queued_requests")));
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
      showEmpty(view, text("not_enough_data"));
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
        value: series.values[i] === null ? text("no_data") : spec.format(series.values[i]),
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
    const items = [{ key: "series-1", name: text("to_clients") },
                   { key: "series-2", name: text("from_application") }];
    legend(view, band ? items.concat({ key: "band", name: text("average_before_history") }) : items);
    lineChart(view, {
      label: text("throughput_label"),
      times: list.map((p) => p.time),
      series: [{ key: "series-1", name: text("to_clients_lower"), values: out },
               { key: "series-2", name: text("from_application_lower"), values: upstream }],
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
    fillTable(view, [text("time"), text("to_clients"), text("from_application")], rows);
  }

  function renderConnections(list, band) {
    const view = chart("chart-connections");
    const live = state.range === "live";
    $("connections-title").textContent = live ? text("connections") : text("peak_connections");
    legend(view, band ? [{ key: "series-1", name: text("peak_connections") },
                         { key: "band", name: text("peak_before_history") }] : []);
    const values = list.map((p) => p.connections);
    lineChart(view, {
      label: live ? text("open_connections") : text("peak_connections_period"),
      times: list.map((p) => p.time),
      series: [{ key: "series-1", name: live ? text("open") : text("peak"), values }],
      band: band && { start: band.start, end: band.end,
                      label: text("peak_before", utcDayFormat(band.end)),
                      values: [band.amounts[F("peak_connections")]] },
      format: count,
      tick: (v) => count(v),
      integer: true,
      when: (i) => list[i].label,
    });
    fillTable(view, [text("time"), live ? text("open") : text("peak")],
              list.map((p) => [p.label, count(p.connections)]));
  }

  function renderThrottle(list, band) {
    const view = chart("chart-throttle");
    const live = state.range === "live";
    const items = [{ key: "series-1", name: text("active_downloads") },
                   { key: "series-2", name: text("queued_downloads") }];
    legend(view, band ? items.concat({ key: "band", name: text("peak_before_history") }) : items);
    lineChart(view, {
      label: text("throttle_capacity_label"),
      times: list.map((p) => p.time),
      series: [{ key: "series-1", name: live ? text("active") : text("peak_active"),
                 values: list.map((p) => p.throttleConnections) },
               { key: "series-2", name: live ? text("queued") : text("peak_queued"),
                 values: list.map((p) => p.throttleQueue) }],
      band: band && { start: band.start, end: band.end,
                      label: text("peak_before", utcDayFormat(band.end)),
                      values: [band.amounts[F("peak_throttle_connections")],
                               band.amounts[F("peak_throttle_queue")]] },
      format: count,
      tick: (v) => count(v),
      integer: true,
      when: (i) => list[i].label,
    });
    fillTable(view, [text("time"), live ? text("active") : text("peak_active"),
                     live ? text("queued") : text("peak_queued")],
              list.map((p) => [p.label, count(p.throttleConnections), count(p.throttleQueue)]));
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
    const describe = (cell) => `${hourFormat(cell.begins)}${cell.partial ? text("so_far") : ""}`;
    fillTable(view, [text("hour_starting"), text("bytes_to_clients")],
              list.map((cell) => [describe(cell), bytes(cell.value)]));
    if (!list.length) {
      showEmpty(view, text("no_hourly_data"));
      view.card.querySelector(".scale").replaceChildren();
      return;
    }
    const { svg, svgNode } = view;
    view.empty.hidden = true;
    svgNode.style.display = "";
    svgNode.setAttribute("aria-label", text("heatmap_label"));
    svg.selectAll("*").remove();
    const width = Math.max(view.plot.clientWidth, 280);
    const narrow = width < 520;
    const rowLabel = narrow ? date({weekday: "short", day: "numeric"}) : dayFormat;
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
        key: null, name: text("to_clients_lower"), value: cell ? bytes(cell.value) : text("no_data"),
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
      cell.textContent = text("no_open_connections");
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
      text("more_connections", count(other.count), bytes(other.in), bytes(other.out)) : "";
  }

  let particleConfig = null;

  async function startParticles() {
    if (typeof window.particlesJS !== "function" ||
        matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (!particleConfig) {
      try {
        const response = await fetch("dashboard/particlejs.json");
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
    $("theme").textContent = theme() === "dark" ? text("light_theme") : text("dark_theme");
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

  $("export").addEventListener("click", async () => {
    const button = $("export");
    button.disabled = true;
    try {
      const response = await fetch("stats/export.csv", {
        headers: { Authorization: `Bearer ${state.token}` },
        cache: "no-store",
      });
      if (response.status === 401) throw new Unauthorized("unauthorized");
      if (!response.ok) throw new Error(`export answered ${response.status}`);
      const disposition = response.headers.get("Content-Disposition") || "";
      const match = /filename="([^"]+)"/.exec(disposition);
      const fallback = `ankah-metrics-${new Date().toISOString().replace(/[-:]/g, "")
        .replace(/\.\d{3}Z$/, "Z")}.csv`;
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = match ? match[1] : fallback;
      link.hidden = true;
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (error) {
      handleError(error);
    } finally {
      button.disabled = false;
    }
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
      button.textContent = text("confirm_reset");
      resetTimer = setTimeout(() => {
        button.classList.remove("is-armed");
        button.textContent = text("reset_statistics");
      }, 4000);
      return;
    }
    clearTimeout(resetTimer);
    button.classList.remove("is-armed");
    button.textContent = text("reset_statistics");
    try {
      const result = await api("stats/reset", "POST");
      const warning = $("persistence-warning");
      warning.hidden = result.persistence !== "failed";
      warning.textContent = result.persistence === "failed"
        ? text("persistence_failed")
        : "";
      state.samples = [];
      await loadHistory(state.fullHistory);
      poll();
    } catch (error) {
      handleError(error);
    }
  });

  $("login").addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = $("code").value.trim();
    $("code").value = "";
    if (!/^[0-9]{6}$/.test(code)) return;
    const button = $("login").querySelector("button[type=submit]");
    button.disabled = true;
    try {
      const response = await fetch("auth/login", {
        method: "POST", headers: {"X-Ankah-Code": code}, cache: "no-store",
      });
      if (response.status === 429) {
        $("login-message").textContent = text("too_many_codes");
        return;
      }
      if (response.status === 401) {
        $("login-message").textContent = text("code_rejected");
        return;
      }
      if (!response.ok) throw new Error(`auth/login answered ${response.status}`);
      const result = await response.json();
      if (!/^[0-9a-f]{64}$/.test(result.token)) throw new Error("invalid session");
      state.token = result.token;
      state.bearer = false;
      store("sessionStorage", "ankah-token", state.token);
      store("sessionStorage", "ankah-bearer", "0");
      start();
    } catch (error) {
      setStatus(text("connection_lost"), true);
    } finally {
      button.disabled = false;
    }
  });

  $("login-mode").addEventListener("click", () => {
    const tokenMode = $("token-login").hidden;
    $("token-login").hidden = !tokenMode;
    $("login").hidden = tokenMode;
    $("login-mode").textContent = tokenMode
      ? text("use_authenticator_code") : text("use_dashboard_token");
    $(tokenMode ? "token" : "code").focus();
  });

  $("token-login").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = $("token").value.trim();
    $("token").value = "";
    if (!/^[0-9a-f]{64}$/.test(value)) {
      setStatus(text("token_invalid"), true);
      return;
    }
    state.token = value;
    state.bearer = true;
    state.setupPending = true;
    store("sessionStorage", "ankah-token", value);
    store("sessionStorage", "ankah-bearer", "1");
    start();
  });

  $("setup").addEventListener("click", async () => {
    try {
      const response = await fetch("auth/qr", {
        headers: {Authorization: `Bearer ${state.token}`}, cache: "no-store",
      });
      if (response.status === 401) throw new Unauthorized("unauthorized");
      if (!response.ok) throw new Error(`auth/qr answered ${response.status}`);
      const url = URL.createObjectURL(await response.blob());
      const qr = $("setup-qr");
      if (qr.dataset.url) URL.revokeObjectURL(qr.dataset.url);
      qr.dataset.url = url;
      qr.src = url;
      $("setup-dialog").showModal();
    } catch (error) {
      handleError(error);
    }
  });
  $("setup-close").addEventListener("click", () => $("setup-dialog").close());
  $("signout").addEventListener("click", async () => {
    const token = state.token;
    showLogin(text("enter_code"));
    try {
      await fetch("auth/logout", {
        method: "POST", headers: {Authorization: `Bearer ${token}`}, cache: "no-store",
      });
    } catch (error) {
      // The local credential has already been removed.
    }
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
  state.bearer = Boolean(state.token) && stored("sessionStorage", "ankah-bearer") !== "0";
  if (state.token) start();
  else showLogin(text("enter_code"));
})();
