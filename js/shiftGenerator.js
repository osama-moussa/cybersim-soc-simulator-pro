// js/shiftGenerator.js — builds a NEW random 2-hour shift from the whole scenario library
// every time the page loads (open, Retry, Random shift, or picking any scenario).
//
// How it plugs in (no edits to engine.js / app.js / toolkit.js):
//   ScenarioEngine.prototype.load is wrapped. When app.js asks for data/scenarios/sc-XXX.json,
//   this file reads index.json + all scenario files, assembles a random shift in memory,
//   and hands it to the ORIGINAL load() through a blob URL.
//
// URL options:
//   ?fixed=1        -> load the original scenario files unchanged (old behaviour)
//   ?seed=abc       -> replay exactly the same generated shift
//   window.SHIFT_GENERATOR = false (before this script runs) -> disable
//
// Load order in index.html: engine.js ... scoring.js, ui/toolkit.js, shiftGenerator.js, app.js

(() => {
  'use strict';

  const BASE = 'data/scenarios/';
  const DURATION = 120;        // shift length in minutes
  const LAST_ALERT_MAX = 105;  // last alert must leave room before the shift ends
  const params = new URLSearchParams(location.search);

  // ---------------------------------------------------------------- seeded random
  function hashSeed(str) {
    let h = 1779033703 ^ str.length;
    for (let i = 0; i < str.length; i++) {
      h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
      h = (h << 13) | (h >>> 19);
    }
    return () => {
      h = Math.imul(h ^ (h >>> 16), 2246822507);
      h = Math.imul(h ^ (h >>> 13), 3266489909);
      return (h ^= h >>> 16) >>> 0;
    };
  }
  function mulberry32(a) {
    return () => {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function makeRng(seed) {
    const rnd = mulberry32(hashSeed(String(seed))());
    const rng = {
      rnd,
      int: (a, b) => a + Math.floor(rnd() * (b - a + 1)),
      pick: arr => arr[Math.floor(rnd() * arr.length)],
      shuffle: arr => {
        const a = arr.slice();
        for (let i = a.length - 1; i > 0; i--) {
          const j = Math.floor(rnd() * (i + 1));
          [a[i], a[j]] = [a[j], a[i]];
        }
        return a;
      },
      gauss: (mean, sd) => {
        const u = Math.max(rnd(), 1e-9), v = rnd();
        return mean + sd * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
      },
    };
    return rng;
  }

  // ---------------------------------------------------------------- time helpers
  const toSec = t => { const [h, m, s = 0] = String(t).split(':').map(Number); return h * 3600 + m * 60 + s; };
  const wrap = sec => ((Math.round(sec) % 86400) + 86400) % 86400;
  const pad = n => String(n).padStart(2, '0');
  const fmt = sec => { const s = wrap(sec); return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`; };
  const fmtHM = sec => fmt(sec).slice(0, 5);
  const RE_HMS = /(?<![:\d])([01]\d|2[0-3]):([0-5]\d):([0-5]\d)(?![:\d])/g;
  const RE_HM = /(?<![:\d])([01]\d|2[0-3]):([0-5]\d)(?![:\d])/g;
  const shiftHMS = (str, delta) => str.replace(RE_HMS, m => fmt(toSec(m) + delta));
  const shiftHM = (str, delta) => str.replace(RE_HM, m => fmtHM(toSec(m + ':00') + delta));

  function mapStrings(v, fn) {
    if (typeof v === 'string') return fn(v);
    if (Array.isArray(v)) return v.map(x => mapStrings(x, fn));
    if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mapStrings(x, fn)]));
    return v;
  }

  // ---------------------------------------------------------------- entity helpers
  const REAL = v => v && String(v).trim() && String(v).trim().toLowerCase() !== 'n/a';
  const IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
  const lower = s => String(s).toLowerCase();

  function hostOfUrl(u) {
    try { return new URL(String(u).replace(/^hxxp/i, 'http')).hostname; } catch { return null; }
  }

  /** Strings that identify an alert: IPs, domains, hashes, file names (all lowercase). */
  function entityStrings(a) {
    const out = new Set();
    const d = a.details || {};
    for (const v of Object.values(d)) {
      if (typeof v !== 'string') continue;
      (v.match(IPV4) || []).forEach(ip => out.add(ip));
    }
    ['domain', 'destination'].forEach(k => d[k] && out.add(lower(d[k])));
    if (d.url) { const h = hostOfUrl(d.url); if (h) out.add(lower(h)); }
    if (d.sender && String(d.sender).includes('@')) out.add(lower(String(d.sender).split('@').pop()));
    if (d.forward_to && String(d.forward_to).includes('@')) out.add(lower(String(d.forward_to).split('@').pop()));
    if (d.file_hash) out.add(lower(d.file_hash));
    if (d.file_name) out.add(lower(d.file_name));
    return [...out].filter(s => s.length >= 5);
  }

  /** Keys used to detect clashes between a TP chain and a benign alert in the same shift. */
  function classKeys(a) {
    const keys = new Set();
    if (REAL(a.host)) keys.add(`host:${lower(a.host)}`);
    if (REAL(a.user)) keys.add(`user:${lower(a.user)}`);
    entityStrings(a).forEach(e => { if (!/\.(exe|dll|7z|zip|com|msi|ps1|bat|dmp)$/.test(e) || /^\d/.test(e)) keys.add(`ent:${e}`); });
    return keys;
  }

  // identifier-like tokens (IPs, hostnames, ticket ids, CamelCase names) used to match notices to alerts
  function idTokens(text) {
    return (String(text).match(/[A-Za-z0-9][A-Za-z0-9._\/-]{3,}/g) || [])
      .map(t => t.replace(/[.,;:]+$/, ''))
      .filter(t => /\d|[._-]/.test(t) || /[a-z][A-Z]/.test(t))
      .map(lower);
  }

  // ---------------------------------------------------------------- library
  let libraryPromise = null;

  async function fetchJson(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${url} (${r.status})`);
    return r.json();
  }

  async function loadLibrary() {
    const index = await fetchJson(`${BASE}index.json`);
    const files = await Promise.all(index.map(e =>
      fetchJson(`${BASE}${e.file || `${e.id}.json`}`).catch(() => null)));
    const scenarios = files.filter(s => s && Array.isArray(s.alerts) && s.alerts.length);
    if (!scenarios.length) throw new Error('No scenarios could be loaded');
    return buildPool(scenarios);
  }

  /** Turn scenarios into reusable units: TP chains (all TP alerts of a scenario together), single FP alerts, noise logs. */
  function buildPool(scenarios) {
    const chains = [], fps = [], noise = [];

    for (const S of scenarios) {
      const startSec = toSec(S.startTime || '09:00:00');
      const ents = S.alerts.map(a => entityStrings(a));
      const linkedLogs = S.alerts.map(() => []);

      // each log belongs to the closest alert it relates to, otherwise it is background noise
      (S.logs || []).forEach(l => {
        const msg = lower(l.msg || '');
        let best = -1, bestOff = Infinity;
        S.alerts.forEach((a, i) => {
          const rel = (REAL(l.host) && l.host === a.host) || (REAL(l.user) && l.user === a.user) ||
                      ents[i].some(e => msg.includes(e));
          if (!rel) return;
          let off = toSec(l.t) - (startSec + a.at * 60);
          off = ((off + 43200) % 86400 + 86400) % 86400 - 43200;
          if (Math.abs(off) < Math.abs(bestOff)) { best = i; bestOff = off; }
        });
        if (best >= 0) linkedLogs[best].push({ log: l, offset: bestOff });
        else noise.push({ t: l.t, src: l.src, host: l.host, user: l.user, msg: l.msg });
      });

      const bundles = S.alerts.map((a, i) => {
        const text = lower(JSON.stringify({ ...a, truth: undefined }) + ' ' +
          linkedLogs[i].map(x => x.log.msg).join(' '));
        const iocs = {};
        for (const [k, v] of Object.entries(S.iocs || {})) if (text.includes(lower(k))) iocs[k] = v;
        return { S, startSec, alert: a, logs: linkedLogs[i], iocs, text, keys: classKeys(a) };
      });

      const tp = bundles.filter(b => b.alert.truth?.verdict === 'TP');
      const fp = bundles.filter(b => b.alert.truth?.verdict === 'FP');
      if (tp.length && tp.length <= 6) chains.push({ kind: 'tp', S, bundles: tp });
      fp.forEach(b => fps.push({ kind: 'fp', S, bundles: [b] }));
    }
    return { chains, fps, noise };
  }

  // ---------------------------------------------------------------- selection
  function selectUnits(pool, rng) {
    const target = Math.round((rng.int(12, 26) + rng.int(12, 26)) / 2);
    const r = rng.rnd();
    const chainCount = r < 0.35 ? 1 : r < 0.75 ? 2 : 3;

    const classes = new Map();   // key -> 'tp' | 'fp'
    const reps = new Map();      // ioc key -> reputation
    const ruleUse = new Map();
    const picked = [];
    let total = 0, tpTotal = 0;

    const fits = unit => {
      for (const b of unit.bundles) {
        for (const k of b.keys) if (classes.has(k) && classes.get(k) !== unit.kind) return false;
        for (const [k, v] of Object.entries(b.iocs)) {
          const key = lower(k);
          if (reps.has(key) && reps.get(key) !== v.reputation) return false;
        }
        if ((ruleUse.get(b.alert.rule) || 0) >= 2 && unit.kind === 'fp') return false;
      }
      return true;
    };
    const commit = unit => {
      for (const b of unit.bundles) {
        b.keys.forEach(k => classes.set(k, unit.kind));
        Object.entries(b.iocs).forEach(([k, v]) => reps.set(lower(k), v.reputation));
        ruleUse.set(b.alert.rule, (ruleUse.get(b.alert.rule) || 0) + 1);
      }
      picked.push(unit);
      total += unit.bundles.length;
      if (unit.kind === 'tp') tpTotal += unit.bundles.length;
    };

    let chainsPicked = 0;
    for (const c of rng.shuffle(pool.chains)) {
      if (chainsPicked >= chainCount) break;
      if (tpTotal + c.bundles.length > Math.ceil(target * 0.45)) continue;
      if (!fits(c)) continue;
      commit(c); chainsPicked++;
    }
    for (const f of rng.shuffle(pool.fps)) {
      if (total >= target) break;
      if (!fits(f)) continue;
      commit(f);
    }
    if (!picked.length) throw new Error('Selection produced no alerts');
    return picked;
  }

  // ---------------------------------------------------------------- timing
  function assignTimes(units, rng) {
    const centers = [rng.int(10, 40), rng.int(45, 75), rng.int(70, 98)].slice(0, rng.int(2, 3));
    const clamp = v => Math.max(0, Math.min(LAST_ALERT_MAX, v));
    const single = () => clamp(rng.rnd() < 0.55 ? rng.rnd() * LAST_ALERT_MAX : rng.gauss(rng.pick(centers), 7));

    for (const u of units) {
      if (u.kind === 'tp') {
        const ats = u.bundles.map(b => b.alert.at);
        const span = Math.max(...ats) - Math.min(...ats);
        const k = 1.5 + rng.rnd() * 2;                       // stretch the attack story out in time
        const dur = Math.min(70, span * k, LAST_ALERT_MAX);
        const scale = span > 0 ? dur / span : 1;
        const anchor = rng.rnd() * Math.max(0, LAST_ALERT_MAX - dur);
        const base = Math.min(...ats);
        u.bundles.forEach(b => { b.newAt = anchor + (b.alert.at - base) * scale; });
      } else {
        u.bundles[0].newAt = single();
      }
    }
    // start the shift quickly, never run past the limit
    const all = units.flatMap(u => u.bundles);
    const min = Math.min(...all.map(b => b.newAt));
    const lead = rng.int(0, 4);
    const shift = min > lead ? min - lead : 0;
    all.forEach(b => { b.newAt = Math.max(0, Math.min(LAST_ALERT_MAX, +(b.newAt - shift).toFixed(1))); });
  }

  // ---------------------------------------------------------------- assemble
  function assemble(pool, units, rng, seed) {
    const startTime = rng.pick(['06:00:00', '08:00:00', '09:00:00', '14:00:00', '16:00:00', '22:00:00']);
    const startSec = toSec(startTime);

    assignTimes(units, rng);
    const bundles = units.flatMap(u => u.bundles).sort((a, b) => a.newAt - b.newAt);

    const alerts = [], logs = [], iocs = {}, users = {}, hosts = new Set(), notices = new Set();
    const calendar = [], calSeen = new Set(), expected = new Set();
    const sceneDelta = new Map();   // scenario -> time delta (seconds) of its first selected alert

    bundles.forEach((b, i) => {
      const a = b.alert;
      const delta = (startSec + b.newAt * 60) - (b.startSec + a.at * 60);
      if (!sceneDelta.has(b.S)) sceneDelta.set(b.S, delta);

      const { truth, ...rest } = a;
      const moved = mapStrings({ summary: rest.summary, details: rest.details }, s => shiftHMS(s, delta));
      alerts.push({
        ...rest,
        at: b.newAt,
        summary: shiftHM(moved.summary, delta),
        details: moved.details,
        truth: { ...truth },
        id: `A-${1001 + i}`,
      });

      b.logs.forEach(({ log, offset }) => {
        const rel = b.newAt * 60 + offset;
        logs.push({ rel, t: fmt(startSec + rel), src: log.src, host: log.host, user: log.user, msg: shiftHMS(log.msg || '', delta) });
      });
      Object.entries(b.iocs).forEach(([k, v]) => { iocs[k] = v; });
      if (REAL(a.host)) hosts.add(a.host);
    });

    // scenario-level data of every scenario that contributed an alert
    const text = new Map();
    bundles.forEach(b => text.set(b.S, (text.get(b.S) || '') + ' ' + b.text));
    for (const [S, delta] of sceneDelta) {
      const t = text.get(S);
      const alertUsers = new Set(bundles.filter(b => b.S === S).flatMap(b => [b.alert.user, b.alert.host]).filter(REAL));
      Object.entries(S.assets?.users || {}).forEach(([u, h]) => {
        if ((alertUsers.has(u) || alertUsers.has(h)) && !(u in users)) users[u] = h;
      });
      (S.assets?.hosts || []).forEach(h => hosts.add(h));
      (S.context?.notices || []).forEach(n => {
        const tokens = idTokens(n);
        if (!tokens.length || tokens.some(tok => t.includes(tok))) notices.add(shiftHM(shiftHMS(n, delta), delta));
      });
      (S.context?.change_calendar || []).forEach(c => {
        const k = JSON.stringify(c);
        if (!calSeen.has(k)) { calSeen.add(k); calendar.push(c); }
      });
    }

    // expected response actions: only from the TP chains that were actually picked
    units.filter(u => u.kind === 'tp').forEach(u =>
      (u.S.expected_actions || []).forEach(x => { if (x !== 'close_false_positive') expected.add(x); }));
    if (alerts.some(a => a.truth.verdict === 'FP')) expected.add('close_false_positive');

    // background noise spread across the shift
    const noiseCount = Math.min(pool.noise.length, rng.int(30, 70));
    rng.shuffle(pool.noise).slice(0, noiseCount).forEach(n => {
      const rel = (rng.rnd() * (DURATION + 15) - 15) * 60;
      logs.push({ rel, t: fmt(startSec + rel), src: n.src, host: n.host, user: n.user, msg: n.msg });
    });
    logs.sort((x, y) => x.rel - y.rel);

    const n = alerts.length;
    const tpCount = alerts.filter(a => a.truth.verdict === 'TP').length;
    return {
      id: 'sc-gen',
      title: `Random Shift ${fmtHM(startSec)} (seed ${seed})`,
      category: 'Mixed',
      outcome: 'mixed',
      difficulty: n >= 20 ? 'Tier 3' : n >= 15 ? 'Tier 2' : 'Tier 1',
      briefing: `Randomly generated 2-hour shift (${n} alerts, seed ${seed}). Alerts arrive at irregular times. ` +
        'Check the notices, logs and IOCs before closing anything, and follow the SOC Tier 1 playbook.',
      startTime,
      durationMinutes: DURATION,
      seed,
      stats: { alerts: n, truePositives: tpCount, falsePositives: n - tpCount },
      context: { change_calendar: calendar, notices: [...notices] },
      assets: { users, hosts: [...hosts] },
      alerts,
      logs: logs.map(({ rel, ...l }) => l),
      iocs,
      expected_actions: [...expected],
    };
  }

  // ---------------------------------------------------------------- public build
  async function build(seedOverride) {
    libraryPromise = libraryPromise || loadLibrary();
    const pool = await libraryPromise;
    const seed = seedOverride || params.get('seed') || Math.floor(Math.random() * 36 ** 6).toString(36).padStart(6, '0');
    const rng = makeRng(seed);
    const units = selectUnits(pool, rng);
    const scenario = assemble(pool, units, rng, seed);
    window.lastShiftSeed = seed;
    console.info(`[ShiftGenerator] seed=${seed} alerts=${scenario.alerts.length} (TP ${scenario.stats.truePositives})`);
    return scenario;
  }

  // ---------------------------------------------------------------- hook into ScenarioEngine
  const Engine = window.ScenarioEngine;
  if (!Engine) { console.warn('[ShiftGenerator] ScenarioEngine not found; load engine.js first.'); return; }

  const originalLoad = Engine.prototype.load;
  Engine.prototype.load = async function (url) {
    const wanted = /data\/scenarios\/sc-[^/]+\.json/.test(String(url));
    if (!wanted || params.has('fixed') || window.SHIFT_GENERATOR === false) return originalLoad.call(this, url);

    let blobUrl = null;
    try {
      const data = await build();
      blobUrl = URL.createObjectURL(new Blob([JSON.stringify(data)], { type: 'application/json' }));
      const out = await originalLoad.call(this, blobUrl);
      this.shiftMinutes = DURATION;
      return out;
    } catch (e) {
      console.warn('[ShiftGenerator] falling back to the fixed scenario:', e);
      return originalLoad.call(this, url);
    } finally {
      if (blobUrl) URL.revokeObjectURL(blobUrl);
    }
  };

  window.ShiftGenerator = { build };
})();
