// js/engine.js — محرك السيناريو: بيقرأ JSON وينزّل التنبيهات حسب ساعة الشيفت

class ScenarioEngine {
  /**
   * @param {object} opts
   * @param {number} opts.msPerMinute  كام ملّي ثانية حقيقية = دقيقة واحدة في الشيفت (الافتراضي 6000 = 6 ثواني)
   * @param {number} opts.tailMinutes  دقايق إضافية بعد آخر تنبيه قبل ما الشيفت يخلص
   */
  constructor({ msPerMinute = 6000, tailMinutes = 15 } = {}) {
    this.msPerMinute = msPerMinute;
    this.tailMinutes = tailMinutes;

    this.scenario = null;
    this.timer = null;
    this.running = false;

    this.elapsedMs = 0;       // الوقت اللي عدّى فعلاً (مش بيزيد وقت الـ pause)
    this.lastTickAt = 0;
    this.released = new Set(); // ids التنبيهات اللي نزلت
    this.ended = false;        // shift already ended? (prevents repeated onEnd)

    // callbacks — اربطهم من app.js
    this.onAlert = () => {};
    this.onTick = () => {};
    this.onEnd = () => {};
  }

  // ---------- تحميل ----------
  async load(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to load scenario: ${url} (${res.status})`);
    const data = await res.json();
    this._validate(data);
    this.scenario = data;
    this.startClock = this._parseTime(data.startTime || '09:00:00');
    this.shiftMinutes = Math.max(...data.alerts.map(a => a.at)) + this.tailMinutes;
    return data;
  }

  _validate(s) {
    if (!s.id || !Array.isArray(s.alerts) || s.alerts.length === 0) {
      throw new Error('Scenario must have id and a non-empty alerts array');
    }
    const ids = new Set();
    const validSeverities = new Set(['Low', 'Medium', 'High', 'Critical']);
    for (const a of s.alerts) {
      if (!a.id || typeof a.id !== 'string') throw new Error('Every alert must have a string id');
      if (ids.has(a.id)) throw new Error(`Duplicate alert id: ${a.id}`);
      ids.add(a.id);
      if (!Number.isFinite(a.at) || a.at < 0 || a.at > 120) throw new Error(`Alert ${a.id} must have a release minute between 0 and 120`);
      if (!validSeverities.has(a.severity)) throw new Error(`Alert ${a.id} has invalid severity: ${a.severity}`);
      if (!a.truth || !['TP', 'FP'].includes(a.truth.verdict)) throw new Error(`Alert ${a.id} must define truth.verdict as TP or FP`);
      if (!validSeverities.has(a.truth.severity)) throw new Error(`Alert ${a.id} has invalid truth severity`);
      if (typeof a.truth.escalate !== 'boolean') throw new Error(`Alert ${a.id} must define truth.escalate as a boolean`);
    }
  }

  // ---------- checkpoint / resume ----------
  createSnapshot(state = window.shiftState) {
    if (!this.scenario || this.ended) return null;
    return {
      version: 1,
      savedAt: Date.now(),
      scenario: JSON.parse(JSON.stringify(this.scenario)),
      elapsedMs: this.elapsedMs,
      released: [...this.released],
      shiftMinutes: this.shiftMinutes,
      msPerMinute: this.msPerMinute,
      state: {
        alerts: JSON.parse(JSON.stringify(state?.alerts || [])),
        decisions: JSON.parse(JSON.stringify(state?.decisions || {})),
        actions: JSON.parse(JSON.stringify(state?.actions || [])),
        activity: JSON.parse(JSON.stringify(state?.activity || [])),
        effects: JSON.parse(JSON.stringify(state?.effects || {})),
        incidents: JSON.parse(JSON.stringify(state?.incidents || {}))
      }
    };
  }

  restoreSnapshot(snapshot) {
    if (!snapshot || snapshot.version !== 1 || !snapshot.scenario || !Array.isArray(snapshot.scenario.alerts)) {
      throw new Error('Saved shift checkpoint is invalid or unsupported.');
    }
    this.pause();
    this.scenario = snapshot.scenario;
    this._validate(this.scenario);
    this.startClock = this._parseTime(this.scenario.startTime || '09:00:00');
    this.shiftMinutes = Number.isFinite(snapshot.shiftMinutes) ? snapshot.shiftMinutes : Math.max(...this.scenario.alerts.map(a => a.at)) + this.tailMinutes;
    this.msPerMinute = Number.isFinite(snapshot.msPerMinute) ? snapshot.msPerMinute : 6000;
    this.elapsedMs = Math.max(0, Number(snapshot.elapsedMs) || 0);
    this.released = new Set(Array.isArray(snapshot.released) ? snapshot.released : []);
    this.ended = false;
    const saved = snapshot.state || {};
    window.shiftState.alerts = Array.isArray(saved.alerts) ? saved.alerts : [];
    window.shiftState.decisions = saved.decisions && typeof saved.decisions === 'object' ? saved.decisions : {};
    window.shiftState.actions = Array.isArray(saved.actions) ? saved.actions : [];
    window.shiftState.activity = Array.isArray(saved.activity) ? saved.activity : [];
    window.shiftState.effects = saved.effects && typeof saved.effects === 'object' ? saved.effects : {};
    window.shiftState.incidents = saved.incidents && typeof saved.incidents === 'object' ? saved.incidents : {};
    return this.scenario;
  }

  // ---------- تحكم ----------
  start() {
    if (!this.scenario) throw new Error('Call load() first');
    if (this.running) return;
    this.running = true;
    this.lastTickAt = performance.now();
    this.timer = setInterval(() => this._tick(), 500);
    this._tick(); // عشان تنبيهات at:0 تنزل فوراً
  }

  pause() {
    if (!this.running) return;
    this._tick();
    this.running = false;
    clearInterval(this.timer);
  }

  resume() { this.start(); }

  setSpeed(msPerMinute) {
    this._tick();
    this.msPerMinute = msPerMinute;
  }

  reset() {
    clearInterval(this.timer);
    this.running = false;
    this.elapsedMs = 0;
    this.released.clear();
    this.ended = false;
  }

  // ---------- الساعة ----------
  /** عدد الدقايق اللي عدّت من أول الشيفت */
  get minutes() { return this.elapsedMs / this.msPerMinute; }

  /** وقت الشيفت الحالي بصيغة HH:MM:SS (بيستخدم نفس صيغة t في اللوجات) */
  get clock() {
    const total = this.startClock + Math.floor(this.minutes * 60);
    const h = String(Math.floor(total / 3600) % 24).padStart(2, '0');
    const m = String(Math.floor((total % 3600) / 60)).padStart(2, '0');
    const s = String(total % 60).padStart(2, '0');
    return `${h}:${m}:${s}`;
  }

  _parseTime(t) {
    const [h, m, s = 0] = t.split(':').map(Number);
    return h * 3600 + m * 60 + s;
  }

  _tick() {
    const now = performance.now();
    if (this.running) this.elapsedMs += now - this.lastTickAt;
    this.lastTickAt = now;

    // نزّل أي تنبيه جه معاده
    for (const a of this.scenario.alerts) {
      if (!this.released.has(a.id) && a.at <= this.minutes) {
        this.released.add(a.id);
        this.onAlert(this._publicAlert(a));
      }
    }

    this.onTick({ clock: this.clock, minutes: this.minutes });

    if (this.minutes >= this.shiftMinutes && !this.ended) {
      this.ended = true; // must be set before pause() to avoid recursion
      this.pause();
      this.onEnd({ minutes: this.minutes });
    }
  }

  // ---------- بيانات ----------
  /** التنبيه بعد ما نشيل منه "truth" عشان مايظهرش للواجهة */
  _publicAlert(a) {
    const { truth, ...rest } = a;
    return { ...rest, releasedAt: this.clock };
  }

  /** للـ scoring بس — متستخدمهاش في الواجهة */
  getTruth(alertId) {
    return this.scenario.alerts.find(a => a.id === alertId)?.truth ?? null;
  }

  get expectedActions() { return this.scenario.expected_actions || []; }
}

window.ScenarioEngine = ScenarioEngine;
