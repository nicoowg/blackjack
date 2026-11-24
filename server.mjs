// Kort: blackjack-server uden afhængigheder.
//   /        spillet (index.html)
//   /ws      spillernes forbindelse (WebSocket)
//   /ok      tjek for tunnelvagten
// Konti (navn + 4-cifret kode) og aura ligger i ~/.kort/konti.json. Koden gemmes kun som scrypt-hash.
// Serveren styrer alt spil (kort, regler, aura), så ingen kan snyde fra browseren.
// Starter selv en cloudflared-tunnel; linket ligger i ~/.kort/link og sendes til alle i lobbyen.
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const HOME = process.env.KORT_HOME || path.join(os.homedir(), '.kort');
const PORT = parseInt(process.env.KORT_PORT || '7761', 10);
const NO_TUNNEL = process.env.KORT_NOTUNNEL === '1';
const DATA = process.env.KORT_DATA || path.join(HOME, 'konti.json');
const START_AURA = 500;
const DECKS = 6;
fs.mkdirSync(HOME, { recursive: true });
const log = (...a) => { try { process.stdout.write(new Date().toISOString().slice(11, 19) + ' ' + a.join(' ') + '\n') } catch (e) {} };

// ---------- konti ----------
let db = { users: {}, tokens: {} };
try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')) } catch (e) {}
db.users ||= {}; db.tokens ||= {};
let saveT = null;
function save() {
  clearTimeout(saveT);
  saveT = setTimeout(() => {
    const tmp = DATA + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 1)); fs.renameSync(tmp, DATA);
  }, 300);
}
const keyOf = (n) => n.toLowerCase();
const cleanName = (s) => String(s || '').normalize('NFC').replace(/[^\p{L}\p{N} ._-]/gu, '').replace(/\s+/g, ' ').trim().slice(0, 14);
const hashPin = (pin, salt) => crypto.scryptSync(pin, salt, 32).toString('hex');
const fails = new Map(); // navn -> {n, until}

function login(nameRaw, pin, create) {
  const name = cleanName(nameRaw);
  if (name.length < 2) return { err: 'navn' };
  if (!/^\d{4}$/.test(String(pin || ''))) return { err: 'kode' };
  const k = keyOf(name), u = db.users[k];
  const f = fails.get(k);
  if (f && f.until > Date.now()) return { err: 'vent', wait: Math.ceil((f.until - Date.now()) / 1000) };
  if (!u) {
    if (!create) return { err: 'ukendt' };
    const salt = crypto.randomBytes(12).toString('hex');
    db.users[k] = { name, salt, pin: hashPin(pin, salt), aura: START_AURA, made: Date.now(), hands: 0, best: START_AURA };
    log('ny konto', name);
  } else {
    const ok = crypto.timingSafeEqual(Buffer.from(hashPin(pin, u.salt), 'hex'), Buffer.from(u.pin, 'hex'));
    if (!ok) {
      const g = f && f.until <= Date.now() && f.n >= 5 ? { n: 0, until: 0 } : (f || { n: 0, until: 0 });
      g.n++; if (g.n >= 5) g.until = Date.now() + 60000;
      fails.set(k, g);
      return { err: 'forkert' };
    }
    fails.delete(k);
  }
  const token = crypto.randomBytes(24).toString('hex');
  db.tokens[token] = k; save();
  return { token, k };
}

// ---------- WebSocket (RFC 6455): korte tekstbeskeder ----------
function accept(req, socket) {
  const key = req.headers['sec-websocket-key'];
  if (!key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return null }
  const acc = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  socket.setNoDelay(true);
  const c = { socket, buf: Buffer.alloc(0), open: true, onmsg: null, onclose: null, last: Date.now() };
  const close = () => { if (!c.open) return; c.open = false; try { socket.destroy() } catch (e) {} if (c.onclose) c.onclose() };
  c.close = close;
  c.send = (o) => {
    if (!c.open) return;
    const p = Buffer.from(typeof o === 'string' ? o : JSON.stringify(o), 'utf8'); let h;
    if (p.length < 126) h = Buffer.from([0x81, p.length]);
    else if (p.length < 65536) { h = Buffer.alloc(4); h[0] = 0x81; h[1] = 126; h.writeUInt16BE(p.length, 2) }
    else { h = Buffer.alloc(10); h[0] = 0x81; h[1] = 127; h.writeBigUInt64BE(BigInt(p.length), 2) }
    try { socket.write(Buffer.concat([h, p])) } catch (e) { close() }
  };
  socket.on('data', (d) => {
    c.buf = Buffer.concat([c.buf, d]);
    if (c.buf.length > 20000) return close();
    for (;;) {
      if (c.buf.length < 2) return;
      const op = c.buf[0] & 0x0f, masked = c.buf[1] & 0x80; let len = c.buf[1] & 0x7f, off = 2;
      if (len === 126) { if (c.buf.length < 4) return; len = c.buf.readUInt16BE(2); off = 4 }
      else if (len === 127) return close();
      if (len > 8000) return close();
      const need = off + (masked ? 4 : 0) + len; if (c.buf.length < need) return;
      let p = c.buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const m = c.buf.subarray(off, off + 4); p = Buffer.from(p); for (let i = 0; i < p.length; i++) p[i] ^= m[i & 3] }
      c.buf = c.buf.subarray(need); c.last = Date.now();
      if (op === 8) return close();
      if (op === 9) { try { socket.write(Buffer.concat([Buffer.from([0x8a, p.length]), p])) } catch (e) {} continue }
      if (op === 1 && c.onmsg) {
        let o = null; try { o = JSON.parse(p.toString('utf8')) } catch (e) {}
        if (o && typeof o === 'object') { try { c.onmsg(o) } catch (e) { log('fejl', e && e.stack) } }
      }
    }
  });
  socket.on('close', close); socket.on('error', close);
  return c;
}

// ---------- kort ----------
let cardId = 1;
const val = (c) => Math.min(c.r, 10);
function score(cards) {
  let t = 0, ace = false;
  for (const c of cards) { if (c.down) continue; t += val(c); if (c.r === 1) ace = true }
  const soft = ace && t + 10 <= 21;
  return { total: soft ? t + 10 : t, soft, low: t };
}
const isBJ = (cards) => cards.length === 2 && score(cards).total === 21;
function rnd(n) { return crypto.randomInt(n) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- bord ----------
const tables = new Map();
const BET_WAIT = 14000, TURN_WAIT = 25000, INS_WAIT = 10000;

class Table {
  constructor(id, solo) {
    this.id = id; this.solo = solo; this.max = solo ? 1 : 5;
    this.seats = Array(this.max).fill(null);
    this.watch = new Set();            // klient-forbindelser
    this.phase = 'bet'; this.dealer = []; this.turn = null; this.timer = null; this.timerKind = '';
    this.shuffle(); this.round = 0;
  }
  shuffle() {
    const s = [];
    for (let d = 0; d < DECKS; d++) for (const su of 'shdc') for (let r = 1; r <= 13; r++) s.push({ r, s: su });
    for (let i = s.length - 1; i > 0; i--) { const j = rnd(i + 1); [s[i], s[j]] = [s[j], s[i]] }
    this.shoe = s; this.pos = 0; this.cut = s.length - 60 - rnd(25); this.shuffledAt = Date.now();
  }
  draw(down = false) {
    if (this.pos >= this.shoe.length) this.shuffle();
    const c = this.shoe[this.pos++];
    return { id: cardId++, r: c.r, s: c.s, down };
  }
  user(k) { return db.users[k] }
  seatOf(k) { return this.seats.findIndex((s) => s && s.k === k) }
  sit(k) {
    let i = this.seatOf(k);
    if (i >= 0) { this.seats[i].away = false; return i }
    // midten først, så udad (bordet fyldes pænt)
    const order = this.max === 1 ? [0] : [2, 1, 3, 0, 4];
    i = order.find((j) => !this.seats[j]);
    if (i === undefined) return -1;
    this.seats[i] = { k, pend: 0, last: 0, ready: false, hands: [], ins: 0, insDone: false, away: false };
    if (this.phase === 'bet') this.rebet(this.seats[i]);
    this.broadcast();
    return i;
  }
  leave(k) {
    const i = this.seatOf(k); if (i < 0) return;
    const s = this.seats[i];
    if (this.phase === 'bet' || !s.hands.length) { this.seats[i] = null; this.checkStart() }
    else { s.away = true; if (this.turn && this.turn.seat === i) this.wake() }  // fjernes når runden er slut
    this.broadcast();
  }
  rebet(s) {
    const u = this.user(s.k);
    s.pend = s.last && u && u.aura >= s.last ? s.last : 0; s.ready = false;
  }
  players() { return this.seats.map((s, i) => ({ s, i })).filter((x) => x.s) }
  active() { return this.players().filter((x) => x.s.hands.length) }

  // ----- beskeder fra spillere -----
  act(k, o) {
    const i = this.seatOf(k); if (i < 0) return;
    const s = this.seats[i], u = this.user(s.k);
    if (this.phase === 'bet') {
      if (o.t === 'chip') {
        const v = [5, 25, 100, 500].includes(o.v) ? o.v : 0;
        if (!v || s.ready || u.aura - s.pend < v || s.pend + v > 5000) return;
        s.pend += v;
      } else if (o.t === 'clear') { if (!s.ready) s.pend = 0 }
      else if (o.t === 'deal') { if (s.pend > 0 && s.pend <= u.aura) { s.ready = true; this.armBetTimer() } this.checkStart() }
      else if (o.t === 'restart') { if (u.aura < 5 && !s.pend) { u.aura = START_AURA; u.restarts = (u.restarts || 0) + 1; save() } }
      return this.broadcast();
    }
    if (this.phase === 'insurance') {
      if (s.insDone || !s.hands.length) return;
      if (o.t === 'ins') { const c = s.hands[0].bet / 2; if (u.aura >= c) { u.aura -= c; s.ins = c; save() } s.insDone = true }
      else if (o.t === 'noins') s.insDone = true;
      else return;
      this.broadcast();
      if (this.players().every((x) => !x.s.hands.length || x.s.insDone)) this.wake();
      return;
    }
    if (this.phase === 'play' && this.turn && this.turn.seat === i && !this.busy) {
      const h = s.hands[this.turn.hand];
      const allowed = this.allowed(s, h);
      if (!allowed.includes(o.t)) return;
      this.busy = true;
      this.doAction(s, h, o.t).finally(() => { this.busy = false });
    }
  }
  allowed(s, h) {
    if (!h || h.done) return [];
    const u = this.user(s.k), a = ['hit', 'stand'];
    if (h.cards.length === 2 && !h.aces && u.aura >= h.bet) a.push('double');
    if (h.cards.length === 2 && val(h.cards[0]) === val(h.cards[1]) && s.hands.length < 4 && u.aura >= h.bet && !h.aces) a.push('split');
    if (h.cards.length === 2 && s.hands.length === 1 && !h.split) a.push('surrender');
    return a;
  }
  async doAction(s, h, t) {
    const u = this.user(s.k);
    if (t === 'hit') { h.cards.push(this.draw()); await this.step(420); this.checkHand(h) }
    else if (t === 'stand') { h.done = true }
    else if (t === 'double') {
      u.aura -= h.bet; h.bet *= 2; h.doubled = true; save();
      const c = this.draw(); c.side = true; h.cards.push(c); await this.step(520);
      h.done = true; if (score(h.cards).total > 21) h.bust = true;
    } else if (t === 'split') {
      u.aura -= h.bet; save();
      const aces = h.cards[0].r === 1;
      const nh = { cards: [h.cards.pop()], bet: h.bet, split: true, aces, done: false };
      h.split = true; h.aces = aces;
      const idx = s.hands.indexOf(h); s.hands.splice(idx + 1, 0, nh);
      await this.step(380);
      h.cards.push(this.draw()); await this.step(420);
      if (aces) { nh.cards.push(this.draw()); await this.step(420); h.done = nh.done = true }
      else this.checkHand(h);
    } else if (t === 'surrender') { h.done = true; h.surr = true; u.aura += h.bet / 2; save() }
    this.broadcast();
    this.wake();
  }
  checkHand(h) {
    const t = score(h.cards).total;
    if (t > 21) { h.bust = true; h.done = true } else if (t === 21) h.done = true;
  }

  // ----- tidsstyring -----
  armBetTimer() {
    if (this.solo || this.timer) return;
    this.setTimer(BET_WAIT, 'bet', () => this.start());
  }
  setTimer(ms, kind, fn) {
    this.clearTimer();
    this.timerKind = kind; this.timerEnd = Date.now() + ms;
    this.timer = setTimeout(() => { this.timer = null; this.timerKind = ''; fn() }, ms);
  }
  clearTimer() { if (this.timer) clearTimeout(this.timer); this.timer = null; this.timerKind = '' }
  wait(ms, kind) {
    // venter på spillerne eller på tiden (solo: ingen tid)
    return new Promise((res) => {
      this._wake = () => { this._wake = null; this.clearTimer(); res() };
      if (ms && !this.solo) this.setTimer(ms, kind, () => this._wake && this._wake());
      else if (ms && this.solo && kind === 'ins') { /* solo: venter på svar */ }
    });
  }
  wake() { if (this._wake) this._wake() }
  checkStart() {
    if (this.phase !== 'bet') return;
    const p = this.players();
    if (!p.length) { this.clearTimer(); return }
    const bettors = p.filter((x) => x.s.pend > 0);
    if (bettors.length && p.every((x) => x.s.ready || x.s.away)) this.start();
  }
  step(ms) { this.broadcast(); return sleep(ms) }

  // ----- runden -----
  async start() {
    if (this.phase !== 'bet') return;
    this.clearTimer();
    const dealt = (s) => s.pend > 0 && !s.away && s.ready && s.pend <= this.user(s.k).aura;
    const ps = this.players().filter((x) => dealt(x.s));
    if (!ps.length) { this.players().forEach((x) => { x.s.ready = false }); return this.broadcast() }
    this.phase = 'deal'; this.round++;
    for (const { s } of this.players()) {
      const u = this.user(s.k);
      if (dealt(s)) {
        u.aura -= s.pend; s.last = s.pend;
        s.hands = [{ cards: [], bet: s.pend, done: false }];
        u.hands = (u.hands || 0) + 1;
        s.pend = 0;
      } else s.hands = [];
      s.ready = false; s.ins = 0; s.insDone = false; s.net = 0;
    }
    save();
    const order = this.active().sort((a, b) => a.i - b.i);
    await this.step(250);
    for (let r = 0; r < 2; r++) {
      for (const { s } of order) { s.hands[0].cards.push(this.draw()); await this.step(330) }
      this.dealer.push(this.draw(r === 1)); await this.step(380);
    }
    const up = this.dealer[0];
    if (up.r === 1) {
      this.phase = 'insurance';
      for (const { s } of order) { if (this.user(s.k).aura < s.hands[0].bet / 2 || isBJ(s.hands[0].cards)) s.insDone = true; if (s.away) s.insDone = true }
      this.broadcast();
      if (order.some(({ s }) => !s.insDone)) await this.wait(INS_WAIT, 'ins');
      order.forEach(({ s }) => { s.insDone = true });
    }
    if (up.r === 1 || val(up) === 10) {
      this.phase = 'peek'; this.peek = true; await this.step(750); this.peek = false;
      const hole = this.dealer[1];
      const dbj = val(up) + val(hole) === 11 && (up.r === 1 || hole.r === 1);
      if (dbj) { hole.down = false; await this.step(600); return this.finish(true) }
      // forsikringen er tabt
      for (const { s } of order) s.ins = 0;
    }
    // naturlige blackjacks betales med det samme
    for (const { s } of order) { const h = s.hands[0]; if (isBJ(h.cards)) { h.done = true; h.bj = true } }
    this.phase = 'play';
    for (const { s, i } of order) {
      for (let hi = 0; hi < s.hands.length; hi++) {
        const h = s.hands[hi];
        this.turn = { seat: i, hand: hi };
        if (h.cards.length === 1) { h.cards.push(this.draw()); await this.step(420); if (h.aces) h.done = true; else this.checkHand(h) }
        while (!h.done) {
          if (s.away) { h.done = true; break }
          this.broadcast();
          await this.wait(TURN_WAIT, 'turn');
          while (this.busy) await sleep(40);
          if (!h.done && !this.solo && this.timerEnd && Date.now() >= this.timerEnd - 50) h.done = true; // tiden løb ud: stå
        }
        this.broadcast(); await sleep(260);
      }
    }
    this.turn = null;
    return this.finish(false);
  }
  async finish(dealerBJ) {
    const order = this.active().sort((a, b) => a.i - b.i);
    this.phase = 'dealer';
    const hole = this.dealer[1];
    if (hole && hole.down) { hole.down = false; await this.step(620) }
    const live = order.some(({ s }) => s.hands.some((h) => !h.bust && !h.surr && !h.bj));
    if (!dealerBJ && live) {
      while (score(this.dealer).total < 17) { this.dealer.push(this.draw()); await this.step(560) }
    }
    const d = score(this.dealer).total, dbust = d > 21;
    for (const { s } of order) {
      const u = this.user(s.k); let net = 0;
      if (s.ins) { if (dealerBJ) { u.aura += s.ins * 3; net += s.ins * 2 } else net -= s.ins }
      for (const h of s.hands) {
        const p = score(h.cards).total; let back = 0;
        if (h.surr) { back = 0; h.res = 'surr'; net -= h.bet / 2; continue }
        if (dealerBJ) { if (h.cards.length === 2 && isBJ(h.cards) && !h.split) { back = h.bet; h.res = 'push' } else h.res = 'lose' }
        else if (h.bj) { back = h.bet * 2.5; h.res = 'bj' }
        else if (h.bust) h.res = 'bust';
        else if (dbust || p > d) { back = h.bet * 2; h.res = 'win' }
        else if (p === d) { back = h.bet; h.res = 'push' }
        else h.res = 'lose';
        h.net = back - h.bet; net += h.net; u.aura += back;
      }
      s.net = net; u.best = Math.max(u.best || 0, u.aura);
    }
    save();
    this.phase = 'result'; this.broadcast();
    await sleep(this.solo ? 2400 : 3600);
    // ryd bordet
    this.dealer = [];
    for (const x of this.players()) { x.s.hands = []; x.s.ins = 0; x.s.net = 0 }
    for (let i = 0; i < this.max; i++) if (this.seats[i] && this.seats[i].away) this.seats[i] = null;
    this.phase = 'bet';
    let shuffled = false;
    if (this.pos >= this.cut) { this.shuffle(); shuffled = true }
    for (const x of this.players()) { if (x.s.pend) x.s.ready = false; else this.rebet(x.s) }
    this.broadcast(shuffled ? { shuffle: true } : null);
    if (!this.players().length && this.solo) tables.delete(this.id);
  }

  // ----- tilstand ud -----
  view(k) {
    const me = this.seatOf(k);
    const pub = (c) => (c.down ? { id: c.id, down: true } : { id: c.id, r: c.r, s: c.s, side: !!c.side });
    const seats = this.seats.map((s, i) => {
      if (!s) return null;
      const u = this.user(s.k);
      return {
        name: u.name, aura: u.aura, pend: s.pend, ready: s.ready, away: s.away, ins: s.ins, net: s.net || 0,
        hands: s.hands.map((h) => {
          const sc = score(h.cards);
          return { cards: h.cards.map(pub), bet: h.bet, total: sc.total, soft: sc.soft && sc.total < 21 && !h.done, done: h.done, res: this.phase === 'result' ? h.res : (h.bust ? 'bust' : h.bj ? 'bj' : h.surr ? 'surr' : ''), net: h.net || 0, doubled: !!h.doubled };
        }),
      };
    });
    const ds = score(this.dealer);
    let actions = [];
    if (me >= 0) {
      const s = this.seats[me], u = this.user(s.k);
      if (this.phase === 'bet') {
        if (u.aura < 5 && !s.pend) actions = ['restart'];
        else if (!s.ready) { actions = [5, 25, 100, 500].filter((v) => u.aura - s.pend >= v).map((v) => 'c' + v); if (s.pend) actions.push('clear', 'deal') }
      } else if (this.phase === 'insurance' && s.hands.length && !s.insDone) actions = ['ins', 'noins'];
      else if (this.phase === 'play' && this.turn && this.turn.seat === me) actions = this.allowed(s, s.hands[this.turn.hand]);
    }
    return {
      t: 'state', id: this.id, solo: this.solo, max: this.max, phase: this.phase, me, seats, actions,
      dealer: { cards: this.dealer.map(pub), total: ds.total, soft: ds.soft && this.phase !== 'result' && this.phase !== 'dealer' },
      turn: this.turn, peek: !!this.peek,
      timer: this.timerKind ? { kind: this.timerKind, left: Math.max(0, this.timerEnd - Date.now()), total: this.timerKind === 'bet' ? BET_WAIT : this.timerKind === 'turn' ? TURN_WAIT : INS_WAIT } : null,
      shoe: { left: this.shoe.length - this.pos, total: this.shoe.length, cut: this.shoe.length - this.cut },
      watchers: this.watch.size,
    };
  }
  broadcast(extra) {
    for (const c of this.watch) { const v = this.view(c.k); if (extra) Object.assign(v, extra); c.send(v) }
    lobbyPush();
  }
}
function getTable(id) {
  if (!tables.has(id)) tables.set(id, new Table(id, id.startsWith('solo:')));
  return tables.get(id);
}
getTable('bord');

// ---------- forbindelser ----------
const conns = new Set();
let link = '';
try { link = fs.readFileSync(path.join(HOME, 'link'), 'utf8').trim() } catch (e) {}
link = '';
const me = (c) => { const u = db.users[c.k]; return u ? { name: u.name, aura: u.aura, best: u.best || u.aura, hands: u.hands || 0 } : null };
function lobbyView(c) {
  const b = tables.get('bord');
  return { t: 'lobby', me: me(c), link, bord: b.players().map((x) => db.users[x.s.k].name), bordFull: b.players().length >= b.max };
}
let lobbyT = null;
function lobbyPush() {
  if (lobbyT) return;
  lobbyT = setTimeout(() => { lobbyT = null; for (const c of conns) if (c.k && !c.table) c.send(lobbyView(c)) }, 120);
}
function conn(c) {
  conns.add(c);
  c.onmsg = (o) => {
    if (o.t === 'ping') return c.send({ t: 'pong' });
    if (o.t === 'exists') { const n = cleanName(o.name); return c.send({ t: 'exists', name: n, yes: !!db.users[keyOf(n)] }) }
    if (o.t === 'login' || o.t === 'create') {
      const r = login(o.name, String(o.pin || ''), o.t === 'create');
      if (r.err) return c.send({ t: 'auth', ok: false, err: r.err, wait: r.wait });
      c.k = r.k; c.send({ t: 'auth', ok: true, token: r.token, me: me(c) }); return c.send(lobbyView(c));
    }
    if (o.t === 'resume') {
      const k = db.tokens[String(o.token || '')];
      if (!k || !db.users[k]) return c.send({ t: 'auth', ok: false, err: 'udløbet' });
      c.k = k; c.send({ t: 'auth', ok: true, token: o.token, me: me(c) });
      // var man midt i en runde, kommer man direkte tilbage til bordet
      for (const tb of tables.values()) { const i = tb.seatOf(k); if (i >= 0 && tb.seats[i].hands.length) return join(c, tb.id) }
      return c.send(lobbyView(c));
    }
    if (!c.k) return;
    if (o.t === 'logout') { delete db.tokens[String(o.token || '')]; save(); leaveTable(c); c.k = null; return c.send({ t: 'auth', ok: false, err: '' }) }
    if (o.t === 'join') return join(c, o.mode === 'solo' ? 'solo:' + c.k : 'bord');
    if (o.t === 'leave') { leaveTable(c); return c.send(lobbyView(c)) }
    if (c.table) tables.get(c.table)?.act(c.k, o);
  };
  c.onclose = () => { conns.delete(c); leaveTable(c) };
}
function join(c, id) {
  leaveTable(c);
  const tb = getTable(id);
  const seat = tb.sit(c.k);
  // samme konto i to vinduer: det nye vindue overtager
  for (const o of tb.watch) if (o.k === c.k && o !== c) { o.table = null; tb.watch.delete(o); o.send(lobbyView(o)) }
  c.table = id; tb.watch.add(c);
  if (seat < 0) c.send({ t: 'full' });
  tb.broadcast();
}
function leaveTable(c) {
  if (!c.table) return;
  const tb = tables.get(c.table); c.table = null;
  if (!tb) return;
  tb.watch.delete(c);
  if (![...tb.watch].some((o) => o.k === c.k)) tb.leave(c.k);
  if (tb.solo && !tb.players().length) tables.delete(tb.id);
  lobbyPush();
}

// ---------- http ----------
const FILES = { '/': 'index.html', '/index.html': 'index.html' };
const server = http.createServer((req, res) => {
  const u = (req.url || '/').split('?')[0];
  if (FILES[u]) {
    fs.readFile(path.join(DIR, FILES[u]), (e, d) => {
      if (e) { res.writeHead(500); return res.end() }
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(d);
    });
  } else if (u === '/ok') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok') }
  else if (u === '/link') { res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' }); res.end(link) }
  else { res.writeHead(404); res.end() }
});
server.on('upgrade', (req, socket) => {
  if ((req.url || '').split('?')[0] !== '/ws') return socket.destroy();
  const c = accept(req, socket); if (c) conn(c);
});
server.on('error', (e) => { log('port:', e.message); process.exit(1) });
server.listen(PORT, '127.0.0.1', () => {
  fs.writeFileSync(path.join(HOME, 'server.pid'), String(process.pid));
  log('lytter på', PORT); if (!NO_TUNNEL) tunnel();
});

// ---------- tunnel (link til vennerne) ----------
let cf = null, cfTries = 0, quitting = false, bad = 0, linkAt = 0;
function setLink(l) {
  link = l;
  try { fs.writeFileSync(path.join(HOME, 'link'), l) } catch (e) {}
  for (const c of conns) if (c.k && !c.table) c.send(lobbyView(c));
  for (const c of conns) c.send({ t: 'link', link: l });
  log('link', l || '(intet)');
}
function tunnel() {
  const bin = ['/opt/homebrew/bin/cloudflared', '/usr/local/bin/cloudflared'].find((p) => fs.existsSync(p)) || 'cloudflared';
  cf = spawn(bin, ['tunnel', '--no-autoupdate', '--url', 'http://127.0.0.1:' + PORT], { stdio: ['ignore', 'pipe', 'pipe'] });
  let url = '', up = false;
  const seen = (d) => {
    const s = String(d), m = s.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (m) url = m[0];
    if (/Registered tunnel connection/.test(s)) up = true;
    if (url && up && url !== link) { const u = url; cfTries = 0; bad = 0; linkAt = Date.now(); setTimeout(() => setLink(u), 1200) }
  };
  cf.stdout.on('data', seen); cf.stderr.on('data', seen);
  cf.on('error', (e) => log('cloudflared:', e.message));
  cf.on('exit', () => { cf = null; if (quitting) return; setLink(''); cfTries++; setTimeout(tunnel, Math.min(3000 * cfTries, 30000)) });
}
const resolver = new dns.Resolver({ timeout: 4000, tries: 1 }); resolver.setServers(['1.1.1.1', '8.8.8.8']);
function linkAlive(u) {
  return new Promise((done) => {
    const name = u.replace('https://', '');
    resolver.resolve4(name, (e, ips) => {
      if (e || !ips || !ips.length) return done(false);
      const r = https.request({ host: ips[0], servername: name, headers: { host: name }, path: '/ok', method: 'GET', timeout: 6000 }, (res) => {
        let b = ''; res.on('data', (d) => { b += d }); res.on('end', () => done(res.statusCode === 200 && b === 'ok'));
      });
      r.on('timeout', () => r.destroy()); r.on('error', () => done(false)); r.end();
    });
  });
}
const netUp = () => new Promise((done) => resolver.resolve4('cloudflare.com', (e, ips) => done(!e && !!ips && ips.length > 0)));
let checking = false;
setInterval(async () => {
  if (quitting || checking || !cf || !link || Date.now() - linkAt < 15000) return;
  checking = true;
  try {
    const u = link, ok = await linkAlive(u);
    if (u !== link || ok) { if (ok) bad = 0; return }
    if (!(await netUp())) return;
    if (++bad >= 3 && cf) { bad = 0; log('linket døde, laver et nyt'); try { cf.kill('SIGTERM') } catch (e) {} }
  } finally { checking = false }
}, 20000);

function quit() {
  if (quitting) return; quitting = true;
  try { if (cf) cf.kill('SIGTERM') } catch (e) {}
  try { if (saveT) { clearTimeout(saveT); fs.writeFileSync(DATA, JSON.stringify(db, null, 1)) } } catch (e) {}
  try { if (fs.readFileSync(path.join(HOME, 'server.pid'), 'utf8') === String(process.pid)) fs.unlinkSync(path.join(HOME, 'server.pid')) } catch (e) {}
  try { fs.writeFileSync(path.join(HOME, 'link'), '') } catch (e) {}
  setTimeout(() => process.exit(0), 300);
}
process.on('uncaughtException', (e) => { log('fejl', e && e.stack) });
process.on('SIGTERM', quit); process.on('SIGINT', quit); process.on('SIGHUP', quit);

// døde forbindelser lukkes; serveren lukker selv efter 2 timer helt uden spillere
let emptySince = Date.now();
setInterval(() => {
  const now = Date.now();
  conns.forEach((c) => { if (now - c.last > 15000) c.close() });
  if (conns.size) emptySince = now;
  else if (now - emptySince > 2 * 3600 * 1000) { log('ingen spillere i 2 timer'); quit() }
}, 3000);
