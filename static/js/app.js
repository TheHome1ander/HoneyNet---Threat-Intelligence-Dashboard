/**
 * HoneyNet Dashboard — app.js
 * WebSocket-driven threat intelligence dashboard.
 *
 * Architecture:
 *   1. On page load: fetch history (REST) + stats (REST), then connect WebSocket.
 *   2. Each WS "event" message: prepend row to table + update counters.
 *   3. Stats refresh every 30s from REST (accurate aggregate source of truth).
 *   4. WS disconnects trigger exponential-backoff reconnection.
 */

'use strict';

/* ── Constants ──────────────────────────────────────────────────────────── */
const MAX_FEED_ROWS   = 5000;   // Max rows displayed before oldest is pruned
const STATS_INTERVAL  = 30000; // Refresh stats every 30s
const WS_RECONNECT_BASE = 1500;
const WS_RECONNECT_MAX  = 30000;

/* ── State ──────────────────────────────────────────────────────────────── */
let ws               = null;
let wsReconnectDelay = WS_RECONNECT_BASE;
let wsConnected      = false;
let feedRowCount     = 0;
let statsData        = null;
let statsTimer       = null;

/* ── DOM refs ───────────────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);

const els = {
  wsPill:       $('wsPill'),
  liveDot:      $('liveDot'),
  wsLabel:      $('wsLabel'),
  headerTotal:  $('headerTotal'),
  headerClients:$('headerClients'),
  headerTime:   $('headerTime'),

  statTotal:    $('statTotal'),
  stat24h:      $('stat24h'),
  stat1h:       $('stat1h'),
  statIPs:      $('statIPs'),

  lvlCritical:  $('lvlCritical'),
  lvlHigh:      $('lvlHigh'),
  lvlMedium:    $('lvlMedium'),
  lvlLow:       $('lvlLow'),
  barCritical:  $('barCritical'),
  barHigh:      $('barHigh'),
  barMedium:    $('barMedium'),
  barLow:       $('barLow'),

  feedBody:     $('feedBody'),
  feedEmpty:    $('feedEmpty'),
  feedCount:    $('feedCount'),
  feedPulse:    $('feedPulse'),
  feedScroll:   $('feedScroll'),
  sortSelect:   $('sortSelect'),

  topIPs:       $('topIPs'),
  topPaths:     $('topPaths'),
  topCountries: $('topCountries'),

  eventModal:   $('eventModal'),
  modalBody:    $('modalBody'),
  modalClose:   $('modalClose'),
  modalBackdrop:$('modalBackdrop'),
};

/* ─────────────────────────────────────────────────────────────────────────
   WebSocket Management
   ───────────────────────────────────────────────────────────────────────── */

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const url   = `${proto}//${location.host}/ws`;

  ws = new WebSocket(url);

  ws.addEventListener('open', () => {
    wsConnected      = true;
    wsReconnectDelay = WS_RECONNECT_BASE;
    setWSStatus('connected', 'LIVE');
  });

  ws.addEventListener('message', e => {
    try {
      const msg = JSON.parse(e.data);
      handleWSMessage(msg);
    } catch (_) { /* ignore parse errors */ }
  });

  ws.addEventListener('close', () => {
    wsConnected = false;
    setWSStatus('disconnected', `Reconnecting in ${(wsReconnectDelay/1000).toFixed(0)}s…`);
    setTimeout(() => {
      wsReconnectDelay = Math.min(wsReconnectDelay * 1.5, WS_RECONNECT_MAX);
      connectWS();
    }, wsReconnectDelay);
  });

  ws.addEventListener('error', () => ws.close());
}

function handleWSMessage(msg) {
  if (msg.type === 'connected') {
    updateHeaderClients(msg.active_clients ?? 1);
  } else if (msg.type === 'event') {
    prependEvent(msg, true);
    bumpStats(msg);
  } else if (msg.type === 'ping') {
    updateHeaderClients(msg.active_clients ?? 0);
    updateClock();
  }
}

function setWSStatus(state, label) {
  els.wsPill.className  = `ws-pill ${state}`;
  els.wsLabel.textContent = label;
}

/* ─────────────────────────────────────────────────────────────────────────
   Initial Data Load
   ───────────────────────────────────────────────────────────────────────── */

async function loadHistory() {
  try {
    const sortBy = els.sortSelect ? els.sortSelect.value : 'time_desc';
    const res  = await fetch(`/api/events?limit=2000&sort_by=${sortBy}`);
    const data = await res.json();
    
    els.feedBody.innerHTML = '';
    feedRowCount = 0;
    
    // Reverse so that the first item in the list ends up at the top after prepending
    data.events.reverse().forEach(ev => prependEvent(ev, false));
    syncFeedEmpty();
  } catch (e) {
    console.warn('Failed to load history:', e);
  }
}

async function loadStats() {
  try {
    const res  = await fetch('/api/events/stats');
    statsData  = await res.json();
    renderStats(statsData);
  } catch (e) {
    console.warn('Failed to load stats:', e);
  }
}

function startStatsTimer() {
  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(loadStats, STATS_INTERVAL);
}

/* ─────────────────────────────────────────────────────────────────────────
   Stats Rendering
   ───────────────────────────────────────────────────────────────────────── */

function renderStats(d) {
  animCount(els.statTotal,   d.total_events);
  animCount(els.stat24h,     d.events_last_24h);
  animCount(els.stat1h,      d.events_last_1h);
  animCount(els.statIPs,     d.unique_ips);
  animCount(els.headerTotal, d.total_events);

  const lv   = d.by_threat_level || {};
  const total = d.total_events || 1;
  animCount(els.lvlCritical, lv.CRITICAL ?? 0);
  animCount(els.lvlHigh,     lv.HIGH     ?? 0);
  animCount(els.lvlMedium,   lv.MEDIUM   ?? 0);
  animCount(els.lvlLow,      lv.LOW      ?? 0);

  els.barCritical.style.width = pct(lv.CRITICAL, total);
  els.barHigh.style.width     = pct(lv.HIGH,     total);
  els.barMedium.style.width   = pct(lv.MEDIUM,   total);
  els.barLow.style.width      = pct(lv.LOW,      total);

  renderBarList(els.topIPs,       d.top_ips       || [], 'ip',      10);
  renderBarList(els.topPaths,     d.top_paths     || [], 'path',    10);
  renderBarList(els.topCountries, d.top_countries || [], 'country',  8);
}

/** Optimistic in-memory counter bump when a live WS event arrives */
function bumpStats(ev) {
  // Increment header total immediately (visual feedback before next REST poll)
  const cur = parseInt(els.headerTotal.textContent, 10) || 0;
  els.headerTotal.textContent = cur + 1;
  els.statTotal.textContent   = cur + 1;

  // Bump the appropriate threat level value
  const lvMap = {
    CRITICAL: els.lvlCritical,
    HIGH:     els.lvlHigh,
    MEDIUM:   els.lvlMedium,
    LOW:      els.lvlLow,
  };
  const el = lvMap[ev.threat_level];
  if (el) {
    const v = parseInt(el.textContent, 10) || 0;
    el.textContent = v + 1;
  }
}

function renderBarList(container, items, labelKey, maxBars) {
  if (!items.length) {
    container.innerHTML = '<div class="bar-empty">No data yet</div>';
    return;
  }
  const top    = items.slice(0, maxBars);
  const maxVal = top[0]?.hits || 1;
  container.innerHTML = top.map(item => {
    const label = item[labelKey] || '—';
    const pctW  = Math.max(4, Math.round((item.hits / maxVal) * 100));
    const disp  = labelKey === 'country'
      ? `${getFlagEmoji(item.country_code ?? '')} ${label}`
      : label;
    return `
      <div class="bar-item">
        <div class="bar-meta">
          <span class="bar-label" title="${escHtml(label)}">${escHtml(disp)}</span>
          <span class="bar-count">${item.hits.toLocaleString()}</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pctW}%"></div>
        </div>
      </div>`;
  }).join('');
}

/* ─────────────────────────────────────────────────────────────────────────
   Live Feed Table
   ───────────────────────────────────────────────────────────────────────── */

/** Prepend one event row to the table. animate=true for live WS events. */
function prependEvent(ev, animate) {
  const tbody = els.feedBody;

  // Prune oldest rows if over limit
  while (tbody.rows.length >= MAX_FEED_ROWS) {
    tbody.deleteRow(tbody.rows.length - 1);
    feedRowCount--;
  }

  const flagsRaw = Array.isArray(ev.flags) ? ev.flags : (ev.flags ? ev.flags.split(',') : []);
  const hasML = flagsRaw.includes('ML_ANOMALY') || flagsRaw.includes('ml_anomaly');
  const displayFlags = flagsRaw.filter(f => f.toUpperCase() !== 'ML_ANOMALY');

  const tr = document.createElement('tr');
  if (animate) tr.classList.add('row-new');
  if (hasML) tr.classList.add('ml-row');
  tr.dataset.eventId = ev.id ?? '';

  const flag     = getFlagEmoji(ev.country_code ?? '');
  const locLabel = ev.city && ev.city !== 'Unknown' && ev.city !== 'Private'
    ? ev.city
    : (ev.country ?? '—');
  const method   = (ev.method || 'GET').toUpperCase();

  const threatHtml = badgeHtml(ev.threat_level);

  tr.innerHTML = `
    <td class="cell-time" title="${escHtml(ev.timestamp ?? '')}">${relTime(ev.timestamp)}</td>
    <td class="cell-loc">
      <span class="cell-loc-flag">${flag}</span>
      <span class="cell-loc-name" title="${escHtml(locLabel)}">${escHtml(locLabel)}</span>
    </td>
    <td class="cell-ip">${escHtml(ev.ip ?? '—')}</td>
    <td class="cell-method ${method.toLowerCase()}">${escHtml(method)}</td>
    <td class="cell-path" title="${escHtml(ev.path ?? '')}">${escHtml(ev.path ?? '—')}</td>
    <td>${threatHtml}</td>
    <td>${flagChips(displayFlags)}</td>
  `;

  tr.addEventListener('click', () => openModal(ev));
  tbody.insertBefore(tr, tbody.firstChild);
  feedRowCount++;

  // Flash the pulse dot
  if (animate) {
    els.feedPulse.classList.remove('active');
    void els.feedPulse.offsetWidth; // reflow trick to restart animation
    els.feedPulse.classList.add('active');
  }

  updateFeedCount();
  syncFeedEmpty();

  // Auto-scroll only if the user is near the top
  if (!animate) return;
  if (els.feedScroll.scrollTop < 120) {
    els.feedScroll.scrollTop = 0;
  }
}

function updateFeedCount() {
  els.feedCount.textContent = `${feedRowCount.toLocaleString()} event${feedRowCount !== 1 ? 's' : ''}`;
}

function syncFeedEmpty() {
  if (feedRowCount === 0) {
    els.feedEmpty.classList.add('visible');
  } else {
    els.feedEmpty.classList.remove('visible');
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   Event Detail Modal
   ───────────────────────────────────────────────────────────────────────── */

function openModal(ev) {
  const flagsRaw = Array.isArray(ev.flags) ? ev.flags : (ev.flags ? ev.flags.split(',') : []);
  const hasML = flagsRaw.includes('ML_ANOMALY') || flagsRaw.includes('ml_anomaly');
  const displayFlags = flagsRaw.filter(f => f.toUpperCase() !== 'ML_ANOMALY');

  const rows = [
    ['Timestamp',    fmtTimestamp(ev.timestamp), true],
    ['IP Address',   ev.ip,                      true],
    ['Location',     `${ev.city ?? '—'}, ${ev.country ?? '—'}`, false],
    ['ISP',          ev.isp ?? '—',              false],
    null, // divider
    ['Method',       ev.method,                  true],
    ['Path',         ev.path,                    true],
    ['Query String', ev.query_string || '(none)', false],
    null,
    ['Threat Level', ev.threat_level,            true],
    ...(hasML ? [
      ['ML Anomaly', '✓ Detected by AI', false],
      ['ML Reason', ev.ml_reason || 'Outlier detected in multi-dimensional feature space', false]
    ] : []),
    ['Flags',        displayFlags.join(', ') || 'none', false],
    ['Scanner',      ev.is_scanner ? '✓ Yes' : 'No', false],
    ['Hit Count',    `${ev.hit_count} total / ${ev.window_count} in window`, false],
    null,
    ['User Agent',   ev.user_agent || '(none)',  false],
    ['Body Preview', ev.body_preview || '(empty)', false],
  ];

  els.modalBody.innerHTML = rows.map(r => {
    if (!r) return '<div class="modal-divider"></div>';
    const [key, val, highlight] = r;
    return `
      <span class="modal-key">${escHtml(key)}</span>
      <span class="modal-val${highlight ? ' highlight' : ''}">${escHtml(String(val ?? '—'))}</span>`;
  }).join('');

  els.eventModal.hidden = false;
}

function closeModal() {
  els.eventModal.hidden = true;
}

/* ─────────────────────────────────────────────────────────────────────────
   Helpers
   ───────────────────────────────────────────────────────────────────────── */

/** Format ISO country code as a cybersecurity-style tag */
function getFlagEmoji(code) {
  if (!code || code === 'XX' || code.length !== 2) return '[--]';
  return `[${code.toUpperCase()}]`;
}

/** Return an HTML threat-level badge */
function badgeHtml(level) {
  const cls = (level || 'LOW').toLowerCase();
  return `<span class="badge badge--${cls}">${escHtml(level || '—')}</span>`;
}

/** Return flag chip HTML for a list of flag strings */
function flagChips(flags) {
  if (!flags.length) return '<span style="color:var(--text-secondary);font-size:11px">—</span>';
  return flags.slice(0, 3).map(f => {
    const cls = f.toLowerCase().replace(/\s/g, '');
    return `<span class="flag-chip ${cls}">${escHtml(f)}</span>`;
  }).join('');
}

/** Relative time from an ISO string */
function relTime(iso) {
  if (!iso) return '—';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff <   5) return 'now';
  if (diff <  60) return `${Math.floor(diff)}s`;
  if (diff < 3600) return `${Math.floor(diff/60)}m`;
  return `${Math.floor(diff/3600)}h`;
}

/** Human-readable full timestamp */
function fmtTimestamp(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium', timeStyle: 'medium'
  });
}

/** Percent string, capped at 100% */
function pct(val, total) {
  if (!val || !total) return '0%';
  return Math.min(100, Math.round((val / total) * 100)) + '%';
}

/** Escape HTML special chars */
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Smooth animated counter using requestAnimationFrame */
function animCount(el, target) {
  if (!el) return;
  const start   = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
  const delta   = target - start;
  if (delta === 0) return;
  const dur     = 600; // ms
  const t0      = performance.now();
  function tick(now) {
    const frac = Math.min((now - t0) / dur, 1);
    const ease = 1 - Math.pow(1 - frac, 3); // easeOutCubic
    el.textContent = Math.round(start + delta * ease).toLocaleString();
    if (frac < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function updateHeaderClients(n) {
  els.headerClients.textContent = n;
}

function updateClock() {
  els.headerTime.textContent = new Date().toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

/* ─────────────────────────────────────────────────────────────────────────
   Relative-time ticker (updates all "Ns ago" cells every 15s)
   ───────────────────────────────────────────────────────────────────────── */
function startTimeTicker() {
  setInterval(() => {
    document.querySelectorAll('.cell-time').forEach(td => {
      const iso = td.title;
      if (iso) td.textContent = relTime(iso);
    });
  }, 15000);
}

/* ─────────────────────────────────────────────────────────────────────────
   Init
   ───────────────────────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', async () => {
  // Wire modal close actions
  els.modalClose.addEventListener('click', closeModal);
  els.modalBackdrop.addEventListener('click', closeModal);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  if (els.sortSelect) {
    els.sortSelect.addEventListener('change', loadHistory);
  }

  // Live clock
  updateClock();
  setInterval(updateClock, 1000);

  // Load history and stats in parallel
  await Promise.allSettled([loadHistory(), loadStats()]);

  // Start periodic stat refresh + relative-time ticker
  startStatsTimer();
  startTimeTicker();

  // Connect WebSocket for live events
  connectWS();
});
