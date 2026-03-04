#!/usr/bin/env python3
import argparse
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

from flask import Flask, jsonify, request

app = Flask(__name__)

LOG_PATH = "network_lowlevel_log.jsonl"
DISCORD_WEBHOOK_URL = ""
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""
NOTIFY_MIN_SEVERITY = "high"
NOTIFY_CACHE: Dict[str, float] = {}
ALERT_WINDOW_MS = 15000
ALERT_BURST_THRESHOLD = 300
ALERT_SCAN_THRESHOLD = 20
ALERT_SYN_THRESHOLD = 40
SUSPICIOUS_PORTS: List[int] = [21, 23, 2323, 445, 3389, 4444, 31337]

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def should_notify(severity: str) -> bool:
    current = SEVERITY_RANK.get(severity, 0)
    minimum = SEVERITY_RANK.get(NOTIFY_MIN_SEVERITY, 3)
    return current >= minimum


def load_dotenv(dotenv_path: str = ".env") -> None:
    if not os.path.exists(dotenv_path):
        return

    try:
        with open(dotenv_path, "r", encoding="utf-8") as fp:
            for raw_line in fp:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("'").strip('"')
                if key:
                    os.environ.setdefault(key, value)
    except OSError:
        return


def post_json(url: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:  # nosec B310
            if 200 <= resp.status < 300:
                return True, "ok"
            return False, f"http_{resp.status}"
    except urllib.error.URLError as exc:
        return False, str(exc)


def send_discord_notification(message: str) -> Tuple[bool, str]:
    if not DISCORD_WEBHOOK_URL:
        return False, "discord_disabled"
    return post_json(DISCORD_WEBHOOK_URL, {"content": message})


def send_telegram_notification(message: str) -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False, "telegram_disabled"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    return post_json(url, {"chat_id": TELEGRAM_CHAT_ID, "text": message})


def read_events_from_cursor(path: str, cursor: int, limit: int) -> Tuple[List[Dict[str, Any]], int, bool]:
    if limit <= 0:
        limit = 1

    if not os.path.exists(path):
        return [], 0, False

    size = os.path.getsize(path)
    reset = False

    if cursor < 0 or cursor > size:
        cursor = 0
        reset = True

    events: List[Dict[str, Any]] = []

    with open(path, "rb") as fp:
        fp.seek(cursor)
        while len(events) < limit:
            line = fp.readline()
            if not line:
                break
            cursor = fp.tell()
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                events.append(json.loads(text))
            except json.JSONDecodeError:
                continue

    return events, cursor, reset


@app.get("/api/events")
def api_events() -> Any:
    cursor_raw = request.args.get("cursor", "0")
    limit_raw = request.args.get("limit", "250")

    try:
        cursor = int(cursor_raw)
    except ValueError:
        cursor = 0

    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 250

    limit = max(1, min(limit, 2000))

    events, next_cursor, reset = read_events_from_cursor(LOG_PATH, cursor, limit)

    return jsonify(
        {
            "events": events,
            "next_cursor": next_cursor,
            "reset": reset,
        }
    )


@app.post("/api/notify")
def api_notify() -> Any:
    payload = request.get_json(silent=True) or {}
    severity = str(payload.get("severity", "low")).lower()
    title = str(payload.get("title", "Alerta"))
    detail = str(payload.get("detail", ""))
    ts = str(payload.get("ts", ""))
    key = str(payload.get("key", f"{severity}:{title}:{detail}"))
    cooldown_ms = int(payload.get("cooldown_ms", 10000))

    if severity not in SEVERITY_RANK:
        return jsonify({"ok": False, "reason": "invalid_severity"}), 400

    if not should_notify(severity):
        return jsonify({"ok": True, "sent": [], "reason": "below_min_severity"})

    now = time.time() * 1000
    last = NOTIFY_CACHE.get(key, 0.0)
    if now - last < max(1000, cooldown_ms):
        return jsonify({"ok": True, "sent": [], "reason": "cooldown"})
    NOTIFY_CACHE[key] = now

    message = (
        f"[{severity.upper()}] {title}\n"
        f"{detail}\n"
        f"ts={ts if ts else 'n/a'}"
    )

    sent: List[str] = []
    errors: Dict[str, str] = {}

    ok_discord, err_discord = send_discord_notification(message)
    if ok_discord:
        sent.append("discord")
    elif err_discord != "discord_disabled":
        errors["discord"] = err_discord

    ok_telegram, err_telegram = send_telegram_notification(message)
    if ok_telegram:
        sent.append("telegram")
    elif err_telegram != "telegram_disabled":
        errors["telegram"] = err_telegram

    return jsonify({"ok": True, "sent": sent, "errors": errors})


@app.get("/api/config")
def api_config() -> Any:
    return jsonify(
        {
            "alert_window_ms": ALERT_WINDOW_MS,
            "alert_burst_threshold": ALERT_BURST_THRESHOLD,
            "alert_scan_threshold": ALERT_SCAN_THRESHOLD,
            "alert_syn_threshold": ALERT_SYN_THRESHOLD,
            "suspicious_ports": SUSPICIOUS_PORTS,
        }
    )


@app.get("/")
def index() -> str:
    return """<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\" />
  <title>Kernel Register Dashboard</title>
  <style>
    :root {
      --bg0: #08141f;
      --bg1: #0d2333;
      --bg2: #143247;
      --card: rgba(9, 22, 33, 0.82);
      --line: #21445b;
      --text: #d9eef7;
      --muted: #8fb0bf;
      --ok: #63d39a;
      --warn: #f4c95d;
      --danger: #ef6461;
      --cyan: #56cfe1;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      font-family: \"IBM Plex Sans\", \"Segoe UI\", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 10% 10%, #18415a 0%, transparent 38%),
        radial-gradient(circle at 92% 20%, #1e5f74 0%, transparent 35%),
        linear-gradient(140deg, var(--bg0), var(--bg1) 45%, var(--bg2));
      overflow-x: hidden;
    }

    .container {
      width: min(1200px, 95vw);
      margin: 28px auto;
      animation: fadeUp .55s ease;
    }

    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(12px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .title {
      margin: 0;
      font-family: \"Space Grotesk\", \"IBM Plex Sans\", sans-serif;
      letter-spacing: .5px;
      font-size: clamp(1.4rem, 2.4vw, 2.2rem);
    }

    .subtitle {
      margin: 8px 0 18px;
      color: var(--muted);
      font-size: .95rem;
    }

    .panel {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 14px;
      backdrop-filter: blur(6px);
      box-shadow: 0 14px 32px rgba(0,0,0,.25);
      padding: 14px;
    }

    .filters {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr auto auto;
      gap: 10px;
      margin-bottom: 14px;
    }

    input, select, button {
      width: 100%;
      border: 1px solid #2a5368;
      border-radius: 9px;
      background: #0c1f2d;
      color: var(--text);
      padding: 10px 12px;
      font: inherit;
    }

    button {
      cursor: pointer;
      transition: transform .15s ease, border-color .2s ease;
    }

    button:hover {
      transform: translateY(-1px);
      border-color: var(--cyan);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 8px;
      margin-bottom: 12px;
    }

    .stat {
      padding: 10px;
      border: 1px solid #2a5368;
      border-radius: 10px;
      background: rgba(10, 28, 40, .75);
      font-size: .9rem;
    }

    .stat strong {
      display: block;
      font-size: 1.1rem;
      margin-top: 2px;
    }

    .alerts {
      border: 1px solid #2a5368;
      border-radius: 10px;
      background: rgba(8, 24, 35, .72);
      margin-bottom: 12px;
      padding: 10px;
    }

    .alerts-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
      color: #b9dce9;
      font-size: .9rem;
    }

    .alerts-list {
      max-height: 180px;
      overflow: auto;
      display: grid;
      gap: 6px;
    }

    .alert-item {
      border: 1px solid #2a5368;
      border-left-width: 6px;
      border-radius: 8px;
      padding: 8px;
      font-size: .84rem;
      background: rgba(12, 30, 44, .8);
      animation: slideIn .25s ease;
    }

    .sev-high { border-left-color: var(--danger); }
    .sev-medium { border-left-color: var(--warn); }
    .sev-low { border-left-color: var(--ok); }

    @keyframes slideIn {
      from { opacity: 0; transform: translateY(-6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .table-wrap {
      max-height: 58vh;
      overflow: auto;
      border: 1px solid #2a5368;
      border-radius: 10px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: .85rem;
    }

    thead th {
      position: sticky;
      top: 0;
      background: #0a1b28;
      z-index: 1;
      text-align: left;
      border-bottom: 1px solid #2a5368;
      color: #b9dce9;
    }

    th, td {
      padding: 8px 10px;
      border-bottom: 1px solid rgba(46, 91, 113, .35);
      white-space: nowrap;
    }

    .p-TCP { color: var(--ok); }
    .p-UDP { color: var(--warn); }
    .p-ICMP { color: var(--danger); }

    .note {
      margin-top: 10px;
      color: var(--muted);
      font-size: .82rem;
    }

    @media (max-width: 900px) {
      .filters { grid-template-columns: 1fr 1fr; }
      .stats { grid-template-columns: repeat(3, 1fr); }
      .table-wrap { max-height: 52vh; }
    }
  </style>
</head>
<body>
  <main class=\"container\">
    <h1 class=\"title\">Kernel Register Dashboard</h1>
    <p class=\"subtitle\">Vista en vivo de eventos de red de bajo nivel + alertas</p>

    <section class=\"panel\">
      <div class=\"filters\">
        <input id=\"search\" placeholder=\"Buscar IP, puerto, flags...\" />
        <select id=\"proto\">
          <option value=\"ALL\">Todos protocolos</option>
          <option value=\"TCP\">TCP</option>
          <option value=\"UDP\">UDP</option>
          <option value=\"ICMP\">ICMP</option>
          <option value=\"OTHER\">OTHER</option>
        </select>
        <select id=\"direction\">
          <option value=\"ALL\">Toda direccion</option>
          <option value=\"to_server\">to_server</option>
          <option value=\"from_server\">from_server</option>
          <option value=\"unknown\">unknown</option>
        </select>
        <button id=\"pauseBtn\">Pausar</button>
        <button id=\"clearBtn\">Limpiar</button>
      </div>

      <div class=\"stats\">
        <div class=\"stat\">Eventos<br/><strong id=\"s-total\">0</strong></div>
        <div class=\"stat\">TCP<br/><strong id=\"s-tcp\">0</strong></div>
        <div class=\"stat\">UDP<br/><strong id=\"s-udp\">0</strong></div>
        <div class=\"stat\">ICMP<br/><strong id=\"s-icmp\">0</strong></div>
        <div class=\"stat\">Alertas<br/><strong id=\"s-alerts\">0</strong></div>
        <div class=\"stat\">Estado<br/><strong id=\"s-state\">LIVE</strong></div>
      </div>

      <div class=\"alerts\">
        <div class=\"alerts-head\">
          <strong>Alertas en tiempo real</strong>
          <button id=\"clearAlertsBtn\" style=\"max-width:180px\">Limpiar alertas</button>
        </div>
        <div class=\"alerts-list\" id=\"alertsList\"></div>
      </div>

      <div class=\"table-wrap\" id=\"tableWrap\">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Dir</th>
              <th>Proto</th>
              <th>Origen</th>
              <th>Destino</th>
              <th>Len</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody id=\"rows\"></tbody>
        </table>
      </div>

      <div class=\"note\">Reglas: SYN flood, port scan y puertos sensibles. Ajustables en el codigo JS.</div>
    </section>
  </main>

<script>
(() => {
  const rowsEl = document.getElementById('rows');
  const tableWrap = document.getElementById('tableWrap');
  const searchEl = document.getElementById('search');
  const protoEl = document.getElementById('proto');
  const dirEl = document.getElementById('direction');
  const pauseBtn = document.getElementById('pauseBtn');
  const clearBtn = document.getElementById('clearBtn');
  const clearAlertsBtn = document.getElementById('clearAlertsBtn');
  const alertsListEl = document.getElementById('alertsList');

  const sTotal = document.getElementById('s-total');
  const sTcp = document.getElementById('s-tcp');
  const sUdp = document.getElementById('s-udp');
  const sIcmp = document.getElementById('s-icmp');
  const sAlerts = document.getElementById('s-alerts');
  const sState = document.getElementById('s-state');

  let cursor = 0;
  let paused = false;
  let events = [];
  let alerts = [];
  const alertCooldown = new Map();
  let recentWindow = [];

  const maxEvents = 5000;
  const maxAlerts = 200;
  let windowMs = 15000;
  let burstThreshold = 300;
  let scanThreshold = 20;
  let synThreshold = 40;
  let suspiciousPorts = new Set([21, 23, 2323, 445, 3389, 4444, 31337]);

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('\"', '&quot;')
      .replaceAll(\"'\", '&#39;');
  }

  function asEpoch(ev) {
    const t = Date.parse(ev.timestamp_utc || '');
    return Number.isNaN(t) ? Date.now() : t;
  }

  function infoText(ev) {
    if (ev.layer4 === 'TCP') return 'flags=' + (ev.flags ?? '-');
    if (ev.layer4 === 'ICMP') return 'type=' + (ev.icmp_type ?? '-') + ' code=' + (ev.icmp_code ?? '-');
    return '-';
  }

  function eventMatches(ev) {
    const proto = protoEl.value;
    const direction = dirEl.value;
    const term = searchEl.value.trim().toLowerCase();

    if (proto !== 'ALL' && ev.layer4 !== proto) return false;
    if (direction !== 'ALL' && ev.direction !== direction) return false;

    if (!term) return true;
    const blob = [
      ev.timestamp_utc,
      ev.src_ip,
      ev.dst_ip,
      ev.src_port,
      ev.dst_port,
      ev.flags,
      ev.layer4,
      ev.direction,
      infoText(ev)
    ].join(' ').toLowerCase();

    return blob.includes(term);
  }

  async function loadConfig() {
    try {
      const res = await fetch('/api/config', { cache: 'no-store' });
      if (!res.ok) return;
      const cfg = await res.json();
      windowMs = Number(cfg.alert_window_ms ?? windowMs);
      burstThreshold = Number(cfg.alert_burst_threshold ?? burstThreshold);
      scanThreshold = Number(cfg.alert_scan_threshold ?? scanThreshold);
      synThreshold = Number(cfg.alert_syn_threshold ?? synThreshold);
      if (Array.isArray(cfg.suspicious_ports) && cfg.suspicious_ports.length) {
        suspiciousPorts = new Set(cfg.suspicious_ports.map(Number));
      }
    } catch (_) {
      // keep defaults
    }
  }

  function emitAlert(severity, title, detail, key, cooldownMs = 10000) {
    const now = Date.now();
    const last = alertCooldown.get(key) ?? 0;
    if (now - last < cooldownMs) {
      return;
    }
    alertCooldown.set(key, now);

    alerts.unshift({
      ts: new Date(now).toISOString(),
      severity,
      title,
      detail,
    });

    if (alerts.length > maxAlerts) {
      alerts = alerts.slice(0, maxAlerts);
    }

    notifyExternal({
      severity,
      title,
      detail,
      ts: new Date(now).toISOString(),
      key,
      cooldown_ms: cooldownMs
    });
  }

  async function notifyExternal(payload) {
    try {
      await fetch('/api/notify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (_) {
      // ignore notification transport errors in UI
    }
  }

  function analyzeAlerts(newEvents) {
    const now = Date.now();

    recentWindow.push(...newEvents.map(ev => ({ ...ev, __t: asEpoch(ev) })));
    recentWindow = recentWindow.filter(ev => (now - ev.__t) <= windowMs);

    const eps = newEvents.length;
    if (eps >= burstThreshold) {
      emitAlert('medium', 'Pico de trafico', `Entraron ${eps} eventos en 1s`, 'burst-1s', 8000);
    }

    const synBySrc = new Map();
    const portsBySrc = new Map();

    for (const ev of recentWindow) {
      const src = ev.src_ip || 'unknown';
      const dst = ev.dst_ip || 'unknown';
      const dport = Number(ev.dst_port ?? -1);

      if (!portsBySrc.has(src)) {
        portsBySrc.set(src, new Set());
      }
      if (dport > 0) {
        portsBySrc.get(src).add(dport);
      }

      if (ev.layer4 === 'TCP') {
        const flags = String(ev.flags || '');
        const isSynOnly = flags.includes('S') && !flags.includes('A');
        if (isSynOnly) {
          const k = `${src}->${dst}`;
          synBySrc.set(k, (synBySrc.get(k) || 0) + 1);
        }
      }

      if (suspiciousPorts.has(dport)) {
        emitAlert(
          'low',
          'Puerto sensible detectado',
          `Conexion a puerto ${dport} desde ${src} hacia ${dst}`,
          `sensitive-${src}-${dst}-${dport}`,
          15000
        );
      }
    }

    for (const [src, ports] of portsBySrc.entries()) {
      if (ports.size >= scanThreshold) {
        emitAlert(
          'medium',
          'Posible port scan',
          `${src} toco ${ports.size} puertos distintos en ${Math.round(windowMs / 1000)}s`,
          `scan-${src}`,
          12000
        );
      }
    }

    for (const [pair, count] of synBySrc.entries()) {
      if (count >= synThreshold) {
        emitAlert(
          'high',
          'Posible SYN flood',
          `${pair} genero ${count} SYN sin ACK en ${Math.round(windowMs / 1000)}s`,
          `synflood-${pair}`,
          10000
        );
      }
    }
  }

  function renderAlerts() {
    sAlerts.textContent = String(alerts.length);

    if (!alerts.length) {
      alertsListEl.innerHTML = '<div class="alert-item sev-low">Sin alertas por ahora.</div>';
      return;
    }

    alertsListEl.innerHTML = alerts.map(a => `
      <div class="alert-item sev-${escapeHtml(a.severity)}">
        <strong>[${escapeHtml(a.severity).toUpperCase()}] ${escapeHtml(a.title)}</strong><br/>
        <span>${escapeHtml(a.detail)}</span><br/>
        <small style="color:#8fb0bf">${escapeHtml(a.ts)}</small>
      </div>
    `).join('');
  }

  function render() {
    const filtered = events.filter(eventMatches);

    sTotal.textContent = String(filtered.length);
    sTcp.textContent = String(filtered.filter(e => e.layer4 === 'TCP').length);
    sUdp.textContent = String(filtered.filter(e => e.layer4 === 'UDP').length);
    sIcmp.textContent = String(filtered.filter(e => e.layer4 === 'ICMP').length);

    rowsEl.innerHTML = filtered.map(ev => {
      const layer4 = String(ev.layer4 || 'OTHER');
      const protoClass = ['TCP', 'UDP', 'ICMP'].includes(layer4) ? ('p-' + layer4) : '';
      const src = `${ev.src_ip}:${ev.src_port ?? '-'}`;
      const dst = `${ev.dst_ip}:${ev.dst_port ?? '-'}`;
      return `
        <tr>
          <td>${escapeHtml(ev.timestamp_utc)}</td>
          <td>${escapeHtml(ev.direction)}</td>
          <td class="${protoClass}">${escapeHtml(layer4)}</td>
          <td>${escapeHtml(src)}</td>
          <td>${escapeHtml(dst)}</td>
          <td>${escapeHtml(ev.packet_len)}</td>
          <td>${escapeHtml(infoText(ev))}</td>
        </tr>`;
    }).join('');

    const atBottom = (tableWrap.scrollTop + tableWrap.clientHeight) >= (tableWrap.scrollHeight - 20);
    if (atBottom) {
      tableWrap.scrollTop = tableWrap.scrollHeight;
    }

    renderAlerts();
  }

  async function poll() {
    if (paused) return;

    try {
      const res = await fetch(`/api/events?cursor=${cursor}&limit=500`, { cache: 'no-store' });
      if (!res.ok) return;
      const data = await res.json();

      if (data.reset) {
        cursor = 0;
      }

      if (Array.isArray(data.events) && data.events.length) {
        events.push(...data.events);
        if (events.length > maxEvents) {
          events = events.slice(events.length - maxEvents);
        }
        analyzeAlerts(data.events);
        render();
      }

      if (typeof data.next_cursor === 'number') {
        cursor = data.next_cursor;
      }
    } catch (_) {
      // keep polling silently
    }
  }

  pauseBtn.addEventListener('click', () => {
    paused = !paused;
    pauseBtn.textContent = paused ? 'Reanudar' : 'Pausar';
    sState.textContent = paused ? 'PAUSED' : 'LIVE';
  });

  clearBtn.addEventListener('click', () => {
    events = [];
    recentWindow = [];
    rowsEl.innerHTML = '';
    render();
  });

  clearAlertsBtn.addEventListener('click', () => {
    alerts = [];
    alertCooldown.clear();
    renderAlerts();
  });

  searchEl.addEventListener('input', render);
  protoEl.addEventListener('change', render);
  dirEl.addEventListener('change', render);

  loadConfig().then(render);
  setInterval(poll, 1000);
})();
</script>
</body>
</html>
"""


def main() -> int:
    load_dotenv(".env")

    parser = argparse.ArgumentParser(description="Dashboard web para eventos de red JSONL")
    parser.add_argument("--log", default="network_lowlevel_log.jsonl", help="Ruta del archivo JSONL")
    parser.add_argument("--host", default="127.0.0.1", help="Host bind del servidor web")
    parser.add_argument("--port", type=int, default=8787, help="Puerto del dashboard")
    parser.add_argument(
        "--discord-webhook-url",
        default=os.getenv("DISCORD_WEBHOOK_URL", ""),
        help="Webhook URL de Discord para notificaciones",
    )
    parser.add_argument(
        "--telegram-bot-token",
        default=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        help="Bot token de Telegram para notificaciones",
    )
    parser.add_argument(
        "--telegram-chat-id",
        default=os.getenv("TELEGRAM_CHAT_ID", ""),
        help="Chat ID de Telegram para notificaciones",
    )
    parser.add_argument(
        "--notify-min-severity",
        choices=["low", "medium", "high"],
        default=os.getenv("NOTIFY_MIN_SEVERITY", "high"),
        help="Severidad minima para enviar notificaciones",
    )
    parser.add_argument(
        "--alert-window-ms",
        type=int,
        default=int(os.getenv("ALERT_WINDOW_MS", "15000")),
        help="Ventana de analisis para alertas en milisegundos",
    )
    parser.add_argument(
        "--alert-burst-threshold",
        type=int,
        default=int(os.getenv("ALERT_BURST_THRESHOLD", "300")),
        help="Eventos por ciclo para alertar pico de trafico",
    )
    parser.add_argument(
        "--alert-scan-threshold",
        type=int,
        default=int(os.getenv("ALERT_SCAN_THRESHOLD", "20")),
        help="Cantidad de puertos distintos para marcar port scan",
    )
    parser.add_argument(
        "--alert-syn-threshold",
        type=int,
        default=int(os.getenv("ALERT_SYN_THRESHOLD", "40")),
        help="SYN sin ACK para marcar posible SYN flood",
    )
    parser.add_argument(
        "--suspicious-ports",
        default=os.getenv("SUSPICIOUS_PORTS", "21,23,2323,445,3389,4444,31337"),
        help="Puertos sensibles separados por coma",
    )
    args = parser.parse_args()

    global LOG_PATH, DISCORD_WEBHOOK_URL, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, NOTIFY_MIN_SEVERITY
    global ALERT_WINDOW_MS, ALERT_BURST_THRESHOLD, ALERT_SCAN_THRESHOLD, ALERT_SYN_THRESHOLD, SUSPICIOUS_PORTS
    LOG_PATH = args.log
    DISCORD_WEBHOOK_URL = args.discord_webhook_url.strip()
    TELEGRAM_BOT_TOKEN = args.telegram_bot_token.strip()
    TELEGRAM_CHAT_ID = args.telegram_chat_id.strip()
    NOTIFY_MIN_SEVERITY = args.notify_min_severity
    ALERT_WINDOW_MS = max(5000, args.alert_window_ms)
    ALERT_BURST_THRESHOLD = max(50, args.alert_burst_threshold)
    ALERT_SCAN_THRESHOLD = max(5, args.alert_scan_threshold)
    ALERT_SYN_THRESHOLD = max(10, args.alert_syn_threshold)
    parsed_ports = []
    for token in args.suspicious_ports.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            parsed_ports.append(port)
    if parsed_ports:
        SUSPICIOUS_PORTS = sorted(set(parsed_ports))

    print(f"Dashboard leyendo: {LOG_PATH}")
    print(f"Abre: http://{args.host}:{args.port}")
    print(f"Notificaciones desde severidad: {NOTIFY_MIN_SEVERITY}")
    print(f"Discord: {'ON' if DISCORD_WEBHOOK_URL else 'OFF'}")
    print(f"Telegram: {'ON' if (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID) else 'OFF'}")
    print(
        "Alertas config: "
        f"window_ms={ALERT_WINDOW_MS}, "
        f"burst={ALERT_BURST_THRESHOLD}, "
        f"scan={ALERT_SCAN_THRESHOLD}, "
        f"syn={ALERT_SYN_THRESHOLD}, "
        f"ports={SUSPICIOUS_PORTS}"
    )

    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
