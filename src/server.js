const express = require('express');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs/promises');
const { randomUUID } = require('crypto');
const { Client } = require('ssh2');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, '..', 'data');
const STORE_FILE = path.join(DATA_DIR, 'payment-pages.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
let storeQueue = Promise.resolve();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

async function ensureStore() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(STORE_FILE);
  } catch {
      await fs.writeFile(
      STORE_FILE,
      JSON.stringify({ methods: [], pages: [] }, null, 2) + '\n',
      'utf8',
    );
  }
}

async function ensureSettings() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(SETTINGS_FILE);
  } catch {
    await fs.writeFile(
      SETTINGS_FILE,
      JSON.stringify({ publicDomain: '', previewBaseUrl: 'http://localhost:3000' }, null, 2) + '\n',
      'utf8',
    );
  }
}

async function readStore() {
  await ensureStore();
  try {
    const raw = await fs.readFile(STORE_FILE, 'utf8');
    const data = JSON.parse(raw);
    return {
      methods: Array.isArray(data.methods) ? data.methods : [],
      pages: Array.isArray(data.pages) ? data.pages : [],
    };
  } catch {
    const fallback = { methods: [], pages: [] };
    await fs.writeFile(STORE_FILE, JSON.stringify(fallback, null, 2) + '\n', 'utf8');
    return fallback;
  }
}

async function writeStore(store) {
  await ensureStore();
  await fs.writeFile(STORE_FILE, JSON.stringify(store, null, 2) + '\n', 'utf8');
}

async function readSettings() {
  await ensureSettings();
  try {
    const raw = await fs.readFile(SETTINGS_FILE, 'utf8');
    const data = JSON.parse(raw);
    return {
      publicDomain: cleanText(data.publicDomain, 200),
      previewBaseUrl: cleanText(data.previewBaseUrl || 'http://localhost:3000', 200),
      sshHost: cleanText(data.sshHost, 120),
      sshPort: cleanText(data.sshPort || '22', 10),
      sshUser: cleanText(data.sshUser, 120),
      sshPrivateKey: cleanText(data.sshPrivateKey, 12000),
      sshPassword: cleanText(data.sshPassword, 200),
      certbotEmail: cleanText(data.certbotEmail, 120),
    };
  } catch {
    const fallback = {
      publicDomain: '',
      previewBaseUrl: 'http://localhost:3000',
      sshHost: '',
      sshPort: '22',
      sshUser: '',
      sshPrivateKey: '',
      sshPassword: '',
      certbotEmail: '',
    };
    await fs.writeFile(SETTINGS_FILE, JSON.stringify(fallback, null, 2) + '\n', 'utf8');
    return fallback;
  }
}

async function writeSettings(settings) {
  await ensureSettings();
  await fs.writeFile(SETTINGS_FILE, JSON.stringify(settings, null, 2) + '\n', 'utf8');
}

function connectSsh({ host, port, username, privateKey, password }) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    conn
      .on('ready', () => resolve(conn))
      .on('error', reject)
      .connect({
        host,
        port: Number(port || 22),
        username,
        ...(privateKey ? { privateKey } : {}),
        ...(!privateKey ? { password: String(password || '') } : {}),
        readyTimeout: 15000,
      });
  });
}

function sshExec(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);
      let stdout = '';
      let stderr = '';
      stream.on('close', (code) => resolve({ code, stdout, stderr }));
      stream.on('data', (chunk) => { stdout += chunk.toString(); });
      stream.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    });
  });
}

function validateSshSettings(payload) {
  if (!payload.host) return 'SSH host is required';
  if (!payload.username) return 'SSH username is required';
  if (!payload.privateKey && !payload.password) return 'SSH private key or password is required';
  return null;
}

function buildInstallScript() {
  return `
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo systemctl enable nginx
sudo systemctl start nginx
echo "Nginx and Certbot installed"
`.trim();
}

function buildCertbotScript(domain, includeWww, email) {
  const www = includeWww ? ` -d www.${domain}` : '';
  const emailLine = email ? `--email '${String(email).replace(/'/g, `'"'"'`)}'` : '--register-unsafely-without-email';
  return `
set -euo pipefail
DOMAIN='${String(domain).replace(/'/g, `'"'"'`)}'
WEB_ROOT="/var/www/$DOMAIN/html"
sudo mkdir -p "$WEB_ROOT"
sudo certbot certonly --webroot -w "$WEB_ROOT" --cert-name "$DOMAIN" -d "$DOMAIN"${www} --non-interactive --agree-tos ${emailLine}
echo "Certificate issued for $DOMAIN"
`.trim();
}

function buildNginxScript(domain) {
  const domainQ = String(domain).replace(/'/g, `'"'"'`);
  return `
set -euo pipefail
DOMAIN='${domainQ}'
WEB_ROOT="/var/www/$DOMAIN/html"
CONFIG_PATH="/etc/nginx/sites-available/$DOMAIN"
ENABLED_PATH="/etc/nginx/sites-enabled/$DOMAIN"
LE_LIVE="/etc/letsencrypt/live/$DOMAIN"
sudo mkdir -p "$WEB_ROOT"
sudo tee "$CONFIG_PATH" > /dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root $WEB_ROOT;
    index index.html;
    location / {
        try_files \\$uri \\$uri/ =404;
    }
}
EOF
if [ -f "$LE_LIVE/fullchain.pem" ] && [ -f "$LE_LIVE/privkey.pem" ]; then
  sudo tee "$CONFIG_PATH" > /dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\\$host\\$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    root $WEB_ROOT;
    index index.html;
    ssl_certificate $LE_LIVE/fullchain.pem;
    ssl_certificate_key $LE_LIVE/privkey.pem;
    location / {
        try_files \\$uri \\$uri/ =404;
    }
}
EOF
fi
if [ ! -e "$ENABLED_PATH" ]; then sudo ln -s "$CONFIG_PATH" "$ENABLED_PATH"; fi
sudo nginx -t
sudo systemctl reload nginx
echo "Nginx configured for $DOMAIN"
`.trim();
}

function withStoreLock(fn) {
  const run = storeQueue.then(fn);
  storeQueue = run.catch(() => {});
  return run;
}

function nowIso() {
  return new Date().toISOString();
}

function cleanText(value, max = 500) {
  return String(value || '').trim().slice(0, max);
}

function cleanSlug(value) {
  return cleanText(value, 80)
    .toLowerCase()
    .replace(/[^a-z0-9-_]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function validateMethod(input) {
  if (!input.name) return 'Название реквизита обязательно';
  if (!input.bank) return 'Банк обязателен';
  if (!input.recipient) return 'Инициалы или получатель обязательны';
  if (!input.value) return 'Телефон или карта обязательны';
  return null;
}

function validatePage(input) {
  if (!input.title) return 'Название страницы обязательно';
  if (!input.slug) return 'Ссылка страницы обязательна';
  if (!input.amount) return 'Сумма обязательна';
  return null;
}

function normalizeMethod(payload) {
  return {
    id: cleanText(payload?.id || randomUUID(), 80),
    name: cleanText(payload?.name, 80),
    bank: cleanText(payload?.bank, 120),
    recipient: cleanText(payload?.recipient, 120),
    value: cleanText(payload?.value, 120),
    note: cleanText(payload?.note, 180),
    active: Boolean(payload?.active),
    createdAt: cleanText(payload?.createdAt || nowIso(), 40),
    updatedAt: nowIso(),
  };
}

function normalizePage(payload) {
  const requisites = Array.isArray(payload?.requisites)
    ? payload.requisites.map((item) => ({
        id: cleanText(item?.id || randomUUID(), 80),
        number: cleanText(item?.number, 120),
        bank: cleanText(item?.bank, 120),
        recipient: cleanText(item?.recipient, 120),
      })).filter((item) => item.number || item.bank || item.recipient)
    : [];
  return {
    id: cleanText(payload?.id || randomUUID(), 80),
    title: cleanText(payload?.title, 120),
    slug: cleanSlug(payload?.slug || payload?.title),
    amount: cleanText(payload?.amount, 30),
    currentMethodId: cleanText(payload?.currentMethodId, 80),
    buttonMode: payload?.buttonMode === 'redirect' ? 'redirect' : 'notice',
    buttonUrl: cleanText(payload?.buttonUrl, 300),
    active: payload?.active !== false,
    requisites,
    createdAt: cleanText(payload?.createdAt || nowIso(), 40),
    updatedAt: nowIso(),
  };
}

function normalizeSettings(payload) {
  return {
    publicDomain: cleanText(payload?.publicDomain, 200),
    previewBaseUrl: cleanText(payload?.previewBaseUrl || 'http://localhost:3000', 200),
    sshHost: cleanText(payload?.sshHost, 120),
    sshPort: cleanText(payload?.sshPort || '22', 10),
    sshUser: cleanText(payload?.sshUser, 120),
    sshPrivateKey: cleanText(payload?.sshPrivateKey, 12000),
    sshPassword: cleanText(payload?.sshPassword, 200),
    certbotEmail: cleanText(payload?.certbotEmail, 120),
  };
}

function renderPaymentPage(page, method) {
  const requisites = Array.isArray(page.requisites) && page.requisites.length
    ? page.requisites
    : method
      ? [{ number: method.value, bank: method.bank, recipient: method.recipient }]
      : [];
  const selected = requisites.length ? requisites[Math.floor(Math.random() * requisites.length)] : null;
  const title = escapeHtml(page.title || 'Оплата заказа');
  const amount = escapeHtml(page.amount || '');
  const bank = escapeHtml(selected?.bank || method?.bank || 'Банк не указан');
  const recipient = escapeHtml(selected?.recipient || method?.recipient || 'Получатель не указан');
  const value = escapeHtml(selected?.number || method?.value || 'Реквизиты не указаны');
  const note = escapeHtml(method?.note || '');
  const url = String(page.buttonUrl || '').trim();
  const useRedirect = page.buttonMode === 'redirect' && url;

  return `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} • Оплата</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    :root {
      --bg: #0f0a1f;
      --card: #1a1333;
      --accent: #7c3aed;
      --accent-light: #a78bfa;
      --text: #e0d4ff;
      --text-light: #c4b5fd;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Inter', sans-serif;
      background: linear-gradient(145deg, #0f0a1f 0%, #1a1333 100%);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }

    .container {
      background: var(--card);
      backdrop-filter: blur(20px);
      border-radius: 28px;
      border: 1px solid rgba(124, 58, 237, 0.25);
      box-shadow: 0 25px 55px -15px rgba(0, 0, 0, 0.65);
      width: 100%;
      max-width: 460px;
      overflow: hidden;
      position: relative;
    }

    .brand {
      position: absolute;
      top: 20px;
      left: 24px;
      font-size: 20px;
      font-weight: 700;
      color: #a78bfa;
    }

    .header {
      padding: 60px 24px 40px;
      text-align: center;
      background: linear-gradient(90deg, #6d28d9, #a855f7);
    }

    .header h1 {
      font-size: 28px;
      font-weight: 700;
      color: white;
      margin-bottom: 8px;
    }

    .header p {
      font-size: 16px;
      color: rgba(255,255,255,0.95);
    }

    .content {
      padding: 32px 24px 40px;
    }

    .amount {
      text-align: center;
      margin-bottom: 32px;
    }

    .amount-label {
      font-size: 15px;
      color: var(--text-light);
      margin-bottom: 8px;
    }

    .amount-value {
      font-size: 46px;
      font-weight: 700;
      color: white;
    }

    .timer {
      text-align: center;
      background: rgba(15, 10, 31, 0.8);
      border-radius: 16px;
      padding: 14px 20px;
      margin-bottom: 28px;
      border: 1px solid rgba(124, 58, 237, 0.3);
    }

    .timer-label { font-size: 13px; color: var(--text-light); margin-bottom: 4px; }
    .timer-value { font-size: 28px; font-weight: 700; color: #f43f5e; }

    .warning {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.4);
      color: #fda4af;
      padding: 16px 20px;
      border-radius: 16px;
      margin-bottom: 28px;
      font-size: 15.5px;
      animation: pulse-warning 2s infinite;
      text-align: center;
    }

    @keyframes pulse-warning {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.75; }
    }

    .info-block {
      background: rgba(15, 10, 31, 0.65);
      border-radius: 20px;
      padding: 24px;
      border: 1px solid rgba(124, 58, 237, 0.2);
      margin-bottom: 28px;
    }

    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px 0;
    }

    .label {
      color: var(--text-light);
      font-size: 15px;
      font-weight: 600;
    }

    .value {
      font-weight: 600;
      font-size: 17px;
      color: white;
      text-align: right;
      word-break: break-word;
    }

    .phone-section {
      margin-bottom: 32px;
    }

    .phone-label {
      font-size: 15px;
      color: var(--text-light);
      margin-bottom: 10px;
      padding-left: 4px;
    }

    .phone-wrapper {
      display: flex;
      align-items: center;
      background: #111827;
      border-radius: 16px;
      padding: 16px 18px;
      gap: 12px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }

    .phone-number {
      font-size: 22px;
      font-weight: 700;
      color: #c4b5fd;
      letter-spacing: 1.5px;
      flex: 1;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .copy-btn {
      background: rgba(124, 58, 237, 0.35);
      color: #c4b5fd;
      border: 1px solid rgba(167, 139, 250, 0.4);
      padding: 10px 20px;
      border-radius: 12px;
      font-size: 14px;
      font-weight: 600;
      white-space: nowrap;
      cursor: pointer;
      transition: 0.2s;
    }

    .copy-btn:hover {
      background: rgba(124, 58, 237, 0.6);
    }

    .copy-btn.copied {
      background: #22c55e;
      color: white;
    }

    .btn {
      width: 100%;
      background: linear-gradient(90deg, #7c3aed, #c026d3);
      color: white;
      border: none;
      padding: 18px;
      font-size: 17px;
      font-weight: 600;
      border-radius: 18px;
      cursor: pointer;
    }

    .legal {
      text-align: center;
      padding: 24px;
      font-size: 12.5px;
      color: #8b5cf6;
      opacity: 0.75;
      border-top: 1px solid rgba(124, 58, 237, 0.15);
    }

    .notice {
      display: none;
      margin-top: 16px;
      padding: 14px 16px;
      border-radius: 14px;
      background: rgba(34, 197, 94, 0.12);
      border: 1px solid rgba(34, 197, 94, 0.24);
      color: #bbf7d0;
      text-align: center;
      font-size: 14px;
    }

    @media (max-width: 520px) {
      .amount-value { font-size: 38px; }
      .header h1 { font-size: 24px; }
      .info-row { gap: 12px; align-items: flex-start; flex-direction: column; }
      .value { text-align: left; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">WBpay</div>
    <div class="header">
      <h1>${title}</h1>
      <p>Перевод по СБП</p>
    </div>

    <div class="content">
      <div class="amount">
        <div class="amount-label">К оплате</div>
        <div class="amount-value">${amount}</div>
      </div>

      <div class="timer">
        <div class="timer-label">Время на оплату</div>
        <div class="timer-value" id="timer">15:00</div>
      </div>

      <div class="warning">
        ⚠️ Переведите точно <strong>${amount}</strong> по указанным реквизитам через СБП в приложении вашего банка.
      </div>

      <div class="info-block">
        <div class="info-row">
          <span class="label">Выберите банк:</span>
          <span class="value">${bank}</span>
        </div>
      </div>

      <div class="phone-section">
        <div class="phone-label">Номер для перевода:</div>
        <div class="phone-wrapper">
          <div class="phone-number" id="paymentValue">${value}</div>
          <button class="copy-btn" id="copyBtn">Скопировать</button>
        </div>
      </div>

      ${note ? `<div class="info-block"><div class="info-row"><span class="label">Получатель:</span><span class="value">${recipient}</span></div><div class="info-row"><span class="label">Комментарий:</span><span class="value">${note}</span></div></div>` : `<div class="info-block"><div class="info-row"><span class="label">Получатель:</span><span class="value">${recipient}</span></div></div>`}

      <button class="btn" id="paidBtn">Я оплатил</button>
      <div class="notice" id="notice">Оплата отправлена. Вернитесь в бот, из которого создали заявку на оплату.</div>
    </div>

    <div class="legal">Страница оплаты и подтверждения заказа</div>
  </div>

  <script>
    const paidBtn = document.getElementById('paidBtn');
    const copyBtn = document.getElementById('copyBtn');
    const notice = document.getElementById('notice');
    const timer = document.getElementById('timer');
    const raw = {
      amount: ${JSON.stringify(page.amount || '')},
      bank: ${JSON.stringify(method?.bank || '')},
      recipient: ${JSON.stringify(method?.recipient || '')},
      value: ${JSON.stringify(method?.value || '')},
      comment: ${JSON.stringify(method?.note || '')},
      redirectUrl: ${JSON.stringify(url)},
      buttonMode: ${JSON.stringify(page.buttonMode || 'notice')},
    };

    let seconds = 15 * 60;
    const tick = () => {
      const m = String(Math.floor(seconds / 60)).padStart(2, '0');
      const s = String(seconds % 60).padStart(2, '0');
      timer.textContent = m + ':' + s;
      if (seconds > 0) seconds -= 1;
    };
    tick();
    setInterval(tick, 1000);

    paidBtn.addEventListener('click', () => {
      if (raw.buttonMode === 'redirect' && raw.redirectUrl) {
        window.location.href = raw.redirectUrl;
        return;
      }
      notice.style.display = 'block';
    });

    copyBtn.addEventListener('click', async () => {
      const text = [
        'Сумма: ' + raw.amount,
        'Банк: ' + raw.bank,
        'Получатель: ' + raw.recipient,
        'Телефон/карта: ' + raw.value,
        ...(raw.comment ? ['Комментарий: ' + raw.comment] : []),
      ].join('\\n');
      try {
        await navigator.clipboard.writeText(text);
        copyBtn.textContent = 'Скопировано';
        copyBtn.classList.add('copied');
        setTimeout(() => {
          copyBtn.textContent = 'Скопировать';
          copyBtn.classList.remove('copied');
        }, 1400);
      } catch {}
    });
  </script>
</body>
</html>`;
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/api/settings', async (_req, res) => {
  const settings = await readSettings();
  res.json({ ok: true, settings });
});

app.post('/api/settings', async (req, res) => {
  try {
    const settings = normalizeSettings(req.body);
    await writeSettings(settings);
    res.json({ ok: true, settings });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/publish/install', async (req, res) => {
  try {
    const settings = await readSettings();
    const validationError = validateSshSettings(req.body || {});
    if (validationError) return res.status(400).json({ ok: false, error: validationError });
    const conn = await connectSsh(req.body);
    try {
      const result = await sshExec(conn, buildInstallScript());
      res.json({ ok: true, stdout: result.stdout, stderr: result.stderr });
    } finally {
      conn.end();
    }
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/publish/configure', async (req, res) => {
  try {
    const settings = normalizeSettings(req.body);
    const domain = settings.publicDomain;
    if (!domain) return res.status(400).json({ ok: false, error: 'Domain is required' });
    const validationError = validateSshSettings(req.body || {});
    if (validationError) return res.status(400).json({ ok: false, error: validationError });
    const conn = await connectSsh(req.body);
    try {
      const result = await sshExec(conn, buildNginxScript(domain));
      await writeSettings(settings);
      res.json({ ok: true, stdout: result.stdout, stderr: result.stderr, settings });
    } finally {
      conn.end();
    }
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/publish/certbot', async (req, res) => {
  try {
    const settings = normalizeSettings(req.body);
    const domain = settings.publicDomain;
    if (!domain) return res.status(400).json({ ok: false, error: 'Domain is required' });
    const validationError = validateSshSettings(req.body || {});
    if (validationError) return res.status(400).json({ ok: false, error: validationError });
    const conn = await connectSsh(req.body);
    try {
      const result = await sshExec(conn, buildCertbotScript(domain, Boolean(req.body?.includeWww), cleanText(req.body?.certbotEmail, 120)));
      await writeSettings(settings);
      res.json({ ok: true, stdout: result.stdout, stderr: result.stderr, settings });
    } finally {
      conn.end();
    }
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/methods', async (_req, res) => {
  const store = await readStore();
  res.json({ ok: true, methods: store.methods });
});

app.post('/api/methods', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const incoming = normalizeMethod(req.body);
      const validationError = validateMethod(incoming);
      if (validationError) {
        const error = new Error(validationError);
        error.statusCode = 400;
        throw error;
      }

      const store = await readStore();
      const existingIndex = store.methods.findIndex((item) => item.id === incoming.id);
      const hasCurrent = store.methods.some((item) => item.active);
      const record = {
        ...incoming,
        active: existingIndex >= 0 ? store.methods[existingIndex].active : incoming.active || !hasCurrent,
      };

      if (existingIndex >= 0) store.methods[existingIndex] = record;
      else store.methods.push(record);

      if (record.active) {
        store.methods = store.methods.map((item) => ({ ...item, active: item.id === record.id, updatedAt: nowIso() }));
      }

      await writeStore(store);
      return { method: record, methods: store.methods };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.patch('/api/methods/:id/current', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const id = cleanText(req.params.id, 80);
      const store = await readStore();
      const method = store.methods.find((item) => item.id === id);
      if (!method) {
        const error = new Error('Method not found');
        error.statusCode = 404;
        throw error;
      }
      store.methods = store.methods.map((item) => ({ ...item, active: item.id === id, updatedAt: nowIso() }));
      await writeStore(store);
      return { methods: store.methods };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/methods/:id', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const id = cleanText(req.params.id, 80);
      const store = await readStore();
      store.methods = store.methods.filter((item) => item.id !== id);
      if (!store.methods.some((item) => item.active) && store.methods[0]) {
        store.methods[0].active = true;
      }
      await writeStore(store);
      return { methods: store.methods };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.get('/api/pages', async (_req, res) => {
  const store = await readStore();
  res.json({ ok: true, pages: store.pages });
});

app.post('/api/pages', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const incoming = normalizePage(req.body);
      const validationError = validatePage(incoming);
      if (validationError) {
        const error = new Error(validationError);
        error.statusCode = 400;
        throw error;
      }

      const store = await readStore();
      const existingIndex = store.pages.findIndex((item) => item.id === incoming.id || item.slug === incoming.slug);
      const currentMethod = store.methods.find((item) => item.id === incoming.currentMethodId && item.active) || store.methods.find((item) => item.active) || store.methods[0] || null;
      const record = {
        ...incoming,
        currentMethodId: currentMethod ? currentMethod.id : cleanText(incoming.currentMethodId, 80),
        requisites: incoming.requisites || [],
      };

      if (existingIndex >= 0) store.pages[existingIndex] = { ...store.pages[existingIndex], ...record, updatedAt: nowIso() };
      else store.pages.push(record);

      await writeStore(store);
      return { page: record, pages: store.pages };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.patch('/api/pages/:id/toggle', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const id = cleanText(req.params.id, 80);
      const store = await readStore();
      const page = store.pages.find((item) => item.id === id);
      if (!page) {
        const error = new Error('Page not found');
        error.statusCode = 404;
        throw error;
      }
      page.active = !page.active;
      page.updatedAt = nowIso();
      await writeStore(store);
      return { pages: store.pages };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.patch('/api/pages/:id/current-method', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const id = cleanText(req.params.id, 80);
      const methodId = cleanText(req.body?.methodId, 80);
      const store = await readStore();
      const page = store.pages.find((item) => item.id === id);
      if (!page) {
        const error = new Error('Page not found');
        error.statusCode = 404;
        throw error;
      }
      const method = store.methods.find((item) => item.id === methodId && item.active);
      if (!method) {
        const error = new Error('Active method not found');
        error.statusCode = 400;
        throw error;
      }
      page.currentMethodId = method.id;
      page.updatedAt = nowIso();
      await writeStore(store);
      return { pages: store.pages };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/pages/:id', async (req, res) => {
  try {
    const result = await withStoreLock(async () => {
      const id = cleanText(req.params.id, 80);
      const store = await readStore();
      store.pages = store.pages.filter((item) => item.id !== id);
      await writeStore(store);
      return { pages: store.pages };
    });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.get('/p/:slug', async (req, res) => {
  const store = await readStore();
  const slug = cleanSlug(req.params.slug);
  const page = store.pages.find((item) => item.slug === slug && item.active);
  if (!page) return res.status(404).send('Page not found');
  const method = store.methods.find((item) => item.id === page.currentMethodId && item.active) || store.methods.find((item) => item.active) || store.methods[0] || null;
  res.type('html').send(renderPaymentPage(page, method));
});

app.get('/test/:slug', async (req, res) => {
  const store = await readStore();
  const slug = cleanSlug(req.params.slug);
  const page = store.pages.find((item) => item.slug === slug);
  if (!page) return res.status(404).send('Page not found');
  const method = store.methods.find((item) => item.id === page.currentMethodId && item.active) || store.methods.find((item) => item.active) || store.methods[0] || null;
  res.type('html').send(renderPaymentPage(page, method));
});

app.get('/api/export', async (_req, res) => {
  const store = await readStore();
  res.json({ ok: true, ...store, publicBaseUrl: '/p/{slug}' });
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server started on http://localhost:${PORT}`);
});
