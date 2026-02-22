const express = require('express');
const helmet = require('helmet');
const { Client } = require('ssh2');
const path = require('path');
const fs = require('fs/promises');
const { promisify } = require('util');
const { execFile } = require('child_process');
const { randomUUID } = require('crypto');

const execFileAsync = promisify(execFile);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MAX_HTML_BYTES = 512 * 1024;
const KEY_DIR = path.join(__dirname, '..', 'data', 'keys');
const DATA_DIR = path.join(__dirname, '..', 'data');
const SERVERS_FILE = path.join(DATA_DIR, 'servers.json');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

async function ensureDataFiles() {
  await fs.mkdir(DATA_DIR, { recursive: true });
  try {
    await fs.access(SERVERS_FILE);
  } catch {
    await fs.writeFile(SERVERS_FILE, '[]\n', 'utf8');
  }
}

async function readServerProfiles() {
  await ensureDataFiles();
  const raw = await fs.readFile(SERVERS_FILE, 'utf8');
  const data = JSON.parse(raw);
  return Array.isArray(data) ? data : [];
}

async function writeServerProfiles(profiles) {
  await ensureDataFiles();
  await fs.writeFile(SERVERS_FILE, `${JSON.stringify(profiles, null, 2)}\n`, 'utf8');
}

function singleQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return false;
  }

  if (domain.length > 253) {
    return false;
  }

  const normalized = domain.toLowerCase().trim();
  const labels = normalized.split('.');
  if (labels.length < 2) {
    return false;
  }

  return labels.every((label) => {
    if (!label || label.length > 63) {
      return false;
    }

    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }

    return /^[a-z0-9-]+$/.test(label);
  });
}

function validateConnectionPayload(payload) {
  if (!payload || typeof payload !== 'object') {
    return 'Invalid request payload';
  }

  const { host, port, username, privateKey, password } = payload;
  if (!host || typeof host !== 'string') {
    return 'SSH host is required';
  }

  if (!username || typeof username !== 'string') {
    return 'SSH username is required';
  }

  if (
    (!privateKey || typeof privateKey !== 'string' || !privateKey.trim()) &&
    (!password || typeof password !== 'string' || !password.trim())
  ) {
    return 'SSH private key or SSH password is required';
  }

  if (port && (Number.isNaN(Number(port)) || Number(port) < 1 || Number(port) > 65535)) {
    return 'Invalid SSH port';
  }

  return null;
}

function sshExec(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) {
        reject(err);
        return;
      }

      let stdout = '';
      let stderr = '';

      stream.on('close', (code) => {
        resolve({ code, stdout, stderr });
      });

      stream.on('data', (chunk) => {
        stdout += chunk.toString();
      });

      stream.stderr.on('data', (chunk) => {
        stderr += chunk.toString();
      });
    });
  });
}

function connectSsh({ host, port, username, privateKey, password }) {
  return new Promise((resolve, reject) => {
    const conn = new Client();

    conn
      .on('ready', () => resolve(conn))
      .on('error', (err) => reject(err))
      .connect({
        host,
        port: Number(port || 22),
        username,
        ...(privateKey && privateKey.trim() ? { privateKey } : {}),
        ...(!privateKey || !privateKey.trim() ? { password: String(password || '') } : {}),
        readyTimeout: 15000,
      });
  });
}

function toSafeKeyName(name) {
  return String(name || 'deployer')
    .toLowerCase()
    .replace(/[^a-z0-9-_]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 50) || 'deployer';
}

function getKeyPaths(keyName) {
  const safeName = toSafeKeyName(keyName);
  return {
    safeName,
    privateKeyPath: path.join(KEY_DIR, safeName),
    publicKeyPath: path.join(KEY_DIR, `${safeName}.pub`),
  };
}

async function ensureManagedKeyPair(keyName) {
  const { safeName, privateKeyPath, publicKeyPath } = getKeyPaths(keyName);
  await fs.mkdir(KEY_DIR, { recursive: true });

  let hasPrivate = true;
  let hasPublic = true;
  try {
    await fs.access(privateKeyPath);
  } catch {
    hasPrivate = false;
  }
  try {
    await fs.access(publicKeyPath);
  } catch {
    hasPublic = false;
  }

  if (!hasPrivate || !hasPublic) {
    await execFileAsync('ssh-keygen', [
      '-t',
      'ed25519',
      '-f',
      privateKeyPath,
      '-N',
      '',
      '-C',
      `managed-${safeName}`,
    ]);
    await fs.chmod(privateKeyPath, 0o600);
    await fs.chmod(publicKeyPath, 0o644);
  }

  const [privateKey, publicKey] = await Promise.all([
    fs.readFile(privateKeyPath, 'utf8'),
    fs.readFile(publicKeyPath, 'utf8'),
  ]);

  return { safeName, privateKey, publicKey, privateKeyPath, publicKeyPath };
}

async function runRemoteScript(connection, script) {
  const wrapped = `bash -lc ${singleQuote(script)}`;
  const result = await sshExec(connection, wrapped);
  if (result.code !== 0) {
    const details = [
      `Exit code: ${result.code}`,
      result.stdout ? `STDOUT:\n${result.stdout}` : '',
      result.stderr ? `STDERR:\n${result.stderr}` : '',
    ]
      .filter(Boolean)
      .join('\n\n');

    const error = new Error(details || 'Remote command failed');
    error.result = result;
    throw error;
  }

  return result;
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

function buildDeployScript(domain, htmlBase64) {
  const domainQ = singleQuote(domain);
  const htmlBase64Q = singleQuote(htmlBase64);

  return `
set -euo pipefail
DOMAIN=${domainQ}
WEB_ROOT="/var/www/$DOMAIN/html"
CONFIG_PATH="/etc/nginx/sites-available/$DOMAIN"
ENABLED_PATH="/etc/nginx/sites-enabled/$DOMAIN"

sudo mkdir -p "$WEB_ROOT"
printf '%s' ${htmlBase64Q} | base64 -d | sudo tee "$WEB_ROOT/index.html" > /dev/null

sudo tee "$CONFIG_PATH" > /dev/null <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    root $WEB_ROOT;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

if [ ! -e "$ENABLED_PATH" ]; then
  sudo ln -s "$CONFIG_PATH" "$ENABLED_PATH"
fi

sudo nginx -t
sudo systemctl reload nginx
echo "HTML deployed for $DOMAIN"
`.trim();
}

function buildCertbotScript(domain, includeWww, certbotEmail) {
  const domainQ = singleQuote(domain);
  const wwwDomain = `www.${domain}`;
  const wwwQ = singleQuote(wwwDomain);
  const certbotEmailArg = certbotEmail
    ? `--email ${singleQuote(certbotEmail)}`
    : '--register-unsafely-without-email';

  return `
set -euo pipefail
DOMAIN=${domainQ}

if ${includeWww ? 'true' : 'false'}; then
  WWW_DOMAIN=${wwwQ}
  sudo certbot --nginx -d "$DOMAIN" -d "$WWW_DOMAIN" --non-interactive --agree-tos ${certbotEmailArg} --redirect
else
  sudo certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos ${certbotEmailArg} --redirect
fi

sudo nginx -t
sudo systemctl reload nginx
echo "Certificate issued for $DOMAIN"
`.trim();
}

function buildEnableDisableScript(domain, enable) {
  const domainQ = singleQuote(domain);

  return `
set -euo pipefail
DOMAIN=${domainQ}
CONFIG_PATH="/etc/nginx/sites-available/$DOMAIN"
ENABLED_PATH="/etc/nginx/sites-enabled/$DOMAIN"

if [ ! -f "$CONFIG_PATH" ]; then
  echo "Config does not exist for $DOMAIN" >&2
  exit 2
fi

if ${enable ? 'true' : 'false'}; then
  if [ ! -e "$ENABLED_PATH" ]; then
    sudo ln -s "$CONFIG_PATH" "$ENABLED_PATH"
  fi
  echo "Site enabled: $DOMAIN"
else
  if [ -L "$ENABLED_PATH" ] || [ -e "$ENABLED_PATH" ]; then
    sudo rm -f "$ENABLED_PATH"
  fi
  echo "Site disabled: $DOMAIN"
fi

sudo nginx -t
sudo systemctl reload nginx
`.trim();
}

async function executeOperation(payload, scriptBuilder) {
  const validationError = validateConnectionPayload(payload);
  if (validationError) {
    const error = new Error(validationError);
    error.statusCode = 400;
    throw error;
  }

  const conn = await connectSsh(payload);
  try {
    const script = scriptBuilder();
    return await runRemoteScript(conn, script);
  } finally {
    conn.end();
  }
}

function getDomainFromPayload(payload) {
  const domain = String(payload?.domain || '').toLowerCase().trim();
  if (!isValidDomain(domain)) {
    const error = new Error('Invalid domain name');
    error.statusCode = 400;
    throw error;
  }

  return domain;
}

function getHtmlFromPayload(payload) {
  const html = String(payload?.html || '');
  if (!html) {
    const error = new Error('HTML content is required');
    error.statusCode = 400;
    throw error;
  }

  if (Buffer.byteLength(html, 'utf8') > MAX_HTML_BYTES) {
    const error = new Error(`HTML is too large. Max size: ${MAX_HTML_BYTES} bytes`);
    error.statusCode = 400;
    throw error;
  }

  return html;
}

function getCertbotEmail(payload) {
  const certbotEmail = String(payload?.certbotEmail || '').trim();
  if (!certbotEmail) {
    return '';
  }

  if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(certbotEmail)) {
    const error = new Error('Invalid certbot email');
    error.statusCode = 400;
    throw error;
  }

  return certbotEmail;
}

function pickProfileFields(payload) {
  return {
    name: String(payload?.name || '').trim(),
    host: String(payload?.host || '').trim(),
    port: String(payload?.port || '22').trim() || '22',
    username: String(payload?.username || '').trim(),
    password: String(payload?.password || ''),
    privateKey: String(payload?.privateKey || ''),
    domain: String(payload?.domain || '').trim(),
    keyName: String(payload?.keyName || '').trim(),
    certbotEmail: String(payload?.certbotEmail || '').trim(),
    html: String(payload?.html || ''),
    includeWww: Boolean(payload?.includeWww),
  };
}

function validateProfile(profile) {
  if (!profile.name) {
    return 'Profile name is required';
  }
  if (!profile.host) {
    return 'SSH host is required';
  }
  if (!profile.username) {
    return 'SSH username is required';
  }
  if (profile.port && (Number.isNaN(Number(profile.port)) || Number(profile.port) < 1 || Number(profile.port) > 65535)) {
    return 'Invalid SSH port';
  }
  return null;
}

app.post('/api/install', async (req, res) => {
  try {
    const result = await executeOperation(req.body, () => buildInstallScript());
    res.json({ ok: true, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.post('/api/deploy', async (req, res) => {
  try {
    const domain = getDomainFromPayload(req.body);
    const html = getHtmlFromPayload(req.body);
    const htmlBase64 = Buffer.from(html, 'utf8').toString('base64');

    const result = await executeOperation(req.body, () => buildDeployScript(domain, htmlBase64));
    res.json({ ok: true, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.post('/api/certbot', async (req, res) => {
  try {
    const domain = getDomainFromPayload(req.body);
    const includeWww = Boolean(req.body?.includeWww);
    const certbotEmail = getCertbotEmail(req.body);

    const result = await executeOperation(req.body, () =>
      buildCertbotScript(domain, includeWww, certbotEmail),
    );
    res.json({ ok: true, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.post('/api/site/enable', async (req, res) => {
  try {
    const domain = getDomainFromPayload(req.body);
    const result = await executeOperation(req.body, () => buildEnableDisableScript(domain, true));
    res.json({ ok: true, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.post('/api/site/disable', async (req, res) => {
  try {
    const domain = getDomainFromPayload(req.body);
    const result = await executeOperation(req.body, () => buildEnableDisableScript(domain, false));
    res.json({ ok: true, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.post('/api/full-deploy', async (req, res) => {
  try {
    const domain = getDomainFromPayload(req.body);
    const html = getHtmlFromPayload(req.body);
    const includeWww = Boolean(req.body?.includeWww);
    const certbotEmail = getCertbotEmail(req.body);
    const htmlBase64 = Buffer.from(html, 'utf8').toString('base64');

    const validationError = validateConnectionPayload(req.body);
    if (validationError) {
      return res.status(400).json({ ok: false, error: validationError });
    }

    const conn = await connectSsh(req.body);
    const stepLogs = [];

    try {
      const installRes = await runRemoteScript(conn, buildInstallScript());
      stepLogs.push({ step: 'install', stdout: installRes.stdout, stderr: installRes.stderr });

      const deployRes = await runRemoteScript(conn, buildDeployScript(domain, htmlBase64));
      stepLogs.push({ step: 'deploy', stdout: deployRes.stdout, stderr: deployRes.stderr });

      const certRes = await runRemoteScript(
        conn,
        buildCertbotScript(domain, includeWww, certbotEmail),
      );
      stepLogs.push({ step: 'certbot', stdout: certRes.stdout, stderr: certRes.stderr });

      res.json({ ok: true, steps: stepLogs });
    } finally {
      conn.end();
    }
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true });
});

app.post('/api/site/status', async (req, res) => {
  try {
    const domain = getDomainFromPayload(req.body);
    const result = await executeOperation(req.body, () => {
      const domainQ = singleQuote(domain);
      return `
set -euo pipefail
DOMAIN=${domainQ}
ENABLED_PATH="/etc/nginx/sites-enabled/$DOMAIN"
if [ -L "$ENABLED_PATH" ] || [ -e "$ENABLED_PATH" ]; then
  echo "enabled"
else
  echo "disabled"
fi
`.trim();
    });

    const status = result.stdout.trim() === 'enabled' ? 'enabled' : 'disabled';
    res.json({ ok: true, status, stdout: result.stdout, stderr: result.stderr });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.post('/api/ssh/bootstrap', async (req, res) => {
  try {
    const validationError = validateConnectionPayload(req.body);
    if (validationError) {
      return res.status(400).json({ ok: false, error: validationError });
    }

    const keyName = toSafeKeyName(req.body?.keyName || 'deployer');
    const managedKey = await ensureManagedKeyPair(keyName);
    const conn = await connectSsh({
      host: req.body.host,
      port: req.body.port,
      username: req.body.username,
      privateKey: req.body.privateKey,
      password: req.body.password,
    });

    try {
      const publicKeyQ = singleQuote(managedKey.publicKey.trim());
      await runRemoteScript(
        conn,
        `
set -euo pipefail
mkdir -p ~/.ssh
chmod 700 ~/.ssh
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
PUB=${publicKeyQ}
if ! grep -qxF "$PUB" ~/.ssh/authorized_keys; then
  echo "$PUB" >> ~/.ssh/authorized_keys
fi
echo "SSH key installed"
`.trim(),
      );
    } finally {
      conn.end();
    }

    res.json({
      ok: true,
      message: 'Managed SSH key installed on server',
      keyName: managedKey.safeName,
      privateKey: managedKey.privateKey,
      publicKey: managedKey.publicKey,
      privateKeyPath: managedKey.privateKeyPath,
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ ok: false, error: error.message });
  }
});

app.get('/api/ssh/managed-keys', async (_req, res) => {
  try {
    await fs.mkdir(KEY_DIR, { recursive: true });
    const entries = await fs.readdir(KEY_DIR, { withFileTypes: true });
    const keys = entries
      .filter((entry) => entry.isFile() && !entry.name.endsWith('.pub'))
      .map((entry) => entry.name);

    res.json({ ok: true, keys });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/servers', async (_req, res) => {
  try {
    const profiles = await readServerProfiles();
    res.json({ ok: true, servers: profiles });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/servers', async (req, res) => {
  try {
    const incoming = pickProfileFields(req.body);
    const validationError = validateProfile(incoming);
    if (validationError) {
      return res.status(400).json({ ok: false, error: validationError });
    }

    const profiles = await readServerProfiles();
    const id = String(req.body?.id || '').trim() || randomUUID();
    const now = new Date().toISOString();
    const existingIndex = profiles.findIndex((item) => item.id === id);
    const record = {
      id,
      ...incoming,
      updatedAt: now,
      createdAt: existingIndex >= 0 ? profiles[existingIndex].createdAt : now,
    };

    if (existingIndex >= 0) {
      profiles[existingIndex] = record;
    } else {
      profiles.push(record);
    }

    await writeServerProfiles(profiles);
    res.json({ ok: true, server: record, servers: profiles });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/servers/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) {
      return res.status(400).json({ ok: false, error: 'Server id is required' });
    }

    const profiles = await readServerProfiles();
    const nextProfiles = profiles.filter((item) => item.id !== id);
    await writeServerProfiles(nextProfiles);
    res.json({ ok: true, servers: nextProfiles });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Server started on http://localhost:${PORT}`);
});
