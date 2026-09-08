// ============================================================================
// Serveur auto-hébergé — Registre locatif SCI BLAFF
// Remplace Firebase : authentification par mot de passe + stockage SQLite,
// le tout hébergé chez vous, sans dépendance externe.
// ============================================================================

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const archiver = require('archiver');

const DATA_DIR = process.env.DATA_DIR || '/data';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'sci.db'));
db.pragma('journal_mode = WAL');

// ---------------------------------------------------------------------------
// Schéma
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_data (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT
  );

  CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL,
    name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    base64 TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS backup_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_hash TEXT,
    last_backup_at TEXT,
    last_status TEXT,
    google_refresh_token TEXT
  );
`);

// Migration douce : ajoute la colonne si la table existait déjà sans elle
// (installations antérieures à l'introduction du flux OAuth).
try {
  db.exec('ALTER TABLE backup_state ADD COLUMN google_refresh_token TEXT');
} catch (e) {
  // Colonne déjà présente : rien à faire.
}

// ---------------------------------------------------------------------------
// Bootstrap : premier compte admin créé depuis les variables d'environnement,
// uniquement si la table users est vide (premier démarrage).
// ---------------------------------------------------------------------------
const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const adminEmail = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD;
  const adminName = process.env.ADMIN_NAME || 'Admin';
  if (!adminEmail || !adminPassword) {
    console.error('╔══════════════════════════════════════════════════════════════════╗');
    console.error('║ ERREUR : aucun compte utilisateur et ADMIN_EMAIL / ADMIN_PASSWORD  ║');
    console.error('║ ne sont pas définis. Ajoutez-les dans docker-compose.yml puis      ║');
    console.error('║ redémarrez le conteneur.                                           ║');
    console.error('╚══════════════════════════════════════════════════════════════════╝');
  } else {
    const hash = bcrypt.hashSync(adminPassword, 10);
    db.prepare('INSERT INTO users (id, email, password_hash, name, created_at) VALUES (?,?,?,?,?)')
      .run(crypto.randomUUID(), adminEmail.toLowerCase(), hash, adminName, new Date().toISOString());
    console.log(`✓ Compte admin créé : ${adminEmail}`);
  }
}

// Données par défaut si jamais aucune n'existe encore
const dataRow = db.prepare('SELECT * FROM app_data WHERE id = 1').get();
if (!dataRow) {
  const defaultData = {
    sci: { name: '', siret: '', adresse: '', gerant: '', immeuble: '' },
    apartments: [
      { id: 'apt1', label: 'Lot 1', surface: '', etage: 'RDC' },
      { id: 'apt2', label: 'Lot 2', surface: '', etage: 'RDC' },
      { id: 'apt3', label: 'Lot 3', surface: '', etage: 'Étage' },
      { id: 'apt4', label: 'Lot 4', surface: '', etage: 'Étage' }
    ],
    leases: [],
    quittances: [],
    emailLog: [],
    bailTemplate: '',
    associes: [],
    activityLog: []
  };
  db.prepare('INSERT INTO app_data (id, json, updated_at, updated_by) VALUES (1, ?, ?, ?)')
    .run(JSON.stringify(defaultData), new Date().toISOString(), 'system');
}

const backupStateRow = db.prepare('SELECT * FROM backup_state WHERE id = 1').get();
if (!backupStateRow) {
  db.prepare('INSERT INTO backup_state (id, last_hash, last_backup_at, last_status) VALUES (1, NULL, NULL, NULL)').run();
}

// ---------------------------------------------------------------------------
// Sessions (tokens opaques, pas de JWT — plus simple à révoquer)
// ---------------------------------------------------------------------------
const SESSION_DURATION_DAYS = 30;

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000);
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .run(token, userId, now.toISOString(), expires.toISOString());
  return token;
}

function getUserFromToken(token) {
  if (!token) return null;
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return null;
  }
  return db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(session.user_id);
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const user = getUserFromToken(token);
  if (!user) return res.status(401).json({ error: 'Non authentifié.' });
  req.user = user;
  next();
}

// Authentification alternative pour l'export automatisé (sauvegarde quotidienne
// déclenchée par Home Assistant, sans session utilisateur classique). Accepte
// une clé fixe définie via l'option "export_api_key" de l'add-on — distincte
// des mots de passe utilisateurs, à usage unique (uniquement cette route).
const EXPORT_API_KEY = process.env.EXPORT_API_KEY || '';
function requireExportKey(req, res, next) {
  if (!EXPORT_API_KEY) return res.status(503).json({ error: "Export non configuré (option 'export_api_key' vide)." });
  const provided = req.headers['x-export-key'] || '';
  if (provided !== EXPORT_API_KEY) return res.status(401).json({ error: 'Clé d\'export invalide.' });
  next();
}

// Nettoyage périodique des sessions expirées
setInterval(() => {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());
}, 6 * 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// App Express
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '30mb' })); // marge pour les pièces jointes en base64 (jusqu'à ~20 Mo de fichier)

// --- Auth ---
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect.' });
  }
  const token = createSession(user.id);
  res.json({ token, user: { email: user.email, name: user.name } });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.slice(7);
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Mot de passe actuel requis et nouveau mot de passe d\'au moins 6 caractères.' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Mot de passe actuel incorrect.' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  res.json({ ok: true });
});

// Gestion des comptes associés (n'importe quel utilisateur connecté peut gérer les
// comptes des autres associés — cohérent avec le reste de l'app, pensée pour une
// petite SCI familiale de confiance, pas un système multi-rôles complexe).
app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, email, name, created_at FROM users').all();
  res.json({ users });
});

app.post('/api/users', requireAuth, (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || !name) return res.status(400).json({ error: 'Email, mot de passe et nom requis.' });
  if (password.length < 6) return res.status(400).json({ error: 'Le mot de passe doit faire au moins 6 caractères.' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'Un compte existe déjà avec cet email.' });
  const hash = bcrypt.hashSync(password, 10);
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO users (id, email, password_hash, name, created_at) VALUES (?,?,?,?,?)')
    .run(id, email.toLowerCase().trim(), hash, name, new Date().toISOString());
  res.json({ id, email: email.toLowerCase().trim(), name });
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Impossible de supprimer son propre compte ici.' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// --- Données de l'application (un seul blob JSON, comme avant) ---
app.get('/api/data', requireAuth, (req, res) => {
  const row = db.prepare('SELECT json, updated_at, updated_by FROM app_data WHERE id = 1').get();
  res.json({ data: JSON.parse(row.json), updatedAt: row.updated_at, updatedBy: row.updated_by });
});

app.put('/api/data', requireAuth, (req, res) => {
  const payload = req.body && req.body.data;
  if (!payload || typeof payload !== 'object') return res.status(400).json({ error: 'Corps de requête invalide.' });
  db.prepare('UPDATE app_data SET json = ?, updated_at = ?, updated_by = ? WHERE id = 1')
    .run(JSON.stringify(payload), new Date().toISOString(), req.user.email);
  res.json({ ok: true, updatedAt: new Date().toISOString() });
});

// --- Pièces jointes ---
app.post('/api/attachments', requireAuth, (req, res) => {
  const { leaseId, name, mimeType, base64 } = req.body || {};
  if (!leaseId || !name || !base64) return res.status(400).json({ error: 'Champs manquants.' });
  if (base64.length > 28_000_000) return res.status(413).json({ error: 'Fichier trop volumineux (~20 Mo max).' });
  const id = crypto.randomUUID();
  db.prepare('INSERT INTO attachments (id, lease_id, name, mime_type, base64, uploaded_at) VALUES (?,?,?,?,?,?)')
    .run(id, leaseId, name, mimeType || 'application/octet-stream', base64, new Date().toISOString());
  res.json({ id, name, mimeType: mimeType || 'application/octet-stream', uploadedAt: new Date().toISOString() });
});

app.get('/api/attachments/:id', requireAuth, (req, res) => {
  const att = db.prepare('SELECT * FROM attachments WHERE id = ?').get(req.params.id);
  if (!att) return res.status(404).json({ error: 'Introuvable.' });
  res.json({ name: att.name, mimeType: att.mime_type, base64: att.base64 });
});

app.delete('/api/attachments/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM attachments WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// --- Export complet (sauvegarde quotidienne) ---
// Combine les deux modes d'authentification : session utilisateur normale
// (usage manuel depuis l'app) OU clé d'export dédiée (automatisation HA).
function requireAuthOrExportKey(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const user = getUserFromToken(token);
  if (user) { req.user = user; return next(); }
  return requireExportKey(req, res, next);
}

// Construit l'archive ZIP complète (données + pièces jointes en clair) et la
// renvoie sous forme de Buffer, avec son empreinte SHA-256 (pour détecter si
// le contenu a changé depuis la dernière sauvegarde automatique).
function buildExportZipBuffer() {
  return new Promise((resolve, reject) => {
    const dataRow = db.prepare('SELECT json FROM app_data WHERE id = 1').get();
    const allAttachments = db.prepare('SELECT * FROM attachments').all();

    const archive = archiver('zip', { zlib: { level: 9 } });
    const chunks = [];
    archive.on('data', (chunk) => chunks.push(chunk));
    archive.on('error', reject);
    archive.on('end', () => {
      const buffer = Buffer.concat(chunks);
      const hash = crypto.createHash('sha256').update(buffer).digest('hex');
      resolve({ buffer, hash });
    });

    archive.append(JSON.stringify(JSON.parse(dataRow.json), null, 2), { name: 'donnees.json' });

    const manifest = allAttachments.map(a => ({
      id: a.id, leaseId: a.lease_id, name: a.name, mimeType: a.mime_type, uploadedAt: a.uploaded_at
    }));
    archive.append(JSON.stringify(manifest, null, 2), { name: 'pieces-jointes/manifeste.json' });

    for (const att of allAttachments) {
      const buffer = Buffer.from(att.base64, 'base64');
      const safeName = `${att.lease_id}__${att.name}`.replace(/[/\\]/g, '_');
      archive.append(buffer, { name: `pieces-jointes/${safeName}` });
    }

    archive.finalize();
  });
}

app.get('/api/export-full', requireAuthOrExportKey, async (req, res) => {
  try {
    const { buffer } = await buildExportZipBuffer();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.attachment(`sci-blaff-sauvegarde-${timestamp}.zip`);
    res.send(buffer);
  } catch (err) {
    console.error('[export-full] erreur:', err);
    res.status(500).json({ error: 'Échec de la génération de l\'export.' });
  }
});

// ---------------------------------------------------------------------------
// Sauvegarde automatique quotidienne vers Google Drive (OAuth avec le compte
// personnel de l'utilisateur — les comptes de service n'ont pas de quota de
// stockage propre sur un compte Google grand public, seulement sur Workspace
// avec des Drives partagés). Ne pousse un nouveau fichier que si le contenu a
// changé depuis la veille (comparaison par empreinte SHA-256).
// ---------------------------------------------------------------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const GOOGLE_DRIVE_FOLDER_ID = process.env.GOOGLE_DRIVE_FOLDER_ID || '';
const GOOGLE_REDIRECT_URI_PATH = '/api/google-oauth/callback';

function getStoredRefreshToken() {
  const row = db.prepare('SELECT google_refresh_token FROM backup_state WHERE id = 1').get();
  return row ? row.google_refresh_token : null;
}

// Démarre le flux d'autorisation : redirige l'utilisateur vers l'écran de
// consentement Google. access_type=offline + prompt=consent garantissent la
// délivrance d'un refresh_token même si l'utilisateur avait déjà autorisé
// l'app par le passé.
app.get('/api/google-oauth/start', requireAuth, (req, res) => {
  if (!GOOGLE_CLIENT_ID) {
    return res.status(503).send("Google OAuth non configuré (renseigne d'abord google_client_id / google_client_secret dans les options de l'add-on).");
  }
  const redirectUri = `${req.protocol}://${req.get('host')}${GOOGLE_REDIRECT_URI_PATH}`;
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/drive.file',
    access_type: 'offline',
    prompt: 'consent'
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

// Callback OAuth : échange le code contre un refresh_token et le stocke.
// Pas de requireAuth ici (Google redirige l'utilisateur, pas un fetch API
// authentifié), mais l'échange lui-même exige le client_secret, donc un
// tiers ne peut pas exploiter cette route sans le connaître.
app.get(GOOGLE_REDIRECT_URI_PATH, async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Autorisation refusée ou paramètre "code" manquant.');
  try {
    const redirectUri = `${req.protocol}://${req.get('host')}${GOOGLE_REDIRECT_URI_PATH}`;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      }).toString()
    });
    const tokenBody = await tokenRes.json();
    if (!tokenBody.refresh_token) {
      // Google ne renvoie un refresh_token que lors du tout premier consentement
      // (ou avec prompt=consent, ce qu'on force déjà) — si absent malgré tout,
      // le message d'erreur explique la marche à suivre.
      return res.status(400).send(
        'Aucun refresh_token reçu de Google : ' + JSON.stringify(tokenBody) +
        '<br><br>Réessaie en révoquant l\'accès existant sur <a href="https://myaccount.google.com/permissions" target="_blank">myaccount.google.com/permissions</a>, puis relance l\'autorisation.'
      );
    }
    db.prepare('UPDATE backup_state SET google_refresh_token = ? WHERE id = 1').run(tokenBody.refresh_token);
    res.send('<h2>✓ Connexion à Google Drive réussie.</h2><p>Tu peux fermer cette page et retourner dans l\'application.</p>');
  } catch (err) {
    res.status(500).send('Erreur lors de l\'échange du code OAuth : ' + err.message);
  }
});

let cachedGoogleToken = null; // { token, expiresAt }

async function getGoogleAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cachedGoogleToken && cachedGoogleToken.expiresAt > now + 60) {
    return cachedGoogleToken.token;
  }
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) throw new Error("Google Drive non autorisé (aucun refresh_token stocké — utilise le lien d'autorisation).");

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: 'refresh_token'
    }).toString()
  });
  const body = await res.json();
  if (!body.access_token) throw new Error('Échec du renouvellement du token Google : ' + JSON.stringify(body));
  cachedGoogleToken = { token: body.access_token, expiresAt: now + (body.expires_in || 3600) };
  return body.access_token;
}

async function uploadToGoogleDrive(buffer, filename) {
  const accessToken = await getGoogleAccessToken();

  const boundary = 'sciblaff' + crypto.randomBytes(8).toString('hex');
  const metadata = { name: filename, parents: GOOGLE_DRIVE_FOLDER_ID ? [GOOGLE_DRIVE_FOLDER_ID] : undefined };

  const bodyParts = [
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify(metadata)}\r\n`,
    `--${boundary}\r\nContent-Type: application/zip\r\n\r\n`
  ];
  const multipartBody = Buffer.concat([
    Buffer.from(bodyParts[0], 'utf8'),
    Buffer.from(bodyParts[1], 'utf8'),
    buffer,
    Buffer.from(`\r\n--${boundary}--`, 'utf8')
  ]);

  const res = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + accessToken,
      'Content-Type': `multipart/related; boundary=${boundary}`
    },
    body: multipartBody
  });
  const body = await res.json();
  if (!res.ok) throw new Error('Échec upload Google Drive : ' + JSON.stringify(body));
  return body; // { id, ... }
}

async function runDailyBackupIfChanged() {
  if (!getStoredRefreshToken()) {
    console.log('[backup] Google Drive non autorisé, sauvegarde ignorée.');
    return;
  }
  try {
    const { buffer, hash } = await buildExportZipBuffer();
    const state = db.prepare('SELECT * FROM backup_state WHERE id = 1').get();
    if (state && state.last_hash === hash) {
      console.log('[backup] Aucune modification depuis la dernière sauvegarde, envoi ignoré.');
      db.prepare('UPDATE backup_state SET last_status = ? WHERE id = 1').run('inchangé, non envoyé');
      return;
    }
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    await uploadToGoogleDrive(buffer, `sci-blaff-sauvegarde-${timestamp}.zip`);
    db.prepare('UPDATE backup_state SET last_hash = ?, last_backup_at = ?, last_status = ? WHERE id = 1')
      .run(hash, new Date().toISOString(), 'envoyé avec succès');
    console.log('[backup] Sauvegarde envoyée vers Google Drive avec succès.');
  } catch (err) {
    console.error('[backup] Échec de la sauvegarde automatique :', err.message);
    db.prepare('UPDATE backup_state SET last_status = ? WHERE id = 1').run('erreur : ' + err.message);
  }
}

// Vérifie chaque minute s'il est l'heure de la sauvegarde quotidienne (03:00),
// avec un verrou pour ne se déclencher qu'une seule fois par jour.
const BACKUP_HOUR = 3;
let lastBackupTriggerDate = null;
setInterval(() => {
  const now = new Date();
  const todayKey = now.toISOString().slice(0, 10);
  if (now.getHours() === BACKUP_HOUR && lastBackupTriggerDate !== todayKey) {
    lastBackupTriggerDate = todayKey;
    runDailyBackupIfChanged();
  }
}, 60 * 1000);

// Endpoint pour déclencher une sauvegarde manuellement (test / bouton dans
// l'interface) et pour consulter l'état de la dernière sauvegarde.
app.post('/api/backup/run-now', requireAuth, async (req, res) => {
  await runDailyBackupIfChanged();
  const state = db.prepare('SELECT * FROM backup_state WHERE id = 1').get();
  res.json({ ok: true, state });
});

app.get('/api/backup/status', requireAuth, (req, res) => {
  const state = db.prepare('SELECT * FROM backup_state WHERE id = 1').get();
  res.json({
    oauthClientConfigured: !!GOOGLE_CLIENT_ID,
    googleDriveConnected: !!getStoredRefreshToken(),
    lastBackupAt: state ? state.last_backup_at : null,
    lastStatus: state ? state.last_status : null
  });
});

// --- Fichiers statiques (le front-end) ---
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Route inconnue.' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SCI BLAFF server en écoute sur le port ${PORT}`);
});
