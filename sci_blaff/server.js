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
`);

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
