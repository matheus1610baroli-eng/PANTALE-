'use strict';

/* ============================================================
   PANTALE — Backend de autenticação
   Node + Express + SQLite (nativo) + bcrypt + JWT
   ------------------------------------------------------------
   - Senhas guardadas com hash bcrypt (nunca em texto puro)
   - Sessão via JWT (token assinado, expira em 7 dias)
   - Serve também o site estático (mesma origem que a API)
============================================================ */

const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mailer = require('./mailer');

const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, '..'); // pasta do site (index.html, assets/)
const DB_PATH = path.join(__dirname, 'pantale.db');
const SECRET_PATH = path.join(__dirname, '.jwt-secret');
const ADMIN_KEY_PATH = path.join(__dirname, '.admin-key');

/* ------------------------------------------------------------
   Segredo do JWT — gerado uma vez e reutilizado.
   Em produção, prefira a variável de ambiente JWT_SECRET.
------------------------------------------------------------ */
function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (fs.existsSync(SECRET_PATH)) return fs.readFileSync(SECRET_PATH, 'utf8').trim();
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_PATH, secret, { mode: 0o600 });
  return secret;
}
const JWT_SECRET = loadSecret();
const TOKEN_TTL = '7d';
const BCRYPT_ROUNDS = 12; // custo do bcrypt (>=12 recomendado) [OWASP A02]

/* ------------------------------------------------------------
   Catálogo de preços — FONTE DA VERDADE no servidor.
   O preço NUNCA vem do cliente, evitando adulteração de valor
   (price tampering). Chave = nome do produto enviado pelo front.
   [OWASP A04 - Insecure Design]
------------------------------------------------------------ */
const CATALOG = {
  'Camiseta': 159,
  'Moletom': 249,
  'Camiseta Camouflage': 209
};

/* Comparação em tempo constante (evita timing attack em segredos) */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

/* ------------------------------------------------------------
   Chave de administração — para você (dono) consultar a base
   de clientes e pedidos. Gerada uma vez; veja no log de início.
------------------------------------------------------------ */
function loadAdminKey() {
  if (process.env.ADMIN_KEY) return process.env.ADMIN_KEY;
  if (fs.existsSync(ADMIN_KEY_PATH)) return fs.readFileSync(ADMIN_KEY_PATH, 'utf8').trim();
  const key = crypto.randomBytes(24).toString('hex');
  fs.writeFileSync(ADMIN_KEY_PATH, key, { mode: 0o600 });
  return key;
}
const ADMIN_KEY = loadAdminKey();

/* ------------------------------------------------------------
   Banco de dados
------------------------------------------------------------ */
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS cart_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    product    TEXT    NOT NULL,
    size       TEXT    NOT NULL,
    price      INTEGER NOT NULL,
    qty        INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    total      INTEGER NOT NULL,
    items      TEXT    NOT NULL,
    method     TEXT    NOT NULL DEFAULT 'pix',
    status     TEXT    NOT NULL DEFAULT 'aguardando_pagamento',
    customer   TEXT    NOT NULL DEFAULT '{}',
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS profiles (
    user_id    INTEGER PRIMARY KEY,
    phone      TEXT NOT NULL DEFAULT '',
    cep        TEXT NOT NULL DEFAULT '',
    address    TEXT NOT NULL DEFAULT '',
    number     TEXT NOT NULL DEFAULT '',
    complement TEXT NOT NULL DEFAULT '',
    district   TEXT NOT NULL DEFAULT '',
    city       TEXT NOT NULL DEFAULT '',
    uf         TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token_hash TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Migrações leves: garantem colunas novas em bancos antigos
try { db.exec("ALTER TABLE orders ADD COLUMN method TEXT NOT NULL DEFAULT 'pix'"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'aguardando_pagamento'"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN customer TEXT NOT NULL DEFAULT '{}'"); } catch (e) {}

const stmtFindByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const stmtFindById = db.prepare('SELECT id, name, email, created_at FROM users WHERE id = ?');
const stmtInsert = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
const stmtUpdatePassword = db.prepare('UPDATE users SET password = ? WHERE id = ?');

/* Redefinição de senha */
const stmtResetInvalidate = db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0');
const stmtResetInsert = db.prepare('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)');
const stmtResetFind = db.prepare('SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?');
const stmtResetMarkUsed = db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?');

/* Sacola (carrinho) */
const stmtCartList = db.prepare('SELECT id, product, size, price, qty FROM cart_items WHERE user_id = ? ORDER BY created_at ASC, id ASC');
const stmtCartFind = db.prepare('SELECT id, qty FROM cart_items WHERE user_id = ? AND product = ? AND size = ?');
const stmtCartInsert = db.prepare('INSERT INTO cart_items (user_id, product, size, price, qty) VALUES (?, ?, ?, ?, ?)');
const stmtCartBumpQty = db.prepare('UPDATE cart_items SET qty = qty + 1 WHERE id = ? AND user_id = ?');
const stmtCartSetQty = db.prepare('UPDATE cart_items SET qty = ? WHERE id = ? AND user_id = ?');
const stmtCartDelete = db.prepare('DELETE FROM cart_items WHERE id = ? AND user_id = ?');
const stmtCartClear = db.prepare('DELETE FROM cart_items WHERE user_id = ?');

/* Pedidos */
const stmtOrderInsert = db.prepare('INSERT INTO orders (user_id, total, items, method, status, customer) VALUES (?, ?, ?, ?, ?, ?)');
const stmtUserStats = db.prepare('SELECT COUNT(*) AS orders, COALESCE(SUM(total), 0) AS total_spent FROM orders WHERE user_id = ?');

/* Perfil / dados de entrega do cliente */
const stmtProfileGet = db.prepare('SELECT phone, cep, address, number, complement, district, city, uf FROM profiles WHERE user_id = ?');
const stmtProfileUpsert = db.prepare(`
  INSERT INTO profiles (user_id, phone, cep, address, number, complement, district, city, uf, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  ON CONFLICT(user_id) DO UPDATE SET
    phone=excluded.phone, cep=excluded.cep, address=excluded.address,
    number=excluded.number, complement=excluded.complement, district=excluded.district,
    city=excluded.city, uf=excluded.uf, updated_at=datetime('now')
`);

/* Gestão (visão do dono): clientes com agregados */
const stmtAdminCustomers = db.prepare(`
  SELECT u.id, u.name, u.email, u.created_at,
         p.phone, p.cep, p.address, p.number, p.complement, p.district, p.city, p.uf,
         COUNT(o.id) AS orders,
         COALESCE(SUM(o.total), 0) AS total_spent,
         MAX(o.created_at) AS last_order
  FROM users u
  LEFT JOIN profiles p ON p.user_id = u.id
  LEFT JOIN orders   o ON o.user_id = u.id
  GROUP BY u.id
  ORDER BY total_spent DESC
`);

function publicProfile(userRow, profRow) {
  profRow = profRow || {};
  return {
    name: userRow.name,
    email: userRow.email,
    phone: profRow.phone || '',
    cep: profRow.cep || '',
    address: profRow.address || '',
    number: profRow.number || '',
    complement: profRow.complement || '',
    district: profRow.district || '',
    city: profRow.city || '',
    uf: profRow.uf || ''
  };
}

function userStats(userId) {
  const s = stmtUserStats.get(userId) || { orders: 0, total_spent: 0 };
  const orders = s.orders || 0;
  const totalSpent = s.total_spent || 0;
  return { orders, totalSpent, avgTicket: orders ? Math.round(totalSpent / orders) : 0 };
}

function cartPayload(userId) {
  const items = stmtCartList.all(userId);
  const total = items.reduce((sum, it) => sum + it.price * it.qty, 0);
  const count = items.reduce((sum, it) => sum + it.qty, 0);
  return { items, total, count };
}

/* ------------------------------------------------------------
   Helpers
------------------------------------------------------------ */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, created_at: row.created_at };
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const row = stmtFindById.get(payload.sub);
    if (!row) return res.status(401).json({ error: 'Sessão inválida.' });
    req.user = row;
    next();
  } catch {
    return res.status(401).json({ error: 'Sessão expirada ou inválida.' });
  }
}

/* ------------------------------------------------------------
   Headers de segurança (sem dependência externa). [OWASP A05]
   CSP permite inline porque o index.html tem <script>/<style>
   embutidos; o restante é estrito.
------------------------------------------------------------ */
function securityHeaders(req, res, next) {
  res.set('X-Frame-Options', 'DENY');                       // clickjacking
  res.set('X-Content-Type-Options', 'nosniff');             // MIME sniffing
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin'); // não vaza ?reset= via Referer
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  res.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.set('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "media-src 'self'",
    "connect-src 'self' https://viacep.com.br",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; '));
  next();
}

/* CORS restrito a origens permitidas (sem wildcard). [OWASP A05]
   Same-origin/curl/apps (sem header Origin) continuam liberados. */
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false); // não envia Access-Control-Allow-Origin → bloqueado no navegador
  }
};

/* ------------------------------------------------------------
   Rate limiting em memória (janela fixa por IP+rota).
   Mitiga brute-force, e-mail bombing e abuso de checkout.
   Para múltiplas instâncias, troque o Map por Redis. [OWASP A07]
------------------------------------------------------------ */
function rateLimit({ windowMs, max, message }) {
  const hits = new Map(); // chave -> { count, resetAt }
  const sweep = setInterval(() => {
    const t = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
  }, windowMs);
  if (sweep.unref) sweep.unref();
  return function (req, res, next) {
    const now = Date.now();
    const key = (req.ip || 'unknown') + '|' + req.baseUrl + req.path;
    let rec = hits.get(key);
    if (!rec || rec.resetAt <= now) { rec = { count: 0, resetAt: now + windowMs }; hits.set(key, rec); }
    rec.count += 1;
    if (rec.count > max) {
      res.set('Retry-After', String(Math.ceil((rec.resetAt - now) / 1000)));
      return res.status(429).json({ error: message || 'Muitas tentativas. Tente novamente mais tarde.' });
    }
    next();
  };
}

/* ------------------------------------------------------------
   App
------------------------------------------------------------ */
const app = express();
app.disable('x-powered-by');     // não vaza a tecnologia (era "Express")
app.set('trust proxy', 1);       // confia no proxy (Vercel/Render/VPS) para req.ip
app.use(securityHeaders);
app.use(cors(corsOptions));
app.use(express.json({ limit: '32kb' })); // limita tamanho do corpo

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Muitas tentativas. Aguarde alguns minutos.' });
const checkoutLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: 'Não foi possível processar agora. Tente novamente mais tarde.' });
app.use(['/api/login', '/api/register', '/api/forgot', '/api/reset'], authLimiter);
app.use('/api/checkout', checkoutLimiter);

// Cadastro
app.post('/api/register', async (req, res) => {
  try {
    let { name, email, password } = req.body || {};
    name = (name || '').trim();
    email = (email || '').trim().toLowerCase();

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Preencha nome, e-mail e senha.' });
    }
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'E-mail inválido.' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: 'A senha deve ter ao menos 6 caracteres.' });
    }
    if (stmtFindByEmail.get(email)) {
      return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
    }

    const hash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
    const info = stmtInsert.run(name, email, hash);
    const row = stmtFindById.get(info.lastInsertRowid);
    const token = signToken(row);
    return res.status(201).json({ token, user: publicUser(row) });
  } catch (err) {
    console.error('register error:', err);
    return res.status(500).json({ error: 'Erro ao cadastrar.' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = (email || '').trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({ error: 'Informe e-mail e senha.' });
    }
    const row = stmtFindByEmail.get(email);
    if (!row) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }
    const ok = await bcrypt.compare(String(password), row.password);
    if (!ok) {
      return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
    }
    const token = signToken(row);
    return res.json({ token, user: publicUser(row) });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Erro ao entrar.' });
  }
});

// Esqueci a senha — gera token e envia link para o e-mail cadastrado
app.post('/api/forgot', async (req, res) => {
  try {
    let { email } = req.body || {};
    email = (email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'Informe um e-mail válido.' });
    }
    const row = stmtFindByEmail.get(email);
    // Mensagem genérica (não revela se o e-mail existe)
    const generic = { ok: true, message: 'Se este e-mail tiver conta, enviamos um link de redefinição.' };

    if (row) {
      const token = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hora
      stmtResetInvalidate.run(row.id);              // invalida pedidos antigos
      stmtResetInsert.run(row.id, tokenHash, expiresAt);

      // Base do link fixada no servidor (APP_URL) — NUNCA vem do cliente,
      // senão um atacante redirecionaria o token de reset. [OWASP A07]
      const base = (process.env.APP_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
      const link = `${base}/?reset=${token}`;
      mailer.sendResetEmail(row.email, row.name, link)
        .then((r) => { if (!r.sent) console.warn('E-mail de reset não enviado:', r.reason); })
        .catch((e) => console.error('Erro no e-mail de reset:', e.message));

      if (!mailer.isEnabled()) generic.aviso = 'E-mail não configurado no servidor (link não enviado).';
    }
    return res.json(generic);
  } catch (err) {
    console.error('forgot error:', err);
    return res.status(500).json({ error: 'Erro ao solicitar redefinição.' });
  }
});

// Redefinir a senha usando o token recebido por e-mail
app.post('/api/reset', async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Token ausente.' });
    if (String(password || '').length < 6) {
      return res.status(400).json({ error: 'A senha deve ter ao menos 6 caracteres.' });
    }
    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    const row = stmtResetFind.get(tokenHash);
    if (!row || row.used || row.expires_at < Date.now()) {
      return res.status(400).json({ error: 'Link inválido ou expirado. Solicite um novo.' });
    }
    const hash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
    stmtUpdatePassword.run(hash, row.user_id);
    stmtResetMarkUsed.run(row.id);

    const user = stmtFindById.get(row.user_id);
    const jwtToken = signToken(user);
    return res.json({ token: jwtToken, user: publicUser(user) });
  } catch (err) {
    console.error('reset error:', err);
    return res.status(500).json({ error: 'Erro ao redefinir a senha.' });
  }
});

// Dados do usuário logado
app.get('/api/me', authRequired, (req, res) => {
  return res.json({ user: publicUser(req.user) });
});

/* ------------------------------------------------------------
   PERFIL / DADOS DE ENTREGA (salvos por cliente)
------------------------------------------------------------ */

// Buscar perfil + estatísticas do próprio cliente
app.get('/api/profile', authRequired, (req, res) => {
  const prof = stmtProfileGet.get(req.user.id);
  return res.json({
    profile: publicProfile(req.user, prof),
    stats: userStats(req.user.id)
  });
});

// Salvar/atualizar perfil (endereço, telefone, CEP...)
app.put('/api/profile', authRequired, (req, res) => {
  const b = req.body || {};
  const clean = (v) => (v == null ? '' : String(v).trim());
  stmtProfileUpsert.run(
    req.user.id,
    clean(b.phone),
    clean(b.cep),
    clean(b.address),
    clean(b.number),
    clean(b.complement),
    clean(b.district),
    clean(b.city),
    clean(b.uf).toUpperCase().slice(0, 2)
  );
  const prof = stmtProfileGet.get(req.user.id);
  return res.json({ profile: publicProfile(req.user, prof) });
});

/* ------------------------------------------------------------
   SACOLA (carrinho) — tudo protegido por login
------------------------------------------------------------ */

// Listar itens da sacola
app.get('/api/cart', authRequired, (req, res) => {
  return res.json(cartPayload(req.user.id));
});

// Adicionar item (ou somar quantidade se já existir mesmo produto+tamanho)
app.post('/api/cart', authRequired, (req, res) => {
  try {
    let { product, size } = req.body || {};
    product = (product || '').trim();
    size = (size || '').trim().slice(0, 8);

    if (!product || !size) {
      return res.status(400).json({ error: 'Produto e tamanho são obrigatórios.' });
    }
    // Preço SEMPRE do catálogo do servidor — ignora qualquer valor do cliente. [OWASP A04]
    const price = CATALOG[product];
    if (!Number.isFinite(price)) {
      return res.status(400).json({ error: 'Produto inválido.' });
    }

    const existing = stmtCartFind.get(req.user.id, product, size);
    if (existing) {
      stmtCartBumpQty.run(existing.id, req.user.id);
    } else {
      stmtCartInsert.run(req.user.id, product, size, price, 1);
    }
    return res.status(201).json(cartPayload(req.user.id));
  } catch (err) {
    console.error('cart add error:', err);
    return res.status(500).json({ error: 'Erro ao adicionar à sacola.' });
  }
});

// Atualizar quantidade de um item
app.patch('/api/cart/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  let qty = parseInt((req.body || {}).qty, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Item inválido.' });
  if (!Number.isFinite(qty)) return res.status(400).json({ error: 'Quantidade inválida.' });
  if (qty <= 0) {
    stmtCartDelete.run(id, req.user.id);
  } else {
    stmtCartSetQty.run(qty, id, req.user.id);
  }
  return res.json(cartPayload(req.user.id));
});

// Remover item
app.delete('/api/cart/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Item inválido.' });
  stmtCartDelete.run(id, req.user.id);
  return res.json(cartPayload(req.user.id));
});

// Finalizar compra — cria um pedido (com dados do cliente) e esvazia a sacola.
// Também salva/atualiza o perfil para facilitar a próxima compra.
app.post('/api/checkout', authRequired, (req, res) => {
  try {
    const body = req.body || {};
    let method = (body.method || 'pix').toString().trim().toLowerCase();
    if (method !== 'pix' && method !== 'cartao') method = 'pix';

    const { items, total } = cartPayload(req.user.id);
    if (!items.length) {
      return res.status(400).json({ error: 'Sua sacola está vazia.' });
    }

    // Dados do cliente para o pedido (snapshot) + salva no perfil
    const c = body.customer || {};
    const clean = (v) => (v == null ? '' : String(v).trim());
    const customer = {
      name: clean(c.name) || req.user.name,
      email: clean(c.email) || req.user.email,
      phone: clean(c.phone),
      cep: clean(c.cep),
      address: clean(c.address),
      number: clean(c.number),
      complement: clean(c.complement),
      district: clean(c.district),
      city: clean(c.city),
      uf: clean(c.uf).toUpperCase().slice(0, 2)
    };
    // Persiste no perfil do cliente (próxima compra já vem preenchida).
    // Só atualiza quando há dados reais, para não apagar o que já estava salvo.
    if (customer.cep || customer.address) {
      stmtProfileUpsert.run(
        req.user.id, customer.phone, customer.cep, customer.address,
        customer.number, customer.complement, customer.district, customer.city, customer.uf
      );
    }

    const status = 'aguardando_pagamento';
    const info = stmtOrderInsert.run(
      req.user.id, total, JSON.stringify(items), method, status, JSON.stringify(customer)
    );
    stmtCartClear.run(req.user.id);

    const orderId = info.lastInsertRowid;
    const createdAt = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

    // Envia o e-mail do pedido (sem travar nem derrubar a compra se falhar)
    mailer.sendOrderEmail({ orderId, total, items, method, status, customer, createdAt })
      .then(function (r) {
        if (!r.sent) console.warn('E-mail do pedido #' + orderId + ' não enviado:', r.reason);
        else console.log('E-mail do pedido #' + orderId + ' enviado para ' + mailer.mailTo);
      })
      .catch(function (e) { console.error('Erro ao enviar e-mail do pedido #' + orderId + ':', e.message); });

    return res.status(201).json({
      orderId: orderId,
      total,
      items,
      method,
      status,
      customer,
      cart: cartPayload(req.user.id)
    });
  } catch (err) {
    console.error('checkout error:', err);
    return res.status(500).json({ error: 'Erro ao finalizar a compra.' });
  }
});

/* ------------------------------------------------------------
   GESTÃO (visão do dono) — protegida por chave de admin.
   Use SOMENTE o header  x-admin-key: <chave>
   (a chave fica em server/.admin-key, fora do webroot).
------------------------------------------------------------ */
function adminRequired(req, res, next) {
  // Aceita a chave APENAS via header (nunca ?key= na URL, que vaza em
  // logs/histórico/Referer). Comparação em tempo constante. [OWASP A01/A09]
  const key = req.headers['x-admin-key'] || '';
  if (!safeEqual(key, ADMIN_KEY)) return res.status(401).json({ error: 'Acesso negado.' });
  next();
}

app.get('/api/admin/customers', adminRequired, (req, res) => {
  const rows = stmtAdminCustomers.all();
  const customers = rows.map((r) => {
    const orders = r.orders || 0;
    const totalSpent = r.total_spent || 0;
    return {
      id: r.id,
      name: r.name,
      email: r.email,
      phone: r.phone || '',
      cep: r.cep || '',
      endereco: [r.address, r.number, r.complement, r.district, r.city, r.uf]
        .filter(Boolean).join(', '),
      pedidos: orders,
      totalGasto: totalSpent,
      ticketMedio: orders ? Math.round(totalSpent / orders) : 0,
      ultimoPedido: r.last_order,
      clienteDesde: r.created_at
    };
  });
  const receitaTotal = customers.reduce((s, c) => s + c.totalGasto, 0);
  return res.json({ totalClientes: customers.length, receitaTotal, customers });
});

/* ------------------------------------------------------------
   Site estático — ALLOWLIST: serve só index.html e assets/.
   NÃO serve a pasta server/ (banco, .jwt-secret, .admin-key,
   mail-config.json) nem backups/dotfiles. Antes, express.static(ROOT)
   expunha pantale.db e a senha do Gmail por HTTP. [OWASP A01/A05]
------------------------------------------------------------ */
app.use('/assets', express.static(path.join(ROOT, 'assets'), {
  dotfiles: 'ignore',
  index: false,
  redirect: false
}));
app.get(['/', '/index.html'], (req, res) => {
  res.sendFile(path.join(ROOT, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Pantale rodando em http://localhost:${PORT}`);
  console.log(`Gestão de clientes:  GET /api/admin/customers  (header x-admin-key; chave em server/.admin-key)`);
  console.log(`E-mail de pedidos:   ${mailer.isEnabled() ? 'ATIVO → ' + mailer.mailTo : 'desativado (configure server/mail-config.json)'}`);
});
