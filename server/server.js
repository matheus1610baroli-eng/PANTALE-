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
const shipping = require('./shipping');
const labels = require('./labels');
const mercadopago = require('./mercadopago');
const backup = require('./backup');

/* Carrega server/.env, se existir. Node 22 traz isso nativo — não
   precisa do pacote dotenv. Tem de vir ANTES de qualquer leitura de
   process.env aqui embaixo. Variável já definida no ambiente (painel
   da hospedagem) vence o arquivo. */
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath) && typeof process.loadEnvFile === 'function') {
    process.loadEnvFile(envPath);
  }
} catch (e) {
  console.warn('Não consegui ler o server/.env:', e.message);
}

const PORT = process.env.PORT || 3000;

/* Endereço público do site. Usado pelo robots.txt/sitemap.xml e pelas
   URLs de retorno e de webhook do Mercado Pago. Em produção defina a
   variável de ambiente SITE_URL. */
const SITE_URL = (process.env.SITE_URL || 'https://pantale.com.br').replace(/\/+$/, '');

/* Base do link de redefinição de senha que vai no e-mail.
   APP_URL só existe para apontar para outro endereço em desenvolvimento;
   o normal é ser o próprio site. Nunca vem do cliente. */
const RESET_LINK_BASE = (process.env.APP_URL || SITE_URL).replace(/\/+$/, '');

const ROOT = path.join(__dirname, '..'); // pasta do site (index.html, assets/)

/* Onde ficam os dados que NÃO podem se perder: o banco, as chaves de
   sessão e os backups.

   Na sua máquina é a própria pasta server/ — nada muda. Já numa
   hospedagem, o disco onde o código roda costuma ser apagado a cada
   publicação; por isso lá se aponta DATA_DIR para um disco persistente
   (ex.: /var/data no Render). Sem isso, cada deploy levaria junto os
   clientes, os pedidos e o login de todo mundo. */
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : __dirname;
try {
  if (DATA_DIR !== __dirname) fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) {
  console.error('Não consegui criar a pasta de dados ' + DATA_DIR + ':', e.message);
}

const DB_PATH = path.join(DATA_DIR, 'pantale.db');
const SECRET_PATH = path.join(DATA_DIR, '.jwt-secret');
const ADMIN_KEY_PATH = path.join(DATA_DIR, '.admin-key');

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
/* Catálogo — a fonte da verdade do preço.
   As CHAVES têm de bater exatamente com o <h3> do card em index.html,
   porque é esse texto que o front manda em /api/cart. Mudou o título
   de um produto no site? Mude aqui também, ou ele para de vender. */
const CATALOG = {
  'Pantech Tennis': 179,
  'Pantech Golf': 179,
  'Ski': 249,
  'Golf': 249,
  'Linho Areia': 169,
  'Linho Folha': 169,
  'Regata Areia': 149,
  'Regata Preta': 149
};

/* Tamanhos vendidos (usado no controle de estoque) */
const SIZES = ['P', 'M', 'G'];

/* ------------------------------------------------------------
   Peças em "últimos ajustes": aparecem na vitrine, com a mancha de
   onça por cima, mas não podem ser compradas.

   Precisa existir AQUI, e não só no visual: quem conhece a API
   consegue mandar um pedido direto, sem passar pela tela. Bloqueio
   que só existe no navegador não é bloqueio.

   Para bloquear uma peça, ponha o nome nesta lista e acrescente a
   classe "is-bloqueado" ao card dela no index.html (mais o véu
   .produto-bloqueio, que é o que desenha a mancha por cima).

   Vazia desde a abertura da loja: a coleção inteira está à venda, e
   quem controla o que aparece agora é o estoque, não esta lista.
------------------------------------------------------------ */
const BLOQUEADOS = new Set([]);

function estaBloqueado(produto) {
  return BLOQUEADOS.has(String(produto));
}

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
    cpf        TEXT NOT NULL DEFAULT '',
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

  CREATE TABLE IF NOT EXISTS stock (
    product    TEXT    NOT NULL,
    size       TEXT    NOT NULL,
    qty        INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (product, size)
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

  /* Troca de e-mail pendente. O endereço novo fica AQUI, não em users,
     até a pessoa clicar no link que mandamos para ele. Enquanto isso a
     conta continua inteira no endereço antigo. */
  CREATE TABLE IF NOT EXISTS email_changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    new_email  TEXT    NOT NULL,
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
try { db.exec('ALTER TABLE orders ADD COLUMN paid_at TEXT'); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN freight TEXT NOT NULL DEFAULT '{}'"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN shipment TEXT NOT NULL DEFAULT '{}'"); } catch (e) {}
try { db.exec("ALTER TABLE orders ADD COLUMN payment TEXT NOT NULL DEFAULT '{}'"); } catch (e) {}
try { db.exec("ALTER TABLE profiles ADD COLUMN cpf TEXT NOT NULL DEFAULT ''"); } catch (e) {}
/* Geração da sessão. Sobe em 1 a cada troca de senha; o número vai
   dentro do JWT e é conferido a cada requisição, então token emitido
   antes da troca para de valer na hora. Começa em 0, e JWT antigo (sem
   o campo) também lê como 0 — publicar isto não desloga ninguém. */
try { db.exec('ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0'); } catch (e) {}

const stmtFindByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const stmtFindById = db.prepare('SELECT id, name, email, created_at, token_version FROM users WHERE id = ?');
const stmtInsert = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
/* Troca de senha e invalidação das sessões antigas na MESMA instrução:
   separar as duas abriria uma janela em que a senha já mudou e o token
   antigo ainda vale — justamente o que este código existe para fechar. */
const stmtUpdatePassword = db.prepare('UPDATE users SET password = ?, token_version = token_version + 1 WHERE id = ?');

/* Redefinição de senha */
const stmtResetInvalidate = db.prepare('UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0');
const stmtResetInsert = db.prepare('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)');
const stmtResetFind = db.prepare('SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?');
const stmtResetMarkUsed = db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?');

/* Troca de e-mail */
// stmtFindById não traz a senha (de propósito); aqui precisamos dela para conferir.
const stmtFindWithPasswordById = db.prepare('SELECT id, name, email, password FROM users WHERE id = ?');
const stmtEmailChangeInvalidate = db.prepare('UPDATE email_changes SET used = 1 WHERE user_id = ? AND used = 0');
const stmtEmailChangeInsert = db.prepare('INSERT INTO email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, ?, ?, ?)');
const stmtEmailChangeFind = db.prepare('SELECT id, user_id, new_email, expires_at, used FROM email_changes WHERE token_hash = ?');
const stmtEmailChangeMarkUsed = db.prepare('UPDATE email_changes SET used = 1 WHERE id = ?');
/* Troca o endereço e derruba as sessões na MESMA instrução, pela mesma razão
   da troca de senha: quem tomou a conta não pode continuar dentro dela. */
const stmtUpdateEmail = db.prepare('UPDATE users SET email = ?, token_version = token_version + 1 WHERE id = ?');

/* Sacola (carrinho) */
const stmtCartList = db.prepare('SELECT id, product, size, price, qty FROM cart_items WHERE user_id = ? ORDER BY created_at ASC, id ASC');
const stmtCartFind = db.prepare('SELECT id, qty FROM cart_items WHERE user_id = ? AND product = ? AND size = ?');
const stmtCartInsert = db.prepare('INSERT INTO cart_items (user_id, product, size, price, qty) VALUES (?, ?, ?, ?, ?)');
const stmtCartBumpQty = db.prepare('UPDATE cart_items SET qty = qty + 1 WHERE id = ? AND user_id = ?');
const stmtCartSetQty = db.prepare('UPDATE cart_items SET qty = ? WHERE id = ? AND user_id = ?');
const stmtCartDelete = db.prepare('DELETE FROM cart_items WHERE id = ? AND user_id = ?');
const stmtCartClear = db.prepare('DELETE FROM cart_items WHERE user_id = ?');

/* ------------------------------------------------------------
   ESTOQUE
   ------------------------------------------------------------
   Regra: se NÃO existe linha para (produto, tamanho), aquele
   tamanho é tratado como "sem controle de estoque" (ilimitado).
   Assim o controle é ligado por peça, sem risco de derrubar as
   vendas de itens que ainda não foram cadastrados.
------------------------------------------------------------ */
const stmtStockAll = db.prepare('SELECT product, size, qty FROM stock');
const stmtStockGet = db.prepare('SELECT qty FROM stock WHERE product = ? AND size = ?');
const stmtStockUpsert = db.prepare(`
  INSERT INTO stock (product, size, qty, updated_at) VALUES (?, ?, ?, datetime('now'))
  ON CONFLICT(product, size) DO UPDATE SET qty = excluded.qty, updated_at = datetime('now')
`);
const stmtStockDelete = db.prepare('DELETE FROM stock WHERE product = ? AND size = ?');
// Só decrementa se houver saldo — protege contra venda em duplicidade (corrida).
const stmtStockDecrement = db.prepare('UPDATE stock SET qty = qty - ?, updated_at = datetime(\'now\') WHERE product = ? AND size = ? AND qty >= ?');
/* Devolve peça à prateleira (estorno, chargeback, pedido não pago que expirou).
   Sem WHERE de saldo: aqui a gente está somando, não gastando. Se a linha não
   existe, aquele item é "sem controle de estoque" e não há o que devolver. */
const stmtStockIncrement = db.prepare('UPDATE stock SET qty = qty + ?, updated_at = datetime(\'now\') WHERE product = ? AND size = ?');

/* Recoloca no estoque os itens de um pedido que deixou de valer.
   Recebe os itens já desserializados de orders.items. */
function devolverEstoque(items) {
  for (const it of (items || [])) {
    const qty = Number(it.qty) || 0;
    if (qty > 0) stmtStockIncrement.run(qty, it.product, it.size);
  }
}

/* Retoma o estoque de um pedido que tinha sido devolvido (a reserva
   expirou e o pagamento chegou atrasado). Devolve a lista do que NÃO
   coube — se alguém levou a peça nesse meio-tempo, quem manda é a
   prateleira, e o pedido precisa de atenção humana. */
function retomarEstoque(items) {
  const faltou = [];
  for (const it of (items || [])) {
    const qty = Number(it.qty) || 0;
    if (qty <= 0) continue;
    if (stockAvailable(it.product, it.size) === Infinity) continue; // sem controle
    const r = stmtStockDecrement.run(qty, it.product, it.size, qty);
    if (!r.changes) faltou.push(it.product + ' (' + it.size + ') x' + qty);
  }
  return faltou;
}

/* Quantidade disponível: número, ou Infinity quando não há controle. */
function stockAvailable(product, size) {
  const row = stmtStockGet.get(product, size);
  return row ? Number(row.qty) : Infinity;
}

/* ------------------------------------------------------------
   CARGA INICIAL DO ESTOQUE (abertura da loja)

   As peças contadas à mão na arara, na ordem [P, M, G].

   Os zeros são obrigatórios, não enfeite: a regra lá em cima é que
   linha ausente = "sem controle" = ILIMITADO. Se aqui só entrassem
   os tamanhos que existem, todo tamanho faltante viraria estoque
   infinito e a loja venderia peça que não existe. Por isso todo
   produto declara os três tamanhos, e o que não temos vai como 0.

   Roda UMA vez: só quando a tabela está vazia. Sem essa trava, cada
   publicação no Render repor-ia o estoque por cima das vendas do dia
   e a loja voltaria a oferecer o que já saiu da arara.
------------------------------------------------------------ */
const ESTOQUE_INICIAL = {
  'Pantech Tennis':   { P: 3, M: 2, G: 0 },
  'Pantech Golf':     { P: 4, M: 2, G: 0 },
  'Ski':              { P: 0, M: 4, G: 1 },
  'Golf':             { P: 1, M: 3, G: 1 },
  'Linho Areia':      { P: 0, M: 5, G: 0 },
  'Linho Folha':      { P: 0, M: 3, G: 0 },
  'Regata Areia':     { P: 1, M: 3, G: 0 },
  'Regata Preta':     { P: 3, M: 3, G: 0 }
};

function semearEstoqueInicial() {
  if (stmtStockAll.all().length > 0) return; // já tem contagem: não encosta

  db.exec('BEGIN IMMEDIATE');
  try {
    for (const produto of Object.keys(CATALOG)) {
      const linha = ESTOQUE_INICIAL[produto] || {};
      for (const tamanho of SIZES) {
        stmtStockUpsert.run(produto, tamanho, Number(linha[tamanho]) || 0);
      }
    }
    db.exec('COMMIT');
  } catch (e) {
    db.exec('ROLLBACK');
    console.error('Falhei ao gravar o estoque inicial:', e.message);
    return;
  }

  const total = stmtStockAll.all().reduce((s, r) => s + Number(r.qty), 0);
  console.log('Estoque inicial gravado: ' + total + ' peças no catálogo.');
}
/* A "Regata Off-white" virou "Regata Areia" na véspera da abertura. O nome
   é a chave que liga estoque, sacola e pedido, então um banco que já tivesse
   gravado o nome antigo ficaria com peças órfãs: fora do CATALOG, invisíveis
   no painel e impossíveis de vender. Renomear aqui deixa a troca segura em
   qualquer banco, tenha ele visto o nome velho ou não. */
try {
  db.exec("UPDATE stock SET product = 'Regata Areia' WHERE product = 'Regata Off-white'");
  db.exec("UPDATE cart_items SET product = 'Regata Areia' WHERE product = 'Regata Off-white'");
} catch (e) {
  console.warn('Renomeação Off-white → Areia falhou:', e.message);
}

semearEstoqueInicial();

/* Pedidos */
const stmtOrderInsert = db.prepare('INSERT INTO orders (user_id, total, items, method, status, customer, freight) VALUES (?, ?, ?, ?, ?, ?, ?)');
const stmtUserStats = db.prepare('SELECT COUNT(*) AS orders, COALESCE(SUM(total), 0) AS total_spent FROM orders WHERE user_id = ?');
const stmtOrderGet = db.prepare('SELECT id, status, paid_at FROM orders WHERE id = ?');
const stmtOrderFull = db.prepare('SELECT id, user_id, status, total, items, customer, freight, shipment, payment FROM orders WHERE id = ?');
const stmtOrderSetShipment = db.prepare('UPDATE orders SET shipment = ? WHERE id = ?');
const stmtOrderSetPayment = db.prepare('UPDATE orders SET payment = ? WHERE id = ?');
const stmtOrderSetStatus = db.prepare('UPDATE orders SET status = ?, paid_at = ? WHERE id = ?');
const ADMIN_ORDER_COLS = `
  SELECT o.id, o.user_id, o.total, o.items, o.method, o.status, o.customer,
         o.created_at, o.paid_at, u.email AS account_email
  FROM orders o
  LEFT JOIN users u ON u.id = o.user_id
`;
const stmtAdminOrders = db.prepare(ADMIN_ORDER_COLS + ' ORDER BY o.created_at DESC, o.id DESC');
const stmtAdminOrderById = db.prepare(ADMIN_ORDER_COLS + ' WHERE o.id = ?');

/* ------------------------------------------------------------
   EXPIRAÇÃO DA RESERVA DE ESTOQUE

   O estoque é baixado no checkout, ANTES do pagamento — é o que
   impede duas pessoas de comprarem a última peça ao mesmo tempo. O
   preço disso é que todo carrinho abandonado no Mercado Pago
   segurava a peça para sempre: a vitrine ia esgotando sozinha, sem
   ninguém ter comprado nada.

   Pior: bastava criar contas e finalizar sem pagar para zerar a loja
   de propósito, sem gastar um centavo.

   60 minutos por padrão, e não 30: Pix no Mercado Pago pode demorar
   mais que meia hora, e cancelar cedo demais troca este problema por
   um pior (cliente paga, pedido já morreu). Ajuste com RESERVA_MINUTOS
   se a sua realidade for outra.
------------------------------------------------------------ */
const RESERVA_MINUTOS = Math.max(5, Number(process.env.RESERVA_MINUTOS) || 60);

const stmtOrdersExpirados = db.prepare(
  "SELECT id, items FROM orders WHERE status = 'aguardando_pagamento'" +
  " AND created_at <= datetime('now', ?)"
);

function expirarReservas(log) {
  const say = log || function () {};
  let vencidos;
  try {
    vencidos = stmtOrdersExpirados.all('-' + RESERVA_MINUTOS + ' minutes');
  } catch (e) {
    say('Expiração de reservas falhou na consulta: ' + e.message);
    return 0;
  }
  if (!vencidos.length) return 0;

  let n = 0;
  for (const row of vencidos) {
    try {
      db.exec('BEGIN IMMEDIATE');
      try {
        devolverEstoque(parseJSON(row.items, []) || []);
        stmtOrderSetStatus.run('cancelado', null, row.id);
        db.exec('COMMIT');
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
      n += 1;
    } catch (e) {
      // Um pedido problemático não pode impedir os outros de liberarem peça.
      say('Não consegui expirar o pedido #' + row.id + ': ' + e.message);
    }
  }
  if (n) say('Reservas expiradas: ' + n + ' pedido(s) sem pagamento há mais de ' + RESERVA_MINUTOS + ' min — estoque devolvido.');
  return n;
}

/* Perfil / dados de entrega do cliente */
const stmtProfileGet = db.prepare('SELECT cpf, phone, cep, address, number, complement, district, city, uf FROM profiles WHERE user_id = ?');
const stmtProfileUpsert = db.prepare(`
  INSERT INTO profiles (user_id, cpf, phone, cep, address, number, complement, district, city, uf, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  ON CONFLICT(user_id) DO UPDATE SET
    cpf=excluded.cpf, phone=excluded.phone, cep=excluded.cep, address=excluded.address,
    number=excluded.number, complement=excluded.complement, district=excluded.district,
    city=excluded.city, uf=excluded.uf, updated_at=datetime('now')
`);

/* Gestão (visão do dono): clientes com agregados */
const stmtAdminCustomers = db.prepare(`
  SELECT u.id, u.name, u.email, u.created_at,
         p.cpf, p.phone, p.cep, p.address, p.number, p.complement, p.district, p.city, p.uf,
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
    cpf: profRow.cpf || '',
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
  // tv = geração da sessão. Ver o ALTER TABLE de token_version lá em cima.
  return jwt.sign(
    { sub: user.id, email: user.email, tv: Number(user.token_version) || 0 },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL }
  );
}

function publicUser(row) {
  return { id: row.id, name: row.name, email: row.email, created_at: row.created_at };
}

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    // algorithms explícito: não deixa o verificador aceitar um algoritmo
    // que a gente nunca usou para assinar. [OWASP A02]
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    const row = stmtFindById.get(payload.sub);
    if (!row) return res.status(401).json({ error: 'Sessão inválida.' });

    /* Token de antes da última troca de senha não vale mais.
       Sem isto, trocar a senha — o gesto universal de "expulsar quem
       entrou na minha conta" — não expulsava ninguém: o token roubado
       continuava valendo pelos 7 dias de validade, e a vítima achava
       que tinha resolvido. */
    if ((Number(payload.tv) || 0) !== (Number(row.token_version) || 0)) {
      return res.status(401).json({ error: 'Sessão encerrada. Entre de novo.' });
    }

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
  // googletagmanager/facebook: GA4 e Pixel da Meta. Sem estes domínios na
  // CSP o navegador bloqueia os scripts e a medição simplesmente não roda —
  // silenciosamente, o que é pior do que não ter analytics. Eles só são
  // baixados depois do aceite no banner de cookies (LGPD).
  res.set('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://connect.facebook.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "media-src 'self'",
    "connect-src 'self' https://viacep.com.br https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com https://www.googletagmanager.com https://connect.facebook.net https://www.facebook.com",
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
/* `key` escolhe o que é "um cliente". O padrão é o IP, que é tudo que
   se tem antes do login. Depois do login prefira o id do usuário: num
   prédio comercial ou no 4G, dezenas de pessoas dividem o mesmo IP, e
   limitar por IP transformaria o limite em bloqueio de gente inocente. */
function rateLimit({ windowMs, max, message, key }) {
  const hits = new Map(); // chave -> { count, resetAt }
  const sweep = setInterval(() => {
    const t = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
  }, windowMs);
  if (sweep.unref) sweep.unref();
  return function (req, res, next) {
    const now = Date.now();
    const quem = (key && key(req)) || req.ip || 'unknown';
    const chave = quem + '|' + req.baseUrl + req.path;
    let rec = hits.get(chave);
    if (!rec || rec.resetAt <= now) { rec = { count: 0, resetAt: now + windowMs }; hits.set(chave, rec); }
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

/* ------------------------------------------------------------
   Rede de segurança para handler `async`.

   O Express 4 não entende Promise: se um handler async rejeita,
   ninguém captura, a rejeição vira `unhandledRejection` e o Node 22
   DERRUBA O PROCESSO por padrão. Ou seja: um erro de SQLite (disco
   cheio, lock) numa rota de pagamento tirava a loja inteira do ar,
   levando junto a venda que estava acontecendo.

   Dava para embrulhar as nove rotas async na mão, mas aí a décima que
   alguém escrever amanhã nasce desprotegida. Embrulhando aqui, uma vez
   só, qualquer rota — inclusive as futuras — manda a rejeição para o
   error handler que fica no fim do arquivo.
------------------------------------------------------------ */
for (const metodo of ['get', 'post', 'put', 'patch', 'delete']) {
  const original = app[metodo].bind(app);
  app[metodo] = function (caminho, ...handlers) {
    // app.get('nome') sem handler é o LEITOR de configuração do Express,
    // não uma rota. Passa direto, senão quebraria app.get('env').
    if (!handlers.length) return original(caminho);
    return original(caminho, ...handlers.map(function (h) {
      // length >= 4 é error handler (err, req, res, next): não se embrulha.
      if (typeof h !== 'function' || h.length >= 4) return h;
      return function (req, res, next) {
        try {
          const r = h(req, res, next);
          if (r && typeof r.then === 'function') r.catch(next);
          return r;
        } catch (e) {
          next(e);
        }
      };
    }));
  };
}

app.disable('x-powered-by');     // não vaza a tecnologia (era "Express")
app.set('trust proxy', 1);       // confia no proxy (Vercel/Render/VPS) para req.ip
app.use(securityHeaders);
app.use(cors(corsOptions));
app.use(express.json({ limit: '32kb' })); // limita tamanho do corpo

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Muitas tentativas. Aguarde alguns minutos.' });
const checkoutLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: 'Não foi possível processar agora. Tente novamente mais tarde.' });
/* /api/email/confirm entra aqui junto com /api/reset: as duas são anônimas e
   gastam um token de uso único vindo do e-mail. Sem o limite, dá para
   martelar palpites de token à vontade. */
app.use(['/api/login', '/api/register', '/api/forgot', '/api/reset', '/api/email/confirm'], authLimiter);
app.use('/api/checkout', checkoutLimiter);

/* ------------------------------------------------------------
   Limites das rotas que custam dinheiro ou chamada externa.

   Estes vão DEPOIS do authRequired na definição da rota, para poder
   contar por usuário em vez de por IP (ver o parâmetro `key`).

   Os números são folgados de propósito: limite de segurança serve
   para cortar abuso automatizado, não para atrapalhar quem está
   comprando. Quem recalcula o frete oito vezes decidindo o CEP é
   cliente indeciso, não atacante.
------------------------------------------------------------ */
const porUsuario = (req) => (req.user ? 'u' + req.user.id : null);

// Cada chamada é uma requisição à API do Melhor Envio, que tem cota.
const freteLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 40, key: porUsuario,
  message: 'Muitos cálculos de frete seguidos. Aguarde um pouco.'
});

// Cada chamada cria uma preferência de pagamento no Mercado Pago.
const pagamentoLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20, key: porUsuario,
  message: 'Muitas tentativas de pagamento. Aguarde um pouco.'
});

/* Pedir troca de e-mail dispara uma mensagem para um endereço que quem pede
   escolhe. Com o teto do escritaLimiter (200 em 15 min) isso vira máquina de
   bombardear a caixa de outra pessoa — e o remetente seria o SMTP da loja,
   que acabaria marcado como spam. Some a isso a conta de envio: e-mail é
   chamada externa, igual ao frete e ao pagamento. Daí o teto apertado. */
const emailTrocaLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5, key: porUsuario,
  message: 'Muitos pedidos de troca de e-mail. Aguarde um pouco.'
});

// Escritas comuns (sacola, perfil): teto alto, só para conter script.
const escritaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 200, key: porUsuario,
  message: 'Muitas alterações seguidas. Aguarde um pouco.'
});

/* O webhook é público — não dá para exigir login de quem o Mercado
   Pago manda. O teto é alto porque notificação legítima vem em rajada
   (o MP reenvia várias vezes o mesmo evento), e devolver 429 para
   notificação boa custaria uma baixa de pedido.

   Isto é a segunda linha: a conferência de assinatura já barra o
   forjado antes de qualquer chamada externa, então uma inundação aqui
   custa só um HMAC. Este limite existe para o caso de inundação pura. */
const webhookLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 600,
  message: 'Muitas notificações. Tente mais tarde.'
});

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

      // Base do link fixada no servidor — NUNCA vem do cliente, senão um
      // atacante redirecionaria o token de reset. [OWASP A07]
      //
      // Cai para SITE_URL, que já é o endereço público e está no render.yaml.
      // Antes dependia só de APP_URL, que ninguém nunca definiu: todo e-mail
      // de redefinição saía com "http://localhost:10000/?reset=..." e nenhum
      // cliente conseguia recuperar a conta. Falha silenciosa — quem não
      // consegue entrar não reclama, só desiste.
      const link = `${RESET_LINK_BASE}/?reset=${token}`;
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

/* ------------------------------------------------------------
   TROCA DE E-MAIL — em dois passos, de propósito

   1) POST /api/email/change   { password, email }  (logado)
      Confere a senha e guarda o endereço novo como PENDENTE.
      Manda um link de confirmação para o endereço novo.
   2) POST /api/email/confirm  { token }
      Só aqui o endereço muda de verdade.

   A senha é exigida no passo 1 porque o e-mail é a chave de
   recuperação da conta: quem trocasse o e-mail com uma sessão
   roubada tomaria a conta para sempre, e o dono não teria como
   voltar — o "esqueci a senha" passaria a cair na caixa do invasor.
------------------------------------------------------------ */
app.post('/api/email/change', authRequired, emailTrocaLimiter, async (req, res) => {
  try {
    const { password } = req.body || {};
    const novo = String((req.body || {}).email || '').trim().toLowerCase();

    if (!EMAIL_RE.test(novo)) {
      return res.status(400).json({ error: 'Informe um e-mail válido.' });
    }
    const atual = stmtFindWithPasswordById.get(req.user.id);
    if (!atual) return res.status(401).json({ error: 'Sessão inválida.' });

    const ok = await bcrypt.compare(String(password || ''), atual.password);
    if (!ok) return res.status(401).json({ error: 'Senha atual incorreta.' });

    if (novo === String(atual.email).toLowerCase()) {
      return res.status(400).json({ error: 'Este já é o e-mail da sua conta.' });
    }
    /* E-mail de outra pessoa: recusa aqui, com mensagem clara. Vazar que o
       endereço existe é aceitável neste ponto — quem pergunta já provou a
       senha da própria conta, então não dá para varrer a base com isso. */
    if (stmtFindByEmail.get(novo)) {
      return res.status(409).json({ error: 'Este e-mail já está em uso por outra conta.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hora
    stmtEmailChangeInvalidate.run(atual.id);       // um pedido pendente por vez
    stmtEmailChangeInsert.run(atual.id, novo, tokenHash, expiresAt);

    const link = `${RESET_LINK_BASE}/?trocaEmail=${token}`;
    mailer.sendEmailChangeEmail(novo, atual.name, link)
      .then((r) => { if (!r.sent) console.warn('E-mail de troca não enviado:', r.reason); })
      .catch((e) => console.error('Erro no e-mail de troca:', e.message));

    const resposta = {
      ok: true,
      message: 'Enviamos um link de confirmação para ' + novo + '. O e-mail só muda depois que você abrir esse link.'
    };
    if (!mailer.isEnabled()) resposta.aviso = 'E-mail não configurado no servidor (link não enviado).';
    return res.json(resposta);
  } catch (err) {
    console.error('email/change error:', err);
    return res.status(500).json({ error: 'Erro ao solicitar a troca de e-mail.' });
  }
});

/* Confirmação. Sem authRequired: a pessoa pode abrir o link em outro
   aparelho, onde não está logada — é justamente o caso de quem está
   migrando de e-mail. O token é a credencial aqui. */
app.post('/api/email/confirm', async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Token ausente.' });

    const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
    const row = stmtEmailChangeFind.get(tokenHash);
    if (!row || row.used || row.expires_at < Date.now()) {
      return res.status(400).json({ error: 'Link inválido ou expirado. Peça a troca de novo.' });
    }

    const user = stmtFindById.get(row.user_id);
    if (!user) return res.status(400).json({ error: 'Conta não encontrada.' });

    /* Confere de novo se o endereço continua livre. Entre o pedido e o
       clique podem ter passado 59 minutos, e outra pessoa pode ter criado
       conta com ele nesse meio-tempo. Sem esta conferência o UPDATE
       estouraria no UNIQUE e a pessoa veria só um erro 500. */
    const ocupado = stmtFindByEmail.get(row.new_email);
    if (ocupado && ocupado.id !== row.user_id) {
      stmtEmailChangeMarkUsed.run(row.id);
      return res.status(409).json({ error: 'Este e-mail já está em uso por outra conta.' });
    }

    const antigo = user.email;
    stmtUpdateEmail.run(row.new_email, row.user_id);
    stmtEmailChangeMarkUsed.run(row.id);
    /* Pedido de senha em aberto vira lixo perigoso: foi emitido para o
       endereço antigo e continuaria valendo para esta conta. */
    stmtResetInvalidate.run(row.user_id);

    mailer.sendEmailChangedNotice(antigo, user.name, row.new_email)
      .then((r) => { if (!r.sent) console.warn('Aviso de troca não enviado:', r.reason); })
      .catch((e) => console.error('Erro no aviso de troca:', e.message));

    /* A troca subiu o token_version e derrubou todas as sessões, inclusive a
       de quem está clicando. Devolvemos um token novo para essa pessoa não
       ser expulsa do próprio site no meio da ação. */
    const atualizado = stmtFindById.get(row.user_id);
    return res.json({ token: signToken(atualizado), user: publicUser(atualizado) });
  } catch (err) {
    console.error('email/confirm error:', err);
    return res.status(500).json({ error: 'Erro ao confirmar o e-mail.' });
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

const CPF_RE = /^\d{11}$/;
function cpfIsValid(digits) {
  if (!CPF_RE.test(digits) || /^(\d)\1{10}$/.test(digits)) return false;
  for (let t = 9; t <= 10; t++) {
    let sum = 0;
    for (let i = 0; i < t; i++) sum += parseInt(digits[i], 10) * (t + 1 - i);
    let check = (sum * 10) % 11;
    if (check === 10) check = 0;
    if (check !== parseInt(digits[t], 10)) return false;
  }
  return true;
}

// Salvar/atualizar perfil (endereço, telefone, CEP, CPF...)
app.put('/api/profile', authRequired, escritaLimiter, (req, res) => {
  const b = req.body || {};
  const clean = (v) => (v == null ? '' : String(v).trim());
  const cpfDigits = clean(b.cpf).replace(/\D/g, '');
  if (cpfDigits && !cpfIsValid(cpfDigits)) {
    return res.status(400).json({ error: 'CPF inválido.' });
  }
  // Não apaga um CPF já salvo se a requisição vier sem esse campo.
  const existing = stmtProfileGet.get(req.user.id) || {};
  stmtProfileUpsert.run(
    req.user.id,
    cpfDigits || existing.cpf || '',
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
app.post('/api/cart', authRequired, escritaLimiter, (req, res) => {
  try {
    let { product, size } = req.body || {};
    product = (product || '').trim();
    size = (size || '').trim().slice(0, 8).toUpperCase();

    if (!product || !size) {
      return res.status(400).json({ error: 'Produto e tamanho são obrigatórios.' });
    }
    // Preço SEMPRE do catálogo do servidor — ignora qualquer valor do cliente. [OWASP A04]
    const price = CATALOG[product];
    if (!Number.isFinite(price)) {
      return res.status(400).json({ error: 'Produto inválido.' });
    }
    /* O tamanho TEM de ser um dos que a loja vende. Sem esta linha, qualquer
       texto passava ("XG", "p", "banana") e caía na regra de que linha
       inexistente no estoque = sem controle = ILIMITADO: dava para encher a
       sacola com 41 camisetas de um tamanho que não existe, furando o estoque
       inteiro e gerando pedido pago que a loja não teria como despachar.
       O toUpperCase() acima é parte da mesma correção — "p" minúsculo não
       casava com a linha "P" do estoque e virava outro tamanho ilimitado. */
    if (SIZES.indexOf(size) === -1) {
      return res.status(400).json({ error: 'Tamanho indisponível.' });
    }
    if (estaBloqueado(product)) {
      return res.status(409).json({ error: 'Esta peça ainda não está à venda.', bloqueado: true });
    }

    const existing = stmtCartFind.get(req.user.id, product, size);
    const desejada = (existing ? existing.qty : 0) + 1;

    // Estoque: não deixa reservar mais do que existe. [venda em duplicidade]
    const disponivel = stockAvailable(product, size);
    if (disponivel <= 0) {
      return res.status(409).json({ error: 'Tamanho ' + size + ' esgotado.', outOfStock: true });
    }
    if (desejada > disponivel) {
      return res.status(409).json({
        error: 'Só temos ' + disponivel + ' unidade(s) do tamanho ' + size + '.',
        available: disponivel
      });
    }

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
app.patch('/api/cart/:id', authRequired, escritaLimiter, (req, res) => {
  const id = parseInt(req.params.id, 10);
  let qty = parseInt((req.body || {}).qty, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Item inválido.' });
  if (!Number.isFinite(qty)) return res.status(400).json({ error: 'Quantidade inválida.' });
  if (qty <= 0) {
    stmtCartDelete.run(id, req.user.id);
    return res.json(cartPayload(req.user.id));
  }

  // Não deixa aumentar acima do estoque disponível
  const item = stmtCartList.all(req.user.id).find((i) => i.id === id);
  if (item) {
    const disponivel = stockAvailable(item.product, item.size);
    if (qty > disponivel) {
      return res.status(409).json({
        error: 'Só temos ' + disponivel + ' unidade(s) do tamanho ' + item.size + '.',
        available: disponivel,
        cart: cartPayload(req.user.id)
      });
    }
  }
  stmtCartSetQty.run(qty, id, req.user.id);
  return res.json(cartPayload(req.user.id));
});

/* Estoque público — o site usa para marcar tamanhos esgotados e avisar
   "últimas peças". Esta rota não tem login: é a vitrine.

   O número sai limitado no teto. O comentário aqui sempre disse que
   não revelava números altos, mas o código devolvia a quantidade
   exata — quem chamasse /api/stock via com precisão quanto a loja tem
   de cada peça, e dava para acompanhar quanto vende por dia só
   comparando as respostas ao longo do tempo. Isso é relatório de
   vendas de graça para quem quiser.

   O front só reage a "esgotado" (<= 0) e a "poucas peças" (<= 3),
   então limitar em 6 não muda nada na tela. */
const ESTOQUE_TETO_PUBLICO = 6;

app.get('/api/stock', (req, res) => {
  const out = {};
  for (const row of stmtStockAll.all()) {
    const qty = Math.max(0, Number(row.qty));
    out[row.product + '|' + row.size] = Math.min(qty, ESTOQUE_TETO_PUBLICO);
  }
  return res.json({ stock: out });
});

// Remover item
app.delete('/api/cart/:id', authRequired, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Item inválido.' });
  stmtCartDelete.run(id, req.user.id);
  return res.json(cartPayload(req.user.id));
});

/* ------------------------------------------------------------
   FRETE (cotação via Melhor Envio) — scope shipping-calculate.
   O browser fala só com o nosso backend; o token nunca sai daqui.
------------------------------------------------------------ */
// Cache curto das opções por usuário (evita bater na API a cada tela e
// dá a fonte de preço confiável na hora do checkout). TTL 20 min.
const freightCache = new Map();
const FREIGHT_TTL_MS = 20 * 60 * 1000;
const onlyDigits = (v) => String(v == null ? '' : v).replace(/\D/g, '');

// Arredonda o frete para reais inteiros (para cima — nunca cobra menos que
// o custo real), mantendo a convenção de valores inteiros do site.
const freightToReais = (v) => Math.max(0, Math.ceil(Number(v) || 0));

app.post('/api/frete', authRequired, freteLimiter, async (req, res) => {
  try {
    const cep = onlyDigits((req.body || {}).cep);
    if (cep.length !== 8) return res.status(400).json({ error: 'CEP inválido.' });

    const { items, total, count } = cartPayload(req.user.id);
    if (!items.length) return res.status(400).json({ error: 'Sua sacola está vazia.' });

    if (!shipping.isEnabled()) {
      // Frete ainda não configurado (falta CEP de origem/token): não bloqueia
      // a compra, apenas informa que o cálculo está indisponível.
      return res.json({ ok: true, available: false, freeShipping: false, subtotal: total, options: [] });
    }

    const r = await shipping.calculate({ destCep: cep, itemCount: count, insuranceValue: total });
    if (!r.ok) return res.status(502).json({ error: r.error || 'Não foi possível calcular o frete.' });

    const options = r.options.map(function (o) {
      return { id: o.id, name: o.name, company: o.company, price: freightToReais(o.price), deliveryDays: o.deliveryDays };
    });

    const freeMin = shipping.freeShippingMin();
    const freeShipping = total >= freeMin;

    freightCache.set(req.user.id, { cep: cep, options: options, ts: Date.now() });

    return res.json({ ok: true, available: true, freeShipping: freeShipping, freeShippingMin: freeMin, subtotal: total, options: options });
  } catch (err) {
    console.error('frete error:', err);
    return res.status(500).json({ error: 'Erro ao calcular o frete.' });
  }
});

// Resolve o frete a cobrar no checkout de forma confiável (não confia no
// preço vindo do cliente): grátis acima do mínimo, senão usa o preço da opção
// escolhida a partir do cache (ou recalcula se o cache expirou).
async function resolveFreight(userId, subtotal, destCep, chosenId) {
  const freeMin = shipping.freeShippingMin();
  if (subtotal >= freeMin) {
    return { price: 0, free: true, id: chosenId || null, name: 'Frete grátis', company: '', deliveryDays: null };
  }
  if (!shipping.isEnabled()) {
    return { price: 0, free: false, unavailable: true, id: null, name: '', company: '', deliveryDays: null };
  }

  let options = null;
  const cached = freightCache.get(userId);
  if (cached && cached.cep === onlyDigits(destCep) && (Date.now() - cached.ts) < FREIGHT_TTL_MS) {
    options = cached.options;
  } else {
    const { count, total } = cartPayload(userId);
    const r = await shipping.calculate({ destCep: destCep, itemCount: count, insuranceValue: total });
    if (r.ok) options = r.options.map(function (o) {
      return { id: o.id, name: o.name, company: o.company, price: freightToReais(o.price), deliveryDays: o.deliveryDays };
    });
  }
  if (!options || !options.length) {
    return { price: 0, free: false, unavailable: true, id: null, name: '', company: '', deliveryDays: null };
  }
  let opt = options.find(function (o) { return String(o.id) === String(chosenId); });
  if (!opt) opt = options[0]; // fallback: opção mais barata
  return { price: opt.price, free: false, id: opt.id, name: opt.name, company: opt.company, deliveryDays: opt.deliveryDays };
}

// Finalizar compra — cria um pedido (com dados do cliente) e esvazia a sacola.
// Também salva/atualiza o perfil para facilitar a próxima compra.
app.post('/api/checkout', authRequired, async (req, res) => {
  try {
    const body = req.body || {};
    let method = (body.method || 'pix').toString().trim().toLowerCase();
    if (method !== 'pix' && method !== 'cartao') method = 'pix';

    const { items, total: subtotal } = cartPayload(req.user.id);
    if (!items.length) {
      return res.status(400).json({ error: 'Sua sacola está vazia.' });
    }

    // Peça bloqueada na sacola: pode ter entrado antes do bloqueio, ou por
    // fora da tela. Barra aqui também — senão o pedido nasce e você teria
    // que cancelar na mão, com o cliente já cobrado.
    const bloqueada = items.find((it) => estaBloqueado(it.product));
    if (bloqueada) {
      return res.status(409).json({
        error: bloqueada.product + ' ainda não está à venda. Remova da sacola para continuar.',
        bloqueado: true,
        cart: cartPayload(req.user.id)
      });
    }

    /* Tamanho fora do catálogo na sacola. Hoje a entrada já barra, mas uma
       sacola salva antes desta correção ainda carrega a linha ruim — e um
       tamanho que não existe no estoque seria lido como "sem controle" e
       passaria batido pela conferência logo abaixo. */
    const tamanhoRuim = items.find((it) => SIZES.indexOf(it.size) === -1);
    if (tamanhoRuim) {
      return res.status(409).json({
        error: 'O tamanho ' + tamanhoRuim.size + ' de ' + tamanhoRuim.product +
               ' não existe. Remova da sacola para continuar.',
        cart: cartPayload(req.user.id)
      });
    }

    // Estoque: confere tudo ANTES de cobrar. Se alguma peça acabou entre
    // colocar na sacola e finalizar, a compra é barrada com aviso claro.
    const semEstoque = [];
    for (const it of items) {
      const disponivel = stockAvailable(it.product, it.size);
      if (it.qty > disponivel) {
        semEstoque.push({ product: it.product, size: it.size, wanted: it.qty, available: disponivel === Infinity ? null : disponivel });
      }
    }
    if (semEstoque.length) {
      const p = semEstoque[0];
      const msg = p.available > 0
        ? 'Só restam ' + p.available + ' unidade(s) de ' + p.product + ' (' + p.size + '). Ajuste a sacola.'
        : p.product + ' (' + p.size + ') esgotou. Remova da sacola para continuar.';
      return res.status(409).json({ error: msg, outOfStock: semEstoque, cart: cartPayload(req.user.id) });
    }

    // Dados do cliente para o pedido (snapshot) + salva no perfil
    const c = body.customer || {};
    const clean = (v) => (v == null ? '' : String(v).trim());
    const cpfDigits = clean(c.cpf).replace(/\D/g, '');
    if (!cpfDigits || !cpfIsValid(cpfDigits)) {
      return res.status(400).json({ error: 'CPF inválido ou não informado.' });
    }
    const customer = {
      name: clean(c.name) || req.user.name,
      email: clean(c.email) || req.user.email,
      cpf: cpfDigits,
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
        req.user.id, customer.cpf, customer.phone, customer.cep, customer.address,
        customer.number, customer.complement, customer.district, customer.city, customer.uf
      );
    }

    // Frete confiável (calculado no servidor). total = produtos + frete.
    const freight = await resolveFreight(req.user.id, subtotal, customer.cep, body.freightId);

    /* Frete indisponível numa compra que NÃO tem frete grátis: antes o
       pedido nascia com entrega R$ 0 e a loja pagava os Correios do
       próprio bolso, sem erro nenhum aparecer. Perder a venda é ruim;
       vender no prejuízo repetidamente é pior — e invisível.

       Cai aqui quando o token do Melhor Envio não está configurado, ou
       quando a API deles está fora do ar. */
    if (freight.unavailable && !freight.free) {
      console.error('[frete] checkout barrado: cotação indisponível para o CEP ' +
                    onlyDigits(customer.cep) + '. Confira ME_TOKEN / ME_ORIGIN_CEP.');
      return res.status(503).json({
        error: 'Não consegui calcular o frete para o seu CEP agora. ' +
               'Tente de novo em alguns minutos ou chame a gente no WhatsApp.',
        freteIndisponivel: true
      });
    }

    const total = subtotal + (freight.price || 0);

    const status = 'aguardando_pagamento';

    // Pedido + baixa de estoque + limpeza da sacola em uma transação só.
    // Se outra pessoa levar a última peça no meio do caminho, o UPDATE
    // condicional não afeta linha nenhuma e desfazemos tudo.
    let info;
    db.exec('BEGIN IMMEDIATE');
    try {
      for (const it of items) {
        if (stockAvailable(it.product, it.size) === Infinity) continue; // item sem controle
        const r = stmtStockDecrement.run(it.qty, it.product, it.size, it.qty);
        if (!r.changes) {
          throw Object.assign(new Error('sem_estoque'), { produto: it.product, tamanho: it.size });
        }
      }
      info = stmtOrderInsert.run(
        req.user.id, total, JSON.stringify(items), method, status,
        JSON.stringify(customer), JSON.stringify(freight)
      );
      stmtCartClear.run(req.user.id);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      if (e && e.message === 'sem_estoque') {
        return res.status(409).json({
          error: e.produto + ' (' + e.tamanho + ') acabou de esgotar. Ajuste a sacola para continuar.',
          outOfStock: [{ product: e.produto, size: e.tamanho }],
          cart: cartPayload(req.user.id)
        });
      }
      throw e;
    }
    freightCache.delete(req.user.id);

    const orderId = info.lastInsertRowid;
    const createdAt = new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

    // Envia o e-mail do pedido (sem travar nem derrubar a compra se falhar)
    mailer.sendOrderEmail({ orderId, total, subtotal, freight, items, method, status, customer, createdAt })
      .then(function (r) {
        if (!r.sent) console.warn('E-mail do pedido #' + orderId + ' não enviado:', r.reason);
        else console.log('E-mail do pedido #' + orderId + ' enviado para ' + mailer.mailTo);
      })
      .catch(function (e) { console.error('Erro ao enviar e-mail do pedido #' + orderId + ':', e.message); });

    return res.status(201).json({
      orderId: orderId,
      subtotal,
      freight,
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

/* ---------------- ESTOQUE (dono) ----------------
   Ver:      GET  /api/admin/stock
   Ajustar:  PUT  /api/admin/stock   { "product": "...", "size": "M", "qty": 5 }
   Em lote:  PUT  /api/admin/stock   { "items": [ {product,size,qty}, ... ] }
   Remover o controle de uma peça: mande "qty": null
------------------------------------------------- */
app.get('/api/admin/stock', adminRequired, (req, res) => {
  const registrados = {};
  for (const row of stmtStockAll.all()) {
    registrados[row.product + '|' + row.size] = Number(row.qty);
  }
  // Mostra todo o catálogo, marcando o que ainda não tem controle
  const stock = [];
  for (const product of Object.keys(CATALOG)) {
    for (const size of SIZES) {
      const chave = product + '|' + size;
      const temControle = Object.prototype.hasOwnProperty.call(registrados, chave);
      stock.push({
        product,
        size,
        preco: CATALOG[product],
        qty: temControle ? registrados[chave] : null,
        controlado: temControle
      });
    }
  }
  return res.json({ stock });
});

app.put('/api/admin/stock', adminRequired, (req, res) => {
  const body = req.body || {};
  const lista = Array.isArray(body.items) ? body.items : [body];
  const aplicados = [];

  for (const item of lista) {
    const product = String((item && item.product) || '').trim();
    const size = String((item && item.size) || '').trim().toUpperCase();
    if (!Object.prototype.hasOwnProperty.call(CATALOG, product)) {
      return res.status(400).json({ error: 'Produto fora do catálogo: ' + product });
    }
    if (SIZES.indexOf(size) === -1) {
      return res.status(400).json({ error: 'Tamanho inválido: ' + size });
    }
    // qty null/'' => desliga o controle de estoque dessa peça
    if (item.qty === null || item.qty === '' || typeof item.qty === 'undefined') {
      stmtStockDelete.run(product, size);
      aplicados.push({ product, size, qty: null, controlado: false });
      continue;
    }
    const qty = parseInt(item.qty, 10);
    if (!Number.isFinite(qty) || qty < 0) {
      return res.status(400).json({ error: 'Quantidade inválida para ' + product + ' (' + size + ').' });
    }
    stmtStockUpsert.run(product, size, qty);
    aplicados.push({ product, size, qty, controlado: true });
  }

  return res.json({ ok: true, updated: aplicados });
});

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

/* Situações possíveis de um pedido. 'pago' é o gatilho da planilha.

   'estornado' é diferente de 'cancelado': cancelado é pedido que nunca foi
   pago (desistência, Pix que expirou); estornado é dinheiro que ENTROU e
   voltou (devolução de Pix, chargeback de cartão). Separar os dois importa
   porque só o estorno pode pegar você com a mercadoria já despachada. */
const ORDER_STATUSES = ['aguardando_pagamento', 'pago', 'enviado', 'cancelado', 'estornado'];

/* Status do Mercado Pago que significam "o dinheiro não está mais aqui".
   https://www.mercadopago.com.br/developers → status de pagamento */
const MP_STATUS_DEVOLVIDO = new Set(['refunded', 'charged_back', 'cancelled']);

/* ------------------------------------------------------------
   Falhas seguidas de assinatura do webhook.

   Existe para separar duas coisas que se parecem no log e são
   completamente diferentes na prática:

   - uma ou outra falha avulsa = alguém sondando a URL. Ignorável.
   - TODAS falhando, uma atrás da outra = o MP_WEBHOOK_SECRET está
     errado, e nesse caso cada notificação recusada é um cliente que
     pagou e cujo pedido não deu baixa.

   O segundo caso é o que fez desligarem a checagem no passado. Em vez
   de tolerar assinatura inválida, a gente grita — e grita mais alto a
   cada falha seguida, até ficar impossível de não ver.
------------------------------------------------------------ */
let falhasSeguidasDeAssinatura = 0;

function registraFalhaDeAssinatura(motivo, dataId) {
  falhasSeguidasDeAssinatura += 1;
  const n = falhasSeguidasDeAssinatura;
  console.warn('[mercadopago] assinatura inválida (' + motivo + ') data.id=' + dataId +
               ' — notificação RECUSADA. Falhas seguidas: ' + n);
  if (n === 3 || n === 10 || (n > 10 && n % 25 === 0)) {
    console.error('[mercadopago] *** ' + n + ' NOTIFICAÇÕES SEGUIDAS RECUSADAS POR ASSINATURA. ***\n' +
                  '    Isto quase certamente é o MP_WEBHOOK_SECRET errado, não um invasor.\n' +
                  '    Enquanto durar, cliente paga e o pedido NÃO dá baixa.\n' +
                  '    Confira a "Assinatura secreta" em: Mercado Pago > Suas integrações >\n' +
                  '    sua aplicação > Webhooks, e compare com a variável no painel do Render.');
  }
}

function parseJSON(text, fallback) {
  try { return JSON.parse(text); } catch (e) { return fallback; }
}

/* Achata a linha do banco no formato usado pelo painel e pela planilha.
   Lê o snapshot de orders.customer: são os dados do momento da compra,
   e não o perfil atual — se o cliente mudar de endereço depois, o pedido
   antigo continua mostrando para onde foi de fato enviado. */
function orderRow(r) {
  const c = parseJSON(r.customer, {}) || {};
  const items = parseJSON(r.items, []) || [];
  return {
    id: r.id,
    status: r.status,
    method: r.method,
    total: r.total,
    createdAt: r.created_at,
    paidAt: r.paid_at || '',
    qty: items.reduce((s, i) => s + (i.qty || 1), 0),
    items: items.map((i) => `${i.qty || 1}x ${i.product} (${i.size})`).join(' | '),
    name: c.name || '',
    email: c.email || '',
    accountEmail: r.account_email || '',
    phone: c.phone || '',
    cep: c.cep || '',
    address: c.address || '',
    number: c.number || '',
    complement: c.complement || '',
    district: c.district || '',
    city: c.city || '',
    uf: c.uf || ''
  };
}

app.get('/api/admin/orders', adminRequired, (req, res) => {
  const orders = stmtAdminOrders.all().map(orderRow);
  const pagos = orders.filter((o) => o.status === 'pago' || o.status === 'enviado');
  return res.json({
    totalPedidos: orders.length,
    totalPagos: pagos.length,
    receitaPaga: pagos.reduce((s, o) => s + o.total, 0),
    orders
  });
});

/* Confirmação manual: você viu o Pix cair, marca aqui. */
app.patch('/api/admin/orders/:id/status', adminRequired, (req, res) => {
  const id = Number(req.params.id);
  const status = String((req.body || {}).status || '').trim().toLowerCase();
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Pedido inválido.' });
  if (!ORDER_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Situação inválida. Use: ' + ORDER_STATUSES.join(', ') });
  }
  const current = stmtOrderGet.get(id);
  if (!current) return res.status(404).json({ error: 'Pedido não encontrado.' });

  // paid_at marca quando o dinheiro entrou: nasce no 'pago', sobrevive ao
  // 'enviado' e some se o pedido voltar a não estar pago.
  let paidAt = null;
  if (status === 'pago' || status === 'enviado') {
    // Mesmo formato/fuso (UTC) que o created_at do SQLite, para as duas
    // colunas de data ordenarem juntas na planilha.
    paidAt = current.paid_at || new Date().toISOString().slice(0, 19).replace('T', ' ');
  }

  /* Cancelar ou estornar na mão também devolve as peças à prateleira.
     O estoque é baixado no checkout, antes do pagamento; sem esta parte,
     todo pedido que você cancelasse deixaria a peça presa para sempre e a
     vitrine iria esgotando sozinha. Só devolve na TRANSIÇÃO para o status
     morto — marcar 'cancelado' duas vezes não soma duas vezes. */
  const morto = (s) => s === 'cancelado' || s === 'estornado';
  const devolve = morto(status) && !morto(current.status);

  if (devolve) {
    const full = stmtOrderFull.get(id);
    db.exec('BEGIN IMMEDIATE');
    try {
      devolverEstoque(parseJSON(full && full.items, []) || []);
      stmtOrderSetStatus.run(status, paidAt, id);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  } else {
    stmtOrderSetStatus.run(status, paidAt, id);
  }

  return res.json(orderRow(stmtAdminOrderById.get(id)));
});

/* Planilha. CSV com BOM + ';' porque é o que o Excel em pt-BR abre
   com acento certo e colunas separadas ao dar duplo clique. */
function csvCell(v) {
  const s = v == null ? '' : String(v);
  return '"' + s.replace(/"/g, '""') + '"';
}

app.get('/api/admin/orders.csv', adminRequired, (req, res) => {
  const cols = [
    ['Pedido', 'id'], ['Data', 'createdAt'], ['Pago em', 'paidAt'], ['Situação', 'status'],
    ['Pagamento', 'method'], ['Total (R$)', 'total'], ['Qtd', 'qty'], ['Itens', 'items'],
    ['Nome', 'name'], ['E-mail', 'email'], ['E-mail da conta', 'accountEmail'],
    ['Telefone', 'phone'], ['CEP', 'cep'], ['Endereço', 'address'], ['Número', 'number'],
    ['Complemento', 'complement'], ['Bairro', 'district'], ['Cidade', 'city'], ['UF', 'uf']
  ];
  const onlyPaid = String(req.query.pagos || '') === '1';
  let orders = stmtAdminOrders.all().map(orderRow);
  if (onlyPaid) orders = orders.filter((o) => o.status === 'pago' || o.status === 'enviado');

  const lines = [cols.map((c) => csvCell(c[0])).join(';')];
  for (const o of orders) lines.push(cols.map((c) => csvCell(o[c[1]])).join(';'));

  return enviarCsv(res, 'pedidos', lines);
});

/* Monta o arquivo e manda para download. O BOM ('﻿') no começo é o que
   faz o Excel entender que o arquivo é UTF-8; sem ele "Endereço" chega como
   "EndereÃ§o" na planilha do cliente. */
function enviarCsv(res, nome, lines) {
  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${nome}-${stamp}.csv"`);
  return res.send('﻿' + lines.join('\r\n') + '\r\n');
}

/* Planilha do estoque: uma linha por peça e tamanho, com um aviso
   na última coluna para quem estiver sem controle. */
app.get('/api/admin/stock.csv', adminRequired, (req, res) => {
  const registrados = {};
  for (const row of stmtStockAll.all()) registrados[row.product + '|' + row.size] = Number(row.qty);

  const lines = [['Peça', 'Tamanho', 'Quantidade', 'Preço (R$)', 'Situação'].map(csvCell).join(';')];
  for (const product of Object.keys(CATALOG)) {
    for (const size of SIZES) {
      const chave = product + '|' + size;
      const tem = Object.prototype.hasOwnProperty.call(registrados, chave);
      const qty = tem ? registrados[chave] : '';
      const situacao = !tem ? 'SEM CONTROLE (vende ilimitado)' : (qty <= 0 ? 'Esgotado' : 'À venda');
      lines.push([product, size, qty, CATALOG[product], situacao].map(csvCell).join(';'));
    }
  }
  return enviarCsv(res, 'estoque', lines);
});

/* Planilha de clientes: quem é, quanto já comprou e como falar com a pessoa. */
app.get('/api/admin/customers.csv', adminRequired, (req, res) => {
  const cols = [
    ['Cliente', 'id'], ['Nome', 'name'], ['E-mail', 'email'], ['Telefone', 'phone'],
    ['CEP', 'cep'], ['Endereço', 'endereco'], ['Pedidos', 'pedidos'],
    ['Total gasto (R$)', 'totalGasto'], ['Ticket médio (R$)', 'ticketMedio'],
    ['Último pedido', 'ultimoPedido'], ['Cliente desde', 'clienteDesde']
  ];
  const rows = stmtAdminCustomers.all().map((r) => {
    const orders = r.orders || 0;
    const totalSpent = r.total_spent || 0;
    return {
      id: r.id, name: r.name, email: r.email, phone: r.phone || '', cep: r.cep || '',
      endereco: [r.address, r.number, r.complement, r.district, r.city, r.uf].filter(Boolean).join(', '),
      pedidos: orders, totalGasto: totalSpent,
      ticketMedio: orders ? Math.round(totalSpent / orders) : 0,
      ultimoPedido: r.last_order || '', clienteDesde: r.created_at
    };
  });
  const lines = [cols.map((c) => csvCell(c[0])).join(';')];
  for (const c of rows) lines.push(cols.map((col) => csvCell(c[col[1]])).join(';'));
  return enviarCsv(res, 'clientes', lines);
});

/* ------------------------------------------------------------
   Situação de um pedido, para o próprio dono dele.
   Usada na volta do Mercado Pago: o site pergunta "já caiu?" antes
   de comemorar. A resposta é a do banco, alimentada pelo webhook —
   nunca o que veio na URL de retorno, que qualquer um digita.
------------------------------------------------------------ */
app.get('/api/orders/:id', authRequired, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Pedido inválido.' });

  const row = stmtOrderFull.get(id);
  if (!row || row.user_id !== req.user.id) {
    return res.status(404).json({ error: 'Pedido não encontrado.' });
  }
  const freight = parseJSON(row.freight, {}) || {};
  return res.json({
    id: row.id,
    status: row.status,
    pago: row.status === 'pago' || row.status === 'enviado',
    total: row.total,
    shipping: freight.price || 0,
    items: parseJSON(row.items, []) || []
  });
});

/* ============================================================
   MERCADO PAGO — Checkout Pro
============================================================ */

/* ------------------------------------------------------------
   Gera a preferência de pagamento de um pedido já criado.
   POST /api/mercadopago   { orderId }  →  { url, preferenceId }

   O pedido tem de existir no banco ANTES: os valores cobrados saem
   de lá, não do navegador. E o pedido tem de ser do próprio usuário
   logado — sem essa checagem, qualquer cliente logado poderia gerar
   cobrança em cima do pedido de outro. [OWASP A01]
------------------------------------------------------------ */
app.post('/api/mercadopago', authRequired, pagamentoLimiter, async (req, res) => {
  const orderId = Number((req.body || {}).orderId);
  if (!Number.isInteger(orderId) || orderId <= 0) {
    return res.status(400).json({ error: 'Pedido inválido.' });
  }

  const row = stmtOrderFull.get(orderId);
  if (!row) return res.status(404).json({ error: 'Pedido não encontrado.' });
  if (row.user_id !== req.user.id) {
    // 404 e não 403: não confirma para um curioso que o pedido existe.
    return res.status(404).json({ error: 'Pedido não encontrado.' });
  }
  if (row.status === 'pago' || row.status === 'enviado') {
    return res.status(409).json({ error: 'Este pedido já está pago.' });
  }

  const pedido = {
    id: row.id,
    total: row.total,
    items: parseJSON(row.items, []) || [],
    customer: parseJSON(row.customer, {}) || {},
    freight: parseJSON(row.freight, {}) || {}
  };

  const r = await mercadopago.createPreference(pedido, {
    siteUrl: SITE_URL,
    notificationUrl: SITE_URL + '/api/mercadopago/webhook'
  });

  if (!r.ok) {
    console.error('[mercadopago] preferência falhou (pedido ' + orderId + '):', r.error);
    return res.status(r.local ? 400 : 502).json({ error: r.error });
  }

  // Guarda a preferência no pedido para conciliar depois no painel.
  const pagamento = Object.assign(parseJSON(row.payment, {}) || {}, {
    provider: 'mercadopago',
    preferenceId: r.preferenceId,
    sandbox: mercadopago.isSandbox(),
    criadoEm: new Date().toISOString()
  });
  stmtOrderSetPayment.run(JSON.stringify(pagamento), orderId);

  return res.json({ ok: true, url: r.url, preferenceId: r.preferenceId });
});

/* ------------------------------------------------------------
   Webhook: o Mercado Pago avisa que um pagamento mudou de estado.

   Regras que importam aqui:
   - A notificação NÃO diz o status; diz só o id. O status a gente
     busca na API, porque só a fonte é confiável.
   - Assinatura conferida antes de qualquer coisa.
   - Idempotente: o Mercado Pago reenvia a mesma notificação várias
     vezes, e o pedido não pode "pagar" duas vezes.
   - Responde 200 em quase tudo, para não gerar reenvio infinito de
     algo que nunca vai dar certo. A exceção é falha nossa ao gravar
     (500), aí o reenvio é justamente o que salva o pagamento.
------------------------------------------------------------ */
app.post('/api/mercadopago/webhook', webhookLimiter, async (req, res) => {
  const body = req.body || {};
  const q = req.query || {};

  // O Mercado Pago manda o id ora na query, ora no corpo, dependendo
  // da versão da notificação. Aceita os dois.
  const tipo = String(body.type || q.type || q.topic || '');
  const dataId = String((body.data && body.data.id) || q['data.id'] || q.id || '');

  if (tipo !== 'payment') {
    // merchant_order e afins: reconhece e ignora, sem virar reenvio.
    return res.status(200).json({ ignored: tipo || 'sem tipo' });
  }
  if (!dataId) return res.status(200).json({ ignored: 'sem data.id' });

  // 1) A notificação veio mesmo do Mercado Pago?
  /* A assinatura volta a BLOQUEAR. Antes ela era só um console.warn e o
     processamento seguia — a defesa em profundidade tinha virado defesa
     única (a consulta à API), e a checagem que detecta o problema antes
     dele acontecer estava desligada sem ninguém perceber.

     O motivo de terem desligado era real: um segredo mal copiado recusa
     TODA notificação boa, o cliente paga e o pedido nunca dá baixa. A
     resposta certa para isso não é tolerar assinatura inválida — é fazer
     o segredo errado ser impossível de não notar. É o que o contador de
     falhas seguidas abaixo faz, junto com o aviso no boot.

     Sem segredo configurado é caso à parte: não dá para validar o que
     não se pode calcular. Aí seguimos pela consulta à API (que é segura
     por si só) e gritamos no log, em vez de derrubar a loja inteira de
     quem ainda não configurou. */
  const assinatura = mercadopago.validateSignature({
    xSignature: req.headers['x-signature'],
    xRequestId: req.headers['x-request-id'],
    dataId: dataId
  });

  if (!assinatura.ok) {
    if (assinatura.reason === 'SemSegredoConfigurado') {
      console.warn('[mercadopago] *** MP_WEBHOOK_SECRET não configurado — ' +
                   'notificação aceita sem conferir assinatura. Cadastre a ' +
                   '"Assinatura secreta" no painel do Mercado Pago. ***');
    } else {
      // Assinatura presente e errada: ou é forjada, ou o segredo está errado.
      // Os dois casos param aqui; o contador diz qual é qual.
      registraFalhaDeAssinatura(assinatura.reason, dataId);
      return res.status(401).json({ error: 'assinatura inválida' });
    }
  } else {
    falhasSeguidasDeAssinatura = 0;
  }

  // 2) Status na fonte, nunca no que chegou pela rede.
  const pag = await mercadopago.getPayment(dataId);
  if (!pag.ok) {
    console.error('[mercadopago] não consegui consultar o pagamento ' + dataId + ':', pag.error);
    // Falha temporária da API deles: peça reenvio.
    return res.status(500).json({ error: 'consulta falhou' });
  }

  const orderId = Number(pag.orderId);
  if (!Number.isInteger(orderId) || orderId <= 0) {
    console.warn('[mercadopago] pagamento ' + dataId + ' sem orderId em metadata/external_reference');
    return res.status(200).json({ ignored: 'sem pedido vinculado' });
  }

  const row = stmtOrderFull.get(orderId);
  if (!row) {
    console.warn('[mercadopago] pagamento ' + dataId + ' aponta para pedido inexistente ' + orderId);
    return res.status(200).json({ ignored: 'pedido inexistente' });
  }

  try {
    const pagamento = Object.assign(parseJSON(row.payment, {}) || {}, {
      provider: 'mercadopago',
      paymentId: String(pag.id),
      status: pag.status,
      statusDetail: pag.statusDetail,
      amount: pag.amount,
      method: pag.method,
      atualizadoEm: new Date().toISOString()
    });
    stmtOrderSetPayment.run(JSON.stringify(pagamento), orderId);

    const jaPago = row.status === 'pago' || row.status === 'enviado';

    if (pag.status === 'approved' && !jaPago) {
      /* O valor pago tem de cobrir o pedido. Antes esta conferência não
         existia: bastava o pagamento estar "approved" para o pedido ser
         dado como quitado, qualquer que fosse o valor. O dado já vinha na
         mão (pag.amount), só não era comparado com nada.

         Não marcamos pago automaticamente quando não bate — mas também
         não jogamos fora: grava a divergência e grita no log, porque um
         cliente que pagou de verdade não pode ficar sem resposta por
         causa de uma diferença de centavos que só você sabe resolver. */
      const pago = Number(pag.amount);
      const devido = Number(row.total);
      const cobre = Number.isFinite(pago) && pago + 0.01 >= devido;

      if (!cobre) {
        pagamento.divergencia = { pago: pago, devido: devido, em: new Date().toISOString() };
        stmtOrderSetPayment.run(JSON.stringify(pagamento), orderId);
        console.error('[mercadopago] *** VALOR NÃO CONFERE — pedido ' + orderId +
                      ' NÃO foi marcado como pago. Pagamento ' + pag.id +
                      ' trouxe R$ ' + pago + ' e o pedido é R$ ' + devido +
                      '. Confira no painel do Mercado Pago antes de despachar. ***');
        return res.status(200).json({ ok: true, aviso: 'valor divergente' });
      }

      /* Pagamento chegou depois da reserva expirar? O estoque já foi
         devolvido à vitrine, então é preciso retomá-lo — senão a peça
         é vendida duas vezes.

         Se não couber (alguém levou nesse meio-tempo), o pedido é
         marcado pago do mesmo jeito: o cliente pagou, e fingir que
         não seria pior. Mas o log grita, porque aí é caso para
         resolver na mão — reembolsar ou repor. */
      if (row.status === 'cancelado') {
        const faltou = retomarEstoque(parseJSON(row.items, []) || []);
        if (faltou.length) {
          console.error('[mercadopago] *** pedido ' + orderId + ' foi PAGO depois da reserva expirar ' +
                        'e não há mais estoque de: ' + faltou.join(', ') +
                        '. O pedido está pago — resolva na mão (repor ou reembolsar). ***');
        } else {
          console.warn('[mercadopago] pedido ' + orderId + ' pago após a reserva expirar — estoque retomado.');
        }
      }

      const paidAt = (pag.approvedAt ? new Date(pag.approvedAt) : new Date())
        .toISOString().slice(0, 19).replace('T', ' ');
      stmtOrderSetStatus.run('pago', paidAt, orderId);
      console.log('[mercadopago] pedido ' + orderId + ' PAGO (pagamento ' + pag.id + ', R$ ' + pag.amount + ')');

    } else if (MP_STATUS_DEVOLVIDO.has(pag.status) && jaPago) {
      /* O dinheiro voltou depois de ter entrado: devolução de Pix ou
         chargeback de cartão. Antes isso caía no console.log genérico e o
         pedido continuava "pago" para sempre — com o estoque baixado e a
         receita do painel inflada. Você descobriria pelo extrato, com a
         mercadoria já despachada.

         Devolver o estoque aqui é seguro contra reenvio: o Mercado Pago
         repete a mesma notificação várias vezes, mas a segunda encontra o
         pedido já em 'estornado' (jaPago falso) e não soma nada. */
      db.exec('BEGIN IMMEDIATE');
      try {
        devolverEstoque(parseJSON(row.items, []) || []);
        stmtOrderSetStatus.run('estornado', null, orderId);
        db.exec('COMMIT');
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
      console.error('[mercadopago] *** ESTORNO — pedido ' + orderId + ' voltou de "' + row.status +
                    '" para "estornado" (pagamento ' + pag.id + ', ' + pag.status + ', R$ ' + pag.amount +
                    '). Estoque devolvido. Se já despachou, corra atrás da mercadoria. ***');

    } else {
      console.log('[mercadopago] pedido ' + orderId + ' — pagamento ' + pag.id + ' está "' + pag.status + '"' + (jaPago ? ' (pedido já estava pago)' : ''));
    }
  } catch (e) {
    console.error('[mercadopago] falha ao gravar o pedido ' + orderId + ':', e.message);
    // Erro nosso: 500 para o Mercado Pago reenviar e não perdermos a baixa.
    return res.status(500).json({ error: 'falha ao gravar' });
  }

  return res.status(200).json({ ok: true });
});

/* ------------------------------------------------------------
   Etiqueta de envio (Melhor Envio)

   Ver situação:  GET  /api/admin/orders/:id/etiqueta
   Emitir:        POST /api/admin/orders/:id/etiqueta   { "comprar": true }

   SEM "comprar": true o envio só entra no carrinho do Melhor Envio e
   NADA é debitado — dá para conferir e finalizar pelo painel deles.
   COM "comprar": true o saldo da conta é debitado na hora. O padrão é
   não comprar de propósito: gastar dinheiro tem que ser um pedido
   explícito, nunca o efeito colateral de uma chamada distraída.
------------------------------------------------------------ */
function pedidoParaEtiqueta(row) {
  return {
    id: row.id,
    status: row.status,
    total: row.total,
    items: parseJSON(row.items, []) || [],
    customer: parseJSON(row.customer, {}) || {},
    freight: parseJSON(row.freight, {}) || {}
  };
}

app.get('/api/admin/orders/:id/etiqueta', adminRequired, (req, res) => {
  const row = stmtOrderFull.get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Pedido não encontrado.' });
  const shipment = parseJSON(row.shipment, {}) || {};
  return res.json({
    orderId: row.id,
    configurado: labels.isEnabled(),
    faltaConfigurar: labels.missing(),
    etiqueta: shipment
  });
});

app.post('/api/admin/orders/:id/etiqueta', adminRequired, async (req, res) => {
  const row = stmtOrderFull.get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: 'Pedido não encontrado.' });

  const jaFeita = parseJSON(row.shipment, {}) || {};
  if (jaFeita.comprada) {
    // Comprar de novo geraria uma segunda etiqueta paga para o mesmo pedido.
    return res.status(409).json({
      error: 'Pedido #' + row.id + ' já tem etiqueta comprada.',
      etiqueta: jaFeita
    });
  }

  const comprar = req.body && req.body.comprar === true;
  const pedido = pedidoParaEtiqueta(row);
  const r = await labels.emitir(pedido, { comprar: comprar });

  // Grava o que deu certo mesmo se um passo posterior falhou: com o
  // cartId em mãos dá para retomar pelo painel do Melhor Envio em vez
  // de pagar outra vez.
  const registro = {
    cartId: r.cartId || jaFeita.cartId || null,
    protocol: r.protocol || jaFeita.protocol || '',
    comprada: !!r.comprada,
    labelUrl: r.labelUrl || '',
    tracking: r.tracking || '',
    price: r.price != null ? r.price : null,
    atualizadoEm: new Date().toISOString(),
    erro: r.ok ? '' : (r.error || '')
  };
  if (registro.cartId) stmtOrderSetShipment.run(JSON.stringify(registro), row.id);

  // 400 = falta preencher algo aqui; 502 = o Melhor Envio recusou/caiu.
  if (!r.ok) return res.status(r.local ? 400 : 502).json({ error: r.error, etiqueta: registro });
  return res.json({ ok: true, etiqueta: registro, aviso: r.aviso || '' });
});

/* ------------------------------------------------------------
   Backup do banco
   Listar:  GET  /api/admin/backups
   Criar:   POST /api/admin/backups
   Baixar:  GET  /api/admin/backups/:nome     (guarde fora do servidor!)
   Um backup que só existe na mesma máquina do banco não protege
   contra o disco morrer — baixe de vez em quando.
------------------------------------------------------------ */
app.get('/api/admin/backups', adminRequired, (req, res) => {
  const items = backup.list().map((b) => ({
    name: b.name,
    createdAt: b.date.toISOString(),
    sizeKb: Math.round(b.size / 1024)
  }));
  return res.json({ backups: items });
});

app.post('/api/admin/backups', adminRequired, (req, res) => {
  const r = backup.run(db);
  if (!r.ok) return res.status(500).json({ error: 'Backup falhou: ' + r.error });
  return res.json({ ok: true, name: r.name, sizeKb: Math.round(r.size / 1024), removed: r.removed });
});

app.get('/api/admin/backups/:nome', adminRequired, (req, res) => {
  // Só nomes que o próprio backup.js gera — corta path traversal
  // (../../.jwt-secret) na raiz. [OWASP A01]
  const nome = String(req.params.nome || '');
  const found = backup.list().find((b) => b.name === nome);
  if (!found) return res.status(404).json({ error: 'Backup não encontrado.' });
  return res.download(found.file, nome);
});

/* ------------------------------------------------------------
   robots.txt e sitemap.xml
   Gerados aqui em vez de virarem arquivos soltos: assim o endereço
   do site mora num lugar só. MUDOU DE DOMÍNIO? Troque SITE_URL
   (ou defina a variável de ambiente) e as tags og:/canonical do
   index.html.

   /api/ fica fora do índice — não há nada lá para buscar, e página
   de erro de API indexada só suja o resultado da marca.
------------------------------------------------------------ */
app.get('/robots.txt', (req, res) => {
  res.type('text/plain').send(
    'User-agent: *\n' +
    'Allow: /\n' +
    'Disallow: /api/\n' +
    'Disallow: /admin\n' +
    '\n' +
    'Sitemap: ' + SITE_URL + '/sitemap.xml\n'
  );
});

app.get('/sitemap.xml', (req, res) => {
  // lastmod real: quando o index.html mudou pela última vez.
  let lastmod;
  try {
    lastmod = fs.statSync(path.join(ROOT, 'index.html')).mtime.toISOString().slice(0, 10);
  } catch (e) {
    lastmod = new Date().toISOString().slice(0, 10);
  }
  res.type('application/xml').send(
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
    '  <url>\n' +
    '    <loc>' + SITE_URL + '/</loc>\n' +
    '    <lastmod>' + lastmod + '</lastmod>\n' +
    '    <changefreq>weekly</changefreq>\n' +
    '    <priority>1.0</priority>\n' +
    '  </url>\n' +
    '</urlset>\n'
  );
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

/* Painel do dono. A PÁGINA é pública de propósito — ela não traz dado
   nenhum dentro, só o formulário que pede a chave. Todo número aparece
   depois, vindo das rotas /api/admin/*, que exigem a chave em cada
   chamada. Proteger o HTML e deixar a API aberta é que seria o erro. */
app.get('/admin', (req, res) => {
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(ROOT, 'admin.html'));
});

/* ------------------------------------------------------------
   Último a ser registrado, de propósito: só chega aqui o que
   escapou de todas as rotas acima.

   Resposta genérica para o cliente (stack trace na tela é presente
   de aniversário para quem está sondando o site) e detalhe completo
   no log, que é onde você vai olhar. [OWASP A05/A09]
------------------------------------------------------------ */
app.use(function (err, req, res, next) {
  console.error('[erro] ' + req.method + ' ' + req.originalUrl + ':', (err && err.stack) || err);
  // Resposta já começou a sair? Não dá para trocar o status; deixa o
  // Express fechar a conexão do jeito dele.
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Erro interno. Tente de novo em instantes.' });
});

/* ------------------------------------------------------------
   Rede de segurança do processo — o que escapou até do error handler.

   As duas metades recebem tratamento diferente de propósito:

   - unhandledRejection: uma Promise solta que ninguém pegou. O
     processo continua íntegro, então derrubar a loja por causa disso
     seria trocar um problema pequeno por um grande. Só registra.

   - uncaughtException: o processo pode estar em estado inconsistente,
     e servir venda a partir daí é pior do que não servir. Registra e
     sai; o Render sobe de novo em segundos, limpo.
------------------------------------------------------------ */
process.on('unhandledRejection', (motivo) => {
  console.error('[erro] Promise rejeitada sem tratamento:', (motivo && motivo.stack) || motivo);
});
process.on('uncaughtException', (e) => {
  console.error('[erro] Exceção não capturada — encerrando para subir limpo:', (e && e.stack) || e);
  process.exit(1);
});

app.listen(PORT, () => {
  console.log(`Pantale rodando em http://localhost:${PORT}`);
  console.log(`Gestão de clientes:  GET /api/admin/customers  (header x-admin-key; chave em server/.admin-key)`);
  console.log(`E-mail de pedidos:   ${mailer.isEnabled() ? 'ATIVO → ' + mailer.mailTo : 'desativado (configure server/mail-config.json)'}`);
  /* Link do "esqueci a senha". Apontar para localhost em produção não dá
     erro nenhum: o e-mail sai, o cliente clica e não abre nada. Por isso
     o endereço aparece no boot, para dar para conferir de olho. */
  console.log(`Link de redefinição: ${RESET_LINK_BASE}/?reset=...`);
  if (/localhost|127\.0\.0\.1/.test(RESET_LINK_BASE)) {
    console.log(`   *** ATENÇÃO: link de redefinição aponta para localhost — ninguém consegue recuperar a conta. Defina SITE_URL. ***`);
  }
  /* Frete desligado é a falha mais cara e mais silenciosa daqui: a loja
     continua vendendo, só que cobrando R$ 0 de entrega — e você descobre
     quando o prejuízo já aconteceu. Por isso o aviso é gritado. */
  if (shipping.isEnabled()) {
    console.log(`Frete (Melhor Envio): ATIVO`);
  } else {
    console.log(`Frete (Melhor Envio): *** DESATIVADO — TODA VENDA SAI COM FRETE R$ 0 ***`);
    shipping.missing().forEach((f) => console.log(`   falta: ${f}`));
  }
  console.log(`Mercado Pago:        ${mercadopago.isEnabled()
    ? (mercadopago.isSandbox() ? 'ATIVO em MODO TESTE (token TEST- — não cobra de verdade)' : 'ATIVO em produção')
    : 'desativado (defina MP_ACCESS_TOKEN)'}`);
  if (mercadopago.isEnabled() && mercadopago.missing().length) {
    console.log(`   atenção: ${mercadopago.missing().join(', ')}`);
  }
  /* A assinatura do webhook só protege se o segredo existir. Sem ele a
     notificação é aceita sem conferência — funciona, mas de olhos fechados. */
  if (mercadopago.isEnabled() && mercadopago.missing().some((m) => /WEBHOOK_SECRET/.test(m))) {
    console.log(`   *** webhook SEM conferência de assinatura (MP_WEBHOOK_SECRET vazio) ***`);
  }
  console.log(`Reserva de estoque:  ${RESERVA_MINUTOS} min sem pagamento e a peça volta para a vitrine`);
  backup.schedule(db, (msg) => console.log(msg));

  /* Varre no boot (para limpar o que ficou preso enquanto o servidor
     esteve fora) e depois a cada 5 minutos. */
  expirarReservas((msg) => console.log(msg));
  const varredura = setInterval(() => expirarReservas((msg) => console.log(msg)), 5 * 60 * 1000);
  if (varredura.unref) varredura.unref();
});
