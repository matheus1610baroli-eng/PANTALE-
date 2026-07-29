/* ============================================================
   Backup do banco (pantale.db)
   ------------------------------------------------------------
   Usa VACUUM INTO: o SQLite escreve uma cópia íntegra do banco
   num arquivo novo, mesmo com o servidor rodando e gravando.
   Copiar o .db "na mão" com o servidor no ar pode gerar um
   arquivo corrompido — por isso não fazemos cp.

   O arquivo gerado é um banco SQLite normal. Restaurar = parar
   o servidor e copiar o backup por cima de server/pantale.db.

   Retenção em camadas (o passado importa menos que o recente):
     - tudo dos últimos 14 dias
     - depois, um por semana, por 8 semanas
     - depois, um por mês, por 12 meses
     - o resto é apagado
============================================================ */
'use strict';

const path = require('node:path');
const fs = require('node:fs');

/* Mesma pasta de dados do server.js: numa hospedagem, DATA_DIR aponta
   para o disco que sobrevive às publicações. Backup gravado no disco
   efêmero seria apagado junto com o banco que ele deveria salvar. */
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;

const DB_PATH = path.join(DATA_DIR, 'pantale.db');
const DIR = path.join(DATA_DIR, 'backups');
const PREFIX = 'pantale-';
const SUFFIX = '.db';

const KEEP_DAYS = 14;
const KEEP_WEEKS = 8;
const KEEP_MONTHS = 12;

const DAY_MS = 24 * 60 * 60 * 1000;
const INTERVAL_MS = DAY_MS;          // um backup por dia
const STALE_MS = 12 * 60 * 60 * 1000; // no boot, refaz se o último passou disso

/* ------------------------------------------------------------
   Nome do arquivo: pantale-2026-07-27_081530.db
   Hora local (é o fuso em que o dono da loja pensa), com
   segundos para dois backups no mesmo minuto não colidirem.
------------------------------------------------------------ */
function pad(n) { return String(n).padStart(2, '0'); }

function stampName(d) {
  return PREFIX +
    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
    '_' + pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds()) +
    SUFFIX;
}

const NAME_RE = /^pantale-(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})(\d{2})\.db$/;

function parseStamp(name) {
  const m = NAME_RE.exec(name);
  if (!m) return null;
  const d = new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return isNaN(d.getTime()) ? null : d;
}

function ensureDir() {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
}

/* Backups existentes, do mais novo para o mais antigo. */
function list() {
  let names;
  try { names = fs.readdirSync(DIR); } catch (e) { return []; }
  return names
    .map(function (name) {
      const date = parseStamp(name);
      if (!date) return null;
      let size = 0;
      try { size = fs.statSync(path.join(DIR, name)).size; } catch (e) { return null; }
      return { name: name, file: path.join(DIR, name), date: date, size: size };
    })
    .filter(Boolean)
    .sort(function (a, b) { return b.date - a.date; });
}

function latest() {
  return list()[0] || null;
}

/* ------------------------------------------------------------
   Cria o snapshot. Recebe a conexão que o servidor já usa —
   assim o VACUUM entra na fila do próprio SQLite em vez de
   disputar lock com uma segunda conexão.
------------------------------------------------------------ */
function create(db) {
  ensureDir();
  const target = path.join(DIR, stampName(new Date()));
  // VACUUM INTO não aceita parâmetro (?), só literal — e recusa
  // sobrescrever arquivo existente. Aspas simples dobradas escapam
  // o caminho (a pasta do projeto pode ter aspas ou espaços).
  const literal = "'" + target.replace(/'/g, "''") + "'";
  db.exec('VACUUM INTO ' + literal);
  try { fs.chmodSync(target, 0o600); } catch (e) {}
  return { file: target, name: path.basename(target), size: fs.statSync(target).size };
}

/* ------------------------------------------------------------
   Aplica a retenção. Como a lista vem do mais novo para o mais
   velho, o primeiro de cada semana/mês é o mais recente dela —
   esse é o que fica.
------------------------------------------------------------ */
function weekKey(d) {
  // Semana começando no domingo, no fuso local.
  const start = new Date(d.getFullYear(), d.getMonth(), d.getDate() - d.getDay());
  return start.getFullYear() + '-' + start.getMonth() + '-' + start.getDate();
}

function monthKey(d) {
  return d.getFullYear() + '-' + d.getMonth();
}

function prune(now) {
  const ref = now || Date.now();
  const all = list();
  const seenWeek = new Set();
  const seenMonth = new Set();
  const removed = [];

  all.forEach(function (b, i) {
    if (i === 0) return; // o mais recente nunca é apagado
    const ageDays = (ref - b.date.getTime()) / DAY_MS;

    let keep;
    if (ageDays <= KEEP_DAYS) {
      keep = true;
    } else if (ageDays <= KEEP_WEEKS * 7) {
      const k = weekKey(b.date);
      keep = !seenWeek.has(k);
      seenWeek.add(k);
    } else if (ageDays <= KEEP_MONTHS * 31) {
      const k = monthKey(b.date);
      keep = !seenMonth.has(k);
      seenMonth.add(k);
    } else {
      keep = false;
    }

    if (!keep) {
      try { fs.unlinkSync(b.file); removed.push(b.name); } catch (e) {}
    }
  });

  return removed;
}

/* Backup + limpeza. Nunca lança: uma falha de backup não pode
   derrubar o servidor nem a requisição que a disparou. */
function run(db) {
  try {
    const made = create(db);
    const removed = prune();
    return { ok: true, name: made.name, size: made.size, removed: removed };
  } catch (e) {
    return { ok: false, error: e && e.message ? e.message : String(e) };
  }
}

/* ------------------------------------------------------------
   Agendamento: um no boot (se o último já está velho) e depois
   um por dia enquanto o servidor viver.
------------------------------------------------------------ */
function schedule(db, log) {
  const say = log || function () {};

  function tick(motivo) {
    const r = run(db);
    if (r.ok) {
      say('Backup ' + motivo + ': ' + r.name + ' (' + Math.round(r.size / 1024) + ' KB)' +
        (r.removed.length ? ' — ' + r.removed.length + ' antigo(s) removido(s)' : ''));
    } else {
      say('Backup FALHOU (' + motivo + '): ' + r.error);
    }
  }

  const last = latest();
  if (!last || Date.now() - last.date.getTime() > STALE_MS) tick('de inicialização');
  else say('Backup: último em ' + last.name + ' — próximo em até 24h');

  const timer = setInterval(function () { tick('diário'); }, INTERVAL_MS);
  if (timer.unref) timer.unref(); // não segura o processo vivo sozinho
  return timer;
}

module.exports = { create, prune, run, schedule, list, latest, DIR };

/* Rodar na mão:  npm run backup  (ou node server/backup.js) */
if (require.main === module) {
  const { DatabaseSync } = require('node:sqlite');
  if (!fs.existsSync(DB_PATH)) {
    console.error('Banco não encontrado em ' + DB_PATH);
    process.exit(1);
  }
  const db = new DatabaseSync(DB_PATH);
  const r = run(db);
  db.close();
  if (!r.ok) {
    console.error('Backup falhou: ' + r.error);
    process.exit(1);
  }
  console.log('Backup criado: ' + path.join(DIR, r.name) + ' (' + Math.round(r.size / 1024) + ' KB)');
  if (r.removed.length) console.log('Removidos pela retenção: ' + r.removed.join(', '));
}
