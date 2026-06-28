'use strict';

/* ============================================================
   PANTALE — Envio de e-mail de pedido (Nodemailer)
   ------------------------------------------------------------
   A cada pedido, manda um e-mail com todas as informações
   para o dono da loja. Credenciais vêm de variáveis de
   ambiente OU do arquivo server/mail-config.json.

   Gmail: gere uma "Senha de app" (precisa de verificação em
   2 etapas ativa) e use como SMTP_PASS / pass.
============================================================ */

const path = require('node:path');
const fs = require('node:fs');
const nodemailer = require('nodemailer');

const CONFIG_PATH = path.join(__dirname, 'mail-config.json');
const DEST_PADRAO = 'matheus1610.baroli@gmail.com';

function loadMailConfig() {
  const cfg = {
    host: process.env.SMTP_HOST || '',
    port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 0,
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    to: process.env.MAIL_TO || '',
    from: process.env.MAIL_FROM || ''
  };
  if ((!cfg.user || !cfg.pass) && fs.existsSync(CONFIG_PATH)) {
    try {
      const f = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      cfg.host = cfg.host || f.host || '';
      cfg.port = cfg.port || f.port || 0;
      cfg.user = cfg.user || f.user || '';
      cfg.pass = cfg.pass || f.pass || '';
      cfg.to = cfg.to || f.to || '';
      cfg.from = cfg.from || f.from || '';
    } catch (e) {
      console.error('mail-config.json inválido:', e.message);
    }
  }
  cfg.to = cfg.to || DEST_PADRAO;
  cfg.from = cfg.from || cfg.user;
  return cfg;
}

const config = loadMailConfig();

let transporter = null;
if (process.env.MAIL_JSON === '1') {
  // Modo de teste: não envia de verdade, só renderiza a mensagem
  transporter = nodemailer.createTransport({ jsonTransport: true });
} else if (config.user && config.pass) {
  transporter = config.host
    ? nodemailer.createTransport({
        host: config.host,
        port: config.port || 587,
        secure: config.port === 465,
        auth: { user: config.user, pass: config.pass }
      })
    : nodemailer.createTransport({
        service: 'gmail',
        auth: { user: config.user, pass: config.pass }
      });
}

function isEnabled() { return !!transporter; }

function brl(n) { return 'R$ ' + Number(n || 0).toLocaleString('pt-BR'); }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  });
}

function buildHtml(order) {
  const c = order.customer || {};
  const itemsRows = (order.items || []).map(function (it) {
    return '<tr>' +
      '<td style="padding:6px 0">' + esc(it.product) + '</td>' +
      '<td style="padding:6px 0">' + esc(it.size) + '</td>' +
      '<td style="padding:6px 0">' + it.qty + '</td>' +
      '<td style="padding:6px 0;text-align:right">' + brl(it.price * it.qty) + '</td>' +
      '</tr>';
  }).join('');
  const local = [c.district, c.city, c.uf].filter(Boolean).join(' · ');
  const metodo = order.method === 'cartao' ? 'Cartão (Mercado Pago)' : 'Pix';
  return '' +
  '<div style="font-family:Arial,Helvetica,sans-serif;color:#241606;max-width:600px;margin:auto;padding:8px">' +
    '<h2 style="margin:0 0 2px">Novo pedido #' + order.orderId + '</h2>' +
    '<p style="color:#7A5C32;margin:0 0 20px">' + esc(order.createdAt || '') + '</p>' +
    '<h3 style="border-bottom:1px solid #eadfc8;padding-bottom:6px;margin-bottom:8px">Cliente</h3>' +
    '<p style="margin:4px 0 18px"><strong>' + esc(c.name) + '</strong><br>' + esc(c.email) + '<br>' + esc(c.phone) + '</p>' +
    '<h3 style="border-bottom:1px solid #eadfc8;padding-bottom:6px;margin-bottom:8px">Entrega</h3>' +
    '<p style="margin:4px 0 18px">' +
      esc(c.address) + ', ' + esc(c.number) + (c.complement ? (' · ' + esc(c.complement)) : '') + '<br>' +
      esc(local) + '<br>CEP ' + esc(c.cep) +
    '</p>' +
    '<h3 style="border-bottom:1px solid #eadfc8;padding-bottom:6px;margin-bottom:8px">Itens</h3>' +
    '<table style="width:100%;border-collapse:collapse;font-size:14px">' +
      '<thead><tr style="text-align:left;color:#7A5C32">' +
        '<th>Produto</th><th>Tam.</th><th>Qtd</th><th style="text-align:right">Subtotal</th>' +
      '</tr></thead><tbody>' + itemsRows + '</tbody></table>' +
    '<p style="font-size:18px;margin:18px 0 4px"><strong>Total: ' + brl(order.total) + '</strong></p>' +
    '<p style="margin:0;color:#7A5C32">Pagamento: ' + metodo + ' · Status: ' + esc(order.status) + '</p>' +
  '</div>';
}

function buildText(order) {
  const c = order.customer || {};
  const items = (order.items || []).map(function (it) {
    return '- ' + it.product + ' (' + it.size + ') x' + it.qty + ' = ' + brl(it.price * it.qty);
  }).join('\n');
  return [
    'Novo pedido #' + order.orderId,
    order.createdAt || '',
    '',
    'CLIENTE',
    c.name, c.email, c.phone,
    '',
    'ENTREGA',
    (c.address || '') + ', ' + (c.number || '') + (c.complement ? (' - ' + c.complement) : ''),
    [c.district, c.city, c.uf].filter(Boolean).join(' - '),
    'CEP ' + (c.cep || ''),
    '',
    'ITENS',
    items,
    '',
    'TOTAL: ' + brl(order.total),
    'Pagamento: ' + (order.method === 'cartao' ? 'Cartao (Mercado Pago)' : 'Pix') + ' - Status: ' + order.status
  ].join('\n');
}

async function sendOrderEmail(order) {
  if (!transporter) return { sent: false, reason: 'mail-nao-configurado' };
  const info = await transporter.sendMail({
    from: config.from ? ('Pantale <' + config.from + '>') : config.user,
    to: config.to,
    subject: 'Novo pedido #' + order.orderId + ' · Pantale · ' + brl(order.total),
    text: buildText(order),
    html: buildHtml(order)
  });
  return { sent: true, info: info };
}

async function sendResetEmail(to, name, link) {
  if (!transporter) return { sent: false, reason: 'mail-nao-configurado' };
  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;color:#241606;max-width:520px;margin:auto;padding:8px">' +
      '<h2 style="margin:0 0 12px">Redefinir senha</h2>' +
      '<p style="line-height:1.6">Olá ' + esc(name) + ', recebemos um pedido para redefinir a senha da sua conta Pantale.</p>' +
      '<p style="line-height:1.6">Clique no botão abaixo para criar uma nova senha. O link vale por <strong>1 hora</strong>.</p>' +
      '<p style="margin:24px 0">' +
        '<a href="' + esc(link) + '" style="background:#C4853A;color:#fff;text-decoration:none;' +
        'padding:13px 26px;border-radius:999px;font-weight:bold;display:inline-block">Redefinir minha senha</a>' +
      '</p>' +
      '<p style="font-size:13px;color:#7A5C32;word-break:break-all">Ou copie e cole este endereço:<br>' + esc(link) + '</p>' +
      '<p style="font-size:13px;color:#7A5C32;margin-top:20px">Se não foi você, ignore este e-mail. Sua senha continua a mesma.</p>' +
    '</div>';
  const text = [
    'Ola ' + name + ',',
    '',
    'Recebemos um pedido para redefinir a senha da sua conta Pantale.',
    'Abra o link abaixo para criar uma nova senha (vale por 1 hora):',
    link,
    '',
    'Se nao foi voce, ignore este e-mail.'
  ].join('\n');
  const info = await transporter.sendMail({
    from: config.from ? ('Pantale <' + config.from + '>') : config.user,
    to: to,
    subject: 'Redefinição de senha · Pantale',
    text: text,
    html: html
  });
  return { sent: true, info: info };
}

module.exports = { sendOrderEmail, sendResetEmail, isEnabled, buildHtml, buildText, mailTo: config.to };
