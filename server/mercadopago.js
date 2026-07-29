/* ============================================================
   Mercado Pago — Checkout Pro
   ------------------------------------------------------------
   Dois caminhos, e é importante não confundir:

   1. PREFERÊNCIA (createPreference): o site diz ao Mercado Pago
      "vou cobrar isto deste cliente". Devolve o init_point, que é
      a URL para onde o cliente é mandado para pagar.

   2. WEBHOOK: depois, o Mercado Pago avisa o site que o pagamento
      mudou de estado. É a ÚNICA fonte confiável de "foi pago" —
      o cliente voltar para a página de sucesso não prova nada,
      porque essa URL pode ser digitada à mão por qualquer um.

   Os preços vêm SEMPRE do pedido gravado no banco, nunca do que o
   navegador manda. É a mesma regra do CATALOG do server.js: se o
   valor viesse do cliente, dava para comprar por R$ 1.
============================================================ */
'use strict';

const path = require('node:path');
const fs = require('node:fs');

const {
  MercadoPagoConfig,
  Preference,
  Payment,
  WebhookSignatureValidator,
  InvalidWebhookSignatureError
} = require('mercadopago');

const CONFIG_PATH = path.join(__dirname, 'mercadopago-config.json');

/* ------------------------------------------------------------
   Credenciais: variável de ambiente primeiro (é assim que se faz
   em produção), com um JSON local de reserva para o dia a dia.
   Mesmo padrão do mailer.js.
------------------------------------------------------------ */
function loadFile() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    return raw && typeof raw === 'object' ? raw : {};
  } catch (e) {
    return {};
  }
}

function config() {
  const f = loadFile();
  return {
    accessToken: (process.env.MP_ACCESS_TOKEN || f.accessToken || '').trim(),
    webhookSecret: (process.env.MP_WEBHOOK_SECRET || f.webhookSecret || '').trim(),
    publicKey: (process.env.MP_PUBLIC_KEY || f.publicKey || '').trim()
  };
}

function isEnabled() {
  return !!config().accessToken;
}

/* Token de teste começa com TEST-. Serve para avisar no log que a
   loja está aceitando "dinheiro de mentira" — erro clássico é subir
   para produção esquecendo de trocar. */
function isSandbox() {
  return /^TEST-/.test(config().accessToken);
}

function missing() {
  const c = config();
  const falta = [];
  if (!c.accessToken) falta.push('MP_ACCESS_TOKEN (Access Token da sua aplicação)');
  if (!c.webhookSecret) falta.push('MP_WEBHOOK_SECRET (Assinatura secreta do webhook)');
  return falta;
}

function client() {
  return new MercadoPagoConfig({
    accessToken: config().accessToken,
    options: { timeout: 10000 }
  });
}

/* ------------------------------------------------------------
   1) Cria a preferência de pagamento a partir do pedido.

   `pedido` é a linha da tabela orders já desserializada:
     { id, total, items:[{product,size,price,qty}], customer:{}, freight:{} }
------------------------------------------------------------ */
async function createPreference(pedido, opcoes) {
  if (!isEnabled()) {
    return { ok: false, local: true, error: 'Mercado Pago não configurado. Falta: ' + missing().join(', ') };
  }

  const o = opcoes || {};
  const siteUrl = String(o.siteUrl || '').replace(/\/+$/, '');
  const itens = pedido.items || [];
  if (!itens.length) return { ok: false, local: true, error: 'Pedido sem itens.' };

  const c = pedido.customer || {};
  const frete = pedido.freight || {};

  const items = itens.map((it) => ({
    id: String(it.product),
    title: it.product + (it.size ? ' — Tam ' + it.size : ''),
    quantity: Number(it.qty) || 1,
    unit_price: Number(it.price) || 0,
    currency_id: 'BRL'
  }));

  const body = {
    items: items,
    // external_reference é o que aparece no extrato e no painel do
    // Mercado Pago; metadata é o que volta no webhook. Mando o id nos
    // dois porque cada um é lido em um lugar diferente.
    external_reference: String(pedido.id),
    metadata: { orderId: pedido.id },
    statement_descriptor: 'PANTALE',
    payer: {
      name: c.name || '',
      email: c.email || '',
      identification: c.cpf ? { type: 'CPF', number: String(c.cpf) } : undefined,
      address: c.cep ? {
        zip_code: String(c.cep).replace(/\D/g, ''),
        street_name: c.address || '',
        street_number: String(c.number || '')
      } : undefined
    }
  };

  // Frete entra como custo de envio, não como "produto": assim o total
  // no Mercado Pago bate com o total do pedido e o cliente enxerga a
  // separação entre peças e entrega.
  const custoFrete = Number(frete.price) || 0;
  if (custoFrete > 0) {
    body.shipments = { cost: custoFrete, mode: 'not_specified' };
  }

  if (siteUrl) {
    body.back_urls = {
      success: siteUrl + '/?pagamento=sucesso&pedido=' + pedido.id,
      pending: siteUrl + '/?pagamento=pendente&pedido=' + pedido.id,
      failure: siteUrl + '/?pagamento=falhou&pedido=' + pedido.id
    };
    // auto_return só vale com https público; em localhost o Mercado
    // Pago recusa a preferência inteira se isso estiver ligado.
    if (/^https:\/\//.test(siteUrl)) body.auto_return = 'approved';
  }

  if (o.notificationUrl && /^https:\/\//.test(o.notificationUrl)) {
    body.notification_url = o.notificationUrl;
  }

  try {
    const resp = await new Preference(client()).create({ body: body });
    return {
      ok: true,
      preferenceId: resp.id,
      initPoint: resp.init_point,
      sandboxInitPoint: resp.sandbox_init_point,
      // Em conta de teste o init_point normal não abre o checkout de
      // sandbox; é o sandbox_init_point que serve.
      url: isSandbox() ? (resp.sandbox_init_point || resp.init_point) : resp.init_point
    };
  } catch (e) {
    return { ok: false, error: mensagemDeErro(e) };
  }
}

/* ------------------------------------------------------------
   2) Consulta um pagamento. Chamado pelo webhook: a notificação
   diz só "o pagamento X mudou", nunca o valor nem o status — isso
   a gente confere na fonte, para ninguém forjar um "aprovado".
------------------------------------------------------------ */
async function getPayment(paymentId) {
  if (!isEnabled()) return { ok: false, error: 'Mercado Pago não configurado.' };
  try {
    const p = await new Payment(client()).get({ id: String(paymentId) });
    return {
      ok: true,
      id: p.id,
      status: p.status,                 // approved | pending | rejected | ...
      statusDetail: p.status_detail,
      amount: p.transaction_amount,
      orderId: (p.metadata && (p.metadata.order_id || p.metadata.orderId)) ||
               (p.external_reference ? Number(p.external_reference) : null),
      method: p.payment_type_id,
      approvedAt: p.date_approved || ''
    };
  } catch (e) {
    return { ok: false, error: mensagemDeErro(e) };
  }
}

/* ------------------------------------------------------------
   3) Confere se a notificação veio mesmo do Mercado Pago.

   Sem isso, qualquer um que descobrisse a URL do webhook poderia
   mandar um POST dizendo "pedido 42 pago" e receber a mercadoria
   de graça. O SDK recalcula o HMAC-SHA256 e compara em tempo
   constante; toleranceSeconds corta reenvio de notificação antiga
   (replay).
------------------------------------------------------------ */
const JANELA_SEGUNDOS = 300;

/* Idade da assinatura, em segundos.

   Cuidado com a unidade: o Mercado Pago já enviou o `ts` em segundos
   (10 dígitos) e em milissegundos (13). Detectamos pelo tamanho em vez
   de assumir — errar aqui não dá erro visível, só recusa silenciosa de
   toda notificação boa, e aí nenhum pedido é dado como pago. */
function idadeDaAssinatura(xSignature) {
  const bruto = Array.isArray(xSignature) ? xSignature[0] : xSignature;
  const m = /(?:^|,)\s*ts=(\d+)/.exec(String(bruto || ''));
  if (!m) return null;
  const ms = m[1].length >= 12 ? Number(m[1]) : Number(m[1]) * 1000;
  if (!isFinite(ms) || ms <= 0) return null;
  return Math.abs(Date.now() - ms) / 1000;
}

function validateSignature({ xSignature, xRequestId, dataId }) {
  const secret = config().webhookSecret;
  if (!secret) return { ok: false, reason: 'SemSegredoConfigurado' };

  try {
    // Sem `toleranceSeconds` de propósito: a checagem de janela do SDK
    // (v3.2.1) trata o ts do header como milissegundos e compara com
    // Date.now(). Quando o Mercado Pago manda em segundos, a diferença
    // dá ~1,7 bilhão e TODA notificação legítima é recusada. A validação
    // do HMAC em si, que é a parte de segurança, continua sendo do SDK.
    WebhookSignatureValidator.validate({
      xSignature: xSignature,
      xRequestId: xRequestId,
      dataId: dataId,
      secret: secret
    });
  } catch (e) {
    if (e instanceof InvalidWebhookSignatureError) {
      return { ok: false, reason: e.reason, requestId: e.requestId };
    }
    return { ok: false, reason: 'ErroInesperado', detalhe: e && e.message };
  }

  // Assinatura confere. Agora a janela, contra reenvio de notificação
  // antiga capturada por alguém (replay).
  const idade = idadeDaAssinatura(xSignature);
  if (idade != null && idade > JANELA_SEGUNDOS) {
    return { ok: false, reason: 'TimestampOutOfTolerance', idadeSegundos: Math.round(idade) };
  }

  return { ok: true };
}

/* O SDK embrulha o erro da API; puxa a mensagem útil de dentro. */
function mensagemDeErro(e) {
  if (!e) return 'Erro desconhecido no Mercado Pago.';
  const causa = e.cause && (Array.isArray(e.cause) ? e.cause[0] : e.cause);
  const detalhe = causa && (causa.description || causa.message || causa.code);
  return 'Mercado Pago: ' + (detalhe || e.message || String(e));
}

module.exports = {
  isEnabled,
  isSandbox,
  missing,
  publicKey: () => config().publicKey,
  createPreference,
  getPayment,
  validateSignature
};
