/* ============================================================
   Frete via Melhor Envio (cotação — scope shipping-calculate)
   ------------------------------------------------------------
   Lê server/melhorenvio-config.json (git-ignored). Faz a chamada
   server-side; o browser nunca vê o token.
   Requer Node >= 18 (fetch global). O projeto já usa Node 22+.
============================================================ */
'use strict';

const path = require('node:path');
const fs = require('node:fs');

const CONFIG_PATH = path.join(__dirname, 'melhorenvio-config.json');

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    return raw && typeof raw === 'object' ? raw : null;
  } catch (e) {
    return null;
  }
}

function apiBase(env) {
  return env === 'sandbox'
    ? 'https://sandbox.melhorenvio.com.br'
    : 'https://www.melhorenvio.com.br';
}

function onlyDigits(v) {
  return String(v == null ? '' : v).replace(/\D/g, '');
}

function isEnabled() {
  const cfg = loadConfig();
  return !!(cfg && cfg.token && onlyDigits(cfg.originCep).length === 8);
}

/* Monta o "pacote" com base na quantidade de itens da sacola.
   Peso = nº de peças × peso unitário; caixa com dimensões fixas. */
function buildPackage(cfg, itemCount) {
  const p = (cfg && cfg.package) || {};
  const perItem = Number(p.weightPerItemKg) || 0.35;
  const n = Math.max(1, Number(itemCount) || 1);
  return {
    height: Number(p.heightCm) || 4,
    width: Number(p.widthCm) || 22,
    length: Number(p.lengthCm) || 30,
    weight: Math.max(0.1, +(perItem * n).toFixed(3))
  };
}

/* Chama o Melhor Envio e devolve opções normalizadas.
   Retorna { ok, options:[{id,name,company,price,deliveryDays}], error } */
async function calculate({ destCep, itemCount, insuranceValue }) {
  const cfg = loadConfig();
  if (!cfg || !cfg.token) return { ok: false, error: 'Frete não configurado (token ausente).' };

  const origin = onlyDigits(cfg.originCep);
  const dest = onlyDigits(destCep);
  if (origin.length !== 8) return { ok: false, error: 'CEP de origem não configurado.' };
  if (dest.length !== 8) return { ok: false, error: 'CEP de destino inválido.' };

  const env = cfg.environment === 'sandbox' ? 'sandbox' : 'production';
  const url = apiBase(env) + '/api/v2/me/shipment/calculate';
  const pkg = buildPackage(cfg, itemCount);

  const body = {
    from: { postal_code: origin },
    to: { postal_code: dest },
    package: pkg,
    options: {
      receipt: false,
      own_hand: false,
      insurance_value: Number(insuranceValue) > 0 ? Number(insuranceValue) : 0
    }
  };

  let resp;
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + cfg.token,
        'User-Agent': cfg.userAgent || 'Pantale (contato)'
      },
      body: JSON.stringify(body)
    });
  } catch (e) {
    return { ok: false, error: 'Não foi possível contatar o Melhor Envio.' };
  }

  let data;
  try { data = await resp.json(); } catch (e) { data = null; }

  if (!resp.ok) {
    const msg = (data && (data.message || data.error)) || ('HTTP ' + resp.status);
    return { ok: false, error: 'Melhor Envio: ' + msg, status: resp.status };
  }
  if (!Array.isArray(data)) {
    return { ok: false, error: 'Resposta inesperada do Melhor Envio.' };
  }

  // Dias de preparo/postagem somados ao prazo de transporte da transportadora
  // (o prazo do Melhor Envio é só o trânsito, a partir da postagem).
  const handling = Math.max(0, Number(cfg.handlingDays) || 0);

  let options = data
    .filter(function (s) { return s && !s.error && s.price != null; })
    .map(function (s) {
      return {
        id: s.id,
        name: s.name,
        company: (s.company && s.company.name) || '',
        price: Math.round(parseFloat(s.price) * 100) / 100,
        deliveryDays: s.delivery_time != null ? Number(s.delivery_time) + handling : null
      };
    })
    .sort(function (a, b) { return a.price - b.price; });

  // Filtra por transportadora, quando configurado (ex.: só Correios,
  // para simplificar a rotina de postagem — um único lugar pra levar tudo).
  const allow = Array.isArray(cfg.allowedCarriers)
    ? cfg.allowedCarriers.map(function (c) { return String(c).toLowerCase(); })
    : null;
  if (allow && allow.length) {
    const filtered = options.filter(function (o) {
      return allow.indexOf(String(o.company).toLowerCase()) !== -1;
    });
    if (filtered.length) options = filtered; // se o filtro zerar tudo, mantém a lista original (não trava a compra)
  }

  if (!options.length) {
    return { ok: false, error: 'Nenhuma opção de frete disponível para este CEP.' };
  }
  return { ok: true, options: options };
}

module.exports = {
  isEnabled,
  calculate,
  // reaproveitados por labels.js (compra de etiqueta), para a leitura da
  // configuração e a escolha de ambiente viverem num lugar só
  loadConfig,
  apiBase,
  onlyDigits,
  buildPackage,
  freeShippingMin: function () {
    const cfg = loadConfig();
    const v = cfg && Number(cfg.freeShippingMin);
    return v > 0 ? v : Infinity;
  }
};
