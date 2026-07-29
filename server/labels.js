/* ============================================================
   Etiqueta de envio via Melhor Envio
   ------------------------------------------------------------
   ATENÇÃO — ESTE ARQUIVO GASTA DINHEIRO.

   O passo `checkout` debita o saldo da sua conta no Melhor Envio
   para comprar a etiqueta. Por isso ele NUNCA roda sozinho: só
   acontece quando quem chama pede explicitamente { comprar: true }.
   O padrão é parar antes de pagar, deixando o envio no carrinho do
   Melhor Envio para você conferir e finalizar por lá se preferir.

   Fluxo da API (nesta ordem, é o que o Melhor Envio exige):
     1. cart      → coloca o envio no carrinho          (não cobra)
     2. checkout  → PAGA a etiqueta com o seu saldo     (COBRA)
     3. generate  → gera a etiqueta de fato
     4. print     → devolve o PDF para imprimir

   Precisa de um SEGUNDO token, diferente do usado na cotação: o de
   cotação só tem o escopo shipping-calculate. Gere em
   melhorenvio.com.br → Integrações → Tokens, com os escopos:
     cart-read  cart-write  shipping-checkout
     shipping-generate  shipping-print  shipping-tracking
============================================================ */
'use strict';

const shipping = require('./shipping');

/* Campos do remetente que o Melhor Envio exige. Sem qualquer um
   deles a API recusa o envio, então conferimos antes de chamar. */
const FROM_REQUIRED = [
  'name', 'phone', 'email', 'address', 'number',
  'district', 'city', 'state_abbr', 'postal_code'
];

function cfg() {
  return shipping.loadConfig() || {};
}

function token() {
  const c = cfg();
  return (c.shipmentToken || '').trim();
}

/* O que ainda falta configurar — em português, para o erro dizer
   exatamente o que preencher em vez de um 422 cru da API. */
function missing() {
  const c = cfg();
  const falta = [];

  if (!token()) falta.push('shipmentToken (2º token, com escopos de shipment)');

  const from = c.from || {};
  for (const campo of FROM_REQUIRED) {
    if (!String(from[campo] || '').trim()) falta.push('from.' + campo);
  }

  const doc = shipping.onlyDigits(from.document);
  const cnpj = shipping.onlyDigits(from.company_document);
  if (doc.length !== 11 && cnpj.length !== 14) {
    falta.push('from.document (CPF, 11 dígitos) ou from.company_document (CNPJ, 14)');
  }

  return falta;
}

function isEnabled() {
  return missing().length === 0;
}

/* ------------------------------------------------------------
   Chamada HTTP autenticada ao Melhor Envio
------------------------------------------------------------ */
async function api(caminho, body, method) {
  const c = cfg();
  const url = shipping.apiBase(c.environment === 'sandbox' ? 'sandbox' : 'production') + caminho;

  let resp;
  try {
    resp = await fetch(url, {
      method: method || 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token(),
        'User-Agent': c.userAgent || 'Pantale (contato)'
      },
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (e) {
    return { ok: false, error: 'Não foi possível contatar o Melhor Envio.' };
  }

  let data = null;
  try { data = await resp.json(); } catch (e) {}

  if (!resp.ok) {
    // O Melhor Envio devolve os erros de validação em .errors {campo: [msgs]}
    let msg = (data && (data.message || data.error)) || ('HTTP ' + resp.status);
    if (data && data.errors && typeof data.errors === 'object') {
      const detalhes = Object.keys(data.errors)
        .map((k) => k + ': ' + [].concat(data.errors[k]).join(', '))
        .join(' | ');
      if (detalhes) msg += ' (' + detalhes + ')';
    }
    if (resp.status === 401 || resp.status === 403) {
      msg += ' — confira se o shipmentToken tem os escopos de shipment (cart-write, shipping-checkout, shipping-generate, shipping-print).';
    }
    return { ok: false, error: 'Melhor Envio: ' + msg, status: resp.status };
  }
  return { ok: true, data: data };
}

/* ------------------------------------------------------------
   Monta o destinatário a partir do snapshot do pedido.
   Usamos o snapshot (orders.customer), não o perfil atual: se o
   cliente mudar de endereço depois, a etiqueta de um pedido antigo
   tem de continuar apontando para onde ele comprou.
------------------------------------------------------------ */
function buildTo(customer) {
  const c = customer || {};
  const doc = shipping.onlyDigits(c.cpf);
  return {
    name: c.name || '',
    phone: c.phone || '',
    email: c.email || '',
    document: doc,
    address: c.address || '',
    complement: c.complement || '',
    number: c.number || '',
    district: c.district || '',
    city: c.city || '',
    state_abbr: (c.uf || '').toUpperCase().slice(0, 2),
    country_id: 'BR',
    postal_code: shipping.onlyDigits(c.cep)
  };
}

function buildFrom() {
  const from = cfg().from || {};
  const out = {
    name: from.name || '',
    phone: from.phone || '',
    email: from.email || '',
    address: from.address || '',
    complement: from.complement || '',
    number: from.number || '',
    district: from.district || '',
    city: from.city || '',
    state_abbr: (from.state_abbr || '').toUpperCase().slice(0, 2),
    country_id: 'BR',
    postal_code: shipping.onlyDigits(from.postal_code)
  };
  const cnpj = shipping.onlyDigits(from.company_document);
  if (cnpj.length === 14) {
    out.company_document = cnpj;
    if (from.state_register) out.state_register = String(from.state_register);
  } else {
    out.document = shipping.onlyDigits(from.document);
  }
  return out;
}

function faltaNoDestinatario(to) {
  const falta = [];
  if (!to.name) falta.push('nome');
  if (!to.address) falta.push('endereço');
  if (!to.number) falta.push('número');
  if (!to.city) falta.push('cidade');
  if (to.state_abbr.length !== 2) falta.push('UF');
  if (to.postal_code.length !== 8) falta.push('CEP');
  if (to.document.length !== 11) falta.push('CPF');
  return falta;
}

/* ------------------------------------------------------------
   1) Coloca o envio no carrinho do Melhor Envio. NÃO cobra nada.
------------------------------------------------------------ */
async function addToCart(pedido) {
  // `local: true` marca a falha que é nossa (config ou dados do pedido),
  // não do Melhor Envio — quem chama usa isso para responder 400 em vez
  // de 502 e não culpar a transportadora por um campo em branco aqui.
  const falta = missing();
  if (falta.length) {
    return { ok: false, local: true, error: 'Etiqueta não configurada. Falta em melhorenvio-config.json: ' + falta.join(', ') };
  }

  const to = buildTo(pedido.customer);
  const faltaDest = faltaNoDestinatario(to);
  if (faltaDest.length) {
    return { ok: false, local: true, error: 'Pedido #' + pedido.id + ' sem dados de entrega: ' + faltaDest.join(', ') + '.' };
  }

  const itens = pedido.items || [];

  /* Qual transportadora usar.

     Pedido com frete grátis (acima de freeShippingMin) grava id nulo:
     o cliente não escolheu serviço nenhum, a loja é que paga. Nesse caso
     cotamos de novo agora e pegamos a opção mais barata — respeitando o
     allowedCarriers da config. Sem isso, justamente os pedidos maiores
     ficariam de fora da automação. */
  let service = pedido.freight && pedido.freight.id;
  let servicoRecotado = false;

  if (!service) {
    const totalPecas0 = itens.reduce((s, it) => s + (it.qty || 1), 0);
    const valor0 = itens.reduce((s, it) => s + (Number(it.price) || 0) * (it.qty || 1), 0);
    const cotacao = await shipping.calculate({
      destCep: (pedido.customer || {}).cep,
      itemCount: totalPecas0,
      insuranceValue: valor0
    });
    if (!cotacao.ok || !cotacao.options.length) {
      return {
        ok: false,
        error: 'Pedido #' + pedido.id + ' não tem serviço de frete definido e a ' +
          'recotação falhou (' + (cotacao.error || 'sem opções') + '). ' +
          'Compre a etiqueta pelo painel do Melhor Envio.'
      };
    }
    service = cotacao.options[0].id; // calculate() já devolve ordenado por preço
    servicoRecotado = true;
  }
  const products = itens.map((it) => ({
    name: it.product + (it.size ? ' (' + it.size + ')' : ''),
    quantity: it.qty || 1,
    unitary_value: Number(it.price) || 0
  }));

  const totalPecas = itens.reduce((s, it) => s + (it.qty || 1), 0);
  const pkg = shipping.buildPackage(cfg(), totalPecas);
  const valorSegurado = itens.reduce((s, it) => s + (Number(it.price) || 0) * (it.qty || 1), 0);

  const body = {
    service: service,
    from: buildFrom(),
    to: to,
    products: products,
    volumes: [{
      height: pkg.height,
      width: pkg.width,
      length: pkg.length,
      weight: pkg.weight
    }],
    options: {
      insurance_value: valorSegurado,
      receipt: false,
      own_hand: false,
      reverse: false,
      non_commercial: true,
      platform: 'Pantale',
      tags: [{ tag: 'pedido-' + pedido.id, url: null }]
    }
  };

  const r = await api('/api/v2/me/cart', body);
  if (!r.ok) return r;

  const id = r.data && r.data.id;
  if (!id) return { ok: false, error: 'Melhor Envio não devolveu o id do envio.' };

  return {
    ok: true,
    cartId: id,
    protocol: (r.data && r.data.protocol) || '',
    price: r.data && r.data.price ? Number(r.data.price) : null,
    servicoRecotado: servicoRecotado
  };
}

/* ------------------------------------------------------------
   2) PAGA a etiqueta com o saldo da conta. É o passo que cobra.
------------------------------------------------------------ */
async function comprar(cartId) {
  return api('/api/v2/me/shipment/checkout', { orders: [cartId] });
}

/* 3) Gera a etiqueta (só depois de paga). */
async function gerar(cartId) {
  return api('/api/v2/me/shipment/generate', { orders: [cartId] });
}

/* 4) Link do PDF para imprimir. */
async function imprimir(cartId) {
  const r = await api('/api/v2/me/shipment/print', { mode: 'private', orders: [cartId] });
  if (!r.ok) return r;
  return { ok: true, url: (r.data && r.data.url) || '' };
}

/* Código de rastreio (disponível depois de gerada). */
async function rastreio(cartId) {
  const r = await api('/api/v2/me/shipment/tracking', { orders: [cartId] });
  if (!r.ok) return r;
  const info = r.data && r.data[cartId];
  return { ok: true, tracking: (info && info.tracking) || '', status: (info && info.status) || '' };
}

/* ------------------------------------------------------------
   Fluxo completo.

   comprar: false (padrão) → para no carrinho, sem gastar nada.
   comprar: true           → paga, gera e devolve o PDF.

   O padrão é o seguro de propósito: um erro de digitação numa rota
   não pode virar uma etiqueta comprada sem querer.
------------------------------------------------------------ */
async function emitir(pedido, opcoes) {
  const deveComprar = !!(opcoes && opcoes.comprar);

  const noCarrinho = await addToCart(pedido);
  if (!noCarrinho.ok) return noCarrinho;

  const base = {
    cartId: noCarrinho.cartId,
    protocol: noCarrinho.protocol,
    price: noCarrinho.price,
    servicoRecotado: noCarrinho.servicoRecotado
  };

  if (!deveComprar) {
    return Object.assign({ ok: true, comprada: false }, base, {
      aviso: 'Envio no carrinho do Melhor Envio, ainda NÃO pago. ' +
        'Finalize no painel, ou chame de novo com comprar=true para debitar do saldo.'
    });
  }

  const pago = await comprar(noCarrinho.cartId);
  if (!pago.ok) return Object.assign({ ok: false, error: pago.error }, base);

  const gerada = await gerar(noCarrinho.cartId);
  if (!gerada.ok) return Object.assign({ ok: false, error: gerada.error, comprada: true }, base);

  const pdf = await imprimir(noCarrinho.cartId);
  const trk = await rastreio(noCarrinho.cartId);

  return Object.assign({ ok: true, comprada: true }, base, {
    labelUrl: pdf.ok ? pdf.url : '',
    tracking: trk.ok ? trk.tracking : ''
  });
}

module.exports = {
  isEnabled,
  missing,
  emitir,
  addToCart,
  imprimir,
  rastreio
};
