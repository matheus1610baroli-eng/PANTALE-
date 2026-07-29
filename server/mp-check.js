/* ============================================================
   Conferidor da configuração do Mercado Pago
   ------------------------------------------------------------
   Rode:  cd server && npm run mp:check

   Diz se as credenciais estão válidas e se o webhook vai ser
   aceito — SEM imprimir segredo nenhum. O que aparece na tela é
   sempre mascarado (TEST-1234…9012), então dá para rodar de boa
   com outra pessoa olhando, ou colar o resultado num chat.
============================================================ */
'use strict';

const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath) && typeof process.loadEnvFile === 'function') {
    process.loadEnvFile(envPath);
  }
} catch (e) {}

const mp = require('./mercadopago');

const VERDE = '\x1b[32m', VERM = '\x1b[31m', AMAR = '\x1b[33m', CINZA = '\x1b[90m', FIM = '\x1b[0m';
const ok = (t) => console.log(`  ${VERDE}✓${FIM} ${t}`);
const erro = (t) => console.log(`  ${VERM}✗${FIM} ${t}`);
const aviso = (t) => console.log(`  ${AMAR}!${FIM} ${t}`);
const dica = (t) => console.log(`    ${CINZA}${t}${FIM}`);

/* Mostra só as pontas. Nunca o meio, que é o que dá acesso. */
function mascarar(v) {
  if (!v) return '(vazio)';
  if (v.length <= 12) return v.slice(0, 2) + '…';
  return v.slice(0, 9) + '…' + v.slice(-4);
}

async function main() {
  console.log('\n=== Configuração do Mercado Pago ===\n');

  const token = (process.env.MP_ACCESS_TOKEN || '').trim();
  const segredo = (process.env.MP_WEBHOOK_SECRET || '').trim();
  let problemas = 0;

  /* --- 1. Access Token --- */
  if (!token) {
    erro('MP_ACCESS_TOKEN está vazio');
    dica('Cole no server/.env, na linha marcada com >>> COLE AQUI <<<');
    problemas++;
  } else if (!/^(TEST|APP_USR)-/.test(token)) {
    erro(`MP_ACCESS_TOKEN não parece um token (${mascarar(token)})`);
    dica('Deve começar com TEST- ou APP_USR-. Talvez você tenha colado a Public Key ou o Client ID.');
    problemas++;
  } else {
    const modo = mp.isSandbox() ? 'TESTE (não cobra de verdade)' : 'PRODUÇÃO (cobra de verdade)';
    ok(`Access Token presente: ${mascarar(token)} — modo ${modo}`);
    if (!mp.isSandbox()) {
      aviso('Você está em PRODUÇÃO. Se ainda não fez uma compra de teste, considere');
      dica('usar as credenciais TEST- primeiro: erro de configuração aqui vira cliente');
      dica('pagando e ficando sem o pedido.');
    }
  }

  /* --- 2. Segredo do webhook --- */
  if (!segredo) {
    erro('MP_WEBHOOK_SECRET está vazio');
    dica('Sem ele o servidor RECUSA todas as notificações e nenhum pedido vira "pago".');
    dica('Está no painel, em Credenciais > Webhooks, depois de cadastrar a URL.');
    problemas++;
  } else if (segredo.length < 16) {
    aviso(`MP_WEBHOOK_SECRET parece curto demais (${segredo.length} caracteres)`);
    dica('Confira se copiou a assinatura secreta inteira.');
    problemas++;
  } else {
    ok(`Assinatura do webhook presente: ${mascarar(segredo)}`);
  }

  /* --- 3. O segredo realmente valida uma assinatura? --- */
  if (segredo) {
    const ts = Math.floor(Date.now() / 1000);
    const id = '123456', rid = 'teste-local';
    const v1 = crypto.createHmac('sha256', segredo)
      .update(`id:${id};request-id:${rid};ts:${ts};`).digest('hex');

    const boa = mp.validateSignature({ xSignature: `ts=${ts},v1=${v1}`, xRequestId: rid, dataId: id });
    const ruim = mp.validateSignature({ xSignature: `ts=${ts},v1=${'0'.repeat(64)}`, xRequestId: rid, dataId: id });

    if (boa.ok && !ruim.ok) ok('Validação de assinatura funcionando (aceita a boa, recusa a forjada)');
    else { erro('Validação de assinatura com comportamento inesperado'); problemas++; }
  }

  /* --- 4. O token funciona mesmo? (consulta a própria conta) --- */
  if (token && /^(TEST|APP_USR)-/.test(token)) {
    // "Conferindo…" só faz sentido num terminal de verdade. Se a saída
    // estiver sendo copiada ou redirecionada, o código de apagar a linha
    // vira lixo no meio do texto.
    const interativo = process.stdout.isTTY;
    const limpar = () => { if (interativo) process.stdout.write('\r\x1b[K'); };
    if (interativo) process.stdout.write('  … conferindo o token com o Mercado Pago');
    try {
      const r = await fetch('https://api.mercadopago.com/users/me', {
        headers: { Authorization: 'Bearer ' + token }
      });
      const d = await r.json().catch(() => ({}));
      limpar();
      if (r.ok) {
        ok(`Token VÁLIDO — conta: ${d.nickname || d.email || d.id} (${d.site_id || '?'})`);
      } else if (r.status === 401 || r.status === 403) {
        erro('Token RECUSADO pelo Mercado Pago (401/403)');
        dica('Se você regenerou o token no painel, o antigo deixou de valer — cole o novo.');
        problemas++;
      } else {
        aviso(`Resposta inesperada do Mercado Pago: HTTP ${r.status}`);
        problemas++;
      }
    } catch (e) {
      limpar();
      aviso('Não consegui falar com o Mercado Pago (sem internet?): ' + e.message);
    }
  }

  /* --- 5. Endereço do site --- */
  const site = (process.env.SITE_URL || '').trim();
  if (!/^https:\/\//.test(site)) {
    aviso(`SITE_URL = "${site}" — o webhook precisa de um endereço https público`);
    dica('Em localhost o Mercado Pago não consegue avisar o servidor. Use ngrok para testar.');
  } else {
    ok(`SITE_URL: ${site}`);
    dica(`Cadastre este webhook no painel: ${site}/api/mercadopago/webhook`);
  }

  console.log('');
  if (problemas === 0) {
    console.log(`${VERDE}Tudo pronto.${FIM} Reinicie o servidor e faça uma compra de teste.\n`);
  } else {
    console.log(`${VERM}${problemas} item(ns) para resolver${FIM} — veja as dicas acima.\n`);
    process.exitCode = 1;
  }
}

main();
