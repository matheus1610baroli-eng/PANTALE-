# Pantale — Backend de autenticação

Login real para os clientes: Node + Express + SQLite (nativo) + bcrypt + JWT.
Sem serviços externos, sem contas — você é dono do código e dos dados.

## Como rodar

```bash
cd server
npm install      # só na primeira vez
npm start        # inicia em http://localhost:3000
```

Abra **http://localhost:3000** — o próprio servidor já entrega o site (`index.html`)
e a API na mesma origem.

## O que ele faz

### Conta
- **Cadastro** (`POST /api/register`) — nome, e-mail e senha (mín. 6 caracteres).
  A senha é guardada com hash **bcrypt**, nunca em texto puro.
- **Login** (`POST /api/login`) — devolve um **token JWT** válido por 7 dias.
- **Sessão** (`GET /api/me`) — rota protegida que identifica o usuário logado.

### Sacola (carrinho) — todas exigem login (Bearer token)
- **Listar** (`GET /api/cart`) — devolve `{ items, total, count }`.
- **Adicionar** (`POST /api/cart`) — `{ product, size, price }`. Mesmo
  produto+tamanho soma a quantidade.
- **Quantidade** (`PATCH /api/cart/:id`) — `{ qty }`. Qty 0 remove o item.
- **Remover** (`DELETE /api/cart/:id`).
- **Finalizar compra** (`POST /api/checkout`) — cria um **pedido** (tabela
  `orders`) com total e snapshot dos itens, e esvazia a sacola. Devolve
  `{ orderId, total, items, cart }`.

A sacola é gravada no SQLite e fica vinculada à conta: o cliente fecha o
navegador, volta depois e a sacola continua lá. O frontend guarda o token no
navegador (`localStorage`) e reconhece o cliente automaticamente.

### E-mail de pedido (Nodemailer)
A cada compra, o servidor envia um e-mail com **todos os dados do pedido**
(cliente, endereço, itens, total, forma de pagamento) para o dono da loja.

Para ativar:

1. Copie `mail-config.example.json` para **`mail-config.json`**.
2. No Gmail, ative a **verificação em 2 etapas** e gere uma **Senha de app**
   em https://myaccount.google.com/apppasswords
3. Preencha o `mail-config.json`:
   ```json
   {
     "user": "seu-email@gmail.com",
     "pass": "senha-de-app-de-16-digitos",
     "to": "matheus1610.baroli@gmail.com"
   }
   ```
4. Reinicie o servidor. No log deve aparecer `E-mail de pedidos: ATIVO`.

Sem configurar, a loja funciona normal — só não dispara o e-mail (o pedido é
criado do mesmo jeito). Também dá para usar variáveis de ambiente
(`SMTP_USER`, `SMTP_PASS`, `MAIL_TO`) em vez do arquivo.

### Gestão de clientes (visão do dono)
`GET /api/admin/customers` lista todos os clientes com nº de pedidos, total
gasto, ticket médio, endereço e último pedido. A chave é gerada sozinha
(`.admin-key`) e vai no **header** `x-admin-key` — nunca na URL, que vazaria
em log e histórico do navegador:

```bash
curl -H "x-admin-key: $(cat server/.admin-key)" http://localhost:3000/api/admin/customers
```

### Pagamento (Mercado Pago — Checkout Pro)

O cliente clica em "Pagar com cartão", o pedido é criado no banco e ele é
levado ao ambiente do Mercado Pago. Quando o pagamento é aprovado, o Mercado
Pago avisa o servidor por **webhook** e o pedido vira `pago` sozinho.

**Por que o webhook importa:** a URL de retorno (`/?pagamento=sucesso`) não
prova nada — qualquer um digita isso no navegador. Só o webhook, com
assinatura conferida, é aceito como confirmação de pagamento.

#### Configurar

1. Em https://www.mercadopago.com.br/developers/panel → sua aplicação →
   **Credenciais**, copie o **Access Token**.
   - `TEST-...` = modo teste, não cobra de verdade
   - `APP_USR-...` = produção, cobra de verdade
2. Na mesma tela, seção **Webhooks**: cadastre a URL
   `https://www.pantale.com.br/api/mercadopago/webhook`, marque o evento
   **Pagamentos** e copie a **Assinatura secreta**.
3. Copie `.env.example` para `.env` e preencha `MP_ACCESS_TOKEN`,
   `MP_WEBHOOK_SECRET` e `SITE_URL`. Em produção, cadastre essas variáveis no
   painel da hospedagem em vez de subir o arquivo.
4. Reinicie. O log mostra se está ativo e em qual modo.

> ⚠️ Sem `MP_WEBHOOK_SECRET` o servidor **recusa todas as notificações** e
> nenhum pedido é dado como pago. É proposital: sem o segredo não há como
> distinguir o Mercado Pago de alguém mandando "pedido 42 pago" para levar
> mercadoria de graça.

#### Testar antes de valer dinheiro

O webhook precisa de uma URL pública — `localhost` o Mercado Pago não alcança.
Para testar na sua máquina, exponha a porta (ex.: `ngrok http 3000`) e cadastre
a URL do túnel no painel. Use os
[cartões de teste](https://www.mercadopago.com.br/developers/pt/docs/checkout-pro/additional-content/your-integrations/test/cards)
com as credenciais `TEST-`.

#### Rotas

| Rota | Quem chama | O que faz |
|---|---|---|
| `POST /api/mercadopago` | o site, com o cliente logado | gera a cobrança do pedido e devolve a URL de pagamento |
| `POST /api/mercadopago/webhook` | o Mercado Pago | confirma o pagamento e marca o pedido como `pago` |
| `GET /api/orders/:id` | o site, na volta do pagamento | diz se o pedido está pago (o cliente só vê os próprios) |

#### Detalhe que vale saber

O evento de conversão do Google/Meta dispara **na volta do pagamento, e só
depois do servidor confirmar que o pedido está pago** — não no clique de
"pagar". Se disparasse no clique, os anúncios aprenderiam a buscar quem clica
e desiste, e você pagaria mais caro por tráfego pior.

**Consequência:** o Pix "copia e cola" manual (configurado direto no
`index.html`) não tem confirmação automática, então esses pedidos só viram
`pago` quando você marca à mão, e só aí contam como venda. Se quiser Pix com
baixa automática, use o Pix **dentro do Checkout Pro** — ele já vem junto no
mesmo fluxo do cartão, sem configuração extra.

### Etiqueta de envio (Melhor Envio)
A loja já **cota** o frete com o token de `shipping-calculate`. Para **comprar a
etiqueta** pelo site é preciso um **segundo token**, com outros escopos.

1. Em melhorenvio.com.br → **Integrações → Tokens**, gere um novo token com os
   escopos `cart-read`, `cart-write`, `shipping-checkout`, `shipping-generate`,
   `shipping-print`, `shipping-tracking`.
2. Cole em `shipmentToken` no `melhorenvio-config.json` e preencha o bloco
   `from` (o remetente: você). Veja o formato em
   `melhorenvio-config.example.json`.
3. Confira o que ainda falta:
   ```bash
   K=$(cat server/.admin-key)
   curl -H "x-admin-key: $K" http://localhost:3000/api/admin/orders/1/etiqueta
   ```
   O campo `faltaConfigurar` lista exatamente os campos em branco.

Emitir a etiqueta de um pedido:

```bash
K=$(cat server/.admin-key)

# 1) SEM gastar nada: coloca o envio no carrinho do Melhor Envio
curl -X POST -H "x-admin-key: $K" -H "Content-Type: application/json" \
  -d '{}' http://localhost:3000/api/admin/orders/42/etiqueta

# 2) COM cobrança: paga com o seu saldo, gera e devolve o PDF
curl -X POST -H "x-admin-key: $K" -H "Content-Type: application/json" \
  -d '{"comprar":true}' http://localhost:3000/api/admin/orders/42/etiqueta
```

> ⚠️ **`"comprar": true` debita o saldo da sua conta no Melhor Envio.** Sem esse
> campo o envio só fica no carrinho deles, sem cobrança — dá para conferir e
> finalizar pelo painel. O padrão é não comprar justamente para uma chamada
> distraída não virar etiqueta paga. Um pedido que já tem etiqueta comprada é
> recusado com erro, para não pagar duas vezes pelo mesmo envio.

A resposta traz `labelUrl` (PDF para imprimir) e `tracking` (código de rastreio),
e os dois ficam gravados no pedido.

Pedido com **frete grátis** não tem transportadora escolhida pelo cliente — nesse
caso o sistema cota de novo na hora e usa a opção mais barata entre as de
`allowedCarriers`.

### Backup do banco
O servidor tira um backup por dia sozinho, e mais um ao iniciar se o último já
passou de 12h. Os arquivos ficam em `server/backups/` (fora do git).

Retenção: tudo dos últimos **14 dias**, depois **um por semana** por 8 semanas,
depois **um por mês** por 12 meses. Um ano de histórico em ~33 arquivos.

Na mão, a qualquer momento:

```bash
cd server && npm run backup
```

Pela API (mesma chave de admin):

```bash
K=$(cat server/.admin-key)
curl -H "x-admin-key: $K" http://localhost:3000/api/admin/backups          # listar
curl -X POST -H "x-admin-key: $K" http://localhost:3000/api/admin/backups  # criar agora
curl -H "x-admin-key: $K" -O -J \
  http://localhost:3000/api/admin/backups/pantale-2026-01-31_030000.db     # baixar
```

**Baixe um backup de vez em quando e guarde em outro lugar** (seu computador,
Drive, pendrive). Backup que só existe no mesmo disco do banco não protege
contra o disco morrer nem contra o servidor ser apagado.

**Restaurar:** pare o servidor, copie o backup por cima do banco e suba de novo.

```bash
cd server
cp backups/pantale-2026-01-31_030000.db pantale.db
npm start
```

> Por que não copiar o `.db` na mão? Com o servidor no ar, um `cp` pode pegar o
> arquivo no meio de uma gravação e gerar um banco corrompido. O backup usa
> `VACUUM INTO`, que o próprio SQLite garante ser uma cópia íntegra.

## Arquivos

- `server.js` — servidor e rotas
- `mailer.js` — envio do e-mail de pedido
- `mercadopago.js` — cobrança e confirmação de pagamento
- `.env` — credenciais e configuração (você cria; **não** vai para o git)
- `shipping.js` — cotação de frete no Melhor Envio
- `labels.js` — compra da etiqueta de envio (**gasta saldo**; ver aviso acima)
- `backup.js` — backup do banco (agendado e manual)
- `mail-config.json` — credenciais de e-mail (você cria; **não** vai para o git)
- `melhorenvio-config.json` — token do frete (você cria; **não** vai para o git)
- `pantale.db` — banco SQLite (criado sozinho; **não** vai para o git)
- `backups/` — cópias do banco (criadas sozinhas; **não** vão para o git)
- `.jwt-secret` — chave de assinatura dos tokens (criada sozinha; segredo)
- `.admin-key` — chave da rota de gestão (criada sozinha; segredo)

## Colocar no ar (produção)

1. Hospede a pasta `server/` em um serviço Node (Render, Railway, Fly.io, VPS…).
2. Defina a variável de ambiente `JWT_SECRET` com um valor forte e secreto.
3. Como o site é servido pelo próprio Node, o frontend usa a mesma origem
   automaticamente — não precisa mudar nada no `index.html`.
