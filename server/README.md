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
`GET /api/admin/customers?key=<chave>` lista todos os clientes com nº de
pedidos, total gasto, ticket médio, endereço e último pedido. A chave é gerada
sozinha (`.admin-key`) e aparece no log ao iniciar o servidor.

## Arquivos

- `server.js` — servidor e rotas
- `mailer.js` — envio do e-mail de pedido
- `mail-config.json` — credenciais de e-mail (você cria; **não** vai para o git)
- `pantale.db` — banco SQLite (criado sozinho; **não** vai para o git)
- `.jwt-secret` — chave de assinatura dos tokens (criada sozinha; segredo)
- `.admin-key` — chave da rota de gestão (criada sozinha; segredo)

## Colocar no ar (produção)

1. Hospede a pasta `server/` em um serviço Node (Render, Railway, Fly.io, VPS…).
2. Defina a variável de ambiente `JWT_SECRET` com um valor forte e secreto.
3. Como o site é servido pelo próprio Node, o frontend usa a mesma origem
   automaticamente — não precisa mudar nada no `index.html`.
