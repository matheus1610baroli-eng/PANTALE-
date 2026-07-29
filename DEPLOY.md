# Colocar a Pantale no ar

Hoje `pantale.com.br` mostra **outro site** (um React/Vite hospedado na Vercel).
Este guia troca aquele pelo projeto desta pasta, sem o site ficar fora do ar no
meio do caminho.

---

## Antes de começar: por que não a Vercel

O domínio já está lá, então seria natural publicar por lá. Não dá:

| Este projeto precisa | O que a Vercel faz |
|---|---|
| Um processo ligado o tempo todo (o backup diário roda de hora em hora contando o tempo) | Roda funções que nascem e morrem a cada visita — o backup nunca dispararia |
| Guardar `pantale.db` num arquivo | Apaga o disco a cada publicação — os clientes e pedidos iriam junto |
| `.jwt-secret` sempre igual | Recriaria a cada deploy, deslogando todo mundo |

Serviços que servem: **Render**, **Railway**, **Fly.io** ou um **VPS**. O
`render.yaml` na raiz já está pronto para o Render.

> **Custo:** o disco que mantém o banco vivo exige plano pago (no Render,
> ~US$ 7/mês). No plano gratuito o disco some e você perde os pedidos. Não vale
> economizar aqui.

---

## Ordem recomendada

Publicar primeiro, apontar o domínio depois. Assim, se algo der errado, o site
antigo continua no ar e ninguém vê a bagunça.

### 1. Subir o código para o GitHub

O `.gitignore` já protege o que é segredo (`.env`, `pantale.db`, `.jwt-secret`,
`.admin-key`, `mail-config.json`, `melhorenvio-config.json`, `backups/`).
Confira antes de publicar:

```bash
git status          # nada de .env ou .db na lista
git add -A
git commit -m "Loja Pantale: pagamento, frete, backup e SEO"
git push
```

### 2. Criar o serviço

No Render: **New → Blueprint** e aponte para o repositório. Ele lê o
`render.yaml` e monta tudo — inclusive o disco persistente em `/var/data`.

### 3. Preencher os segredos no painel

O `render.yaml` marca estes como `sync: false`, ou seja, o Render pergunta o
valor e guarda criptografado, sem passar pelo git:

| Variável | Onde conseguir |
|---|---|
| `MP_ACCESS_TOKEN` | Painel do Mercado Pago → Credenciais |
| `MP_WEBHOOK_SECRET` | Painel do Mercado Pago → Webhooks (aparece após salvar) |
| `JWT_SECRET` | Invente uma frase longa e aleatória |
| `SMTP_USER` / `SMTP_PASS` / `MAIL_TO` | Sua senha de app do Gmail |

**Comece com as credenciais de TESTE do Mercado Pago** (`TEST-...`). Só troque
pelas de produção depois da primeira compra fingida funcionar.

### 4. Levar os dados atuais

Seus 17 clientes e 6 pedidos estão só na sua máquina. Gere um backup e envie
para o disco do servidor:

```bash
cd server && npm run backup
```

O arquivo sai em `server/backups/`. No Render, use o **Shell** do serviço para
subir esse arquivo como `/var/data/pantale.db`. Faça isso **antes** do primeiro
acesso de cliente, senão o servidor cria um banco vazio e você teria que mesclar
os dois depois.

> Se preferir começar do zero na loja nova, pule este passo — mas guarde o
> backup mesmo assim, é o histórico dos seus primeiros clientes.

### 5. Testar na URL provisória

O Render te dá um endereço tipo `pantale.onrender.com`. Antes de mexer no
domínio, teste tudo por lá:

- [ ] O site abre e a coleção aparece
- [ ] Dá para criar conta e entrar
- [ ] O frete calcula ao digitar o CEP
- [ ] `npm run mp:check` (no Shell do Render) diz que o token é válido
- [ ] Uma compra de teste vira "pago" sozinha

Para o webhook funcionar nessa fase, cadastre no Mercado Pago, no campo
**modo teste**:

```
https://pantale.onrender.com/api/mercadopago/webhook
```

### 6. Só então apontar o domínio

Quando tudo acima passar:

1. No Render, adicione o domínio `pantale.com.br` e `www.pantale.com.br`
2. Ele mostra os registros DNS a configurar
3. Mude o DNS onde o domínio foi registrado, tirando os apontamentos da Vercel
4. Espere propagar (minutos a algumas horas)
5. Atualize `SITE_URL` para `https://www.pantale.com.br`
6. Atualize a URL do webhook no Mercado Pago para o domínio final

**Só depois disso** apague o projeto antigo na Vercel. Enquanto o DNS não
propagar por completo, parte dos visitantes ainda cai lá — apagar antes deixaria
essas pessoas vendo erro.

---

## Depois de no ar

- **Baixe um backup de vez em quando** e guarde fora do servidor:
  `GET /api/admin/backups` (veja `server/README.md`). Backup que só existe no
  mesmo disco do banco não protege contra o disco morrer.
- **Troque para as credenciais de produção** do Mercado Pago quando a compra de
  teste estiver funcionando, e refaça uma compra real de valor baixo para
  confirmar.
- **Confira o log** depois da primeira venda: ele registra
  `[mercadopago] pedido N PAGO`.
