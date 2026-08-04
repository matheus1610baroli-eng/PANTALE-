# O que falta para a Pantale vender

Estado atual: o site está **no ar** em `https://pantale-site.onrender.com`,
rodando no Render (plano Starter, com disco persistente). O domínio
`pantale.com.br` ainda aponta para o site antigo (React/Vite na Vercel).

Lista em ordem de importância. Faça de cima para baixo — cada item protege
o seguinte.

---

## 🔴 CRÍTICO — sem isso a loja não vende

### 1. Compra de teste (provar o webhook) · 5 min · grátis

É o último elo não testado: o Mercado Pago avisar o servidor que o pagamento
caiu, e o pedido virar "pago" sozinho. Se falhar, o cliente paga e o pedido
fica preso em "aguardando pagamento".

No site, faça um pedido. Na tela do Mercado Pago **NÃO clique em "Entrar com
a minha conta"** — desça até **"Sem conta Mercado Pago" → Cartão**:

| Campo | Valor |
|---|---|
| Número | `4235 6477 2802 5682` |
| Nome do titular | `APRO` |
| Validade | `11/30` |
| CVV | `123` |
| CPF | `123.456.789-09` |

> Logar com a conta real dá erro: o Mercado Pago não deixa vendedor de teste
> negociar com comprador real. Pagando sem conta, o problema não existe.

**Sucesso:** volta ao site e aparece *"Pagamento confirmado! Pedido #N entrou
em produção."*

### 2. Credenciais reais do Mercado Pago · 10 min

O token que está no servidor pertence a uma **conta de teste**
(`TESTUSER...`). Enquanto ele estiver lá, o dinheiro das vendas vai para uma
conta fictícia.

No Render → **Environment**, troque:

- `MP_ACCESS_TOKEN` → Access Token da **sua conta real** (aba de produção)
- `MP_WEBHOOK_SECRET` → assinatura secreta do webhook de **produção**

Para conferir depois, no **Shell** do Render:

```bash
npm run mp:check
```

Ele diz se o token é válido e se a conta é real ou de teste — sem mostrar
nenhuma credencial na tela.

### 3. Importar os 17 clientes e 6 pedidos · 15 min

O servidor subiu com banco vazio. Os dados reais estão só na sua máquina.

**Faça antes do primeiro cliente real.** Depois, juntar dois bancos com
pedidos diferentes vira trabalho manual.

Gere o backup local:

```bash
cd server && npm run backup
```

O arquivo sai em `server/backups/`. Ele precisa ir para `/var/data/pantale.db`
no servidor (é o disco que sobrevive às publicações).

### 4. Apontar o domínio · 20 min + até 2h de propagação

1. No Render: **Settings → Custom Domain** → adicione `pantale.com.br` e
   `www.pantale.com.br`
2. O Render mostra os registros DNS a configurar
3. No registrador do domínio: remova os apontamentos da Vercel, coloque os do
   Render
4. Espere propagar
5. No Render, mude `SITE_URL` para `https://www.pantale.com.br`
6. No Mercado Pago, atualize a URL do webhook para
   `https://www.pantale.com.br/api/mercadopago/webhook`
7. **Só então** apague o projeto antigo na Vercel — antes disso, parte dos
   visitantes ainda cai lá, e apagar deixaria essas pessoas vendo erro

> `SITE_URL` errada é falha silenciosa: o cliente paga, é devolvido para o
> site errado e o pedido não dá baixa, sem nenhum erro aparecer.

### 5. Uma compra real de confirmação · 10 min · ~R$ 7 de taxa

No domínio final, com seu cartão de verdade. Confirma que o dinheiro entra na
sua conta e que o pedido dá baixa sozinho.

No log do Render deve aparecer: `[mercadopago] pedido N PAGO`.

---

## 🟡 IMPORTANTE — dá para vender sem, mas dá trabalho

### 6. Segundo token do Melhor Envio · 20 min

Hoje a loja **cota** o frete, mas não **compra** a etiqueta sozinha.

Falta um token com escopos de shipment (o de cotação não serve) mais os dados
de remetente: nome, telefone, e-mail, endereço completo e CPF ou CNPJ.
Veja `server/melhorenvio-config.example.json`.

**Sem isso:** você gera cada etiqueta à mão no site do Melhor Envio, uns 3
minutos por pedido.

---

## 🟢 QUANDO DER

### 7. Quatro arquivos que faltam · 5 min se você tiver

O site pede estes e não encontra:

```
assets/favicon.png                      ícone da aba do navegador
assets/hero_oncinha.mp4                 vídeo da animação de abertura
assets/img_pelagem_close.jpg            abertura
assets/img_camiseta_wellness_frente.jpg abertura
```

São marcados como `ASSET PENDENTE` no código — espaços reservados esperando os
arquivos. O site funciona sem eles: a animação de abertura passa direto e o
visitante cai no banner, sem nada quebrado à vista.

Se os arquivos não existem, vale remover a animação em vez de deixá-la vazia.

### 8. Google Analytics + Pixel da Meta · 30 min

Estão vazios em `index.html` (`ga4: ''` e `metaPixel: ''`). Todo o
rastreamento já está programado — view_item, add_to_cart, begin_checkout e
purchase — esperando só os dois códigos.

A conversão dispara **depois** do servidor confirmar o pagamento, não no
clique de pagar. Isso faz o Google e a Meta aprenderem com vendas reais em
vez de com quem clica e desiste.

Só faz falta quando você começar a anunciar.

---

## Resumo

| Bloco | Tempo | Quando |
|---|---|---|
| Vender (1 a 5) | ~1h + espera do DNS | agora |
| Parar de gerar etiqueta à mão (6) | 20 min | esta semana |
| Acabamento (7 e 8) | ~40 min | antes de anunciar |

---

## Manutenção depois de no ar

- **Baixe um backup de vez em quando** e guarde fora do servidor:
  `GET /api/admin/backups` (veja `server/README.md`). Backup que mora no mesmo
  disco do banco não protege contra o disco morrer.
- **Confira o log** depois da primeira venda de verdade.
- O backup automático roda sozinho todo dia, com retenção de 14 dias / 8
  semanas / 12 meses.
