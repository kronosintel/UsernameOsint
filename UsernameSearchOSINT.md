UsernameSearchOSINT

Aplicação Flask para verificar, de forma defensiva e limitada, se um nome de usuário aparece em páginas públicas de plataformas selecionadas. A ferramenta não confirma identidade, não coleta dados privados e não deve ser usada para assédio, perseguição ou violação dos termos de uso.

Melhorias implementadas

•
Validação de entrada com limite de 64 caracteres e rejeição de caracteres usados em URLs ambíguas.

•
Token CSRF para o formulário e cookies de sessão com configurações mais seguras.

•
debug desativado por padrão e configuração por variáveis de ambiente.

•
Timeout, limite de workers e User-Agent identificável para reduzir impacto nos serviços consultados.

•
Diferenciação entre encontrado, não encontrado, bloqueado, limitado, indisponível e erro.

•
Catálogo ampliado para dezenas de plataformas de código, redes sociais, publicação, portfólio, vídeo, áudio, jogos e interesses.

•
A resposta HTTP 200 não é mais considerada prova automática: páginas comuns de erro são verificadas por marcadores.

•
Escape automático dos dados nos templates, rel="noopener noreferrer" nos links externos e cabeçalhos de segurança.

•
Testes automatizados para validação, status inconclusivo e proteção CSRF.

Instalação e uso

Bash


git clone https://github.com/HackUnderway/UsernameSearchOSINT.git
cd UsernameSearchOSINT
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python3 username_search_osint.py



Abra http://127.0.0.1:5000 no navegador. Para produção, use um servidor WSGI (por exemplo, Gunicorn ) atrás de um proxy reverso; não use o servidor de desenvolvimento do Flask exposto à internet.

Configuração opcional

Variável
Padrão
Função
FLASK_SECRET_KEY
aleatória por processo
Chave persistente da sessão; defina em produção
FLASK_DEBUG
0
Habilita debug somente para desenvolvimento local
REQUEST_TIMEOUT
8
Timeout de cada consulta em segundos
MAX_WORKERS
8
Número máximo de verificações simultâneas, limitado a 20
PORT
5000
Porta local
COOKIE_SECURE
0
Use 1 quando a aplicação estiver servida exclusivamente por HTTPS




Status dos resultados

•
perfil possivelmente encontrado: a página respondeu e não exibiu um marcador conhecido de inexistência.

•
não encontrado (sinal explícito): a plataforma respondeu com 404 ou um marcador de página inexistente.

•
inconclusivo: houve bloqueio, rate limit, timeout, falha de conexão ou outro erro. Esse status não significa que o perfil não exista.

Mesmo um resultado encontrado pode ser um perfil homônimo. Faça validação independente e autorizada antes de qualquer conclusão.

O catálogo inclui, entre outras, GitHub, GitLab, Bitbucket, Codeberg, npm, PyPI, Docker Hub, Hugging Face, Kaggle, Instagram, X, Reddit, TikTok, Pinterest, Mastodon, Bluesky, Threads, Telegram, Medium, Substack, Tumblr, Linktree, Patreon, Dribbble, Behance, Twitch, Steam, Spotify, SoundCloud, Vimeo, YouTube, Goodreads, Letterboxd, Chess.com e Lichess. Plataformas podem mudar URLs, exigir login, aplicar rate limits ou renderizar páginas dinamicamente; nesses casos o resultado aparece como inconclusivo.

Integração Maigret

O comando `/user nome_do_usuario` também tenta consultar o Maigret por meio da função reutilizável `consultar_username`, definida em `maigret_lookup.py`. Por padrão, a consulta usa os sites padrão do Maigret. Para consultar todos os sites disponíveis, defina `MAIGRET_ALL_SITES=1` no ambiente. Se o Maigret não estiver disponível, exceder o timeout ou não retornar dados estruturados, o bot usa automaticamente o catálogo interno anterior.

Novos módulos de consulta

Cada tipo de pesquisa está isolado em um arquivo que pode ser chamado pelo dispatcher em `usernamesearchosint.py`:

| Comando | Módulo | Fonte ou comportamento |
|---|---|---|
| `/email` | `email_tools.py` | Have I Been Pwned, com `HIBP_API_KEY`; retorna apenas metadados de violações, nunca senhas. |
| `/placa` | `plate_tools.py` | Validação de placa e referência oficial; dados veiculares dependem de API autorizada configurada em `PLACA_API_URL`. Não consulta proprietário, CPF ou endereço. |
| `/dominio` | `domain_tools.py` | VirusTotal opcional via `VT_API_KEY`, além de referências de Google Safe Browsing, URLScan e ICANN WHOIS. |
| `/nome` | `name_tools.py` | Links de pesquisa pública no Jusbrasil, Escavador e busca de publicações; não confirma identidade nem faz scraping de área protegida. |
| `/cnpj` | `cnpj_tools.py` | Consulta cadastral pública pela BrasilAPI, com validação dos dígitos do CNPJ. |

As fontes podem impor login, limites de requisição ou alterar suas URLs. Os status `reference_only`, `api_key_required`, `inconclusive` e `rate_limited` não significam que um registro foi encontrado. Use os módulos somente para consultas legítimas, autorizadas e compatíveis com a legislação e os termos dos provedores.

Passo a passo para atualizar no Render

1. No GitHub, abra o repositório e confirme que os arquivos `email_tools.py`, `plate_tools.py`, `domain_tools.py`, `name_tools.py`, `cnpj_tools.py`, `maigret_lookup.py`, `usernamesearchosint.py`, `requirements.txt` e `render.yaml` estão no branch implantado.
2. No painel do Render, abra o serviço `username-search-osint` e acesse **Settings → Environment**.
3. Adicione os segredos somente como variáveis protegidas: `HIBP_API_KEY` para o Have I Been Pwned e `VT_API_KEY` para o VirusTotal. Nunca coloque essas chaves no código, no README ou em commits.
4. Para uma API veicular contratada e autorizada, adicione `PLACA_API_URL` contendo `{placa}` no lugar do parâmetro, por exemplo `https://provedor.example/vehicles/{placa}`, e adicione `PLACA_API_KEY` se o provedor exigir Bearer token. Sem essas variáveis, o módulo de placa fica deliberadamente limitado a referências oficiais e não coleta dados pessoais.
5. Mantenha `MAIGRET_ALL_SITES=0` para a consulta padrão. Use `1` somente se aceitar o maior tempo e volume de requisições da varredura completa.
6. Salve as variáveis e acione **Manual Deploy → Deploy latest commit**. O Render executará `pip install -r requirements.txt` e iniciará o Gunicorn conforme `render.yaml`.
7. Aguarde o status **Live** e teste `/health`. Depois, envie no Telegram consultas de teste com dados que você tem autorização para consultar: `/email`, `/placa`, `/dominio`, `/nome` e `/cnpj`.
8. Consulte os logs do Render se houver `api_key_required`, `rate_limited` ou `inconclusive`. Esses estados são tratados pelo código e não devem ser convertidos em um falso “encontrado”.

Os segredos configurados no Render continuam fora do GitHub. Se uma chave já tiver sido exposta em commits anteriores, revogue-a no provedor e gere uma nova.

Comandos administrativos

O painel `/admin` e todos os comandos abaixo exigem que o ID do usuário do Telegram seja igual ao valor de `ADMIN_ID` configurado no Render:

```text
/admin                         resumo de usuários, relatórios e últimos acessos
/admin_user nome_do_usuario    consulta Maigret/username
/admin_email email@dominio     consulta de exposição do e-mail
/admin_nome Nome Completo      pesquisa pública de processos e publicações
/admin_fone 11999998888        consulta de telefone
/admin_cnpj 11222333000181     consulta cadastral de CNPJ
/admin_placa ABC1D23            referência de consulta de placa
/admin_dominio exemplo.com     reputação e sinais do domínio
```

Também é possível usar o formato unificado, sempre restrito ao `ADMIN_ID`:

```text
/admin user nome_do_usuario
/admin email email@dominio.com
/admin nome Nome Completo
/admin fone 11999998888
/admin cnpj 11222333000181
/admin placa ABC1D23
/admin dominio exemplo.com
```

O comando `/admin` sem argumentos continua abrindo o painel administrativo. Os comandos públicos `/user`, `/email`, `/nome`, `/fone`, `/cnpj`, `/placa` e `/dominio` seguem a regra normal de consulta gratuita ou cobrança.

Os comandos administrativos usam os mesmos módulos dos comandos públicos, mas ficam bloqueados para qualquer usuário que não corresponda ao `ADMIN_ID`. O painel exibe contagens e links dos últimos relatórios; ele não despeja os resultados completos no chat.

Notificações de `/start` e consultas

Cada execução de `/start` envia um aviso operacional para `CANAL_PRINCIPAL_ID`. Cada consulta válida também envia um aviso com usuário, ID do Telegram, módulo, alvo, horário e valor configurado. O valor padrão é **R$ 5,90**, controlado por `CONSULTA_PRECO`; essa notificação registra o preço da consulta, mas não realiza uma cobrança automaticamente. Para cobrar antes de liberar o relatório, é necessário conectar um fluxo de pagamento Mercado Pago separado.

No Render, configure:

```text
CANAL_PRINCIPAL_ID=-100...
GRUPO_LOGS_ID=-100...       # opcional; recebe uma cópia dos logs
CONSULTA_PRECO=5.90
```

O bot precisa ser administrador do canal/grupo e ter permissão para enviar mensagens. O ID deve ser numérico, normalmente começando por `-100`. O valor do exemplo enviado pelo usuário não deve ser colocado no GitHub nem no código.

Como o token do Telegram apareceu na imagem enviada, ele deve ser revogado no BotFather e substituído no Render. Configure também `TELEGRAM_TOKEN` e, se usar webhook, `TELEGRAM_SECRET_TOKEN` somente nas variáveis protegidas do Render.

Fluxo de pagamento Mercado Pago

Para usuários não administrativos, cada consulta cria uma preferência separada de **R$ 5,90**. O bot envia o botão de checkout e cria um registro `pending` no banco. O relatório só é processado quando o webhook `/webhooks/mercadopago` consulta a API do Mercado Pago e confirma o status `approved`. O webhook usa `external_reference` e não confia apenas no conteúdo recebido na notificação. Pagamentos pendentes expiram em 30 minutos por padrão, controlados por `PAGAMENTO_EXPIRACAO_MINUTOS`.

Membros do `CANAL_PRINCIPAL_ID` recebem uma única consulta gratuita, consumida na primeira consulta válida depois que o bot confirma a participação no canal. Consultas seguintes geram cobrança normalmente. Para cobranças, o bot envia um QR code gerado a partir do link de checkout, um botão para abrir o Mercado Pago e o link em texto copiável. Um único lembrete é enviado dez minutos depois se a cobrança continuar pendente; a marcação do lembrete fica no SQLite para não repetir o aviso dentro do mesmo processo.

O `/start` mostra um botão para entrar no canal e outro para verificar a entrada. Depois da confirmação, o usuário recebe a instrução para usar `/user`, `/email`, `/nome`, `/fone`, `/cnpj`, `/placa` ou `/dominio`. O relatório completo é liberado somente para a consulta gratuita válida, para o administrador com bypass ativo ou após o Mercado Pago confirmar `approved`.

Para testar o checkout usando o próprio administrador, defina temporariamente:

```text
ADMIN_BYPASS_PAYMENT=0
```

Com `ADMIN_BYPASS_PAYMENT=1`, o administrador não paga por definição. Usuários comuns nunca recebem esse bypass.

No Render, adicione a credencial de produção somente como variável protegida:

```text
MERCADOPAGO_ACCESS_TOKEN=seu_access_token
PAGAMENTO_EXPIRACAO_MINUTOS=30
```

O endereço público usado como `notification_url` é:

```text
https://usernameosint-1-vcj4.onrender.com/webhooks/mercadopago
```

O webhook do Telegram usa uma rota fixa, sem token na URL:

```text
https://usernameosint-1-vcj4.onrender.com/telegram
```

O valor de `TELEGRAM_SECRET_TOKEN` é enviado pelo Telegram no cabeçalho `X-Telegram-Bot-Api-Secret-Token`.

Depois de salvar as variáveis, faça **Manual Deploy → Deploy latest commit**. Teste primeiro em ambiente de teste do Mercado Pago; só mantenha um token de produção quando estiver confirmado que o valor, o usuário, o módulo e a liberação do relatório estão corretos. Nunca publique o token em issues, commits, screenshots ou mensagens.

Render Web Service

O projeto já está preparado para o Render. Use `pip install -r requirements.txt` como Build Command e `gunicorn --workers 2 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT usernamesearchosint:app` como Start Command. A rota `/` retorna texto simples, `/healthz` responde `{"status":"healthy"}` e pode ser usada como Health Check Path. O arquivo `render.yaml` contém essa configuração de forma declarativa.

O Render fornece a porta na variável PORT; o Gunicorn deve escutar em 0.0.0.0:$PORT. Isso é obrigatório para o serviço receber tráfego externo. No plano gratuito, o serviço pode ser suspenso por inatividade; o endpoint de saúde ajuda o Render a verificar o serviço, mas não impede essa suspensão. Para execução contínua, é necessário um plano que não suspenda o serviço.

Testes

Bash


python3 -m unittest -v
python3 -m py_compile username_search_osint.py



As plataformas podem alterar HTML, redirecionamentos e políticas anti-automação. Por isso, os resultados são indicadores públicos, não garantias.

Licença

Consulte LICENSE.
