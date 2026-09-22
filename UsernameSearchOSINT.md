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

Render Web Service

O projeto já está preparado para o Render. Use pip install -r requirements.txt como Build Command e gunicorn --workers 2 --threads 4 --timeout 120 --bind 0.0.0.0:$PORT username_search_osint:app como Start Command. A rota / retorna texto simples e não depende da pasta templates, enquanto /health responde {"status":"ok"} e pode ser usado como Health Check Path. O arquivo render.yaml contém essa configuração de forma declarativa.

O Render fornece a porta na variável PORT; o Gunicorn deve escutar em 0.0.0.0:$PORT. Isso é obrigatório para o serviço receber tráfego externo. No plano gratuito, o serviço pode ser suspenso por inatividade; o endpoint de saúde ajuda o Render a verificar o serviço, mas não impede essa suspensão. Para execução contínua, é necessário um plano que não suspenda o serviço.

Testes

Bash


python3 -m unittest -v
python3 -m py_compile username_search_osint.py



As plataformas podem alterar HTML, redirecionamentos e políticas anti-automação. Por isso, os resultados são indicadores públicos, não garantias.

Licença

Consulte LICENSE.
