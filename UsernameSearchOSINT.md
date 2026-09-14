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

