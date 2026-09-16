"""
Kronos Intel OSINT Bot v6.0
- Módulo Duplo de Busca: Username OU Nome Completo
- Pesquisa de Processos Judiciais, Diários Oficiais e Transparência
- Exclusivamente Download em TXT (Módulo PDF Removido)
- Dashboard HTML Interativo Redesenhado
- URL Base: https://usernameosint-1-vcj4.onrender.com
"""
from __future__ import annotations

import base64
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Lock, Thread
from typing import Any

import requests
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Update
import mercadopago
from flask import Flask, jsonify, request, render_template_string, Response, send_file

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=16 * 1024,
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DEFAULT_TIMEOUT = 3.0
PORT = int(os.getenv("PORT", "5000"))
PRECO_VIP = 3.90
DB_FILE = "kronos_osint.db"
db_lock = Lock()

# --- BANCO DE DADOS SQLITE ---
def init_db():
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                payment_id TEXT PRIMARY KEY,
                user_id INTEGER,
                target_username TEXT,
                amount REAL,
                status TEXT,
                reminded INTEGER DEFAULT 0,
                token TEXT,
                results_json TEXT,
                query_type TEXT DEFAULT 'username',
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                key TEXT PRIMARY KEY,
                value INTEGER DEFAULT 0
            )
        """)
        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES ('total_searches', 0)")
        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES ('total_reports', 0)")
        conn.commit()
        conn.close()

init_db()

def db_execute(query: str, params: tuple = (), fetchone=False, fetchall=False, commit=False):
    with db_lock:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(query, params)
        res = None
        if fetchone:
            res = cursor.fetchone()
        elif fetchall:
            res = cursor.fetchall()
        if commit:
            conn.commit()
        conn.close()
        return res

# --- CONFIGURAÇÃO BOT & MERCADO PAGO ---
ADMIN_ID = int(os.getenv("ADMIN_ID", "5041637922"))
SUPORTE_USERNAME = os.getenv("SUPORTE_USERNAME", "kronos_intel")
BOT_USERNAME = os.getenv("BOT_USERNAME", "KronosIntelBot")
WEB_BASE_URL = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com")

MERCADOPAGO_TOKEN = os.getenv("MERCADOPAGO_TOKEN")
sdk = mercadopago.SDK(MERCADOPAGO_TOKEN) if MERCADOPAGO_TOKEN else None

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8625009528:AAHfx5Te-ngeeNMnlB_8hbP40wrpx6_1wIA")
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=False) if TELEGRAM_TOKEN else None

PLATFORM_URLS = {
    "GitHub": "https://api.github.com/users/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Bitbucket": "https://bitbucket.org/{username}/",
    "Codeberg": "https://codeberg.org/{username}",
    "PyPI": "https://pypi.org/user/{username}/",
    "Docker Hub": "https://hub.docker.com/u/{username}",
    "Hugging Face": "https://huggingface.co/{username}",
    "Kaggle": "https://www.kaggle.com/{username}",
    "Replit": "https://replit.com/@{username}",
    "CodePen": "https://codepen.io/{username}",
    "StackOverflow": "https://stackoverflow.com/users/{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "X (Twitter)": "https://x.com/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}/",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Telegram": "https://t.me/{username}",
    "Snapchat": "https://www.snapchat.com/add/{username}",
    "Tumblr": "https://{username}.tumblr.com",
    "Threads": "https://www.threads.net/@{username}",
    "Mastodon": "https://mastodon.social/@{username}",
    "Bluesky": "https://bsky.app/profile/{username}.bsky.social",
    "Medium": "https://medium.com/@{username}",
    "Substack": "https://{username}.substack.com",
    "DeviantArt": "https://www.deviantart.com/{username}",
    "Behance": "https://www.behance.net/{username}",
    "Dribbble": "https://dribbble.com/{username}",
    "Vimeo": "https://vimeo.com/{username}",
    "Patreon": "https://www.patreon.com/{username}",
    "Flickr": "https://www.flickr.com/people/{username}/",
    "WordPress": "https://{username}.wordpress.com",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "SoundCloud": "https://soundcloud.com/{username}",
    "Spotify": "https://open.spotify.com/user/{username}",
    "Chess.com": "https://www.chess.com/member/{username}",
    "Roblox": "https://www.roblox.com/user.aspx?username={username}",
    "Lichess": "https://lichess.org/@/{username}",
    "Kick": "https://kick.com/{username}",
    "Keybase": "https://keybase.io/{username}",
    "About.me": "https://about.me/{username}",
    "Linktree": "https://linktr.ee/{username}",
    "Disqus": "https://disqus.com/by/{username}/",
    "Gravatar": "https://en.gravatar.com/{username}",
}

NOT_FOUND_MARKERS = {
    "gitlab": ("the page you're looking for doesn't exist",),
    "bitbucket": ("this page doesn't exist",),
    "codeberg": ("page not found",),
    "pypi": ("404 not found",),
    "keybase": ("user not found",),
    "instagram": ("page isn't available", "sorry, this page isn't available"),
    "reddit": ("this page is empty", "page not found"),
    "tiktok": ("couldn't find this account",),
    "telegram": ("if you have telegram",),
    "substack": ("page not found",),
    "youtube": ("this page isn't available",),
    "medium": ("404", "out of bounds"),
    "vimeo": ("404", "not found"),
    "behance": ("oops! we can't find that page",),
    "dribbble": ("404", "page not found"),
    "replit": ("404", "not found"),
}

def registrar_acesso(user_id: int):
    now_str = datetime.now().isoformat()
    db_execute(
        "INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING",
        (user_id, now_str), commit=True
    )
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_searches'", commit=True)

def registrar_relatorio():
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_reports'", commit=True)

def e_nome_completo(termo: str) -> bool:
    partes = termo.strip().split()
    return len(partes) >= 2 and all(len(p) >= 2 for p in partes)

# --- MOTOR OSINT PARALELO ---
class FastOSINTChecker:
    def __init__(self, username: str, timeout: float = DEFAULT_TIMEOUT):
        self.username = username
        self.timeout = timeout
        self.results: dict[str, dict[str, Any]] = {}
        self._lock = Lock()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    def check_site(self, platform: str, url: str) -> None:
        try:
            resp = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            status = resp.status_code
            if status == 404:
                res = {"exists": False}
            elif 200 <= status < 400:
                text = resp.text[:50000].lower()
                markers = NOT_FOUND_MARKERS.get(platform.lower(), ())
                if any(m in text for m in markers):
                    res = {"exists": False}
                else:
                    res = {"exists": True, "url": url}
            else:
                res = {"exists": None}
        except Exception:
            res = {"exists": None}

        with self._lock:
            self.results[platform] = res

    def run(self) -> dict[str, dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [
                executor.submit(self.check_site, p, u.format(username=self.username))
                for p, u in PLATFORM_URLS.items()
            ]
            for f in futures:
                try:
                    f.result(timeout=4.0)
                except Exception:
                    pass
        return self.results

def executar_varredura_osint(target: str) -> dict[str, dict[str, Any]]:
    if e_nome_completo(target):
        # Mapeamento direcionado para NOME COMPLETO
        encoded_name = urllib.parse.quote(f'"{target}"')
        return {
            "Jusbrasil (Processos)": {"exists": True, "url": f"https://www.jusbrasil.com.br/busca?q={encoded_name}"},
            "Escavador (Diários)": {"exists": True, "url": f"https://www.escavador.com/busca?q={encoded_name}"},
            "Jusfy / Diários": {"exists": True, "url": f"https://www.google.com/search?q=site:jusbrasil.com.br+OR+site:escavador.com+{encoded_name}"},
            "Portal Transparência": {"exists": True, "url": f"https://www.portaltransparencia.gov.br/busca?termo={urllib.parse.quote(target)}"},
            "Diário Oficial União": {"exists": True, "url": f"https://www.google.com/search?q=site:in.gov.br+{encoded_name}"},
            "Google Acadêmico": {"exists": True, "url": f"https://scholar.google.com.br/scholar?q={encoded_name}"},
            "Certidões e Registros": {"exists": True, "url": f"https://www.google.com/search?q=%22certidao%22+{encoded_name}"},
            "Notícias / Citações": {"exists": True, "url": f"https://www.google.com/search?q={encoded_name}&tbm=nws"},
        }
    else:
        return FastOSINTChecker(target).run()

# --- GERADOR DE RELATÓRIO TXT ---
def construir_relatorio_osint(target: str, resultados: dict[str, dict[str, Any]]) -> io.BytesIO:
    is_name = e_nome_completo(target)
    encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    hibp_link = f"https://haveibeenpwned.com/account/{target}"
    intelx_link = f"https://intelx.io/?s={urllib.parse.quote(target)}"
    dehashed_link = f"https://dehashed.com/search?query={urllib.parse.quote(target)}"
    google_exact = f"https://www.google.com/search?q=%22{urllib.parse.quote(target)}%22"

    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT
===================================================================
ALVO ANALISADO: {target}
TIPO DE CONSULTA: {"NOME COMPLETO (JUDICIAL / PROCESSO)" if is_name else "USERNAME / ALIAS"}
DATA DA CONSULTA: {data_atual}
SISTEMA: Kronos Engine v6.0
===================================================================

1. MAPEAMENTO E FONTES LOCALIZADAS
-------------------------------------------------------------------
"""
    if encontrados:
        for p in encontrados:
            url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=target))
            corpo += f"[+] {p.ljust(25)} : {url}\n"
    else:
        corpo += "[-] Nenhuma ocorrência direta indexada.\n"

    corpo += f"""
2. VARREDURA DE VAZAMENTOS, DEEP WEB E DORKS
-------------------------------------------------------------------
[+] Have I Been Pwned      : {hibp_link}
[+] Intelligence X (IntelX): {intelx_link}
[+] DeHashed Database      : {dehashed_link}
[+] Google Exact Match     : {google_exact}

===================================================================
Documento confidencial gerado por Kronos Intel OSINT Service.
===================================================================
"""
    buf = io.BytesIO(corpo.encode('utf-8'))
    buf.name = f"Relatorio_OSINT_{target.replace(' ', '_')}.txt"
    return buf

def gerar_pix_mercadopago(user_id: int, target: str, valor: float = PRECO_VIP) -> tuple[str | None, bytes | None, str | None]:
    if not sdk:
        return None, None, None
    token_relatorio = secrets.token_urlsafe(16)
    qtype = "fullname" if e_nome_completo(target) else "username"
    payment_data = {
        "transaction_amount": float(valor),
        "description": f"Relatorio OSINT - {target}",
        "payment_method_id": "pix",
        "payer": {"email": f"user_{user_id}@telegram.com", "first_name": "Usuario", "last_name": str(user_id)},
        "metadata": {"telegram_user_id": user_id, "target_username": target, "token": token_relatorio}
    }
    try:
        res = sdk.payment().create(payment_data).get("response", {})
        tx = res.get("point_of_interaction", {}).get("transaction_data", {})
        qr_code = tx.get("qr_code")
        qr_base64 = tx.get("qr_code_base64")
        img_bytes = base64.b64decode(qr_base64) if qr_base64 else None
        
        pid = str(res.get("id"))
        db_execute("INSERT INTO payments (payment_id, user_id, target_username, amount, status, reminded, token, query_type, created_at) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
                   (pid, user_id, target, valor, token_relatorio, qtype, datetime.now().isoformat()), commit=True)
        return qr_code, img_bytes, token_relatorio
    except Exception as e:
        logger.error("Erro ao gerar Pix: %s", str(e))
        return None, None, None

def enviar_relatorio_espelho_admin(target: str, documento: io.BytesIO, user_id: int, tipo_consulta: str):
    if bot and ADMIN_ID and user_id != ADMIN_ID:
        try:
            documento.seek(0)
            captura_legenda = f"👁‍🗨 [ESPELHO OSINT]\n• Tipo: {tipo_consulta}\n• Usuário Solicitante: {user_id}\n• Alvo: {target}"
            bot.send_document(chat_id=ADMIN_ID, document=documento, caption=captura_legenda)
            documento.seek(0)
        except Exception as e:
            logger.error("Erro ao enviar cópia ao admin: %s", str(e))

# --- REMARKETING THREAD ---
def worker_remarketing_pix():
    while True:
        try:
            time.sleep(60)
            pendentes = db_execute(
                "SELECT payment_id, user_id, target_username, created_at FROM payments WHERE status = 'pending' AND reminded = 0",
                fetchall=True
            )
            if not pendentes:
                continue

            now = datetime.now()
            for p in pendentes:
                pid, uid, target, created_str = p[0], p[1], p[2], p[3]
                try:
                    created_time = datetime.fromisoformat(created_str)
                    if (now - created_time).total_seconds() / 60 >= 10:
                        db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                        if bot:
                            msg_lembrete = (
                                f"⏳ SUA CHAVE PIX PARA {target} ESTÁ QUASE EXPIRANDO!\n\n"
                                f"Aproveite a oferta de R$ 19,90 por apenas R$ 3,90 para liberar a investigação completa.\n"
                                f"Clique no botão abaixo para concluir:"
                            )
                            markup = InlineKeyboardMarkup(row_width=1)
                            markup.add(InlineKeyboardButton(f"⚡ 🔓 DESBLOQUEAR RELATÓRIO DE {target} (R$ 3,90) 🔓 ⚡", callback_data=f"buy_{target}"))
                            markup.add(InlineKeyboardButton("💬 Suporte", url=f"https://t.me/{SUPORTE_USERNAME}"))
                            bot.send_message(uid, msg_lembrete)
                except Exception as ex:
                    logger.error("Erro no remarketing: %s", str(ex))

        except Exception as e:
            logger.error("Erro no worker de remarketing: %s", str(e))

Thread(target=worker_remarketing_pix, daemon=True).start()

# --- TEMPLATE HTML DASHBOARD ---
HTML_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kronos Intel — Painel Executivo OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {
            --bg-color: #0b0f19;
            --card-bg: rgba(22, 27, 34, 0.85);
            --border-color: #30363d;
            --accent-blue: #00f0ff;
            --accent-green: #00ff87;
            --text-main: #e6edf3;
        }

        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 50% 0%, rgba(0, 240, 255, 0.08), transparent 70%);
            color: var(--text-main);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
        }

        .navbar {
            background-color: rgba(13, 17, 23, 0.9);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-color);
        }

        .navbar-brand {
            font-family: monospace;
            font-weight: 700;
            color: var(--accent-blue) !important;
        }

        .card-custom {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            margin-bottom: 24px;
        }

        .card-header-custom {
            background: rgba(255, 255, 255, 0.03);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 20px;
            font-family: monospace;
            font-weight: 600;
        }

        .btn-platform {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 12px 16px;
            border-radius: 12px;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.2s ease;
        }

        .btn-platform:hover {
            background: rgba(0, 255, 135, 0.1);
            border-color: var(--accent-green);
            color: var(--accent-green);
        }

        .btn-dork {
            background: rgba(0, 240, 255, 0.05);
            border: 1px solid rgba(0, 240, 255, 0.2);
            color: var(--accent-blue);
            padding: 10px 16px;
            border-radius: 10px;
            text-decoration: none;
            display: flex;
            align-items: center;
            transition: all 0.2s ease;
        }

        .btn-dork:hover {
            background: rgba(0, 240, 255, 0.2);
            color: #fff;
        }

        .code-tag {
            font-family: monospace;
            color: var(--accent-blue);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark sticky-top mb-4">
        <div class="container">
            <span class="navbar-brand h1 mb-0"><i class="bi bi-shield-shaded me-2"></i>KRONOS_INTEL // OSINT</span>
            <a href="/download/txt/{{ token }}" class="btn btn-outline-info btn-sm rounded-3"><i class="bi bi-file-earmark-text me-1"></i> BAIXAR RELATÓRIO (.TXT)</a>
        </div>
    </nav>

    <div class="container pb-5">
        <div class="card-custom">
            <div class="card-body p-4">
                <span class="text-uppercase text-muted small code-tag">[ ALVO SELECIONADO ]</span>
                <h2 class="text-white mb-1 font-monospace"><i class="bi bi-terminal me-2"></i>{{ target }}</h2>
                <p class="text-muted mb-0 small"><i class="bi bi-clock me-1"></i> Auditado em: {{ data_atual }} | Módulo: {{ query_type }}</p>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-7">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase">
                        <i class="bi bi-diagram-3 me-2 text-primary"></i>Fontes e Mapeamento
                    </div>
                    <div class="card-body p-4">
                        {% if encontrados %}
                        <div class="row g-3">
                            {% for p in encontrados %}
                            <div class="col-md-6">
                                <a href="{{ p.url }}" target="_blank" class="btn-platform">
                                    <span><i class="bi bi-link-45deg me-2 code-tag"></i>{{ p.nome }}</span>
                                    <i class="bi bi-box-arrow-up-right small"></i>
                                </a>
                            </div>
                            {% endfor %}
                        </div>
                        {% else %}
                        <p class="text-muted mb-0">Nenhuma ocorrência direta mapeada para este termo.</p>
                        {% endif %}
                    </div>
                </div>
            </div>

            <div class="col-lg-5">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase text-warning">
                        <i class="bi bi-incognito me-2"></i>Vazamentos & Deep Search
                    </div>
                    <div class="card-body p-4 d-grid gap-2">
                        <a href="https://haveibeenpwned.com/account/{{ target }}" target="_blank" class="btn-dork"><i class="bi bi-search me-2"></i>Have I Been Pwned</a>
                        <a href="https://intelx.io/?s={{ target }}" target="_blank" class="btn-dork"><i class="bi bi-cpu me-2"></i>Intelligence X (IntelX)</a>
                        <a href="https://dehashed.com/search?query={{ target }}" target="_blank" class="btn-dork"><i class="bi bi-database-check me-2"></i>DeHashed Base</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# --- ROTAS FLASK PARA WEB DASHBOARD E DOWNLOAD TXT ---
@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, query_type, created_at FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou acesso pendente.", 404

    target, results_json_str, query_type, created_at = p[0], p[1], p[2], p[3]
    results_json = json.loads(results_json_str)
    
    encontrados = []
    for plat in results_json:
        if results_json[plat].get("exists") is True:
            url = results_json[plat].get("url", PLATFORM_URLS.get(plat, "").format(username=target))
            encontrados.append({"nome": plat, "url": url})

    data_formatada = datetime.fromisoformat(created_at).strftime("%d/%m/%Y %H:%M:%S")

    return render_template_string(
        HTML_DASHBOARD_TEMPLATE,
        target=target,
        token=token,
        encontrados=encontrados,
        query_type=query_type.upper(),
        data_atual=data_formatada
    )

@app.route("/download/txt/<token>")
def download_txt(token):
    p = db_execute("SELECT target_username, results_json FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

    target, results_json_str = p[0], p[1]
    results_json = json.loads(results_json_str)
    
    txt_buf = construir_relatorio_osint(target, results_json)
    txt_buf.seek(0)

    return send_file(
        txt_buf,
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"Relatorio_OSINT_{target.replace(' ', '_')}.txt"
    )

# --- HANDLERS TELEGRAM ---
if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        bot.reply_to(
            message,
            f"👋 Kronos Intel — OSINT Bot v6.0\n\n"
            f"Envie um **username** (ex: `alvo123`) para buscar redes sociais OU um **Nome Completo** (ex: `João da Silva`) para mapear processos judiciais, Jusbrasil e diários oficiais.\n\n"
            f"🛠 Suporte: @{SUPORTE_USERNAME}",
            parse_mode="Markdown"
        )

    @bot.message_handler(commands=['stats'])
    def handle_stats_command(message):
        if message.from_user.id != ADMIN_ID:
            return

        total_users = db_execute("SELECT COUNT(*) FROM users", fetchone=True)[0]
        searches = db_execute("SELECT value FROM metrics WHERE key = 'total_searches'", fetchone=True)[0]
        reports = db_execute("SELECT value FROM metrics WHERE key = 'total_reports'", fetchone=True)[0]
        vendas = db_execute("SELECT COUNT(*), SUM(amount) FROM payments WHERE status = 'approved'", fetchone=True)
        
        qtd_vendas = vendas[0] if vendas else 0
        faturamento = vendas[1] if vendas and vendas[1] else 0.0

        painel = (
            f"📊 PAINEL DE CONTROLE KRONOS INTEL\n"
            f"───────────────────────────────\n"
            f"👤 Usuários Registrados: {total_users}\n"
            f"🔎 Total de Pesquisas: {searches}\n"
            f"📄 Relatórios Gerados: {reports}\n"
            f"💰 Vendas Aprovadas: {qtd_vendas} (R$ {faturamento:.2f})"
        )
        bot.send_message(message.chat.id, painel)

    @bot.message_handler(func=lambda message: True)
    def handle_search(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)
        
        texto = message.text.strip()
        eh_admin_mode = False

        if "admin" in texto.lower() and user_id == ADMIN_ID:
            eh_admin_mode = True
            target = texto.lower().replace("admin", "").replace("@", "").strip()
        else:
            target = texto.replace("@", "").strip()

        if len(target) < 2:
            bot.reply_to(message, "⚠️ Termo de busca muito curto.")
            return

        is_fullname = e_nome_completo(target)

        # FLUXO ADMIN
        if eh_admin_mode:
            msg_status = bot.reply_to(message, f"👑 [ADMIN VIP] Processando {target}...")
            resultados = executar_varredura_osint(target)
            results_json = json.dumps(resultados)
            token_relatorio = secrets.token_urlsafe(16)
            pid_admin = f"admin_{int(time.time())}"

            db_execute(
                "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, query_type, results_json, created_at) VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?)",
                (pid_admin, user_id, target, token_relatorio, "fullname" if is_fullname else "username", results_json, datetime.now().isoformat()),
                commit=True
            )
            registrar_relatorio()

            try:
                bot.edit_message_text(f"✅ Varredura concluída para {target}!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

            link_web = f"{WEB_BASE_URL.rstrip('/')}/relatorio/{token_relatorio}"
            markup = InlineKeyboardMarkup(row_width=1)
            markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web (ADMIN)", url=link_web))

            bot.send_message(
                message.chat.id,
                f"👑 [MODO ADMIN] Painel Interativo Web gerado para {target}:",
                reply_markup=markup
            )
            return

        # FLUXO PRINCIPAL
        tipo_msg = "Mapeando processos e diários oficiais" if is_fullname else "Mapeando redes sociais e perfis"
        msg_status = bot.reply_to(message, f"🔎 {tipo_msg} para '{target}'...")
        resultados = executar_varredura_osint(target)
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]

        try:
            bot.edit_message_text(f"✅ Varredura concluída para '{target}'!", chat_id=message.chat.id, message_id=msg_status.message_id)
        except Exception:
            pass

        if encontrados:
            if is_fullname:
                texto_resultado = (
                    f"⚖️ REGISTROS JUDICIAIS E OFICIAIS IDENTIFICADOS PARA:\n"
                    f"👉 **{target}**\n"
                    f"───────────────────────────────\n\n"
                    f"• Jusbrasil / Diários de Justiça\n"
                    f"• Escavador / Processos Públicos\n"
                    f"• Portal da Transparência / Sanções\n"
                    f"• Diário Oficial da União (DOU)\n\n"
                    f"Deseja liberar o Painel Interativo Web com os links diretos de consulta para cada tribunal e baixar o relatório completo?\n\n"
                    f"🔥 OFERTA LIMITADA: De R$ 19,90 por apenas R$ 3,90 no Pix!"
                )
            else:
                lista_plataformas = "\n".join([f"• {p}" for p in encontrados])
                texto_resultado = (
                    f"🎯 PLATAFORMAS ENCONTRADAS PARA @{target}\n"
                    f"───────────────────────────────\n\n"
                    f"{lista_plataformas}\n\n"
                    f"Deseja liberar o Painel Interativo Web com os links clicáveis e o relatório TXT?\n\n"
                    f"🔥 OFERTA LIMITADA: De R$ 19,90 por apenas R$ 3,90 no Pix!"
                )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("⚡ 🔓 LIBERAR RELATÓRIO COMPLETO (R$ 3,90) 🔓 ⚡", callback_data=f"buy_{target}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data="final_cancel")
            btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
            markup.add(btn_sim, btn_nao, btn_suporte)

            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup, parse_mode="Markdown")
        else:
            bot.send_message(message.chat.id, f"ℹ️ Varredura concluída: Nenhuma ocorrência direta localizada para '{target}'.")

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("buy_"):
            target = call.data.split("buy_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, "Gerando Chave Pix de R$ 3,90...")
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target, valor=PRECO_VIP)

            if qr_pix:
                texto_oferta = (
                    f"🔒 PACOTE KRONOS INTEL VIP — {target}\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Interativo Web (HTML) com links diretos\n"
                    f"2. Opção de Download do Relatório Executivo (.TXT)\n"
                    f"3. Dorks Judiciais e Bases de Processos\n"
                    f"4. Checagem em Bases de Vazamentos\n\n"
                    f"💰 Valor: De R$ 19,90 por R$ 3,90 no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O painel interativo será liberado automaticamente assim que o pagamento for confirmado."
                )

                markup = InlineKeyboardMarkup(row_width=1)
                btn_copiar = InlineKeyboardButton("📋 Copiar Chave Pix (Texto)", callback_data=f"getkey_{user_id}")
                btn_suporte = InlineKeyboardButton("💬 Precisa de Ajuda?", url=f"https://t.me/{SUPORTE_USERNAME}")
                markup.add(btn_copiar, btn_suporte)

                if qr_img_bytes:
                    bot.send_photo(call.message.chat.id, photo=qr_img_bytes, caption=texto_oferta, reply_markup=markup)
                else:
                    bot.send_message(call.message.chat.id, text=texto_oferta, reply_markup=markup)
            else:
                bot.send_message(call.message.chat.id, "⚠️ Erro ao gerar chave Pix. Tente novamente em instantes.")

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta finalizada.")
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text="👍 Entendido! Envie outro nome ou username quando quiser realizar uma nova pesquisa.")

        elif call.data.startswith("getkey_"):
            bot.answer_callback_query(call.id, "Enviando chave...")
            msg_texto = call.message.caption or call.message.text
            lines = msg_texto.split("\n\n") if msg_texto else []
            pix_key = None
            for l in lines:
                if len(l) > 50 and not l.startswith("🔒") and not l.startswith("⚡"):
                    pix_key = l.strip()
                    break
            if pix_key:
                bot.send_message(call.message.chat.id, text=f"`{pix_key}`", parse_mode="Markdown")

# --- ROTA RECEPTORA DO TELEGRAM WEBHOOK ---
@app.route(f"/telegram/{TELEGRAM_TOKEN}", methods=["POST"])
def telegram_webhook():
    if bot:
        data = request.get_json(force=True, silent=True)
        if data:
            update = Update.de_json(data)
            bot.process_new_updates([update])
            return jsonify({"status": "ok"}), 200
    return jsonify({"error": "unauthorized"}), 403

# --- WEBHOOK MERCADO PAGO ---
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    try:
        if request.method == "GET" or request.args.get("id") == "123456":
            return jsonify({"status": "ok"}), 200

        payment_id = request.args.get("id")
        try:
            data = request.get_json(force=False, silent=True) or {}
            if isinstance(data, dict):
                if data.get("type") == "payment":
                    payment_id = data.get("data", {}).get("id")
                elif "id" in data and not payment_id:
                    payment_id = data.get("id")
        except Exception:
            pass

        if str(payment_id) == "123456" or not payment_id:
            return jsonify({"status": "ok"}), 200

        pid_str = str(payment_id)
        
        p_check = db_execute("SELECT status, token FROM payments WHERE payment_id = ?", (pid_str,), fetchone=True)
        if p_check and p_check[0] == "approved":
            return jsonify({"status": "ok"}), 200

        if payment_id and sdk:
            try:
                payment_info = sdk.payment().get(str(payment_id)).get("response", {})
                if payment_info.get("status") == "approved":
                    metadata = payment_info.get("metadata", {})
                    telegram_id = metadata.get("telegram_user_id")
                    target = metadata.get("target_username", "alvo")
                    token_relatorio = metadata.get("token") or secrets.token_urlsafe(16)

                    resultados = executar_varredura_osint(target)
                    results_json = json.dumps(resultados)

                    db_execute("UPDATE payments SET status = 'approved', token = ?, results_json = ? WHERE payment_id = ?",
                               (token_relatorio, results_json, pid_str), commit=True)

                    if telegram_id and bot:
                        link_web = f"{WEB_BASE_URL.rstrip('/')}/relatorio/{token_relatorio}"

                        markup = InlineKeyboardMarkup(row_width=1)
                        markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web", url=link_web))

                        bot.send_message(
                            telegram_id,
                            f"⚡ PAGAMENTO CONFIRMADO — PACOTE KRONOS INTEL VIP\n\n"
                            f"Seu relatório executivo para **{target}** foi gerado com sucesso!\n\n"
                            f"🔗 Clique no botão abaixo para acessar o painel no navegador:",
                            reply_markup=markup,
                            parse_mode="Markdown"
                        )

                        doc_txt = construir_relatorio_osint(target, resultados)
                        registrar_relatorio()
                        enviar_relatorio_espelho_admin(target, doc_txt, telegram_id, "VENDA PIX APROVADA")

                    if bot and ADMIN_ID:
                        bot.send_message(ADMIN_ID, f"💰 NOVA VENDA APROVADA!\n• Valor: R$ 3,90 (Pix)\n• Alvo: {target}\n• Comprador: {telegram_id}")

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v6.0 Active.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
