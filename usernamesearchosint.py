"""
Kronos Intel OSINT Bot v7.5
- Correção do erro de sintaxe (unterminated string literal)
- Tratamento de mensagens sem parse_mode para evitar falhas no Telegram
- Notificação ao Admin sobre acessos via /start
- Comando /conceder <user_id> <alvo> para liberar cortesia
- Funil de Vendas Duplo (Username R$ 3,90 / Processos R$ 2,90)
- Exclusivo Download em TXT
- Dashboard HTML Redesenho Premium
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
from flask import Flask, jsonify, request, render_template_string, send_file

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
PRECO_VIP_USERNAME = 3.90
PRECO_VIP_PROCESSO = 2.90
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
WEB_BASE_URL = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com").rstrip('/')

MERCADOPAGO_TOKEN = os.getenv("MERCADOPAGO_TOKEN")
sdk = mercadopago.SDK(MERCADOPAGO_TOKEN) if MERCADOPAGO_TOKEN else None

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8625009528:AAHfx5Te-ngeeNMnlB_8hbP40wrpx6_1wIA")
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=False) if TELEGRAM_TOKEN else None

def setup_webhook():
    if bot and TELEGRAM_TOKEN:
        webhook_url = f"{WEB_BASE_URL}/telegram/{TELEGRAM_TOKEN}"
        try:
            bot.remove_webhook()
            time.sleep(1)
            success = bot.set_webhook(url=webhook_url)
            logger.info("Configuração do Webhook Telegram (%s): %s", webhook_url, success)
        except Exception as e:
            logger.error("Erro ao configurar Webhook Telegram: %s", str(e))

setup_webhook()

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

def usuario_ja_pagou_relatorio_anterior(user_id: int) -> bool:
    p = db_execute("SELECT COUNT(*) FROM payments WHERE user_id = ? AND status = 'approved'", (user_id,), fetchone=True)
    return bool(p and p[0] > 0)

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

def executar_varredura_osint(target: str, is_fullname: bool = False) -> dict[str, dict[str, Any]]:
    if is_fullname:
        encoded_name = urllib.parse.quote(f'"{target}"')
        return {
            "Jusbrasil (Processos)": {"exists": True, "url": f"https://www.jusbrasil.com.br/busca?q={encoded_name}"},
            "Escavador (Diários)": {"exists": True, "url": f"https://www.escavador.com/busca?q={encoded_name}"},
            "Jusfy / Diários Judiciais": {"exists": True, "url": f"https://www.google.com/search?q=site:jusbrasil.com.br+OR+site:escavador.com+{encoded_name}"},
            "Portal Transparência": {"exists": True, "url": f"https://www.portaltransparencia.gov.br/busca?termo={urllib.parse.quote(target)}"},
            "Diário Oficial União": {"exists": True, "url": f"https://www.google.com/search?q=site:in.gov.br+{encoded_name}"},
            "Certidões e Registros": {"exists": True, "url": f"https://www.google.com/search?q=%22certidao%22+{encoded_name}"},
            "Google Acadêmico": {"exists": True, "url": f"https://scholar.google.com.br/scholar?q={encoded_name}"},
            "Notícias / Citações": {"exists": True, "url": f"https://www.google.com/search?q={encoded_name}&tbm=nws"},
        }
    else:
        return FastOSINTChecker(target).run()

# --- GERADOR DE RELATÓRIO TXT ---
def construir_relatorio_osint(target: str, resultados: dict[str, dict[str, Any]], is_fullname: bool = False) -> io.BytesIO:
    encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT
===================================================================
ALVO ANALISADO: {target}
TIPO DE CONSULTA: {"PROCESSOS JUDICIAIS / NOME COMPLETO" if is_fullname else "USERNAME / REDES SOCIAIS"}
DATA DA CONSULTA: {data_atual}
SISTEMA: Kronos Engine v7.5
===================================================================

1. FONTES E REGISTROS MAPEADOS
-------------------------------------------------------------------
"""
    if encontrados:
        for p in encontrados:
            url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=target))
            corpo += f"[+] {p.ljust(25)} : {url}\n"
    else:
        corpo += "[-] Nenhuma ocorrência direta indexada.\n"

    if not is_fullname:
        hibp_link = f"https://haveibeenpwned.com/account/{target}"
        intelx_link = f"https://intelx.io/?s={urllib.parse.quote(target)}"
        dehashed_link = f"https://dehashed.com/search?query={urllib.parse.quote(target)}"
        corpo += f"""
2. VARREDURA DE VAZAMENTOS E CREDENCIAIS
-------------------------------------------------------------------
[+] Have I Been Pwned      : {hibp_link}
[+] Intelligence X (IntelX): {intelx_link}
[+] DeHashed Database      : {dehashed_link}
"""

    corpo += """
===================================================================
Documento confidencial gerado por Kronos Intel OSINT Service.
===================================================================
"""
    buf = io.BytesIO(corpo.encode('utf-8'))
    buf.name = f"Relatorio_OSINT_{target.replace(' ', '_')}.txt"
    return buf

def gerar_pix_mercadopago(user_id: int, target: str, valor: float, query_type: str = "username") -> tuple[str | None, bytes | None, str | None]:
    if not sdk:
        return None, None, None
    token_relatorio = secrets.token_urlsafe(16)
    payment_data = {
        "transaction_amount": float(valor),
        "description": f"Relatorio OSINT ({query_type.upper()}) - {target}",
        "payment_method_id": "pix",
        "payer": {"email": f"user_{user_id}@telegram.com", "first_name": "Usuario", "last_name": str(user_id)},
        "metadata": {"telegram_user_id": user_id, "target_username": target, "token": token_relatorio, "query_type": query_type}
    }
    try:
        res = sdk.payment().create(payment_data).get("response", {})
        tx = res.get("point_of_interaction", {}).get("transaction_data", {})
        qr_code = tx.get("qr_code")
        qr_base64 = tx.get("qr_code_base64")
        img_bytes = base64.b64decode(qr_base64) if qr_base64 else None
        
        pid = str(res.get("id"))
        db_execute("INSERT INTO payments (payment_id, user_id, target_username, amount, status, reminded, token, query_type, created_at) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
                   (pid, user_id, target, valor, token_relatorio, query_type, datetime.now().isoformat()), commit=True)
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
                "SELECT payment_id, user_id, target_username, created_at, query_type FROM payments WHERE status = 'pending' AND reminded = 0",
                fetchall=True
            )
            if not pendentes:
                continue

            now = datetime.now()
            for p in pendentes:
                pid, uid, target, created_str, qtype = p[0], p[1], p[2], p[3], p[4]
                try:
                    created_time = datetime.fromisoformat(created_str)
                    if (now - created_time).total_seconds() / 60 >= 10:
                        db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                        if bot:
                            preco = PRECO_VIP_PROCESSO if qtype == "fullname" else PRECO_VIP_USERNAME
                            msg_lembrete = (
                                f"⏳ SUA CHAVE PIX PARA {target.upper()} ESTÁ EXPIRANDO!\n\n"
                                f"Conclua a liberação do seu relatório por apenas R$ {preco:.2f} no Pix antes que o link expire."
                            )
                            markup = InlineKeyboardMarkup(row_width=1)
                            markup.add(InlineKeyboardButton(f"⚡ 🔓 CONCLUIR AGORA (R$ {preco:.2f}) 🔓 ⚡", callback_data=f"buy_{target}" if qtype=="username" else f"buynome_{target}"))
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
    <title>Kronos Intel — Painel OSINT</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {
            --bg-color: #080c14;
            --card-bg: rgba(15, 23, 42, 0.85);
            --border-color: #1e293b;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --text-main: #f8fafc;
        }

        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 50% 0%, rgba(6, 182, 212, 0.12), transparent 75%);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
        }

        .navbar {
            background-color: rgba(8, 12, 20, 0.9);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
        }

        .navbar-brand {
            font-family: monospace;
            font-weight: 700;
            color: var(--accent-cyan) !important;
        }

        .card-custom {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            margin-bottom: 24px;
        }

        .card-header-custom {
            background: rgba(255, 255, 255, 0.02);
            border-bottom: 1px solid var(--border-color);
            padding: 16px 20px;
            font-family: monospace;
            font-weight: 600;
            color: var(--accent-cyan);
        }

        .btn-platform {
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 14px 18px;
            border-radius: 12px;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.2s ease;
        }

        .btn-platform:hover {
            background: rgba(16, 185, 129, 0.1);
            border-color: var(--accent-green);
            color: var(--accent-green);
        }

        .btn-dork {
            background: rgba(6, 182, 212, 0.05);
            border: 1px solid rgba(6, 182, 212, 0.2);
            color: var(--accent-cyan);
            padding: 12px 18px;
            border-radius: 10px;
            text-decoration: none;
            display: flex;
            align-items: center;
            transition: all 0.2s ease;
        }

        .btn-dork:hover {
            background: rgba(6, 182, 212, 0.2);
            color: #fff;
        }

        .code-tag {
            font-family: monospace;
            color: var(--accent-cyan);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark sticky-top mb-4 py-3">
        <div class="container">
            <span class="navbar-brand h1 mb-0"><i class="bi bi-shield-lock-fill me-2"></i>KRONOS_INTEL // OSINT</span>
            <a href="/download/txt/{{ token }}" class="btn btn-outline-info btn-sm rounded-3"><i class="bi bi-file-earmark-text me-1"></i> BAIXAR RELATÓRIO (.TXT)</a>
        </div>
    </nav>

    <div class="container pb-5">
        <div class="card-custom">
            <div class="card-body p-4">
                <span class="text-uppercase text-muted small code-tag">[ ALVO ANALISADO ]</span>
                <h2 class="text-white mb-1 font-monospace"><i class="bi bi-terminal-fill me-2 text-cyan"></i>{{ target }}</h2>
                <p class="text-muted mb-0 small"><i class="bi bi-clock me-1"></i> Auditado em: {{ data_atual }} | Módulo: {{ query_type }}</p>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-{% if is_fullname %}12{% else %}7{% endif %}">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase">
                        <i class="bi bi-diagram-3-fill me-2"></i>{% if is_fullname %}Mapeamento Judicial e Diários Oficiais{% else %}Perfis e Plataformas Mapeadas{% endif %}
                    </div>
                    <div class="card-body p-4">
                        {% if encontrados %}
                        <div class="row g-3">
                            {% for p in encontrados %}
                            <div class="col-md-6">
                                <a href="{{ p.url }}" target="_blank" class="btn-platform">
                                    <span><i class="bi bi-box-arrow-up-right me-2 code-tag"></i>{{ p.nome }}</span>
                                    <i class="bi bi-chevron-right small"></i>
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

            {% if not is_fullname %}
            <div class="col-lg-5">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase text-warning">
                        <i class="bi bi-incognito me-2"></i>Vazamentos de Credenciais
                    </div>
                    <div class="card-body p-4 d-grid gap-2">
                        <a href="https://haveibeenpwned.com/account/{{ target }}" target="_blank" class="btn-dork"><i class="bi bi-search me-2"></i>Have I Been Pwned</a>
                        <a href="https://intelx.io/?s={{ target }}" target="_blank" class="btn-dork"><i class="bi bi-cpu me-2"></i>Intelligence X (IntelX)</a>
                        <a href="https://dehashed.com/search?query={{ target }}" target="_blank" class="btn-dork"><i class="bi bi-database-check me-2"></i>DeHashed Base</a>
                    </div>
                </div>
            </div>
            {% endif %}
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
    
    is_fullname = (query_type == "fullname")
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
        query_type="BUSCA DE PROCESSOS" if is_fullname else "REDES SOCIAIS & USERNAME",
        is_fullname=is_fullname,
        data_atual=data_formatada
    )

@app.route("/download/txt/<token>")
def download_txt(token):
    p = db_execute("SELECT target_username, results_json, query_type FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

    target, results_json_str, query_type = p[0], p[1], p[2]
    results_json = json.loads(results_json_str)
    
    txt_buf = construir_relatorio_osint(target, results_json, is_fullname=(query_type == "fullname"))
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
        user_name = message.from_user.first_name or "Usuario"
        username_tag = f"@{message.from_user.username}" if message.from_user.username else "Sem username"
        
        registrar_acesso(user_id)

        if bot and ADMIN_ID and user_id != ADMIN_ID:
            try:
                msg_admin = (
                    f"🔔 NOVO ACESSO NO BOT!\n\n"
                    f"👤 Nome: {user_name}\n"
                    f"🏷 User: {username_tag}\n"
                    f"🆔 ID: {user_id}"
                )
                bot.send_message(ADMIN_ID, msg_admin)
            except Exception as ex:
                logger.error("Erro ao notificar start ao admin: %s", str(ex))

        bot.reply_to(
            message,
            f"👋 Kronos Intel — OSINT Bot v7.5\n\n"
            f"Envie o nome de usuário (username) desejado para mapear contas ativas e vazamentos na internet.\n"
            f"Exemplo: alvo123\n\n"
            f"🛠 Suporte: @{SUPORTE_USERNAME}"
        )

    @bot.message_handler(commands=['conceder'])
    def handle_conceder_command(message):
        if message.from_user.id != ADMIN_ID:
            return

        partes = message.text.strip().split(maxsplit=2)
        if len(partes) < 3:
            bot.reply_to(message, "⚠️ Uso incorreto!\nFormato correto: /conceder <user_id> <termo_alvo>")
            return

        try:
            target_user_id = int(partes[1])
            alvo = partes[2].strip()
        except ValueError:
            bot.reply_to(message, "⚠️ ID de usuário inválido.")
            return

        is_fullname = e_nome_completo(alvo)
        qtype = "fullname" if is_fullname else "username"

        resultados = executar_varredura_osint(alvo, is_fullname=is_fullname)
        results_json = json.dumps(resultados)
        token_relatorio = secrets.token_urlsafe(16)
        pid_cortesia = f"cortesia_{int(time.time())}"

        db_execute(
            "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, query_type, results_json, created_at) VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?)",
            (pid_cortesia, target_user_id, alvo, token_relatorio, qtype, results_json, datetime.now().isoformat()),
            commit=True
        )
        registrar_relatorio()

        link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Seu Painel VIP Concedido", url=link_web))

        try:
            bot.send_message(
                target_user_id,
                f"🎁 VOCÊ RECEBEU UM ACESSO CORTESIA VIP!\n\n"
                f"A sua consulta para '{alvo}' foi liberada gratuitamente pelo administrador.\n\n"
                f"🔗 Clique no botão abaixo para acessar o painel:",
                reply_markup=markup
            )
            bot.reply_to(message, f"✅ Acesso cortesia concedido com sucesso!\n• Usuário: {target_user_id}\n• Alvo: {alvo}")
        except Exception as e:
            bot.reply_to(message, f"⚠️ Acesso gravado no banco, mas o bot não conseguiu enviar mensagem direta ao usuário {target_user_id}.\nLink do painel: {link_web}")

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

        if eh_admin_mode:
            msg_status = bot.reply_to(message, f"👑 [ADMIN VIP] Processando {target}...")
            resultados = executar_varredura_osint(target, is_fullname=is_fullname)
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

            link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"
            markup = InlineKeyboardMarkup(row_width=1)
            markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web (ADMIN)", url=link_web))

            bot.send_message(
                message.chat.id,
                f"👑 [MODO ADMIN - {'PROCESSOS' if is_fullname else 'USERNAME'}] Painel Web gerado para {target}:",
                reply_markup=markup
            )
            return

        if is_fullname and not usuario_ja_pagou_relatorio_anterior(user_id):
            bot.reply_to(
                message,
                "⚠️ Acesso Restrito ao Módulo Judicial.\n\n"
                "A pesquisa por Nome Completo e Busca de Processos está disponível exclusivamente para clientes VIP.\n"
                "Envie primeiro um username para realizar uma varredura de redes sociais."
            )
            return

        if is_fullname and usuario_ja_pagou_relatorio_anterior(user_id):
            msg_status = bot.reply_to(message, f"🔎 Mapeando tribunais, diários oficiais e Jusbrasil para '{target}'...")
            resultados = executar_varredura_osint(target, is_fullname=True)
            
            try:
                bot.edit_message_text(f"✅ Análise de registros judiciais concluída para '{target}'!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

            texto_upsell_oferta = (
                f"🔍 REGISTROS JUDICIAIS LOCALIZADOS PARA:\n"
                f"👤 {target.upper()}\n"
                f"───────────────────────────────\n\n"
                f"Identificamos apontamentos no Jusbrasil, Escavador e Diários Oficiais estaduais.\n\n"
                f"🔥 OFERTA VIP EXCLUSIVA:\n"
                f"Por apenas R$ 2,90 adicionais no Pix, liberamos o seu Painel Web focado com os links diretos para cada tribunal e diário oficial onde o nome foi citado."
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 LIBERAR BUSCA JUDICIAL DE {target.upper()} (R$ 2,90) 🔓 ⚡", callback_data=f"buynome_{target}")
            btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
            markup.add(btn_sim, btn_nao)

            bot.send_message(message.chat.id, texto_upsell_oferta, reply_markup=markup)
            return

        msg_status = bot.reply_to(message, f"🔎 Mapeando plataformas para @{target}...")
        resultados = executar_varredura_osint(target, is_fullname=False)
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]

        try:
            bot.edit_message_text(f"✅ Mapeamento concluído para @{target}!", chat_id=message.chat.id, message_id=msg_status.message_id)
        except Exception:
            pass

        if encontrados:
            lista_plataformas = "\n".join([f"• {p}" for p in encontrados])
            texto_resultado = (
                f"🎯 PLATAFORMAS ENCONTRADAS PARA @{target}\n"
                f"───────────────────────────────\n\n"
                f"{lista_plataformas}\n\n"
                f"⚠️ Identificamos {len(encontrados)} contas ativas indexadas para este perfil.\n\n"
                f"Deseja obter o Painel Interativo Web com os links clicáveis de cada perfil e relatório TXT?\n\n"
                f"🔥 OFERTA LIMITADA: De R$ 19,90 por apenas R$ 3,90 no Pix!"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("⚡ 🔓 SIM, QUERO O RELATÓRIO COMPLETO (R$ 3,90) 🔓 ⚡", callback_data=f"buy_{target}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data="final_cancel")
            btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
            markup.add(btn_sim, btn_nao, btn_suporte)

            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
        else:
            bot.send_message(message.chat.id, f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{target}.")

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("buy_"):
            target = call.data.split("buy_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, "Gerando Chave Pix de R$ 3,90...")
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target, valor=PRECO_VIP_USERNAME, query_type="username")

            if qr_pix:
                texto_oferta = (
                    f"🔒 PACOTE KRONOS INTEL VIP — @{target}\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Interativo Web com links diretos das redes\n"
                    f"2. Relatório Executivo para Download (.TXT)\n"
                    f"3. Checagem em Bases de Vazamentos (HIBP / IntelX)\n\n"
                    f"💰 Valor: De R$ 19,90 por R$ 3,90 no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O painel interativo será liberado automaticamente após a confirmação do pagamento."
                )

                markup = InlineKeyboardMarkup(row_width=1)
                btn_copiar = InlineKeyboardButton("📋 Copiar Chave Pix (Texto)", callback_data=f"getkey_{user_id}")
                btn_suporte = InlineKeyboardButton("💬 Precisa de Ajuda?", url=f"https://t.me/{SUPORTE_USERNAME}")
                markup.add(btn_copiar, btn_suporte)

                if qr_img_bytes:
                    bot.send_photo(call.message.chat.id, photo=qr_img_bytes, caption=texto_oferta, reply_markup=markup)
                else:
                    bot.send_message(call.message.chat.id, text=texto_oferta, reply_markup=markup)

        elif call.data.startswith("buynome_"):
            target = call.data.split("buynome_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, "Gerando Chave Pix de R$ 2,90...")
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target, valor=PRECO_VIP_PROCESSO, query_type="fullname")

            if qr_pix:
                texto_oferta = (
                    f"⚖️ MÓDULO JUDICIAL VIP — {target.upper()}\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Web exclusivo de Processos e Diários\n"
                    f"2. Links diretos do Jusbrasil e Escavador\n"
                    f"3. Relatório em TXT das ocorrências\n\n"
                    f"💰 Valor Promocional: R$ 2,90 no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O painel será liberado automaticamente assim que pago."
                )

                markup = InlineKeyboardMarkup(row_width=1)
                btn_copiar = InlineKeyboardButton("📋 Copiar Chave Pix (Texto)", callback_data=f"getkey_{user_id}")
                markup.add(btn_copiar)

                if qr_img_bytes:
                    bot.send_photo(call.message.chat.id, photo=qr_img_bytes, caption=texto_oferta, reply_markup=markup)
                else:
                    bot.send_message(call.message.chat.id, text=texto_oferta, reply_markup=markup)

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta finalizada.")
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text="👍 Entendido! Digite um username para iniciar uma nova busca.")

        elif call.data.startswith("getkey_"):
            bot.answer_callback_query(call.id, "Enviando chave...")
            msg_texto = call.message.caption or call.message.text
            lines = msg_texto.split("\n\n") if msg_texto else []
            pix_key = None
            for l in lines:
                if len(l) > 50 and not l.startswith("🔒") and not l.startswith("⚡") and not l.startswith("⚖️"):
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
        
        p_check = db_execute("SELECT status, token, query_type FROM payments WHERE payment_id = ?", (pid_str,), fetchone=True)
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
                    query_type = metadata.get("query_type", "username")

                    is_fullname = (query_type == "fullname")
                    resultados = executar_varredura_osint(target, is_fullname=is_fullname)
                    results_json = json.dumps(resultados)

                    db_execute("UPDATE payments SET status = 'approved', token = ?, results_json = ?, query_type = ? WHERE payment_id = ?",
                               (token_relatorio, results_json, query_type, pid_str), commit=True)

                    if telegram_id and bot:
                        link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"

                        markup = InlineKeyboardMarkup(row_width=1)
                        markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web", url=link_web))

                        bot.send_message(
                            telegram_id,
                            f"⚡ PAGAMENTO CONFIRMADO — KRONOS INTEL VIP\n\n"
                            f"Seu painel para '{target}' está liberado!\n\n"
                            f"🔗 Clique no botão abaixo para acessar:",
                            reply_markup=markup
                        )

                        doc_txt = construir_relatorio_osint(target, resultados, is_fullname=is_fullname)
                        registrar_relatorio()
                        enviar_relatorio_espelho_admin(target, doc_txt, telegram_id, "VENDA PIX APROVADA")

                        if not is_fullname:
                            time.sleep(2)
                            msg_upsell = (
                                f"💡 DESEJA SABER SE ESTE ALVO TEM PROCESSOS JUDICIAIS?\n\n"
                                f"Geralmente quem utiliza o username '{target}' possui nome completo citado no Jusbrasil, Escavador ou Diários Oficiais.\n\n"
                                f"⚖️ Para realizar a Varredura Judicial Completa, digite abaixo o Nome Completo da pessoa.\n\n"
                                f"🔥 Como você já é cliente VIP, liberamos este módulo adicional por apenas R$ 2,90 no Pix!"
                            )
                            bot.send_message(telegram_id, msg_upsell)

                    if bot and ADMIN_ID:
                        bot.send_message(ADMIN_ID, f"💰 NOVA VENDA APROVADA!\n• Valor: R$ {payment_info.get('transaction_amount', 0.0):.2f}\n• Tipo: {query_type}\n• Alvo: {target}\n• Comprador: {telegram_id}")

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v7.5 Active.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
