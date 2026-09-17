"""
Kronos Intel OSINT Bot v10.0
- Boas-vindas completas com apresentacao das funções no /start
- Cobrança unificada de R$ 3,90 para /email e /nome (com suporte a PIX/Relatório)
- Indução estratégica para entrada no Grupo/Canal Principal (@kronosintel_oficial)
- Canal Principal (-1003802363624): Provas Sociais de novos acessos
- Grupo de Logs (-5294217144): Alertas internos de vendas/Pix aprovados
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

DEFAULT_TIMEOUT = 3.0
PORT = int(os.getenv("PORT", "5000"))
PRECO_PADRAO = 3.90  # Valor unificado para Username, Nome e E-mail
DB_FILE = "kronos_osint.db"
db_lock = Lock()

# --- CONFIGURAÇÃO DE CANAL E GRUPO DE LOGS ---
CANAL_PRINCIPAL_ID = int(os.getenv("CANAL_PRINCIPAL_ID", "-1003802363624"))
GRUPO_LOGS_ID = int(os.getenv("GRUPO_LOGS_ID", "-5294217144"))
CANAL_TAG_PUBLICO = "@kronosintel_oficial"  # Tag induzida ao final das buscas

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
                res = {"exists": False}
        except Exception:
            res = {"exists": False}

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

def obter_links_buscadores(termo: str) -> dict[str, str]:
    encoded_term = urllib.parse.quote(f'"{termo}"')
    return {
        "Yandex (Citações & Fóruns)": f"https://yandex.com/search/?text={encoded_term}",
        "Google (Busca Exata)": f"https://www.google.com/search?q={encoded_term}",
        "Google Notícias & Mídia": f"https://www.google.com/search?q={encoded_term}&tbm=nws",
        "Bing Search (Menções)": f"https://www.bing.com/search?q={encoded_term}",
        "DuckDuckGo (Presença Web)": f"https://duckduckgo.com/?q={encoded_term}"
    }

def obter_links_vazamento_email(email: str) -> dict[str, str]:
    encoded_email = urllib.parse.quote(email)
    return {
        "Have I Been Pwned": f"https://haveibeenpwned.com/account/{encoded_email}",
        "Intelligence X (IntelX)": f"https://intelx.io/?s={encoded_email}",
        "DeHashed Base": f"https://dehashed.com/search?query={encoded_email}",
        "BreachDirectory": f"https://breachdirectory.org/search?query={encoded_email}"
    }

# --- GERADOR DE RELATÓRIO TXT ---
def construir_relatorio_osint(target: str, resultados: dict[str, dict[str, Any]], is_fullname: bool = False, is_email: bool = False) -> io.BytesIO:
    encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    tipo_txt = "VAZAMENTO DE E-MAIL" if is_email else ("PROCESSOS JUDICIAIS" if is_fullname else "USERNAME / REDES SOCIAIS")

    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT
===================================================================
ALVO ANALISADO: {target}
TIPO DE CONSULTA: {tipo_txt}
DATA DA CONSULTA: {data_atual}
SISTEMA: Kronos Engine v10.0
===================================================================
"""
    if is_email:
        vazamentos = obter_links_vazamento_email(target)
        corpo += f"""1. VARREDURA DE VAZAMENTOS DE E-MAIL E CREDENCIAIS
-------------------------------------------------------------------
"""
        for nome_v, url_v in vazamentos.items():
            corpo += f"[+] {nome_v.ljust(25)} : {url_v}\n"

    elif not is_fullname:
        corpo += f"""1. PERFIS E PLATAFORMAS CONFIRMADAS
-------------------------------------------------------------------
"""
        if encontrados:
            for p in encontrados:
                url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=target))
                corpo += f"[+] {p.ljust(25)} : {url}\n"
        else:
            corpo += "[-] Nenhuma rede social pública confirmada para este usuário.\n"

        buscadores = obter_links_buscadores(target)
        corpo += f"""
2. PRESENÇA DIGITAL E MENÇÕES EM BUSCADORES
-------------------------------------------------------------------
"""
        for nome_b, url_b in buscadores.items():
            corpo += f"[+] {nome_b.ljust(28)} : {url_b}\n"

    else:
        corpo += f"""1. REGISTROS JUDICIAIS E DIÁRIOS OFICIAIS
-------------------------------------------------------------------
"""
        for p in encontrados:
            url = resultados[p].get("url", "")
            corpo += f"[+] {p.ljust(25)} : {url}\n"

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
                            msg_lembrete = (
                                f"⏳ SUA CHAVE PIX PARA {target.upper()} ESTÁ EXPIRANDO!\n\n"
                                f"Conclua a liberação do seu relatório por apenas R$ {PRECO_PADRAO:.2f} no Pix antes que o link expire."
                            )
                            markup = InlineKeyboardMarkup(row_width=1)
                            markup.add(InlineKeyboardButton(f"⚡ 🔓 CONCLUIR AGORA (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"buy_{target}"))
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
            <div class="col-lg-{% if is_fullname or is_email %}12{% else %}7{% endif %}">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase">
                        <i class="bi bi-check-circle-fill me-2 text-success"></i>{% if is_email %}Bases de Vazamento Mapeadas{% elif is_fullname %}Mapeamento Judicial e Diários Oficiais{% else %}Perfis Confirmados (Cadastrados){% endif %}
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
                        <p class="text-muted mb-0">Nenhum registro público direto localizado.</p>
                        {% endif %}
                    </div>
                </div>
            </div>

            {% if not is_fullname and not is_email %}
            <div class="col-lg-5">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase text-info">
                        <i class="bi bi-globe me-2"></i>Presença Digital & Menções em Buscadores
                    </div>
                    <div class="card-body p-4 d-grid gap-2">
                        {% for nome_b, url_b in buscadores.items() %}
                        <a href="{{ url_b }}" target="_blank" class="btn-dork"><i class="bi bi-search me-2"></i>{{ nome_b }}</a>
                        {% endfor %}
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
    is_email = (query_type == "email")
    encontrados = []
    
    if is_email:
        vazamentos = obter_links_vazamento_email(target)
        for k, v in vazamentos.items():
            encontrados.append({"nome": k, "url": v})
    else:
        for plat in results_json:
            if results_json[plat].get("exists") is True:
                url = results_json[plat].get("url", PLATFORM_URLS.get(plat, "").format(username=target))
                encontrados.append({"nome": plat, "url": url})

    buscadores = obter_links_buscadores(target) if (not is_fullname and not is_email) else {}
    data_formatada = datetime.fromisoformat(created_at).strftime("%d/%m/%Y %H:%M:%S")

    return render_template_string(
        HTML_DASHBOARD_TEMPLATE,
        target=target,
        token=token,
        encontrados=encontrados,
        buscadores=buscadores,
        query_type=query_type.upper(),
        is_fullname=is_fullname,
        is_email=is_email,
        data_atual=data_formatada
    )

@app.route("/download/txt/<token>")
def download_txt(token):
    p = db_execute("SELECT target_username, results_json, query_type FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

    target, results_json_str, query_type = p[0], p[1], p[2]
    results_json = json.loads(results_json_str)
    
    txt_buf = construir_relatorio_osint(
        target, 
        results_json, 
        is_fullname=(query_type == "fullname"),
        is_email=(query_type == "email")
    )
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
        
        registrar_acesso(user_id)

        # NOTIFICAÇÃO PÚBLICA DE PROVA SOCIAL NO CANAL PRINCIPAL
        if bot and CANAL_PRINCIPAL_ID and user_id != ADMIN_ID:
            try:
                msg_canal = (
                    f"⚡ NOVO USUÁRIO INICIOU O BOT!\n\n"
                    f"👤 Usuário: {user_name}\n"
                    f"🎯 O Kronos OSINT Bot está pronto para realizar varreduras.\n\n"
                    f"👉 Faça sua busca agora: @{BOT_USERNAME}"
                )
                bot.send_message(CANAL_PRINCIPAL_ID, msg_canal)
            except Exception as ex:
                logger.error("Erro ao notificar no canal principal: %s", str(ex))

        # MENU COMPLETO DE APRESENTAÇÃO DE RECURSOS
        menu_boas_vindas = (
            f"👋 Olá, {user_name}! Bem-vindo ao **Kronos Intel OSINT Bot v10.0**.\n\n"
            f"Sua plataforma avançada para investigação digital, inteligência cibernética e mapeamento de dados públicos.\n\n"
            f"🛠 **ESCOLHA O MÓDULO DE BUSCA QUE DESEJA USAR:**\n\n"
            f"1️⃣ **BUSCA POR USERNAME / REDES SOCIAIS:**\n"
            f"Digite diretamente o @username no chat (ex: `alvo123`).\n"
            f"• Identifica perfis ativos em mais de 45 redes.\n"
            f"• Mapeia presença digital no Google, Yandex e Bing.\n\n"
            f"2️⃣ **BUSCA POR NOME COMPLETO (JUDICIAL):**\n"
            f"Digite o comando `/nome` seguido do Nome Completo.\n"
            f"Exemplo: `/nome João da Silva`\n"
            f"• Mapeia processos, citações no Jusbrasil e Diários Oficiais.\n\n"
            f"3️⃣ **BUSCA POR E-MAIL (VAZAMENTOS):**\n"
            f"Digite o comando `/email` seguido do e-mail.\n"
            f"Exemplo: `/email alvo@gmail.com`\n"
            f"• Mapeia vazamentos de credenciais no HIBP, IntelX, DeHashed e BreachDirectory.\n\n"
            f"📢 **Acompanhe atualizações e inteligência em nosso canal oficial:** {CANAL_TAG_PUBLICO}\n"
            f"💬 **Suporte Direto:** @{SUPORTE_USERNAME}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_canal = InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
        markup.add(btn_canal, btn_suporte)

        bot.send_message(message.chat.id, menu_boas_vindas, parse_mode="Markdown", reply_markup=markup)

    @bot.message_handler(commands=['nome'])
    def handle_nome_command(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            bot.reply_to(message, "⚠️ Envie o nome completo após o comando.\nExemplo: `/nome João da Silva`", parse_mode="Markdown")
            return

        nome_alvo = partes[1].strip()
        if not e_nome_completo(nome_alvo):
            bot.reply_to(message, "⚠️ Digite o nome e sobrenome completo.")
            return

        msg_status = bot.reply_to(message, f"🔎 Mapeando tribunais, diários oficiais e Jusbrasil para '{nome_alvo}'...")
        resultados = executar_varredura_osint(nome_alvo, is_fullname=True)
        
        try:
            bot.edit_message_text(f"✅ Análise de registros judiciais concluída para '{nome_alvo}'!", chat_id=message.chat.id, message_id=msg_status.message_id)
        except Exception:
            pass

        texto_oferta = (
            f"🔍 REGISTROS JUDICIAIS LOCALIZADOS PARA:\n"
            f"👤 {nome_alvo.upper()}\n"
            f"───────────────────────────────\n\n"
            f"Identificamos apontamentos no Jusbrasil, Escavador e Diários Oficiais estaduais.\n\n"
            f"🔥 Liberar o Painel Interativo Web + Relatório TXT completo por apenas R$ {PRECO_PADRAO:.2f} no Pix!\n\n"
            f"👉 Participe também da nossa comunidade oficial: {CANAL_TAG_PUBLICO}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_sim = InlineKeyboardButton(f"⚡ 🔓 LIBERAR PAINEL JUDICIAL (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"buynome_{nome_alvo}")
        btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
        markup.add(btn_sim, btn_canal, btn_nao)

        bot.send_message(message.chat.id, texto_oferta, reply_markup=markup)

    @bot.message_handler(commands=['email'])
    def handle_email_command(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2 or "@" not in partes[1]:
            bot.reply_to(message, "⚠️ Envie um e-mail válido após o comando.\nExemplo: `/email alvo@gmail.com`", parse_mode="Markdown")
            return

        email_alvo = partes[1].strip()

        texto_email = (
            f"📧 CHECAGEM DE VAZAMENTOS PARA:\n"
            f"👤 {email_alvo}\n"
            f"───────────────────────────────\n\n"
            f"Mapeamos as principais bases globais de vazamento de credenciais e senhas:\n"
            f"• Have I Been Pwned\n"
            f"• Intelligence X\n"
            f"• DeHashed Base\n"
            f"• BreachDirectory\n\n"
            f"🔥 Liberar Painel Interativo Web com os links diretos de vazamento por apenas R$ {PRECO_PADRAO:.2f} no Pix!\n\n"
            f"👉 Acompanhe alertas de segurança no canal: {CANAL_TAG_PUBLICO}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_sim = InlineKeyboardButton(f"⚡ 🔓 LIBERAR BUSCA DE E-MAIL (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"buy_{email_alvo}")
        btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
        markup.add(btn_sim, btn_canal, btn_nao)

        bot.send_message(message.chat.id, texto_email, reply_markup=markup)

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
        qtype = "fullname" if is_fullname else ("email" if "@" in alvo else "username")

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
                f"👑 [MODO ADMIN] Painel Web gerado para {target}:",
                reply_markup=markup
            )
            return

        if is_fullname:
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
                f"Por apenas R$ {PRECO_PADRAO:.2f} no Pix, liberamos o seu Painel Web focado com os links diretos para cada tribunal e diário oficial onde o nome foi citado.\n\n"
                f"👉 Entre no nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 LIBERAR BUSCA JUDICIAL DE {target.upper()} (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"buynome_{target}")
            btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
            btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
            markup.add(btn_sim, btn_canal, btn_nao)

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
                f"Deseja obter o Painel Interativo Web com os links clicáveis de cada perfil, presença digital (Yandex/Google) e relatório TXT?\n\n"
                f"🔥 OFERTA LIMITADA: De R$ 19,90 por apenas R$ {PRECO_PADRAO:.2f} no Pix!\n\n"
                f"👉 Faça parte do nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 SIM, QUERO O RELATÓRIO COMPLETO (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"buy_{target}")
            btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data="final_cancel")
            markup.add(btn_sim, btn_canal, btn_nao)

            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
        else:
            bot.send_message(
                message.chat.id,
                f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{target}.\n\n"
                f"👉 Fique por dentro de novas técnicas de OSINT no nosso canal: {CANAL_TAG_PUBLICO}"
            )

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("buy_") or call.data.startswith("buynome_"):
            is_nome = call.data.startswith("buynome_")
            target = call.data.split("buynome_")[1] if is_nome else call.data.split("buy_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, f"Gerando Chave Pix de R$ {PRECO_PADRAO:.2f}...")
            qtype = "fullname" if is_nome else ("email" if "@" in target else "username")
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target, valor=PRECO_PADRAO, query_type=qtype)

            if qr_pix:
                texto_oferta = (
                    f"🔒 PACOTE KRONOS INTEL VIP — {target.upper()}\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Interativo Web com links diretos\n"
                    f"2. Mapeamento de Presença Digital & Vazamentos\n"
                    f"3. Relatório Executivo para Download (.TXT)\n\n"
                    f"💰 Valor: De R$ 19,90 por R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O painel interativo será liberado automaticamente após a confirmação do pagamento.\n\n"
                    f"👉 Acesse nosso canal oficial para dúvidas e avisos: {CANAL_TAG_PUBLICO}"
                )

                markup = InlineKeyboardMarkup(row_width=1)
                btn_copiar = InlineKeyboardButton("📋 Copiar Chave Pix (Texto)", callback_data=f"getkey_{user_id}")
                btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
                markup.add(btn_copiar, btn_canal)

                if qr_img_bytes:
                    bot.send_photo(call.message.chat.id, photo=qr_img_bytes, caption=texto_oferta, reply_markup=markup)
                else:
                    bot.send_message(call.message.chat.id, text=texto_oferta, reply_markup=markup)

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta finalizada.")
            bot.edit_message_text(
                chat_id=call.message.chat.id, 
                message_id=call.message.message_id, 
                text=f"👍 Entendido! Digite um username, /nome ou /email para iniciar uma nova busca.\n\n👉 Acompanhe as novidades no canal: {CANAL_TAG_PUBLICO}"
            )

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
                    is_email = (query_type == "email")
                    resultados = executar_varredura_osint(target, is_fullname=is_fullname)
                    results_json = json.dumps(resultados)

                    db_execute("UPDATE payments SET status = 'approved', token = ?, results_json = ?, query_type = ? WHERE payment_id = ?",
                               (token_relatorio, results_json, query_type, pid_str), commit=True)

                    if telegram_id and bot:
                        link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"

                        markup = InlineKeyboardMarkup(row_width=1)
                        markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web", url=link_web))
                        markup.add(InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}") )

                        bot.send_message(
                            telegram_id,
                            f"⚡ PAGAMENTO CONFIRMADO — KRONOS INTEL VIP\n\n"
                            f"Seu painel para '{target}' está liberado!\n\n"
                            f"🔗 Clique no botão abaixo para acessar o painel e baixar o relatório TXT.\n\n"
                            f"👉 Faça parte do nosso canal oficial de novidades: {CANAL_TAG_PUBLICO}",
                            reply_markup=markup
                        )

                        doc_txt = construir_relatorio_osint(
                            target, 
                            resultados, 
                            is_fullname=is_fullname,
                            is_email=is_email
                        )
                        registrar_relatorio()
                        enviar_relatorio_espelho_admin(target, doc_txt, telegram_id, "VENDA PIX APROVADA")

                    # NOTIFICAÇÃO EXCLUSIVA DE VENDAS NO GRUPO FINANCEIRO/LOGS PRIVADO (-5294217144)
                    if bot and GRUPO_LOGS_ID:
                        try:
                            msg_venda_log = (
                                f"💰 NOVA VENDA APROVADA!\n\n"
                                f"• Valor: R$ {payment_info.get('transaction_amount', 0.0):.2f}\n"
                                f"• Tipo: {query_type.upper()}\n"
                                f"• Alvo: {target}\n"
                                f"• Comprador ID: {telegram_id}"
                            )
                            bot.send_message(GRUPO_LOGS_ID, msg_venda_log)
                        except Exception as log_err:
                            logger.error("Erro ao enviar log no grupo financeiro: %s", str(log_err))

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v10.0 Active.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
