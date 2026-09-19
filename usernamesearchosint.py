"""
Kronos Intel OSINT Bot v19.0
- Reivindicação atômica de pagamento no Webhook via RETURNING (Zero duplicidade de requisições)
- Proteção de privacidade nos logs do servidor (Token oculto em setup_webhook)
- Limite de taxa (Rate Limiting) de 6 buscas por hora por usuário
- Expiração periódica de dados pessoais e hashes conforme LGPD (+ comando /apagar)
- Suporte a coluna 'pix_code' para cópia direta da chave sem parsing de texto
- Marcador de ausência de conta corrigido para Steam
- Suporte Oficial: @kronos_intel
"""
from __future__ import annotations

import base64
import hashlib
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
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
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
    MAX_CONTENT_LENGTH=1024 * 1024,  # 1 MB
)

DEFAULT_TIMEOUT = 3.0
PORT = int(os.getenv("PORT", "5000"))
PRECO_PADRAO = 3.90
DB_FILE = os.getenv("DB_FILE", "kronos_osint.db")
db_lock = Lock()
TIMEZONE_BR = ZoneInfo("America/Sao_Paulo")
RE_USERNAME = re.compile(r"^[A-Za-z0-9._-]{2,40}$")

# --- CONFIGURAÇÕES DE AMBIENTE ---
CANAL_PRINCIPAL_ID = int(os.getenv("CANAL_PRINCIPAL_ID", "-1003802363624"))
LOG_GROUP_ID = int(os.getenv("LOG_GROUP_ID", "-1003986408630"))
CANAL_TAG_PUBLICO = os.getenv("CANAL_TAG_PUBLICO", "@kronosintel_oficial")
ADMIN_ID = int(os.getenv("ADMIN_ID", "5041637922"))
SUPORTE_USERNAME = os.getenv("SUPORTE_USERNAME", "kronos_intel")
BOT_USERNAME = os.getenv("BOT_USERNAME", "KronosSearchbot")
WEB_BASE_URL = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com").rstrip('/')

MERCADOPAGO_TOKEN = os.getenv("MERCADOPAGO_TOKEN")
sdk = mercadopago.SDK(MERCADOPAGO_TOKEN) if MERCADOPAGO_TOKEN else None

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=False) if TELEGRAM_TOKEN else None

# --- HISTÓRICO DE RATE LIMITING EN-MEMÓRIA ---
_hist_rate_limit: dict[int, list[float]] = {}
_rate_limit_lock = Lock()

def limite_busca_ok(user_id: int, maximo: int = 6, janela_segundos: int = 3600) -> bool:
    agora = time.time()
    with _rate_limit_lock:
        historico = [t for t in _hist_rate_limit.get(user_id, []) if agora - t < janela_segundos]
        if len(historico) >= maximo:
            _hist_rate_limit[user_id] = historico
            return False
        historico.append(agora)
        _hist_rate_limit[user_id] = historico
        return True

# --- BANCO DE DADOS SQLITE / POSTGRES ---
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
                pix_code TEXT,
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS target_hashes (
                hash_id TEXT PRIMARY KEY,
                target_value TEXT,
                query_type TEXT,
                created_at TEXT
            )
        """)
        
        # Garante a existência da coluna pix_code em bancos de dados existentes
        try:
            cursor.execute("ALTER TABLE payments ADD COLUMN pix_code TEXT")
        except sqlite3.OperationalError:
            pass

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

# --- GESTÃO DE HASHES DE CALLBACK PARA EVITAR ERRO DE 64 BYTES NO TELEGRAM ---
def registrar_hash_alvo(alvo: str, query_type: str) -> str:
    hash_curto = hashlib.md5(f"{alvo}_{query_type}".encode('utf-8')).hexdigest()[:10]
    db_execute(
        "INSERT INTO target_hashes (hash_id, target_value, query_type, created_at) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(hash_id) DO UPDATE SET target_value = EXCLUDED.target_value",
        (hash_curto, alvo, query_type, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )
    return hash_curto

def obter_alvo_por_hash(hash_curto: str) -> tuple[str | None, str | None]:
    res = db_execute("SELECT target_value, query_type FROM target_hashes WHERE hash_id = ?", (hash_curto,), fetchone=True)
    if res:
        return res[0], res[1]
    return None, None

def obter_grupo_logs_id() -> int:
    return LOG_GROUP_ID

def setup_webhook():
    if bot and TELEGRAM_TOKEN:
        webhook_url = f"{WEB_BASE_URL}/telegram/{TELEGRAM_TOKEN}"
        try:
            bot.remove_webhook()
            time.sleep(1)
            success = bot.set_webhook(url=webhook_url)
            logger.info("Webhook Telegram configurado: %s", success)
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
    "Reddit": "https://www.reddit.com/user/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Telegram": "https://t.me/{username}",
    "Tumblr": "https://{username}.tumblr.com",
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
    "steam": ("the specified profile could not be found", "could not be found", "error"),
}

def registrar_acesso(user_id: int):
    now_str = datetime.now(TIMEZONE_BR).isoformat()
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

def e_email_valido(termo: str) -> bool:
    padrao = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(padrao, termo.strip()))

def e_url(termo: str) -> bool:
    if e_email_valido(termo):
        return False
    if "/" in termo or "http://" in termo or "https://" in termo:
        padrao_url = re.compile(
            r'^(?:http|ftp)s?://'
            r'|(?:www\.)'
            r'|[a-zA-Z0-9.-]+\.(?:com|org|net|gov|edu|io|br|me|dev|app|co|xyz)'
        , re.IGNORECASE)
        return bool(padrao_url.search(termo))
    return False

def responder_seguro(message, texto, parse_mode=None, reply_markup=None):
    try:
        return bot.reply_to(message, texto, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception:
        try:
            return bot.send_message(message.chat.id, texto, parse_mode=parse_mode, reply_markup=reply_markup)
        except Exception as e:
            logger.error("Erro ao enviar mensagem para chat %s: %s", message.chat.id, str(e))
            return None

def orientar_uso_correto(chat_id: int):
    msg_guia = (
        "💡 **COMO UTILIZAR O BOT CORRETAMENTE:**\n\n"
        "1️⃣ **Para buscar por Username (Redes Sociais):**\n"
        "• Use: `/user alvo123`\n"
        "*(Apenas o nome de usuário sem espaços, links ou @)*\n\n"
        "2️⃣ **Para buscar por E-mail (Fontes de Verificação):**\n"
        "• Use: `/email exemplo@dominio.com`\n\n"
        "3️⃣ **Para buscar por Nome Completo (Atalhos Judiciais):**\n"
        "• Use: `/nome João da Silva`"
    )
    try:
        bot.send_message(chat_id, msg_guia, parse_mode="Markdown")
    except Exception as e:
        logger.error("Erro ao enviar orientação para %s: %s", chat_id, str(e))

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
            target_url = url.format(username=self.username)
            resp = requests.get(target_url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
            status = resp.status_code
            if status == 404:
                res = {"exists": False}
            elif 200 <= status < 400:
                text = resp.text[:50000].lower()
                markers = NOT_FOUND_MARKERS.get(platform.lower(), ())
                if any(m in text for m in markers):
                    res = {"exists": False}
                else:
                    res = {"exists": True, "url": target_url}
            else:
                res = {"exists": False}
        except Exception:
            res = {"exists": False}

        with self._lock:
            self.results[platform] = res

    def run(self) -> dict[str, dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [
                executor.submit(self.check_site, p, u)
                for p, u in PLATFORM_URLS.items()
            ]
            for f in futures:
                try:
                    f.result(timeout=4.0)
                except Exception:
                    pass
        return self.results

def executar_varredura_osint(target: str, is_fullname: bool = False, is_email: bool = False) -> dict[str, dict[str, Any]]:
    if is_email:
        encoded_email = urllib.parse.quote(target)
        return {
            "Have I Been Pwned": {"exists": True, "url": f"https://haveibeenpwned.com/account/{encoded_email}"},
            "DeHashed Base": {"exists": True, "url": f"https://dehashed.com/search?query={encoded_email}"},
            "Intelligence X (IntelX)": {"exists": True, "url": f"https://intelx.io/?s={encoded_email}"},
            "BreachDirectory": {"exists": True, "url": f"https://breachdirectory.org/search?query={encoded_email}"},
            "Leak-Lookup Engine": {"exists": True, "url": f"https://leak-lookup.com/search?type=email&query={encoded_email}"},
            "Scylla.sh Data Leak": {"exists": True, "url": f"https://scylla.sh/search?q=email:{encoded_email}"},
            "Hudson Rock Cybercrime": {"exists": True, "url": f"https://cavalier.hudsonrock.com/api/v1/osint-tools/search-by-email?email={encoded_email}"}
        }
    elif is_fullname:
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

def construir_relatorio_osint(target: str, resultados: dict[str, dict[str, Any]], is_fullname: bool = False, is_email: bool = False) -> io.BytesIO:
    encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
    data_atual = datetime.now(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")

    tipo_txt = "CONSULTA DE E-MAIL" if is_email else ("BUSCA JUDICIAL" if is_fullname else "USERNAME / REDES SOCIAIS")

    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT
===================================================================
ALVO ANALISADO: {target}
TIPO DE CONSULTA: {tipo_txt}
DATA DA CONSULTA: {data_atual}
SISTEMA: Kronos Engine v19.0
===================================================================
"""
    if is_email:
        corpo += f"""1. BASES DE CONSULTA DE E-MAIL E FONTES
-------------------------------------------------------------------
"""
        for p in resultados:
            corpo += f"[+] {p.ljust(25)} : {resultados[p].get('url')}\n"

    elif not is_fullname:
        corpo += f"""1. PERFIS E PLATAFORMAS LOCALIZADAS
-------------------------------------------------------------------
"""
        if encontrados:
            for p in encontrados:
                url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=target))
                corpo += f"[+] {p.ljust(25)} : {url}\n"
        else:
            corpo += "[-] Nenhuma rede social pública identificada para este nome de usuário.\n"

        buscadores = obter_links_buscadores(target)
        corpo += f"""
2. PRESENÇA DIGITAL E MENÇÕES EM BUSCADORES
-------------------------------------------------------------------
"""
        for nome_b, url_b in buscadores.items():
            corpo += f"[+] {nome_b.ljust(28)} : {url_b}\n"

    else:
        corpo += f"""1. ATALHOS DE BUSCA JUDICIAL E DIÁRIOS OFICIAIS
-------------------------------------------------------------------
"""
        for p in resultados:
            corpo += f"[+] {p.ljust(25)} : {resultados[p].get('url')}\n"

    corpo += """
===================================================================
Documento de compilação gerado por Kronos Intel OSINT Service.
===================================================================
"""
    buf = io.BytesIO(corpo.encode('utf-8'))
    buf.name = f"Relatorio_OSINT_{target.replace(' ', '_')}.txt"
    return buf

# --- GERAR PIX COM EXPIRAÇÃO REAL DE 30 MINUTOS E DESCRIÇÃO ANÔNIMA ---
def gerar_pix_mercadopago(user_id: int, target: str, valor: float, query_type: str = "username") -> tuple[str | None, bytes | None, str | None]:
    if not sdk:
        return None, None, None
    token_relatorio = secrets.token_urlsafe(16)
    
    expiracao = (datetime.now(TIMEZONE_BR) + timedelta(minutes=30)).isoformat(timespec="milliseconds")
    
    payment_data = {
        "transaction_amount": float(valor),
        "description": "Consulta de Dados Publicos OSINT",
        "payment_method_id": "pix",
        "date_of_expiration": expiracao,
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
        
        db_execute(
            "INSERT INTO payments (payment_id, user_id, target_username, amount, status, reminded, token, pix_code, query_type, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?) "
            "ON CONFLICT(payment_id) DO UPDATE SET target_username=excluded.target_username, token=excluded.token, pix_code=excluded.pix_code, query_type=excluded.query_type",
            (pid, user_id, target, valor, token_relatorio, qr_code, query_type, datetime.now(TIMEZONE_BR).isoformat()),
            commit=True
        )
        return qr_code, img_bytes, token_relatorio
    except Exception as e:
        logger.error("Erro ao gerar Pix: %s", str(e))
        return None, None, None

# --- WORKER: REMARKETING E RETENÇÃO DE DADOS (LGPD) ---
def worker_background():
    while True:
        try:
            time.sleep(60)
            now = datetime.now(TIMEZONE_BR)

            # 1. REMARKETING
            pendentes = db_execute(
                "SELECT payment_id, user_id, target_username, created_at, query_type FROM payments WHERE status = 'pending' AND reminded = 0",
                fetchall=True
            )
            if pendentes:
                for p in pendentes:
                    pid, uid, target, created_str, qtype = p[0], p[1], p[2], p[3], p[4]
                    try:
                        created_time = datetime.fromisoformat(created_str)
                        if created_time.tzinfo is None:
                            created_time = created_time.replace(tzinfo=TIMEZONE_BR)
                        minutos_decorridos = (now - created_time).total_seconds() / 60
                        
                        if 10 <= minutos_decorridos < 30:
                            db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                            if bot:
                                hash_alvo = registrar_hash_alvo(target, qtype)
                                msg_lembrete = (
                                    f"⏳ O seu código Pix de consulta expira em breve.\n\n"
                                    f"Conclua a liberação do seu relatório interativo por R$ {PRECO_PADRAO:.2f} no Pix."
                                )
                                markup = InlineKeyboardMarkup(row_width=1)
                                markup.add(InlineKeyboardButton(f"⚡ 🔓 CONCLUIR AGORA (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}"))
                                bot.send_message(uid, msg_lembrete, parse_mode="Markdown", reply_markup=markup)
                        elif minutos_decorridos >= 30:
                            db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                    except Exception as ex:
                        logger.error("Erro no remarketing: %s", str(ex))

            # 2. RETENÇÃO E APAGAMENTO DE DADOS (LGPD)
            lim_hashes = (now - timedelta(days=1)).isoformat()
            db_execute("DELETE FROM target_hashes WHERE created_at < ?", (lim_hashes,), commit=True)
            
            lim_payments = (now - timedelta(days=30)).isoformat()
            db_execute("UPDATE payments SET results_json=NULL, target_username='(expirado)' WHERE created_at < ?", (lim_payments,), commit=True)

        except Exception as e:
            logger.error("Erro no worker background: %s", str(e))

Thread(target=worker_background, daemon=True).start()

HTML_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kronos Intel — Painel OSINT VIP</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        :root {
            --bg-color: #030712;
            --card-bg: rgba(17, 24, 39, 0.85);
            --border-color: #1f2937;
            --accent-cyan: #38bdf8;
            --accent-green: #34d399;
            --text-main: #f9fafb;
        }

        body {
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 50% 0%, rgba(56, 189, 248, 0.15), transparent 80%);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            min-height: 100vh;
        }

        .navbar {
            background-color: rgba(3, 7, 18, 0.95);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border-color);
        }

        .navbar-brand {
            font-family: monospace;
            font-weight: 700;
            color: var(--accent-cyan) !important;
            letter-spacing: 1px;
        }

        .card-custom {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            margin-bottom: 24px;
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
        }

        .card-header-custom {
            background: rgba(255, 255, 255, 0.03);
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
            transition: all 0.25s ease;
        }

        .btn-platform:hover {
            background: rgba(52, 211, 153, 0.12);
            border-color: var(--accent-green);
            color: var(--accent-green);
            transform: translateY(-2px);
        }

        .btn-dork {
            background: rgba(56, 189, 248, 0.06);
            border: 1px solid rgba(56, 189, 248, 0.2);
            color: var(--accent-cyan);
            padding: 12px 18px;
            border-radius: 10px;
            text-decoration: none;
            display: flex;
            align-items: center;
            transition: all 0.2s ease;
        }

        .btn-dork:hover {
            background: rgba(56, 189, 248, 0.25);
            color: #fff;
        }

        .code-tag {
            font-family: monospace;
            color: var(--accent-cyan);
        }

        .badge-found {
            background-color: rgba(52, 211, 153, 0.2);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark sticky-top mb-4 py-3">
        <div class="container">
            <span class="navbar-brand h1 mb-0"><i class="bi bi-shield-lock-fill me-2"></i>KRONOS_INTEL // OSINT VIP</span>
            <a href="/download/txt/{{ token }}" class="btn btn-outline-info btn-sm rounded-3"><i class="bi bi-file-earmark-text me-1"></i> BAIXAR RELATÓRIO (.TXT)</a>
        </div>
    </nav>

    <div class="container pb-5">
        <div class="card-custom">
            <div class="card-body p-4">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="text-uppercase small code-tag">[ ALVO ANALISADO ]</span>
                    <span class="badge badge-found px-3 py-2 rounded-pill small"><i class="bi bi-check2-circle me-1"></i> Mapeamento Concluído</span>
                </div>
                <h2 class="text-white mb-1 font-monospace"><i class="bi bi-terminal-fill me-2 text-cyan"></i>{{ target }}</h2>
                <p class="text-muted mb-0 small"><i class="bi bi-clock me-1"></i> Auditado em: {{ data_atual }} | Módulo: {{ modulo_titulo }}</p>
            </div>
        </div>

        <div class="row">
            <div class="col-lg-{% if is_fullname or is_email %}12{% else %}7{% endif %}">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase">
                        <i class="bi bi-check-circle-fill me-2 text-success"></i>
                        {% if is_email %}
                            Bases e Fontes de Consulta de E-mail Mapeadas
                        {% elif is_fullname %}
                            Atalhos Mapeados para Tribunais e Diários Oficiais
                        {% else %}
                            Possíveis Perfis Localizados
                        {% endif %}
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
                        <p class="text-muted mb-0">Nenhum registro público direto localizado para este termo.</p>
                        {% endif %}
                    </div>
                </div>
            </div>

            {% if not is_fullname and not is_email %}
            <div class="col-lg-5">
                <div class="card-custom">
                    <div class="card-header-custom text-uppercase text-info">
                        <i class="bi bi-globe me-2"></i>Presença Digital & Menções
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

@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, query_type, created_at FROM payments WHERE token = ? AND status = 'approved' AND results_json IS NOT NULL", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado, expirado ou acesso pendente.", 404

    target, results_json_str, query_type, created_at = p[0], p[1], p[2], p[3]
    results_json = json.loads(results_json_str)
    
    is_fullname = (query_type == "fullname")
    is_email = (query_type == "email")
    encontrados = []
    
    if is_email or is_fullname:
        for k, v in results_json.items():
            encontrados.append({"nome": k, "url": v.get("url")})
    else:
        for plat, data in results_json.items():
            if data.get("exists") is True:
                url = data.get("url", PLATFORM_URLS.get(plat, "").format(username=target))
                encontrados.append({"nome": plat, "url": url})

    buscadores = obter_links_buscadores(target) if (not is_fullname and not is_email) else {}
    
    dt_obj = datetime.fromisoformat(created_at)
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=TIMEZONE_BR)
    data_formatada = dt_obj.astimezone(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")

    modulo_titulo = "CONSULTA DE E-MAIL" if is_email else ("BUSCA JUDICIAL" if is_fullname else "REDES SOCIAIS & USERNAME")

    return render_template_string(
        HTML_DASHBOARD_TEMPLATE,
        target=target,
        token=token,
        encontrados=encontrados,
        buscadores=buscadores,
        modulo_titulo=modulo_titulo,
        is_fullname=is_fullname,
        is_email=is_email,
        data_atual=data_formatada
    )

@app.route("/download/txt/<token>")
def download_txt(token):
    p = db_execute("SELECT target_username, results_json, query_type FROM payments WHERE token = ? AND status = 'approved' AND results_json IS NOT NULL", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou expirado.", 404

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

        if bot and CANAL_PRINCIPAL_ID and user_id != ADMIN_ID:
            try:
                msg_canal = "⚡ Novo usuário iniciou o bot de consultas OSINT!"
                bot.send_message(CANAL_PRINCIPAL_ID, msg_canal)
            except Exception as ex:
                logger.error("Erro ao notificar no canal principal: %s", str(ex))

        menu_boas_vindas = (
            f"👋 Olá, {user_name}! Bem-vindo ao **Kronos Intel OSINT Bot v19.0**.\n\n"
            f"Sua plataforma avançada para investigação digital e inteligência cibernética.\n\n"
            f"🛠 **ESCOLHA O MÓDULO DE BUSCA QUE DESEJA USAR:**\n\n"
            f"1️⃣ **BUSCA POR USERNAME / REDES SOCIAIS:**\n"
            f"• Use `/user alvo123`\n"
            f"• Mapeia possíveis perfis em plataformas abertas.\n\n"
            f"2️⃣ **BUSCA POR E-MAIL (FONTES DE VERIFICAÇÃO):**\n"
            f"• Use `/email alvo@gmail.com`\n"
            f"• Gera painel de busca em bases globais.\n\n"
            f"3️⃣ **BUSCA POR NOME COMPLETO (ATALHOS JUDICIAIS):**\n"
            f"• Use `/nome João da Silva`\n"
            f"• Conecta aos motores do Jusbrasil, Escavador e Diários Oficiais.\n\n"
            f"⚙️ **PRIVACIDADE (LGPD):**\n"
            f"• Use `/apagar` para excluir instantaneamente todos os seus registros.\n\n"
            f"📢 **Canal Oficial:** {CANAL_TAG_PUBLICO}\n"
            f"💬 **Suporte Direto:** @{SUPORTE_USERNAME}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_canal = InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
        markup.add(btn_canal, btn_suporte)

        bot.send_message(message.chat.id, menu_boas_vindas, parse_mode="Markdown", reply_markup=markup)

    @bot.message_handler(commands=['apagar'])
    def handle_apagar_dados(message):
        user_id = message.from_user.id
        db_execute("DELETE FROM users WHERE user_id = ?", (user_id,), commit=True)
        db_execute("UPDATE payments SET target_username='(apagado)', results_json=NULL, pix_code=NULL WHERE user_id = ?", (user_id,), commit=True)
        bot.reply_to(message, "🗑️ **Solicitação de Privacidade LGPD Concluída:** Seus dados de acesso e pesquisas associados foram apagados permanentemente do sistema.", parse_mode="Markdown")

    @bot.message_handler(content_types=['document', 'photo', 'audio', 'video', 'voice', 'sticker'])
    def handle_invalid_media(message):
        if message.chat.type in ['group', 'supergroup']:
            return
        responder_seguro(message, "⚠️ **Comando Inválido!**\nEnvio de arquivos, PDFs, imagens ou mídias não são aceitos.", parse_mode="Markdown")
        orientar_uso_correto(message.chat.id)

    # --- COMANDO /user (EXCLUSIVO PARA USERNAME) ---
    @bot.message_handler(commands=['user'])
    def handle_user_command(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ **Limite de buscas atingido!**\nVocê atingiu o limite de 6 consultas por hora. Aguarde um momento para realizar novas varreduras.")
            return

        texto_limpo = message.text.replace("\n", " ").strip()
        partes = texto_limpo.split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ **Comando Incompleto!**\nEnvie o username após o comando `/user`.\nExemplo: `/user alvo123`", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        target_user = partes[1].replace("@", "").strip()

        if not RE_USERNAME.match(target_user):
            responder_seguro(message, "⚠️ **Username Inválido!**\nEnvia apenas letras, números, pontos e traços (sem e-mail, espaços ou links).", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        msg_status = responder_seguro(message, f"🔎 Mapeando plataformas para @{target_user}...")
        resultados = executar_varredura_osint(target_user, is_fullname=False, is_email=False)
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]

        if msg_status:
            try:
                bot.edit_message_text(f"✅ Mapeamento concluído para @{target_user}!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

        if encontrados:
            hash_alvo = registrar_hash_alvo(target_user, "username")
            lista_plataformas = "\n".join([f"• {p}" for p in encontrados])
            texto_resultado = (
                f"🎯 POSSÍVEIS PERFIS PARA @{target_user}\n"
                f"───────────────────────────────\n\n"
                f"{lista_plataformas}\n\n"
                f"⚠️ Identificamos {len(encontrados)} possíveis plataformas associadas a este termo.\n\n"
                f"Deseja obter o Painel Interativo Web com os links diretos para cada perfil, presença digital (Yandex/Google) e relatório TXT?\n\n"
                f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                f"👉 Faça parte do nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 OBTER RELATÓRIO COMPLETO (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
            btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data="final_cancel")
            markup.add(btn_sim, btn_canal, btn_nao)

            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
        else:
            bot.send_message(
                message.chat.id,
                f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{target_user}.\n\n"
                f"👉 Fique por dentro de novas técnicas de OSINT no nosso canal: {CANAL_TAG_PUBLICO}"
            )

    # --- COMANDO /email (EXCLUSIVO PARA BUSCA DE E-MAIL) ---
    @bot.message_handler(commands=['email'])
    def handle_email_command(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ **Limite de buscas atingido!**\nVocê atingiu o limite de 6 consultas por hora.")
            return

        texto_limpo = message.text.replace("\n", " ").strip()
        partes = texto_limpo.split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ **Comando Incompleto!**\nEnvie o e-mail após o comando `/email`.\nExemplo: `/email alvo@gmail.com`", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        email_alvo = partes[1].strip()

        if not e_email_valido(email_alvo):
            responder_seguro(message, "⚠️ **Comando Inválido para E-mail!**\nO comando `/email` exige um e-mail válido no formato `usuario@dominio.com`.", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        hash_alvo = registrar_hash_alvo(email_alvo, "email")

        texto_email = (
            f"📧 MÓDULO DE CONSULTA DE E-MAIL:\n"
            f"👤 {email_alvo}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com os atalhos organizados para as principais plataformas de verificação:\n"
            f"• Have I Been Pwned\n"
            f"• DeHashed\n"
            f"• Intelligence X (IntelX)\n"
            f"• BreachDirectory\n"
            f"• Leak-Lookup & Scylla\n\n"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Acompanhe alertas no canal: {CANAL_TAG_PUBLICO}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_sim = InlineKeyboardButton(f"⚡ 🔓 GERAR PAINEL DE E-MAIL (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
        btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
        markup.add(btn_sim, btn_canal, btn_nao)

        bot.send_message(message.chat.id, texto_email, reply_markup=markup)

    # --- COMANDO /nome (EXCLUSIVO PARA NOME COMPLETO) ---
    @bot.message_handler(commands=['nome'])
    def handle_nome_command(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ **Limite de buscas atingido!**\nVocê atingiu o limite de 6 consultas por hora.")
            return

        texto_limpo = message.text.replace("\n", " ").strip()
        partes = texto_limpo.split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ **Comando Incompleto!**\nEnvie o nome completo após o comando `/nome`.\nExemplo: `/nome João da Silva`", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        nome_alvo = partes[1].strip()

        if not e_nome_completo(nome_alvo) or "@" in nome_alvo or e_url(nome_alvo):
            responder_seguro(message, "⚠️ **Comando Inválido para Nome Completo!**\nO comando `/nome` exige nome e sobrenome completo (sem e-mails ou URLs).", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        hash_alvo = registrar_hash_alvo(nome_alvo, "fullname")

        texto_oferta = (
            f"🔍 BUSCA JUDICIAL E REGISTROS PÚBLICOS:\n"
            f"👤 {nome_alvo.upper()}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com consultas configuradas para os principais portais públicos:\n"
            f"• Jusbrasil e Escavador\n"
            f"• Diários Oficiais Estaduais e União\n"
            f"• Portal da Transparência\n\n"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Entre no nosso canal oficial: {CANAL_TAG_PUBLICO}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_sim = InlineKeyboardButton(f"⚡ 🔓 GERAR PAINEL JUDICIAL (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
        btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
        markup.add(btn_sim, btn_canal, btn_nao)

        bot.send_message(message.chat.id, texto_oferta, reply_markup=markup)

    # --- COMANDO /stats (ENVIO EXCLUSIVO PARA O GRUPO DE LOGS CONFIGURADO) ---
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

        data_hora_solicitacao = datetime.now(TIMEZONE_BR).strftime('%d/%m/%Y às %H:%M:%S')

        relatorio_financeiro = (
            f"📊 **RELATÓRIO FINANCEIRO E MÉTRICAS DE USO**\n"
            f"───────────────────────────────\n"
            f"👤 **Usuários Totais Registrados:** {total_users}\n"
            f"🔎 **Total de Buscas Executadas:** {searches}\n"
            f"📄 **Relatórios VIP Gerados:** {reports}\n"
            f"💰 **Vendas Aprovadas (Pix):** {qtd_vendas}\n"
            f"💵 **Faturamento Total Adquirido:** R$ {faturamento:.2f}\n"
            f"───────────────────────────────\n"
            f"📅 **Solicitado em:** {data_hora_solicitacao}"
        )

        grupo_target = obter_grupo_logs_id()
        
        try:
            bot.send_message(grupo_target, relatorio_financeiro, parse_mode="Markdown")
            logger.info("Relatório de estatísticas enviado para o grupo de logs: %s", grupo_target)
            if message.chat.type == 'private':
                bot.reply_to(message, "✅ Relatório de estatísticas enviado diretamente para o grupo de logs/financeiro.")
        except Exception as e:
            logger.error("Falha ao enviar relatório para o grupo (%s): %s", grupo_target, str(e))
            bot.reply_to(
                message,
                f"⚠️ **Erro ao enviar para o grupo ({grupo_target}):** Verifique se o bot é administrador do grupo.",
                parse_mode="Markdown"
            )

    @bot.message_handler(commands=['conceder'])
    def handle_conceder_command(message):
        if message.from_user.id != ADMIN_ID:
            return

        partes = message.text.strip().split(maxsplit=2)
        if len(partes) < 3:
            responder_seguro(message, "⚠️ Uso incorreto!\nFormato correto: /conceder <user_id> <termo_alvo>")
            return

        try:
            target_user_id = int(partes[1])
            alvo = partes[2].strip()
        except ValueError:
            responder_seguro(message, "⚠️ ID de usuário inválido.")
            return

        is_fullname = e_nome_completo(alvo)
        is_email = e_email_valido(alvo)
        qtype = "email" if is_email else ("fullname" if is_fullname else "username")

        resultados = executar_varredura_osint(alvo, is_fullname=is_fullname, is_email=is_email)
        results_json = json.dumps(resultados)
        token_relatorio = secrets.token_urlsafe(16)
        pid_cortesia = f"cortesia_{int(time.time())}"

        db_execute(
            "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at) "
            "VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?) "
            "ON CONFLICT(payment_id) DO UPDATE SET status='approved', token=excluded.token, results_json=excluded.results_json",
            (pid_cortesia, target_user_id, alvo, token_relatorio, qtype, results_json, datetime.now(TIMEZONE_BR).isoformat()),
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
                f"A sua consulta foi liberada gratuitamente pelo administrador.\n\n"
                f"🔗 Clique no botão abaixo para acessar o painel:",
                reply_markup=markup
            )
            responder_seguro(message, f"✅ Acesso cortesia concedido com sucesso para o ID {target_user_id}.")
        except Exception as e:
            responder_seguro(message, f"⚠️ Acesso gravado no banco. Link do painel: {link_web}")

    # ENTRADA DE TEXTO DIRETO NO CHAT E MODO ADMIN
    @bot.message_handler(func=lambda message: True)
    def handle_search(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        if message.chat.type in ['group', 'supergroup']:
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ **Limite de buscas atingido!**\nVocê atingiu o limite de 6 consultas por hora.")
            return
        
        texto = message.text.replace("\n", " ").strip()
        
        if user_id == ADMIN_ID and texto.lower().startswith("admin"):
            partes_admin = texto.split(maxsplit=2)
            
            if len(partes_admin) >= 3 and partes_admin[1].lower() in ["user", "nome", "email"]:
                subcomando = partes_admin[1].lower()
                target = partes_admin[2].replace("@", "").strip()
                
                is_email = (subcomando == "email")
                is_fullname = (subcomando == "nome")
            else:
                target = texto.lower().replace("admin", "").replace("@", "").strip()
                is_email = e_email_valido(target)
                is_fullname = e_nome_completo(target) if not is_email else False

            if len(target) < 2:
                responder_seguro(message, "⚠️ Termo de busca muito curto para modo Admin.")
                return

            qtype = "email" if is_email else ("fullname" if is_fullname else "username")

            msg_status = responder_seguro(message, f"👑 [ADMIN VIP - {qtype.upper()}] Processando consulta...")
            resultados = executar_varredura_osint(target, is_fullname=is_fullname, is_email=is_email)
            results_json = json.dumps(resultados)
            token_relatorio = secrets.token_urlsafe(16)
            pid_admin = f"admin_{int(time.time())}"

            db_execute(
                "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, query_type, results_json, created_at) "
                "VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?) "
                "ON CONFLICT(payment_id) DO UPDATE SET status='approved', token=excluded.token",
                (pid_admin, user_id, target, token_relatorio, qtype, results_json, datetime.now(TIMEZONE_BR).isoformat()),
                commit=True
            )
            registrar_relatorio()

            if msg_status:
                try:
                    bot.edit_message_text(f"✅ Varredura Módulo {qtype.upper()} concluída!", chat_id=message.chat.id, message_id=msg_status.message_id)
                except Exception:
                    pass

            link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"
            markup = InlineKeyboardMarkup(row_width=1)
            markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web (ADMIN)", url=link_web))

            bot.send_message(
                message.chat.id,
                f"👑 [MODO ADMIN - {qtype.upper()}] Painel Web gerado com sucesso:",
                reply_markup=markup
            )
            return

        target = texto.replace("@", "").strip()

        if e_url(target):
            responder_seguro(message, "⚠️ **Comando Inválido!**\nBusca por URLs/links não são aceitas. Digite apenas o username, /email ou /nome.", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        if len(target) < 2:
            responder_seguro(message, "⚠️ Termo de busca muito curto.")
            return

        if e_email_valido(target):
            hash_alvo = registrar_hash_alvo(target, "email")
            texto_email = (
                f"📧 MÓDULO DE CONSULTA DE E-MAIL:\n"
                f"👤 {target}\n"
                f"───────────────────────────────\n\n"
                f"Gere o Painel Web Interativo com os atalhos organizados para as principais plataformas de verificação:\n"
                f"• Have I Been Pwned\n"
                f"• DeHashed\n"
                f"• Intelligence X (IntelX)\n"
                f"• BreachDirectory\n"
                f"• Leak-Lookup & Scylla\n\n"
                f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                f"👉 Acompanhe alertas no canal: {CANAL_TAG_PUBLICO}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 GERAR PAINEL DE E-MAIL (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
            btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
            btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
            markup.add(btn_sim, btn_canal, btn_nao)

            bot.send_message(message.chat.id, texto_email, reply_markup=markup)
            return

        if e_nome_completo(target):
            hash_alvo = registrar_hash_alvo(target, "fullname")
            texto_upsell_oferta = (
                f"🔍 BUSCA JUDICIAL E REGISTROS PÚBLICOS:\n"
                f"👤 {target.upper()}\n"
                f"───────────────────────────────\n\n"
                f"Gere o Painel Web Interativo com consultas configuradas para os principais portais públicos:\n"
                f"• Jusbrasil e Escavador\n"
                f"• Diários Oficiais Estaduais e União\n"
                f"• Portal da Transparência\n\n"
                f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                f"👉 Entre no nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 GERAR PAINEL JUDICIAL (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
            btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
            btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
            markup.add(btn_sim, btn_canal, btn_nao)

            bot.send_message(message.chat.id, texto_upsell_oferta, reply_markup=markup)
            return

        if not RE_USERNAME.match(target):
            responder_seguro(message, "⚠️ **Username Inválido!**\nUse apenas letras, números, pontos ou traços.", parse_mode="Markdown")
            orientar_uso_correto(message.chat.id)
            return

        msg_status = responder_seguro(message, f"🔎 Mapeando plataformas para @{target}...")
        resultados = executar_varredura_osint(target, is_fullname=False, is_email=False)
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]

        if msg_status:
            try:
                bot.edit_message_text(f"✅ Mapeamento concluído para @{target}!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

        if encontrados:
            hash_alvo = registrar_hash_alvo(target, "username")
            lista_plataformas = "\n".join([f"• {p}" for p in encontrados])
            texto_resultado = (
                f"🎯 POSSÍVEIS PERFIS PARA @{target}\n"
                f"───────────────────────────────\n\n"
                f"{lista_plataformas}\n\n"
                f"⚠️ Identificamos {len(encontrados)} possíveis plataformas associadas a este termo.\n\n"
                f"Deseja obter o Painel Interativo Web com os links diretos para cada perfil, presença digital (Yandex/Google) e relatório TXT?\n\n"
                f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                f"👉 Faça parte do nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton(f"⚡ 🔓 OBTER RELATÓRIO COMPLETO (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
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

    # --- CALLBACK LISTENER COM EXTRAÇÃO DE PIX_CODE DO BANCO ---
    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("b_"):
            hash_curto = call.data.split("b_")[1]
            target, qtype = obter_alvo_por_hash(hash_curto)

            if not target:
                bot.answer_callback_query(call.id, "Sessão expirada. Por favor, envie a busca novamente.")
                return

            user_id = call.from_user.id
            bot.answer_callback_query(call.id, f"Gerando Chave Pix de R$ {PRECO_PADRAO:.2f}...")
            
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target, valor=PRECO_PADRAO, query_type=qtype)

            if qr_pix:
                texto_oferta = (
                    f"🔒 CONSULTA KRONOS INTEL VIP\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Interativo Web Exclusivo ({qtype.upper()})\n"
                    f"2. Mapeamento Direto de Fontes e Dados\n"
                    f"3. Relatório Executivo para Download (.TXT)\n\n"
                    f"💰 Valor: R$ {PRECO_PADRAO:.2f} no Pix (Válido por 30 minutos)\n\n"
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
                text=f"👍 Entendido! Digite um username, /email ou /nome para iniciar uma nova busca.\n\n👉 Acompanhe as novidades no canal: {CANAL_TAG_PUBLICO}"
            )

        elif call.data.startswith("getkey_"):
            try:
                uid = int(call.data.split("getkey_")[1])
                row = db_execute("SELECT pix_code FROM payments WHERE user_id = ? AND status = 'pending' ORDER BY created_at DESC LIMIT 1", (uid,), fetchone=True)
                if row and row[0]:
                    bot.answer_callback_query(call.id, "Enviando chave...")
                    bot.send_message(call.message.chat.id, text=f"`{row[0]}`", parse_mode="Markdown")
                else:
                    bot.answer_callback_query(call.id, "Chave Pix não encontrada ou já expirada.")
            except Exception as e:
                logger.error("Erro ao buscar pix_code no banco: %s", str(e))
                bot.answer_callback_query(call.id, "Erro ao recuperar chave Pix.")

@app.route(f"/telegram/{TELEGRAM_TOKEN}", methods=["POST"])
def telegram_webhook():
    if bot:
        try:
            data = request.get_json(force=True, silent=True)
            if data:
                update = Update.de_json(data)
                bot.process_new_updates([update])
                return jsonify({"status": "ok"}), 200
        except Exception as err:
            logger.exception("Erro ao processar update no webhook do Telegram: %s", str(err))
            return jsonify({"status": "ok"}), 200
    return jsonify({"error": "unauthorized"}), 403

# --- WEBHOOK MP COM REIVINDICAÇÃO ATÔMICA E ZERO DUPLICIDADE ---
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
        
        # Pre-check básico antes de bater na API do Mercado Pago
        p_check = db_execute("SELECT status FROM payments WHERE payment_id = ?", (pid_str,), fetchone=True)
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
                    resultados = executar_varredura_osint(target, is_fullname=is_fullname, is_email=is_email)
                    results_json = json.dumps(resultados)

                    # REIVINDICAÇÃO ATÔMICA
                    claimed = db_execute(
                        "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at) "
                        "VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?) "
                        "ON CONFLICT(payment_id) DO UPDATE SET status='approved', token=excluded.token, "
                        "results_json=excluded.results_json, query_type=excluded.query_type "
                        "WHERE payments.status <> 'approved' RETURNING payment_id",
                        (pid_str, telegram_id, target, payment_info.get("transaction_amount", PRECO_PADRAO),
                         token_relatorio, results_json, query_type, datetime.now(TIMEZONE_BR).isoformat()),
                        fetchone=True, commit=True
                    )

                    if not claimed:
                        return jsonify({"status": "ok"}), 200

                    if telegram_id and bot:
                        link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"

                        markup = InlineKeyboardMarkup(row_width=1)
                        markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web", url=link_web))
                        markup.add(InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}") )

                        bot.send_message(
                            telegram_id,
                            f"⚡ PAGAMENTO CONFIRMADO — KRONOS INTEL VIP\n\n"
                            f"Sua consulta foi liberada com sucesso!\n\n"
                            f"🔗 Clique no botão abaixo para acessar o painel e baixar o relatório TXT.\n\n"
                            f"👉 Faça parte do nosso canal oficial de novidades: {CANAL_TAG_PUBLICO}",
                            reply_markup=markup
                        )

                        registrar_relatorio()

                    grupo_logs_id = obter_grupo_logs_id()
                    if bot and grupo_logs_id:
                        try:
                            msg_venda_log = (
                                f"💰 NOVA VENDA APROVADA!\n\n"
                                f"• Valor: R$ {payment_info.get('transaction_amount', 0.0):.2f}\n"
                                f"• Módulo: {query_type.upper()}\n"
                                f"• Comprador ID: {telegram_id}"
                            )
                            bot.send_message(grupo_logs_id, msg_venda_log)
                        except Exception as log_err:
                            logger.error("Erro ao enviar log no grupo financeiro: %s", str(log_err))

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v19.0 Active.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
