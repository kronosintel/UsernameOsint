"""
Kronos Intel OSINT Bot v34.1 VIP
- Motor OSINT Tri-Estado Conservador (Zero Falso Positivo por construção)
- Verificação via APIs JSON nativas (GitHub, GitLab, Bluesky, Mastodon, Reddit, Keybase, etc.)
- SQLite em modo WAL com busy_timeout e Lock Cooperativo via banco de dados
- Validação Criptográfica de Webhook Mercado Pago (X-Signature HMAC-SHA256 e validação de troco/dono)
- Sanitização de PDF ReportLab e HTML Telegram contra falhas de renderização
- Sanitização LGPD Completa (Purge total de registros do usuário)
- Suporte Oficial: @kronosintel
"""
from __future__ import annotations

import base64
import hashlib
import html
import hmac
import io
import json
import logging
import os
import re
import secrets
import socket
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

# Dependências do ReportLab para geração de PDF
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

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

DEFAULT_TIMEOUT = 4.0
PORT = int(os.getenv("PORT", "5000"))
PRECO_PADRAO = 3.90
DB_FILE = os.getenv("DB_FILE", "/var/data/kronos_osint.db" if os.path.exists("/var/data") else "kronos_osint.db")
db_lock = Lock()
TIMEZONE_BR = ZoneInfo("America/Sao_Paulo")

RE_USERNAME = re.compile(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9._-]{2,40}$")
RE_CNPJ = re.compile(r"^\d{14}$")
RE_PLACA = re.compile(r"^[A-Z]{3}[0-9][A-Z0-9][0-9]{2}$")
RE_FONE = re.compile(r"^\d{10,11}$")

CANAL_PRINCIPAL_ID = int(os.getenv("CANAL_PRINCIPAL_ID", "-1003802363624"))
LOG_GROUP_ID = int(os.getenv("LOG_GROUP_ID", "-1003986408630"))
CANAL_TAG_PUBLICO = os.getenv("CANAL_TAG_PUBLICO", "@kronosinteloficial")
ADMIN_ID = int(os.getenv("ADMIN_ID", "5041637922"))
SUPORTE_USERNAME = os.getenv("SUPORTE_USERNAME", "kronosintel")
BOT_USERNAME = os.getenv("BOT_USERNAME", "KronosSearchbot")
WEB_BASE_URL = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com").rstrip('/')

MERCADOPAGO_TOKEN = os.getenv("MERCADOPAGO_TOKEN")
MERCADOPAGO_WEBHOOK_SECRET = (os.getenv("MERCADOPAGO_WEBHOOK_SECRET") or "").strip()
sdk = mercadopago.SDK(MERCADOPAGO_TOKEN) if MERCADOPAGO_TOKEN else None

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=False) if TELEGRAM_TOKEN else None

# Hash de segurança do path do webhook Telegram
WEBHOOK_SECRET_PATH = hashlib.sha256((TELEGRAM_TOKEN or "secret").encode()).hexdigest()[:32] if TELEGRAM_TOKEN else "secret_path"

_hist_rate_limit: dict[int, list[float]] = {}
_rate_limit_lock = Lock()
_orphan_alerts_sent: set[str] = set()
_orphan_lock = Lock()

DDD_ESTADOS = {
    "11": "São Paulo (Grande SP)", "12": "São Paulo (Vale do Paraíba/Litoral Norte)", "13": "São Paulo (Baixada Santista)",
    "14": "São Paulo (Bauru/Marília/Jaú)", "15": "São Paulo (Sorocaba/Itapetininga)", "16": "São Paulo (Ribeirão Preto/Franca)",
    "17": "São Paulo (São José do Rio Preto)", "18": "São Paulo (Presidente Prudente/Araçatuba)", "19": "São Paulo (Campinas/Piracicaba)",
    "21": "Rio de Janeiro (Capital/Metropolitana)", "22": "Rio de Janeiro (Norte/Região dos Lagos)", "24": "Rio de Janeiro (Serrana/Sul Fluminense)",
    "27": "Espírito Santo (Vitória/Metropolitana)", "28": "Espírito Santo (Sul)",
    "31": "Minas Gerais (Belo Horizonte)", "32": "Minas Gerais (Juiz de Fora)", "33": "Minas Gerais (Governador Valadares)",
    "34": "Minas Gerais (Uberlândia/Triângulo)", "35": "Minas Gerais (Poços de Caldas/Pouso Alegre)", "37": "Minas Gerais (Divinópolis)", "38": "Minas Gerais (Montes Claros)",
    "41": "Paraná (Curitiba)", "42": "Paraná (Ponta Grossa)", "43": "Paraná (Londrina)", "44": "Paraná (Maringá)", "45": "Paraná (Cascavel)", "46": "Paraná (Francisco Beltrão)",
    "47": "Santa Catarina (Joinville/Blumenau)", "48": "Santa Catarina (Florianópolis)", "49": "Santa Catarina (Chapecó)",
    "51": "Rio Grande do Sul (Porto Alegre)", "53": "Rio Grande do Sul (Pelotas)", "54": "Rio Grande do Sul (Caxias do Sul)", "55": "Rio Grande do Sul (Santa Maria)",
    "61": "Distrito Federal / Goiás (Entorno)", "62": "Goiás (Goiânia)", "64": "Goiás (Rio Verde)",
    "63": "Tocantins (Palmas)", "65": "Mato Grosso (Cuiabá)", "66": "Mato Grosso (Rondonópolis)", "67": "Mato Grosso do Sul (Campo Grande)",
    "68": "Acre (Rio Branco)", "69": "Rondônia (Porto Velho)",
    "71": "Bahia (Salvador)", "73": "Bahia (Ilhéus/Porto Seguro)", "74": "Bahia (Juazeiro)", "75": "Bahia (Feira de Santana)", "77": "Bahia (Vitória da Conquista)",
    "79": "Sergipe (Aracaju)", "81": "Pernambuco (Recife)", "82": "Alagoas (Maceió)", "83": "Paraíba (João Pessoa)", "84": "Rio Grande do Norte (Natal)",
    "85": "Ceará (Fortaleza)", "86": "Piauí (Teresina)", "87": "Pernambuco (Petrolina)", "88": "Ceará (Juazeiro do Norte)", "89": "Piauí (Picos)",
    "91": "Pará (Belém)", "92": "Amazonas (Manaus)", "93": "Pará (Santarém)", "94": "Pará (Marabá)", "95": "Roraima (Boa Vista)",
    "96": "Amapá (Macapá)", "97": "Amazonas (Coari)", "98": "Maranhão (São Luís)", "99": "Maranhão (Imperatriz)"
}

def escapar_html(texto: str) -> str:
    if not texto:
        return ""
    return html.escape(str(texto))

def sanitizar_pdf(texto: str) -> str:
    s = str(texto if texto is not None else "")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def link_pdf(url: str) -> str:
    seguro = re.sub(r"[\"'\s]", "", str(url or ""))
    if not seguro.lower().startswith(("http://", "https://")):
        return sanitizar_pdf(url)
    return f'<a href="{sanitizar_pdf(seguro)}">{sanitizar_pdf(seguro)}</a>'

def limite_busca_ok(user_id: int, maximo: int = 6, janela_segundos: int = 3600) -> bool:
    if user_id == ADMIN_ID:
        return True
    agora = time.time()
    with _rate_limit_lock:
        if len(_hist_rate_limit) > 5000:
            for k in [k for k, v in _hist_rate_limit.items() if not v or agora - v[-1] > 7200]:
                _hist_rate_limit.pop(k, None)
                
        historico = [t for t in _hist_rate_limit.get(user_id, []) if agora - t < janela_segundos]
        if len(historico) >= maximo:
            _hist_rate_limit[user_id] = historico
            return False
        historico.append(agora)
        _hist_rate_limit[user_id] = historico
        return True

def init_db():
    with db_lock:
        conn = sqlite3.connect(DB_FILE, timeout=30.0)
        cursor = conn.cursor()
        
        # Ativações para concorrência
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA busy_timeout = 30000")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                created_at TEXT,
                banned INTEGER DEFAULT 0,
                ban_reason TEXT
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
                results_json TEXT,
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS free_claims (
                user_id INTEGER PRIMARY KEY,
                claimed_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coupons (
                code TEXT PRIMARY KEY,
                max_uses INTEGER,
                uses_count INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS coupon_redemptions (
                code TEXT,
                user_id INTEGER,
                redeemed_at TEXT,
                PRIMARY KEY (code, user_id)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS worker_locks (
                nome TEXT PRIMARY KEY,
                expira_em TEXT
            )
        """)
        
        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES ('total_searches', 0)")
        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES ('total_reports', 0)")
        
        conn.commit()
        conn.close()

init_db()

def db_execute(query: str, params: tuple = (), fetchone=False, fetchall=False, commit=False):
    with db_lock:
        conn = sqlite3.connect(DB_FILE, timeout=30.0)
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

def adquirir_lock_worker(nome: str, renovar_s: int = 240) -> bool:
    agora = datetime.now(TIMEZONE_BR)
    expira = (agora + timedelta(seconds=renovar_s)).isoformat()
    with db_lock:
        conn = sqlite3.connect(DB_FILE, timeout=30.0)
        try:
            cur = conn.execute("CREATE TABLE IF NOT EXISTS worker_locks (nome TEXT PRIMARY KEY, expira_em TEXT)")
            cur = conn.execute(
                "INSERT INTO worker_locks (nome, expira_em) VALUES (?, ?) "
                "ON CONFLICT(nome) DO UPDATE SET expira_em = excluded.expira_em "
                "WHERE worker_locks.expira_em < ?",
                (nome, expira, agora.isoformat())
            )
            conn.commit()
            return cur.rowcount > 0
        except Exception as e:
            logger.error("Erro no Lock de Worker: %s", str(e))
            return False
        finally:
            conn.close()

def usuario_esta_banido(user_id: int) -> bool:
    res = db_execute("SELECT banned FROM users WHERE user_id = ?", (user_id,), fetchone=True)
    return res is not None and res[0] == 1

def usuario_ja_usou_gratis(user_id: int) -> bool:
    res = db_execute("SELECT 1 FROM free_claims WHERE user_id = ?", (user_id,), fetchone=True)
    return res is not None

def usuario_e_membro_canal(user_id: int) -> bool:
    if not bot or not CANAL_PRINCIPAL_ID:
        return False
    try:
        member = bot.get_chat_member(CANAL_PRINCIPAL_ID, user_id)
        return member.status in ['member', 'administrator', 'creator']
    except Exception as e:
        logger.error("Erro ao verificar membro no canal: %s", str(e))
        return False

def registrar_hash_alvo(alvo: str, query_type: str, resultados: dict | None = None) -> str:
    hash_curto = hashlib.md5(f"{alvo}_{query_type}".encode('utf-8')).hexdigest()[:10]
    res_json_str = json.dumps(resultados) if resultados else None
    db_execute(
        "INSERT INTO target_hashes (hash_id, target_value, query_type, results_json, created_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(hash_id) DO UPDATE SET target_value = EXCLUDED.target_value, query_type = EXCLUDED.query_type, "
        "results_json = COALESCE(EXCLUDED.results_json, target_hashes.results_json), created_at = EXCLUDED.created_at",
        (hash_curto, alvo, query_type, res_json_str, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )
    return hash_curto

def obter_alvo_por_hash(hash_curto: str) -> tuple[str | None, str | None, str | None]:
    res = db_execute("SELECT target_value, query_type, results_json FROM target_hashes WHERE hash_id = ?", (hash_curto,), fetchone=True)
    if res:
        return res[0], res[1], res[2]
    return None, None, None

def obter_grupo_logs_id() -> int:
    return LOG_GROUP_ID

def notificar_uso_grupo_logs(from_user, modulo_nome: str):
    if not bot or not LOG_GROUP_ID or from_user.id == ADMIN_ID:
        return
    try:
        raw_first = escapar_html(from_user.first_name or "Usuario")
        raw_last = escapar_html(from_user.last_name or "")
        nome_completo = f"{raw_first} {raw_last}".strip()
        username_str = f"@{escapar_html(from_user.username)}" if from_user.username else "Sem @username"
        data_hora = datetime.now(TIMEZONE_BR).strftime('%d/%m/%Y às %H:%M:%S')

        msg_log = (
            f"<b>🔎 NOVA CONSULTA EXECUTADA</b>\n"
            f"───────────────────────────────\n"
            f"• <b>ID do Usuário:</b> <code>{from_user.id}</code>\n"
            f"• <b>Nome:</b> {nome_completo}\n"
            f"• <b>Username:</b> {username_str}\n"
            f"• <b>Módulo Solicitado:</b> {escapar_html(modulo_nome.upper())}\n"
            f"• <b>Termo Varrito:</b> [PROTEGIDO POR PRIVACIDADE]\n"
            f"• <b>Data/Hora:</b> {data_hora}"
        )
        bot.send_message(LOG_GROUP_ID, msg_log, parse_mode="HTML")
    except Exception as e:
        logger.error("Erro ao enviar log de uso para o grupo: %s", str(e))

def setup_webhook():
    if bot and TELEGRAM_TOKEN:
        webhook_url = f"{WEB_BASE_URL}/telegram/{WEBHOOK_SECRET_PATH}"
        try:
            bot.remove_webhook()
            success = bot.set_webhook(url=webhook_url)
            logger.info("Webhook Telegram configurado: %s", success)
        except Exception as e:
            logger.error("Erro ao configurar Webhook Telegram: %s", str(e))

# --- MOTOR OSINT CONSERVADOR TRI-ESTADO (v34.1) ---
LIMITE_CORPO = 400_000
STATUS_NAO_EXISTE = (404, 410)
STATUS_INCONCLUSIVO = (401, 403, 405, 406, 409, 429, 451, 500, 501, 502, 503, 504, 520, 522, 524)
REDIRECT_NAO_ENCONTRADO = ("/login", "/signin", "/signup", "/register", "/home", "404", "/error", "not-found", "notfound", "typo", "subdomain=")

PLATAFORMAS: dict[str, dict[str, Any]] = {
    # APIs JSON (404 Real)
    "GitHub":       {"url": "https://api.github.com/users/{username}", "fonte": "api", "json": "nao_vazio", "cabecalhos": {"Accept": "application/vnd.github+json"}},
    "GitLab":       {"url": "https://gitlab.com/api/v4/users?username={username}", "fonte": "api", "json": "lista_cheia"},
    "Codeberg":     {"url": "https://codeberg.org/api/v1/users/{username}", "fonte": "api", "json": "nao_vazio"},
    "Bitbucket":    {"url": "https://api.bitbucket.org/2.0/users/{username}", "fonte": "api", "json": "nao_vazio"},
    "Docker Hub":   {"url": "https://hub.docker.com/v2/users/{username}/", "fonte": "api", "json": "nao_vazio"},
    "Hugging Face": {"url": "https://huggingface.co/api/users/{username}/overview", "fonte": "api", "json": "nao_vazio"},
    "Reddit":       {"url": "https://www.reddit.com/user/{username}/about.json", "fonte": "api", "json": "reddit", "cabecalhos": {"User-Agent": "kronos-osint/1.0 (contato: @kronosintel)"}},
    "Mastodon":     {"url": "https://mastodon.social/api/v1/accounts/lookup?acct={username}", "fonte": "api", "json": "nao_vazio"},
    "Bluesky":      {"url": "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={username}.bsky.social", "fonte": "api", "json": "nao_vazio", "status_nao_existe": (400, 404, 410)},
    "Lichess":      {"url": "https://lichess.org/api/user/{username}", "fonte": "api", "json": "nao_vazio"},
    "Chess.com":    {"url": "https://api.chess.com/pub/player/{username}", "fonte": "api", "json": "nao_vazio"},
    "Keybase":      {"url": "https://keybase.io/_/api/1.0/user/lookup.json?username={username}", "fonte": "api", "json": "keybase"},
    "npm":          {"url": "https://registry.npmjs.org/-/user/org.couchdb.user:{username}", "fonte": "api", "json": "nao_vazio"},

    # HTML com Indicador Positivo
    "YouTube":      {"url": "https://www.youtube.com/@{username}", "fonte": "html", "positivo": r'"channelId":"UC', "negativo": "this page isn't available"},
    "Twitch":       {"url": "https://www.twitch.tv/{username}", "fonte": "html", "positivo": r'"userLogin":"{username}"'},
    "Telegram":     {"url": "https://t.me/{username}", "fonte": "html", "positivo": r'tgme_page_title'},
    "Medium":       {"url": "https://medium.com/@{username}", "fonte": "html", "positivo": r'property="og:type" content="profile"', "negativo": "out of bounds"},
    "SoundCloud":   {"url": "https://soundcloud.com/{username}", "fonte": "html", "positivo": r'soundcloud:users:'},
    "Behance":      {"url": "https://www.behance.net/{username}", "fonte": "html", "positivo": r'featured_projects', "negativo": "we can't find that page"},
    "Dribbble":     {"url": "https://dribbble.com/{username}", "fonte": "html", "positivo": r'profile-avatar', "negativo": "page not found"},
    "Kaggle":       {"url": "https://www.kaggle.com/{username}", "fonte": "html", "positivo": r'"userUrl"'},
    "Replit":       {"url": "https://replit.com/@{username}", "fonte": "html", "positivo": r'userByUsername'},
    "Flickr":       {"url": "https://www.flickr.com/people/{username}/", "fonte": "html", "positivo": r'flickr\.com/photos/'},
    "Patreon":      {"url": "https://www.patreon.com/{username}", "fonte": "html", "positivo": r'patron_count'},
    "About.me":     {"url": "https://about.me/{username}", "fonte": "html", "positivo": r'user-name'},
    "Linktree":     {"url": "https://linktr.ee/{username}", "fonte": "html", "positivo": r'profile_title'},
    "Gravatar":     {"url": "https://en.gravatar.com/{username}", "fonte": "html", "positivo": r'gravatar\.com/avatar/'},
    "Kick":         {"url": "https://kick.com/{username}", "fonte": "html", "positivo": r'"user_id":'},
    "Roblox":       {"url": "https://www.roblox.com/user.aspx?username={username}", "fonte": "html", "positivo": r'profile-header'},
    "CodePen":      {"url": "https://codepen.io/{username}", "fonte": "html", "positivo": r'profile-header'},
    "Steam":        {"url": "https://steamcommunity.com/id/{username}", "fonte": "html", "positivo": r'actual_persona_name', "negativo": "the specified profile could not be found"},
    "PyPI":         {"url": "https://pypi.org/user/{username}/", "fonte": "html", "positivo": r'author-profile__name', "negativo": "404 not found"},

    # HTML com Inexistência Comprovada via HTTP Status
    "Tumblr":       {"url": "https://{username}.tumblr.com", "fonte": "html", "confiavel_200": True},
    "Disqus":       {"url": "https://disqus.com/by/{username}/", "fonte": "html", "confiavel_200": True},
    "WordPress":    {"url": "https://{username}.wordpress.com", "fonte": "html", "confiavel_200": True},
}

PLATFORM_URLS = {p: cfg["url"] for p, cfg in PLATAFORMAS.items()}

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
        "💡 COMO UTILIZAR O BOT CORRETAMENTE:\n\n"
        "1️⃣ 👤 Username: /user alvo123\n"
        "2️⃣ 📧 E-mail: /email alvo@dominio.com\n"
        "3️⃣ ⚖️ Nome Completo: /nome João da Silva\n"
        "4️⃣ 📱 Telefone: /fone 11999998888\n"
        "5️⃣ 🏢 CNPJ: /cnpj 00000000000191\n"
        "6️⃣ 🚗 Placa: /placa ABC1D23\n"
        "7️⃣ 🌐 Domínio: /dominio site.com"
    )
    try:
        bot.send_message(chat_id, msg_guia)
    except Exception as e:
        logger.error("Erro ao enviar orientação para %s: %s", chat_id, str(e))

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

    @staticmethod
    def _casa(padrao, texto: str) -> bool:
        if not padrao:
            return False
        try:
            return bool(re.search(padrao, texto, re.I | re.S))
        except re.error:
            return str(padrao).lower() in texto

    def _avaliar_json(self, cfg, resp):
        try:
            d = resp.json()
        except Exception:
            return None
        modo = cfg.get("json", "nao_vazio")
        if modo == "lista_cheia":
            return isinstance(d, list) and len(d) > 0
        if modo == "keybase":
            return bool(d.get("them"))
        if modo == "reddit":
            d = d.get("data") or {}
            return bool(d) and not d.get("is_suspended")
        return bool(d)

    def check_site(self, platform: str, cfg: dict) -> None:
        url = cfg["url"].format(username=self.username)
        fonte = cfg.get("fonte", "html")
        headers = dict(self.headers)
        headers.update(cfg.get("cabecalhos", {}))

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=(fonte == "api"))
            s = resp.status_code
            ne = tuple(cfg.get("status_nao_existe", STATUS_NAO_EXISTE))

            if s in ne:
                res = {"exists": False, "status": "nao_existe", "motivo": f"http_{s}"}
            elif s in STATUS_INCONCLUSIVO or s >= 500:
                res = {"exists": False, "status": "desconhecido", "motivo": f"http_{s}_bloqueio_ou_limite"}
            elif s in (301, 302, 303, 307, 308):
                loc = (resp.headers.get("Location") or "").lower()
                alvo = self.username.lower()
                if any(x in loc for x in REDIRECT_NAO_ENCONTRADO) or alvo not in loc:
                    res = {"exists": False, "status": "nao_existe", "motivo": "redirect_fora_do_perfil"}
                else:
                    res = {"exists": True, "url": url, "confianca": 0.70, "status": "existe", "motivo": "redirect_para_perfil"}
            elif 200 <= s < 300:
                if fonte == "api":
                    ok = self._avaliar_json(cfg, resp)
                    if ok is True:
                        res = {"exists": True, "url": url, "confianca": 1.0, "status": "existe", "motivo": "api_confirmou"}
                    elif ok is False:
                        res = {"exists": False, "status": "nao_existe", "motivo": "api_vazia_ou_suspensa"}
                    else:
                        res = {"exists": False, "status": "desconhecido", "motivo": "api_json_invalido"}
                else:
                    corpo = resp.text[:LIMITE_CORPO]
                    pos = cfg.get("positivo")
                    neg = cfg.get("negativo")

                    if neg and self._casa(neg, corpo):
                        res = {"exists": False, "status": "nao_existe", "motivo": "marcador_negativo_encontrado"}
                    elif pos and self._casa(pos, corpo):
                        res = {"exists": True, "url": url, "confianca": 0.95, "status": "existe", "motivo": "marcador_positivo_encontrado"}
                    elif cfg.get("confiavel_200"):
                        res = {"exists": True, "url": url, "confianca": 0.85, "status": "existe", "motivo": "http_200_confiavel"}
                    else:
                        res = {"exists": False, "status": "desconhecido", "motivo": "sem_marcador_positivo"}
            else:
                res = {"exists": False, "status": "desconhecido", "motivo": f"http_{s}_nao_tratado"}
        except Exception:
            res = {"exists": False, "status": "desconhecido", "motivo": "excecao_conexao"}

        with self._lock:
            self.results[platform] = res

    def run(self) -> dict[str, dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=20) as ex:
            futuros = [ex.submit(self.check_site, nome, cfg) for nome, cfg in PLATAFORMAS.items()]
            for f in futuros:
                try:
                    f.result(timeout=12.0)
                except Exception:
                    pass

        # Segunda passada de re-confirmação
        duvidosos = [(n, c) for n, c in PLATAFORMAS.items()
                     if self.results.get(n, {}).get("status") == "existe"
                     and self.results[n].get("confianca", 1.0) < 0.80]

        for nome, cfg in duvidosos:
            url = cfg["url"].format(username=self.username)
            try:
                r2 = requests.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)
                if r2.status_code in STATUS_NAO_EXISTE or any(x in r2.url.lower() for x in REDIRECT_NAO_ENCONTRADO):
                    self.results[nome] = {"exists": False, "status": "nao_existe", "motivo": "reconfirmacao_falhou"}
                else:
                    self.results[nome]["confianca"] = 0.90
            except Exception:
                self.results[nome] = {"exists": False, "status": "desconhecido", "motivo": "reconfirmacao_erro"}

        return self.results

def buscar_dados_cnpj_brasilapi(cnpj: str) -> dict[str, Any]:
    try:
        url = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj}"
        resp = requests.get(url, timeout=5.0)
        if resp.status_code == 200:
            d = resp.json()
            qsa_list = [f"{s.get('nome_socio', '')} ({s.get('qualificacao_socio', '')})" for s in d.get("qsa", [])]
            return {
                "Razão Social": d.get("razao_social"),
                "Nome Fantasia": d.get("nome_fantasia") or "Não Informado",
                "Situação Cadastral": d.get("descricao_situacao_cadastral"),
                "Data de Abertura": d.get("data_inicio_atividade"),
                "Capital Social": f"R$ {d.get('capital_social', 0):,.2f}",
                "Atividade Principal": d.get("cnae_fiscal_descricao"),
                "Endereço": f"{d.get('logradouro')}, {d.get('numero')} - {d.get('bairro')}, {d.get('municipio')}/{d.get('uf')} (CEP: {d.get('cep')})",
                "Quadro Societário (QSA)": ", ".join(qsa_list) if qsa_list else "Sem sócios declarados"
            }
    except Exception as e:
        logger.error("Erro na BrasilAPI CNPJ: %s", str(e))
    return {}

def analisar_infraestrutura_dominio(dominio: str) -> dict[str, Any]:
    dados = {}
    try:
        ip = socket.gethostbyname(dominio)
        dados["Endereço IP Servidor"] = ip
    except Exception:
        dados["Endereço IP Servidor"] = "Indisponível"

    try:
        resp = requests.get(f"https://dns.google/resolve?name={dominio}&type=MX", timeout=4.0)
        if resp.status_code == 200:
            mxs = [item.get("data") for item in resp.json().get("Answer", []) if "data" in item]
            dados["Servidores de E-mail (MX)"] = ", ".join(mxs) if mxs else "Nenhum registro MX localizado"
    except Exception:
        dados["Servidores de E-mail (MX)"] = "Consulta Falhou"

    return dados

def executar_varredura_osint(target: str, query_type: str = "username") -> dict[str, dict[str, Any]]:
    if query_type == "email":
        encoded_email = urllib.parse.quote(target)
        return {
            "Have I Been Pwned (Base de Vazamentos)": {"exists": True, "url": f"https://haveibeenpwned.com/account/{encoded_email}"},
            "DeHashed CyberIntelligence": {"exists": True, "url": f"https://dehashed.com/search?query={encoded_email}"},
            "Intelligence X (IntelX)": {"exists": True, "url": f"https://intelx.io/?s={encoded_email}"},
            "BreachDirectory Engine": {"exists": True, "url": f"https://breachdirectory.org/search?query={encoded_email}"},
            "Scylla.sh Data Leak": {"exists": True, "url": f"https://scylla.sh/search?q=email:{encoded_email}"},
            "Hudson Rock Crime Database": {"exists": True, "url": f"https://cavalier.hudsonrock.com/api/v1/osint-tools/search-by-email?email={encoded_email}"}
        }
    elif query_type == "fullname":
        encoded_name = urllib.parse.quote(f'"{target}"')
        return {
            "Jusbrasil (Processos e Diários)": {"exists": True, "url": f"https://www.jusbrasil.com.br/busca?q={encoded_name}"},
            "Escavador (Publicações Judiciais)": {"exists": True, "url": f"https://www.escavador.com/busca?q={encoded_name}"},
            "Portal da Transparência Federal": {"exists": True, "url": f"https://www.portaltransparencia.gov.br/busca?termo={urllib.parse.quote(target)}"},
            "Diário Oficial da União (IN.gov)": {"exists": True, "url": f"https://www.google.com/search?q=site:in.gov.br+{encoded_name}"},
            "Google Acadêmico & Publicações": {"exists": True, "url": f"https://scholar.google.com.br/scholar?q={encoded_name}"},
        }
    elif query_type == "fone":
        limpo = re.sub(r'\D', '', target)
        ddd = limpo[:2] if len(limpo) >= 10 else "N/A"
        regiao = DDD_ESTADOS.get(ddd, "Região Não Mapeada")

        res = {
            "Região & DDD": {"exists": True, "url": f"https://www.google.com/search?q=DDD+{ddd}"},
            "WhatsApp Direct Chat": {"exists": True, "url": f"https://wa.me/55{limpo}"},
            "Sync.ME Caller ID": {"exists": True, "url": f"https://sync.me/search/?number=55{limpo}"},
            "Truecaller Directory": {"exists": True, "url": f"https://www.truecaller.com/search/br/{limpo}"},
            "QualEmpresa Operadora": {"exists": True, "url": f"https://www.qualempresa.com.br/telefone/{limpo}"},
            "Google Search (Vazamentos)": {"exists": True, "url": f"https://www.google.com/search?q=%22{limpo}%22"}
        }
        res["Região Geográfica / UF"] = {"exists": True, "url": "#", "detalhes": regiao}
        return res

    elif query_type == "cnpj":
        limpo = re.sub(r'\D', '', target)
        dados_reais = buscar_dados_cnpj_brasilapi(limpo)

        res = {
            "Receita Federal (Comprovante)": {"exists": True, "url": f"https://solucoes.receita.fazenda.gov.br/servicos/cnpjreva/cnpjreva_solicitacao.asp?cnpj={limpo}"},
            "CNPJ.biz Consultas": {"exists": True, "url": f"https://cnpj.biz/{limpo}"},
            "Casa dos Dados (QSA)": {"exists": True, "url": f"https://casadosdados.com.br/solucao/cnpj/{limpo}"},
            "Transparência CC Empresa": {"exists": True, "url": f"https://transparencia.cc/cnpj/{limpo}"},
            "Jusbrasil Societário": {"exists": True, "url": f"https://www.jusbrasil.com.br/busca?q={limpo}"}
        }
        if dados_reais:
            res["Dados Oficiais Receita Federal"] = {"exists": True, "url": "#", "detalhes": dados_reais}
        return res

    elif query_type == "placa":
        placa = target.upper().replace("-", "")
        return {
            "Sinesp Cidadão (Atalho)": {"exists": True, "url": f"https://www.google.com/search?q=consultar+placa+{placa}"},
            "Tabela FIPE Veículos": {"exists": True, "url": f"https://www.google.com/search?q=fipe+placa+{placa}"},
            "QualVeiculo Registro": {"exists": True, "url": f"https://www.qualveiculo.net/?placa={placa}"},
            "Olho No Carro (Histórico)": {"exists": True, "url": f"https://www.olhonocarro.com.br/"}
        }
    elif query_type == "dominio":
        dom = target.lower().replace("https://", "").replace("http://", "").strip('/')
        dados_dns = analisar_infraestrutura_dominio(dom)

        res = {
            "Whois ICANN / DomainTools": {"exists": True, "url": f"https://whois.domaintools.com/{dom}"},
            "DNS Dumpster Infra": {"exists": True, "url": f"https://dnsdumpster.com/"},
            "SecurityTrails DNS History": {"exists": True, "url": f"https://securitytrails.com/domain/{dom}/dns"},
            "Shodan Host Search": {"exists": True, "url": f"https://www.shodan.io/search?query={dom}"},
            "Wayback Machine Archive": {"exists": True, "url": f"https://web.archive.org/web/*/{dom}"}
        }
        if dados_dns:
            res["Análise de DNS & Infraestrutura"] = {"exists": True, "url": "#", "detalhes": dados_dns}
        return res
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

def gerar_pdf_osint(target: str, resultados: dict[str, dict[str, Any]], query_type: str = "username") -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=20, textColor=colors.HexColor('#38bdf8'), spaceAfter=4)
    subtitle_style = ParagraphStyle('SubTitleStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=10, textColor=colors.HexColor('#9ca3af'), spaceAfter=15)
    header_table_style = ParagraphStyle('HeaderTableStyle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9, textColor=colors.HexColor('#ffffff'))
    cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#374151'))
    cell_url_style = ParagraphStyle('CellUrlStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#2563eb'))

    story.append(Paragraph("KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT", title_style))
    story.append(Paragraph("SISTEMA DE INTELIGÊNCIA CIBERNÉTICA E AUDITORIA DIGITAL VIP", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#38bdf8'), spaceAfter=15))

    data_atual = datetime.now(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")
    titulos_map = {
        "email": "CONSULTA DE E-MAIL & VAZAMENTOS", "fullname": "BUSCA JUDICIAL & REGISTROS", "fone": "TELEFONE & WHATSAPP",
        "cnpj": "REGISTRO EMPRESARIAL (CNPJ)", "placa": "REGISTRO DE VEÍCULOS (PLACA)", "dominio": "INFRAESTRUTURA DE DOMÍNIO", "username": "USERNAME / REDES SOCIAIS"
    }

    meta_data = [
        [Paragraph("<b>ALVO ANALISADO:</b>", cell_style), Paragraph(f"<b>{sanitizar_pdf(target)}</b>", cell_style)],
        [Paragraph("<b>MÓDULO DE BUSCA:</b>", cell_style), Paragraph(titulos_map.get(query_type, "GERAL"), cell_style)],
        [Paragraph("<b>DATA DA AUDITORIA:</b>", cell_style), Paragraph(data_atual, cell_style)],
        [Paragraph("<b>INTEGRIDADE HASH SHA-256:</b>", cell_style), Paragraph(hashlib.sha256(f"{target}_{data_atual}".encode()).hexdigest()[:24] + "...", cell_style)],
    ]
    t_meta = Table(meta_data, colWidths=[160, 380])
    t_meta.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f3f4f6')), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')), ('PADDING', (0,0), (-1,-1), 6)]))
    story.append(t_meta)
    story.append(Spacer(1, 15))

    story.append(Paragraph("<b>1. DADOS DE INTELIGÊNCIA EXTRAÍDOS</b>", styles['Heading2']))
    story.append(Spacer(1, 6))

    table_data = [[Paragraph("PLATAFORMA / CAMPO", header_table_style), Paragraph("INFORMAÇÃO / LINK DIRETO", header_table_style)]]

    for p, v in resultados.items():
        if isinstance(v, dict):
            if "detalhes" in v and isinstance(v["detalhes"], dict):
                for sub_k, sub_v in v["detalhes"].items():
                    table_data.append([Paragraph(f"<b>{sanitizar_pdf(sub_k)}</b>", cell_style), Paragraph(sanitizar_pdf(sub_v), cell_style)])
            elif "detalhes" in v:
                table_data.append([Paragraph(f"<b>{sanitizar_pdf(p)}</b>", cell_style), Paragraph(sanitizar_pdf(v["detalhes"]), cell_style)])
            elif v.get("exists") is True:
                url_str = v.get('url', '')
                table_data.append([Paragraph(f"<b>{sanitizar_pdf(p)}</b>", cell_style), Paragraph(link_pdf(url_str), cell_url_style)])

    t_results = Table(table_data, colWidths=[180, 360])
    t_results.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('PADDING', (0,0), (-1,-1), 6),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_results)
    story.append(Spacer(1, 20))

    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#94a3b8'), spaceAfter=10))
    story.append(Paragraph("<font size=8 color='#64748b'>Documento compilado de dados públicos abertos por Kronos Intel OSINT Service. Para suporte: @kronosintel</font>", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer

def construir_relatorio_osint(target: str, resultados: dict[str, dict[str, Any]], query_type: str = "username") -> io.BytesIO:
    data_atual = datetime.now(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")
    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT
===================================================================
ALVO ANALISADO: {target}
TIPO DE CONSULTA: {query_type.upper()}
DATA DA CONSULTA: {data_atual}
SISTEMA: Kronos Engine v34.1 VIP
===================================================================
1. DADOS DE INTELIGÊNCIA E BASES MAPEADAS
-------------------------------------------------------------------
"""
    for p, v in resultados.items():
        if isinstance(v, dict):
            if "detalhes" in v and isinstance(v["detalhes"], dict):
                corpo += f"\n[+] --- {p.upper()} ---\n"
                for sub_k, sub_v in v["detalhes"].items():
                    corpo += f"    • {sub_k.ljust(25)} : {sub_v}\n"
            elif "detalhes" in v:
                corpo += f"[+] {p.ljust(28)} : {v['detalhes']}\n"
            elif v.get("exists") is True:
                url_str = v.get('url', '')
                corpo += f"[+] {p.ljust(28)} : {url_str}\n"

    corpo += """
===================================================================
Documento de compilação gerado por Kronos Intel OSINT Service.
===================================================================
"""
    buf = io.BytesIO(corpo.encode('utf-8'))
    buf.name = f"Relatorio_OSINT_{target.replace(' ', '_')}.txt"
    return buf

def gerar_pix_mercadopago(user_id: int, target: str, valor: float, query_type: str = "username", results_json_str: str | None = None) -> tuple[str | None, bytes | None, str | None]:
    if not sdk:
        return None, None, None
    token_relatorio = secrets.token_urlsafe(16)
    expiracao = (datetime.now(TIMEZONE_BR) + timedelta(minutes=30)).isoformat(timespec="milliseconds")
    
    payment_data = {
        "transaction_amount": float(valor),
        "description": "Consulta de Dados Publicos OSINT",
        "payment_method_id": "pix",
        "date_of_expiration": expiracao,
        "notification_url": f"{WEB_BASE_URL}/webhook",
        "payer": {"email": f"user_{user_id}@telegram.com", "first_name": "Usuario", "last_name": str(user_id)},
        "metadata": {"telegram_user_id": user_id, "token": token_relatorio}
    }
    try:
        res = sdk.payment().create(payment_data).get("response", {})
        tx = res.get("point_of_interaction", {}).get("transaction_data", {})
        qr_code = tx.get("qr_code")
        qr_base64 = tx.get("qr_code_base64")
        img_bytes = base64.b64decode(qr_base64) if qr_base64 else None
        
        pid = str(res.get("id"))
        
        db_execute(
            "INSERT INTO payments (payment_id, user_id, target_username, amount, status, reminded, token, pix_code, results_json, query_type, created_at) "
            "VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?, ?) "
            "ON CONFLICT(payment_id) DO UPDATE SET target_username=excluded.target_username, token=excluded.token, "
            "pix_code=excluded.pix_code, results_json=COALESCE(excluded.results_json, payments.results_json), query_type=excluded.query_type",
            (pid, user_id, target, valor, token_relatorio, qr_code, results_json_str, query_type, datetime.now(TIMEZONE_BR).isoformat()),
            commit=True
        )
        return qr_code, img_bytes, token_relatorio
    except Exception as e:
        logger.error("Erro ao gerar Pix: %s", str(e))
        return None, None, None

def gerar_painel_gratuito_membro(user_id: int, target: str, query_type: str, resultados: dict) -> str:
    results_json = json.dumps(resultados)
    token_relatorio = secrets.token_urlsafe(16)
    pid_free = f"free_claim_{user_id}_{secrets.token_hex(6)}"

    db_execute(
        "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at) "
        "VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?) "
        "ON CONFLICT(payment_id) DO UPDATE SET status='approved', token=excluded.token, results_json=excluded.results_json",
        (pid_free, user_id, target, token_relatorio, query_type, results_json, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )
    registrar_relatorio()

    return f"{WEB_BASE_URL}/relatorio/{token_relatorio}"

def executar_consulta_admin_direta(admin_id: int, target: str, query_type: str) -> tuple[str, str]:
    resultados = executar_varredura_osint(target, query_type=query_type)
    results_json = json.dumps(resultados)
    token_relatorio = secrets.token_urlsafe(16)
    pid_admin = f"admin_exec_{admin_id}_{secrets.token_hex(6)}"

    db_execute(
        "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at) "
        "VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?) "
        "ON CONFLICT(payment_id) DO UPDATE SET status='approved', token=excluded.token, results_json=excluded.results_json",
        (pid_admin, admin_id, target, token_relatorio, query_type, results_json, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )
    registrar_relatorio()
    link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"
    return link_web, token_relatorio

def construir_markup_oferta(hash_alvo: str, user_id: int) -> InlineKeyboardMarkup:
    markup = InlineKeyboardMarkup(row_width=1)
    
    if not usuario_ja_usou_gratis(user_id):
        btn_gratis = InlineKeyboardButton("🎁 RESGATAR RELATÓRIO GRATUITO (Membros)", callback_data=f"claimfree_{hash_alvo}")
        markup.add(btn_gratis)

    btn_sim = InlineKeyboardButton(f"⚡ 🔓 OBTER PAINEL COMPLETO (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
    btn_canal = InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
    btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
    
    markup.add(btn_sim, btn_canal, btn_nao)
    return markup

def worker_divulgacao_diaria():
    if not adquirir_lock_worker("divulgacao_diaria", renovar_s=1800):
        return

    ultimo_envio = None
    while True:
        try:
            time.sleep(300)
            now = datetime.now(TIMEZONE_BR)

            if now.hour == 10 and (ultimo_envio is None or ultimo_envio.date() < now.date()):
                if bot and CANAL_PRINCIPAL_ID:
                    msg_divulgacao = (
                        "👑 KRONOS INTEL — CENTRAL DE INVESTIGAÇÃO OSINT ⚡\n\n"
                        "Quer localizar dados públicos, perfis de redes sociais, vazamentos de e-mail ou consultas empresariais em segundos?\n\n"
                        "🛠️ VEJA COMO É FÁCIL USAR O NOSSO BOT:\n\n"
                        "1️⃣ 👤 Username: /user alvo123\n"
                        "2️⃣ 📧 E-mail: /email exemplo@dominio.com\n"
                        "3️⃣ ⚖️ Nome Completo: /nome Carlos Eduardo\n"
                        "4️⃣ 📱 Telefone: /fone 11999998888\n"
                        "5️⃣ 🏢 CNPJ / Empresas: /cnpj 00000000000191\n"
                        "6️⃣ 🚗 Veículos (Placa): /placa ABC1D23\n"
                        "7️⃣ 🌐 Domínios & DNS: /dominio site.com\n\n"
                        "🎁 NOVO NO CANAL? GANHE 1 CONSULTA GRATUITA!\n"
                        "Todos os membros do nosso canal oficial ganham 1 relatório VIP completo de cortesia.\n\n"
                        "👇 Clique abaixo para iniciar suas buscas agora mesmo:"
                    )

                    markup = InlineKeyboardMarkup(row_width=1)
                    btn_usar = InlineKeyboardButton("🚀 Abrir Bot de Consultas Agora", url=f"https://t.me/{BOT_USERNAME}")
                    markup.add(btn_usar)

                    bot.send_message(CANAL_PRINCIPAL_ID, msg_divulgacao, reply_markup=markup)
                    ultimo_envio = now
                    logger.info("Mensagem diária de divulgação enviada no Canal Principal com sucesso.")
        except Exception as e:
            logger.error("Erro no worker de divulgação diária: %s", str(e))

def worker_background():
    if not adquirir_lock_worker("background_remarketing", renovar_s=300):
        return

    while True:
        try:
            time.sleep(60)
            now = datetime.now(TIMEZONE_BR)

            pendentes = db_execute(
                "SELECT payment_id, user_id, target_username, created_at, query_type, results_json FROM payments WHERE status = 'pending' AND reminded = 0",
                fetchall=True
            )
            if pendentes:
                for p in pendentes:
                    pid, uid, target, created_str, qtype, rj = p[0], p[1], p[2], p[3], p[4], p[5]
                    
                    if target.startswith("(") or not rj:
                        db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                        continue

                    try:
                        created_time = datetime.fromisoformat(created_str)
                        if created_time.tzinfo is None:
                            created_time = created_time.replace(tzinfo=TIMEZONE_BR)
                        minutos_decorridos = (now - created_time).total_seconds() / 60
                        
                        if 10 <= minutos_decorridos < 30:
                            db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                            if bot:
                                parsed_rj = json.loads(rj) if rj else None
                                hash_alvo = registrar_hash_alvo(target, qtype, parsed_rj)
                                msg_lembrete = (
                                    f"⏳ O seu código Pix de consulta expira em breve.\n\n"
                                    f"Conclua a liberação do seu relatório interativo por R$ {PRECO_PADRAO:.2f} no Pix."
                                )
                                markup = InlineKeyboardMarkup(row_width=1)
                                markup.add(InlineKeyboardButton(f"⚡ 🔓 CONCLUIR AGORA (R$ {PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}"))
                                bot.send_message(uid, msg_lembrete, reply_markup=markup)
                        elif minutos_decorridos >= 30:
                            db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                    except Exception as ex:
                        logger.error("Erro no remarketing: %s", str(ex))

            lim_hashes = (now - timedelta(days=1)).isoformat()
            db_execute("DELETE FROM target_hashes WHERE created_at < ?", (lim_hashes,), commit=True)
            
            lim_payments = (now - timedelta(days=30)).isoformat()
            db_execute("UPDATE payments SET results_json=NULL, target_username='(expirado)' WHERE created_at < ? AND target_username NOT LIKE '(%'", (lim_payments,), commit=True)

        except Exception as e:
            logger.error("Erro no worker background: %s", str(e))

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

        .code-tag {
            font-family: monospace;
            color: var(--accent-cyan);
        }

        .badge-found {
            background-color: rgba(52, 211, 153, 0.2);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
        }

        .info-label {
            color: #9ca3af;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .info-value {
            color: #f9fafb;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark sticky-top mb-4 py-3">
        <div class="container d-flex justify-content-between align-items-center">
            <span class="navbar-brand h1 mb-0"><i class="bi bi-shield-lock-fill me-2"></i>KRONOS_INTEL // OSINT VIP</span>
            <div>
                <a href="/download/pdf/{{ token }}" class="btn btn-info btn-sm rounded-3 me-2 text-white font-weight-bold"><i class="bi bi-file-earmark-pdf-fill me-1"></i> BAIXAR PDF VIP</a>
                <a href="/download/txt/{{ token }}" class="btn btn-outline-secondary btn-sm rounded-3"><i class="bi bi-file-earmark-text me-1"></i> TXT</a>
            </div>
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

        {% if detalhes_extra %}
        <div class="card-custom">
            <div class="card-header-custom text-uppercase">
                <i class="bi bi-database-check me-2 text-info"></i>
                Dados Estruturados Oficiais
            </div>
            <div class="card-body p-4">
                <div class="row g-3">
                    {% for k, v in detalhes_extra.items() %}
                    <div class="col-md-6 col-lg-4">
                        <div class="p-3 border rounded-3 bg-dark bg-opacity-50 h-100">
                            <div class="info-label mb-1">{{ k }}</div>
                            <div class="info-value text-break">{{ v }}</div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}

        <div class="card-custom">
            <div class="card-header-custom text-uppercase">
                <i class="bi bi-check-circle-fill me-2 text-success"></i>
                Bases, Fontes e Atalhos Mapeados
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
</body>
</html>
"""

@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, query_type, created_at FROM payments WHERE token = ? AND status = 'approved' AND results_json IS NOT NULL", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado, expirado ou acesso pendente.", 404

    target, results_json_str, query_type, created_at = p[0], p[1], p[2], p[3]
    
    try:
        results_json = json.loads(results_json_str) if isinstance(results_json_str, str) else results_json_str
    except Exception:
        results_json = {}

    encontrados = []
    detalhes_extra = {}

    if isinstance(results_json, dict):
        for k, v in results_json.items():
            if isinstance(v, dict):
                if "detalhes" in v and isinstance(v["detalhes"], dict):
                    detalhes_extra.update(v["detalhes"])
                elif "detalhes" in v:
                    detalhes_extra[k] = v["detalhes"]
                elif v.get("exists") is True and v.get("url") != "#":
                    encontrados.append({"nome": k, "url": v.get("url")})

    try:
        dt_obj = datetime.fromisoformat(created_at)
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=TIMEZONE_BR)
        data_formatada = dt_obj.astimezone(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        data_formatada = datetime.now(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")

    titulos_map = {
        "email": "CONSULTA DE E-MAIL", "fullname": "BUSCA JUDICIAL", "fone": "TELEFONE & WHATSAPP",
        "cnpj": "REGISTRO CNPJ", "placa": "VEÍCULOS (PLACA)", "dominio": "DOMÍNIOS & DNS", "username": "USERNAME / REDES SOCIAIS"
    }

    return render_template_string(
        HTML_DASHBOARD_TEMPLATE,
        target=target,
        token=token,
        encontrados=encontrados,
        detalhes_extra=detalhes_extra,
        modulo_titulo=titulos_map.get(query_type, "GERAL"),
        data_atual=data_formatada
    )

@app.route("/download/pdf/<token>")
def download_pdf(token):
    p = db_execute("SELECT target_username, results_json, query_type FROM payments WHERE token = ? AND status = 'approved' AND results_json IS NOT NULL", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou expirado.", 404

    target, results_json_str, query_type = p[0], p[1], p[2]
    try:
        results_json = json.loads(results_json_str) if isinstance(results_json_str, str) else results_json_str
    except Exception:
        results_json = {}
    
    pdf_buf = gerar_pdf_osint(target, results_json, query_type=query_type)

    return send_file(
        pdf_buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"Relatorio_VIP_{target.replace(' ', '_')}.pdf"
    )

@app.route("/download/txt/<token>")
def download_txt(token):
    p = db_execute("SELECT target_username, results_json, query_type FROM payments WHERE token = ? AND status = 'approved' AND results_json IS NOT NULL", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou expirado.", 404

    target, results_json_str, query_type = p[0], p[1], p[2]
    try:
        results_json = json.loads(results_json_str) if isinstance(results_json_str, str) else results_json_str
    except Exception:
        results_json = {}
    
    txt_buf = construir_relatorio_osint(target, results_json, query_type=query_type)
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
        
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        raw_first = escapar_html(message.from_user.first_name or "Usuario")
        raw_last = escapar_html(message.from_user.last_name or "")
        username_tg = f"@{escapar_html(message.from_user.username)}" if message.from_user.username else "Sem @username"
        nome_completo_tg = f"{raw_first} {raw_last}".strip()
        user_name = "".join(c for c in raw_first if c.isalnum() or c == " ")[:30].strip() or "Usuario"
        
        novo = db_execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,), fetchone=True) is None
        registrar_acesso(user_id)

        if message.chat.type == 'private' and novo and user_id != ADMIN_ID:
            grupo_logs_id = obter_grupo_logs_id()
            if grupo_logs_id:
                try:
                    data_hora_acesso = datetime.now(TIMEZONE_BR).strftime('%d/%m/%Y às %H:%M:%S')
                    msg_controle_logs = (
                        f"<b>👤 NOVO USUÁRIO (/start)</b>\n"
                        f"<b>ID:</b> <code>{user_id}</code>\n"
                        f"<b>Nome:</b> {nome_completo_tg}\n"
                        f"<b>Username:</b> {username_tg}\n"
                        f"<b>Chat:</b> tg://user?id={user_id}\n"
                        f"<b>Data:</b> {data_hora_acesso}"
                    )
                    bot.send_message(grupo_logs_id, msg_controle_logs, parse_mode="HTML")
                except Exception as ex_log:
                    logger.error("Erro ao enviar notificação de start no grupo de logs: %s", str(ex_log))

            if CANAL_PRINCIPAL_ID:
                try:
                    bot.send_message(CANAL_PRINCIPAL_ID, "⚡ Mais um usuário iniciou o bot de consultas OSINT!")
                except Exception as ex_canal:
                    logger.error("Erro ao notificar no canal principal: %s", str(ex_canal))

        menu_boas_vindas = (
            f"👑 KRONOS INTEL OSINT BOT v34.1 VIP ⚡\n"
            f"─────────────────────────────────────────────\n"
            f"👋 Olá, {user_name}! Bem-vindo à sua central avançada de inteligência cibernética e investigação digital!\n\n"
            f"🎁 GANHE 1 RELATÓRIO COMPLETO GRATUITO!\n"
            f"Membros do nosso canal oficial possuem direito a 1 consulta totalmente grátis!\n\n"
            f"🛠️ MÓDULOS DE CONSULTA DISPONÍVEIS:\n\n"
            f"1️⃣ 👤 USERNAME / REDES SOCIAIS:\n"
            f"   • /user alvo123\n\n"
            f"2️⃣ 📧 CONSULTA DE E-MAIL & VAZAMENTOS:\n"
            f"   • /email exemplo@dominio.com\n\n"
            f"3️⃣ ⚖️ NOME COMPLETO (ATALHOS JUDICIAIS):\n"
            f"   • /nome João da Silva\n\n"
            f"4️⃣ 📱 TELEFONE & WHATSAPP:\n"
            f"   • /fone 11999998888\n\n"
            f"5️⃣ 🏢 CNPJ & REGISTRO EMPRESARIAL:\n"
            f"   • /cnpj 00000000000191\n\n"
            f"6️⃣ 🚗 CONSULTA DE VEÍCULOS (PLACA):\n"
            f"   • /placa ABC1D23\n\n"
            f"7️⃣ 🌐 DOMÍNIOS & INFRAESTRUTURA WEB:\n"
            f"   • /dominio site.com\n\n"
            f"🎟️ CUPOM DE DESCONTO / CORTESIA:\n"
            f"   • /resgatar CODIGO\n\n"
            f"⚙️ PRIVACIDADE (LGPD):\n"
            f"   • Use /apagar para excluir seus registros.\n\n"
            f"📢 Canal Oficial: {CANAL_TAG_PUBLICO}\n"
            f"💬 Suporte Direto: @{SUPORTE_USERNAME}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        btn_canal = InlineKeyboardButton("📢 Entrar no Canal Oficial (Ganhar Relatório Grátis)", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
        btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
        markup.add(btn_canal, btn_suporte)

        bot.send_message(message.chat.id, menu_boas_vindas, reply_markup=markup)

    @bot.message_handler(commands=['admin'])
    def handle_admin_panel(message):
        if message.from_user.id != ADMIN_ID:
            return

        res_users = db_execute("SELECT COUNT(*) FROM users", fetchone=True)
        total_users = res_users[0] if res_users else 0

        res_searches = db_execute("SELECT value FROM metrics WHERE key = 'total_searches'", fetchone=True)
        searches = res_searches[0] if res_searches else 0

        vendas = db_execute("SELECT COUNT(*), SUM(amount) FROM payments WHERE status = 'approved' AND amount > 0", fetchone=True)
        qtd_vendas = vendas[0] if (vendas and vendas[0] is not None) else 0
        faturamento = vendas[1] if (vendas and vendas[1] is not None) else 0.0

        texto_admin = (
            f"👑 PAINEL CENTRAL DE ADMINISTRAÇÃO KRONOS INTEL\n"
            f"─────────────────────────────────────────────\n"
            f"📊 Métricas de Operação:\n"
            f"• Usuários Totais: {total_users}\n"
            f"• Buscas Executadas: {searches}\n"
            f"• Vendas Aprovadas: {qtd_vendas} (R$ {faturamento:.2f})\n\n"
            f"🛠️ COMANDOS DE GESTÃO DE USUÁRIOS:\n"
            f"• /ban <user_id> [motivo]\n"
            f"• /unban <user_id>\n"
            f"• /userinfo <user_id>\n"
            f"• /broadcast <mensagem_massa>\n"
            f"• /gerar_cupom <CODIGO> <limite_usos>\n\n"
            f"🛠️ COMANDOS DE CONSULTA DIRETA (ADMIN):\n"
            f"📱 /admin_fone 11999998888\n"
            f"🏢 /admin_cnpj 00000000000191\n"
            f"🚗 /admin_placa ABC1D23\n"
            f"🌐 /admin_dominio site.com\n"
            f"👤 /admin_user alvo123\n"
            f"📧 /admin_email alvo@dominio.com\n"
            f"⚖️ /admin_nome Carlos Eduardo\n\n"
            f"🎁 CONCESSÃO DE CORTESIA:\n"
            f"• /conceder <user_id> <termo_alvo>\n\n"
            f"📊 ENVIAR RELATÓRIO FINANCEIRO PRO GRUPO:\n"
            f"• /stats"
        )
        responder_seguro(message, texto_admin)

    @bot.message_handler(commands=['ban'])
    def handle_ban_command(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=2)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /ban <user_id> [motivo]")
            return
        try:
            target_id = int(partes[1])
            motivo = partes[2] if len(partes) > 2 else "Violação dos Termos de Uso"
            db_execute("UPDATE users SET banned = 1, ban_reason = ? WHERE user_id = ?", (motivo, target_id), commit=True)
            responder_seguro(message, f"🚫 Utilizador `{target_id}` banido com sucesso.\nMotivo: {motivo}")
        except ValueError:
            responder_seguro(message, "⚠️ ID inválido.")

    @bot.message_handler(commands=['unban'])
    def handle_unban_command(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /unban <user_id>")
            return
        try:
            target_id = int(partes[1])
            db_execute("UPDATE users SET banned = 0, ban_reason = NULL WHERE user_id = ?", (target_id,), commit=True)
            responder_seguro(message, f"✅ Utilizador `{target_id}` desbanido com sucesso.")
        except ValueError:
            responder_seguro(message, "⚠️ ID inválido.")

    @bot.message_handler(commands=['userinfo'])
    def handle_userinfo_command(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /userinfo <user_id>")
            return
        try:
            target_id = int(partes[1])
            u = db_execute("SELECT user_id, created_at, banned, ban_reason FROM users WHERE user_id = ?", (target_id,), fetchone=True)
            if not u:
                responder_seguro(message, "⚠️ Utilizador não encontrado na base de dados.")
                return
            gratis = usuario_ja_usou_gratis(target_id)
            compras = db_execute("SELECT COUNT(*), SUM(amount) FROM payments WHERE user_id = ? AND status = 'approved'", (target_id,), fetchone=True)
            qtd_compras = compras[0] if (compras and compras[0] is not None) else 0
            val_compras = compras[1] if (compras and compras[1] is not None) else 0.0

            msg_info = (
                f"👤 INFORMAÇÕES DO UTILIZADOR `{target_id}`\n"
                f"───────────────────────────────\n"
                f"• Registrado em: {u[1]}\n"
                f"• Status de Ban: {'🔴 BANIDO (' + str(u[3]) + ')' if u[2] == 1 else '🟢 ATIVO'}\n"
                f"• Usou Cortesia Grátis: {'SIM' if gratis else 'NÃO'}\n"
                f"• Total de Compras Aprovadas: {qtd_compras} (R$ {val_compras:.2f})"
            )
            responder_seguro(message, msg_info)
        except ValueError:
            responder_seguro(message, "⚠️ ID inválido.")

    @bot.message_handler(commands=['gerar_cupom'])
    def handle_gerar_cupom(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=2)
        if len(partes) < 3:
            responder_seguro(message, "⚠️ Uso correto: /gerar_cupom <CODIGO> <limite_usos>")
            return
        codigo = partes[1].upper().strip()
        try:
            limite = int(partes[2])
            db_execute(
                "INSERT INTO coupons (code, max_uses, uses_count, created_at) VALUES (?, ?, 0, ?) "
                "ON CONFLICT(code) DO UPDATE SET max_uses = excluded.max_uses",
                (codigo, limite, datetime.now(TIMEZONE_BR).isoformat()), commit=True
            )
            responder_seguro(message, f"🎟️ Cupom `{codigo}` gerado com sucesso para {limite} utilizações!")
        except ValueError:
            responder_seguro(message, "⚠️ O limite deve ser um número inteiro.")

    def _executar_broadcast_async(admin_chat_id: int, msg_text: str):
        usuarios = db_execute("SELECT user_id FROM users WHERE banned = 0", fetchall=True)
        if not usuarios:
            bot.send_message(admin_chat_id, "Nenhum utilizador encontrado para broadcast.")
            return

        sucessos, falhas = 0, 0
        for row in usuarios:
            uid = row[0]
            try:
                bot.send_message(uid, f"📢 NOTIFICAÇÃO KRONOS INTEL:\n\n{msg_text}")
                sucessos += 1
                time.sleep(0.04)
            except Exception:
                falhas += 1

        bot.send_message(admin_chat_id, f"✅ Transmissão Concluída!\n• Entregues: {sucessos}\n• Falhas: {falhas}")

    @bot.message_handler(commands=['broadcast'])
    def handle_broadcast(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /broadcast <mensagem>")
            return
        
        msg_broadcast = partes[1].strip()
        responder_seguro(message, "📢 Transmissão iniciada em segundo plano...")
        Thread(target=_executar_broadcast_async, args=(message.chat.id, msg_broadcast), daemon=True).start()

    @bot.message_handler(commands=['resgatar'])
    def handle_resgatar_cupom(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            return

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Digite o código do cupom após o comando.\nExemplo: /resgatar KRONOS100")
            return

        codigo = partes[1].upper().strip()
        cupom = db_execute("SELECT max_uses, uses_count FROM coupons WHERE code = ?", (codigo,), fetchone=True)
        if not cupom:
            responder_seguro(message, "❌ Cupom inválido ou inexistente.")
            return

        max_uses, uses_count = cupom[0], cupom[1]
        if uses_count >= max_uses:
            responder_seguro(message, "❌ Este cupom já atingiu o limite máximo de utilizações.")
            return

        ja_usou = db_execute("SELECT 1 FROM coupon_redemptions WHERE code = ? AND user_id = ?", (codigo, user_id), fetchone=True)
        if ja_usou:
            responder_seguro(message, "⚠️ Você já resgatou este cupom anteriormente.")
            return

        db_execute("INSERT INTO coupon_redemptions (code, user_id, redeemed_at) VALUES (?, ?, ?)", (codigo, user_id, datetime.now(TIMEZONE_BR).isoformat()), commit=True)
        db_execute("UPDATE coupons SET uses_count = uses_count + 1 WHERE code = ?", (codigo,), commit=True)
        db_execute("DELETE FROM free_claims WHERE user_id = ?", (user_id,), commit=True)

        responder_seguro(message, f"🎉 CUPOM `{codigo}` RESGATADO COM SUCESSO!\n\nFoi-lhe concedida 1 consulta VIP gratuita no bot. Realize a sua busca utilizando um dos comandos disponíveis!")

    @bot.message_handler(commands=['admin_fone'])
    def handle_admin_fone(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_fone 11999998888")
            return
        target = re.sub(r'\D', '', partes[1])
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "fone")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin de Telefone concluída para +55 {target}:", reply_markup=markup)

    @bot.message_handler(commands=['admin_cnpj'])
    def handle_admin_cnpj(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_cnpj 00000000000191")
            return
        target = re.sub(r'\D', '', partes[1])
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "cnpj")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin de CNPJ concluída para {target}:", reply_markup=markup)

    @bot.message_handler(commands=['admin_placa'])
    def handle_admin_placa(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_placa ABC1D23")
            return
        target = partes[1].upper().replace("-", "").strip()
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "placa")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin de Placa concluída para {target}:", reply_markup=markup)

    @bot.message_handler(commands=['admin_dominio'])
    def handle_admin_dominio(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_dominio site.com")
            return
        target = partes[1].lower().replace("https://", "").replace("http://", "").strip('/')
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "dominio")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin de Domínio concluída para {target}:", reply_markup=markup)

    @bot.message_handler(commands=['admin_user'])
    def handle_admin_user(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_user alvo123")
            return
        target = partes[1].replace("@", "").strip()
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "username")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin de Username concluída para @{target}:", reply_markup=markup)

    @bot.message_handler(commands=['admin_email'])
    def handle_admin_email(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_email alvo@dominio.com")
            return
        target = partes[1].strip()
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "email")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin de E-mail concluída para {target}:", reply_markup=markup)

    @bot.message_handler(commands=['admin_nome'])
    def handle_admin_nome(message):
        if message.from_user.id != ADMIN_ID:
            return
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Uso correto: /admin_nome Carlos Eduardo")
            return
        target = partes[1].strip()
        link_web, token = executar_consulta_admin_direta(message.from_user.id, target, "fullname")
        
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("🌐 Acessar Painel VIP do Admin", url=link_web))
        markup.add(InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token}"))
        responder_seguro(message, f"✅ Consulta Admin Judicial concluída para {target}:", reply_markup=markup)

    @bot.message_handler(commands=['apagar'])
    def handle_apagar_dados(message):
        user_id = message.from_user.id
        db_execute("DELETE FROM users WHERE user_id = ?", (user_id,), commit=True)
        db_execute("UPDATE payments SET target_username='(apagado)', results_json=NULL, pix_code=NULL WHERE user_id = ?", (user_id,), commit=True)
        db_execute("DELETE FROM free_claims WHERE user_id = ?", (user_id,), commit=True)
        db_execute("DELETE FROM coupon_redemptions WHERE user_id = ?", (user_id,), commit=True)
        bot.reply_to(message, "🗑️ Solicitação de Privacidade LGPD Concluída: Seus dados de acesso e pesquisas associados foram apagados permanentemente do sistema.")

    @bot.message_handler(commands=['fone'])
    def handle_fone_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "Telefone & WhatsApp (/fone)")

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie o telefone após o comando /fone.\nExemplo: /fone 11999998888")
            return

        target = re.sub(r'\D', '', partes[1])
        if not RE_FONE.match(target):
            responder_seguro(message, "⚠️ Telefone Inválido!\nDigite o DDD + Número sem espaços ou traços (ex: 11999998888).")
            return

        resultados = executar_varredura_osint(target, query_type="fone")
        hash_alvo = registrar_hash_alvo(target, "fone", resultados)

        status_gratis_txt = ""
        if not usuario_ja_usou_gratis(user_id):
            status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

        texto = (
            f"📱 MÓDULO DE CONSULTA DE TELEFONE:\n"
            f"👤 +55 {target}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com consultas configuradas para:\n"
            f"• WhatsApp Direct | Sync.ME | Truecaller | QualEmpresa | Google\n\n"
            f"{status_gratis_txt}"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Canal Oficial: {CANAL_TAG_PUBLICO}"
        )
        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto, reply_markup=markup)

    @bot.message_handler(commands=['cnpj'])
    def handle_cnpj_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "CNPJ / Empresarial (/cnpj)")

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie o CNPJ após o comando /cnpj.\nExemplo: /cnpj 00000000000191")
            return

        target = re.sub(r'\D', '', partes[1])
        if not RE_CNPJ.match(target):
            responder_seguro(message, "⚠️ CNPJ Inválido!\nDigite apenas os 14 números do CNPJ.")
            return

        resultados = executar_varredura_osint(target, query_type="cnpj")
        hash_alvo = registrar_hash_alvo(target, "cnpj", resultados)

        status_gratis_txt = ""
        if not usuario_ja_usou_gratis(user_id):
            status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

        texto = (
            f"🏢 CONSULTA EMPRESARIAL (CNPJ):\n"
            f"👤 {target}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com atalhos para:\n"
            f"• Receita Federal | Casa dos Dados (QSA) | CNPJ.biz | Transparência\n\n"
            f"{status_gratis_txt}"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Canal Oficial: {CANAL_TAG_PUBLICO}"
        )
        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto, reply_markup=markup)

    @bot.message_handler(commands=['placa'])
    def handle_placa_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "Veículos / Placa (/placa)")

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie a placa após o comando /placa.\nExemplo: /placa ABC1D23")
            return

        target = partes[1].upper().replace("-", "").strip()
        if not RE_PLACA.match(target):
            responder_seguro(message, "⚠️ Placa Inválida!\nDigite a placa no formato tradicional (ABC1234) ou Mercosul (ABC1D23).")
            return

        resultados = executar_varredura_osint(target, query_type="placa")
        hash_alvo = registrar_hash_alvo(target, "placa", resultados)

        status_gratis_txt = ""
        if not usuario_ja_usou_gratis(user_id):
            status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

        texto = (
            f"🚗 CONSULTA DE VEÍCULOS (PLACA):\n"
            f"👤 {target}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com consultas para:\n"
            f"• Sinesp Cidadão | Tabela FIPE | QualVeiculo | Histórico\n\n"
            f"{status_gratis_txt}"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Canal Oficial: {CANAL_TAG_PUBLICO}"
        )
        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto, reply_markup=markup)

    @bot.message_handler(commands=['dominio'])
    def handle_dominio_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "Domínios & DNS (/dominio)")

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie o domínio após o comando /dominio.\nExemplo: /dominio site.com")
            return

        target = partes[1].lower().replace("https://", "").replace("http://", "").strip('/')
        resultados = executar_varredura_osint(target, query_type="dominio")
        hash_alvo = registrar_hash_alvo(target, "dominio", resultados)

        status_gratis_txt = ""
        if not usuario_ja_usou_gratis(user_id):
            status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

        texto = (
            f"🌐 CONSULTA DE INFRAESTRUTURA E DOMÍNIO:\n"
            f"👤 {target}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com ferramentas de análise:\n"
            f"• Whois ICANN | DNS Dumpster | SecurityTrails | Shodan | Wayback Machine\n\n"
            f"{status_gratis_txt}"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Canal Oficial: {CANAL_TAG_PUBLICO}"
        )
        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto, reply_markup=markup)

    @bot.message_handler(commands=['user'])
    def handle_user_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "Username / Redes Sociais (/user)")

        texto_limpo = message.text.replace("\n", " ").strip()
        partes = texto_limpo.split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie o username após o comando /user.\nExemplo: /user alvo123")
            orientar_uso_correto(message.chat.id)
            return

        target_user = partes[1].replace("@", "").strip()

        if not RE_USERNAME.match(target_user):
            responder_seguro(message, "⚠️ Username Inválido!\nEnvia apenas letras, números, pontos e traços.")
            orientar_uso_correto(message.chat.id)
            return

        msg_status = responder_seguro(message, f"🔎 Mapeando plataformas para @{target_user}...")
        resultados = executar_varredura_osint(target_user, query_type="username")
        encontrados = [p for p, data in resultados.items() if isinstance(data, dict) and data.get("exists") is True]

        if msg_status:
            try:
                bot.edit_message_text(f"✅ Mapeamento concluído para @{target_user}!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

        if encontrados:
            hash_alvo = registrar_hash_alvo(target_user, "username", resultados)
            lista_plataformas = "\n".join([f"• {p}" for p in encontrados])
            
            status_gratis_txt = ""
            if not usuario_ja_usou_gratis(user_id):
                status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Como ainda não resgatou a sua consulta gratuita de membro do grupo, pode gerar este relatório SEM CUSTO clicando no botão abaixo!\n\n"

            texto_resultado = (
                f"🎯 POSSÍVEIS PERFIS PARA @{target_user}\n"
                f"───────────────────────────────\n\n"
                f"{lista_plataformas}\n\n"
                f"⚠️ Identificamos {len(encontrados)} possíveis plataformas associadas a este termo.\n\n"
                f"{status_gratis_txt}"
                f"💳 Valor normal da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                f"👉 Faça parte do nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = construir_markup_oferta(hash_alvo, user_id)
            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
        else:
            bot.send_message(
                message.chat.id,
                f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{target_user}.\n\n"
                f"👉 Fique por dentro de novas técnicas de OSINT no nosso canal: {CANAL_TAG_PUBLICO}"
            )

    @bot.message_handler(commands=['email'])
    def handle_email_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "E-mail & Vazamentos (/email)")

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie o e-mail após o comando /email.\nExemplo: /email alvo@gmail.com")
            return

        email_alvo = partes[1].strip()
        if not e_email_valido(email_alvo):
            responder_seguro(message, "⚠️ E-mail Inválido!\nUse o formato usuario@dominio.com.")
            return

        resultados = executar_varredura_osint(email_alvo, query_type="email")
        hash_alvo = registrar_hash_alvo(email_alvo, "email", resultados)

        status_gratis_txt = ""
        if not usuario_ja_usou_gratis(user_id):
            status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

        texto_email = (
            f"📧 MÓDULO DE CONSULTA DE E-MAIL:\n"
            f"👤 {email_alvo}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com os atalhos organizados para as principais plataformas de verificação:\n"
            f"• Have I Been Pwned | DeHashed | IntelX | BreachDirectory | Scylla\n\n"
            f"{status_gratis_txt}"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Acompanhe alertas no canal: {CANAL_TAG_PUBLICO}"
        )
        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto_email, reply_markup=markup)

    @bot.message_handler(commands=['nome'])
    def handle_nome_command(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)
        notificar_uso_grupo_logs(message.from_user, "Busca Judicial & Registros (/nome)")

        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, "⚠️ Comando Incompleto!\nEnvie o nome completo após o comando /nome.\nExemplo: /nome João da Silva")
            return

        nome_alvo = partes[1].strip()
        if not e_nome_completo(nome_alvo):
            responder_seguro(message, "⚠️ Nome Inválido!\nDigite nome e sobrenome completo.")
            return

        resultados = executar_varredura_osint(nome_alvo, query_type="fullname")
        hash_alvo = registrar_hash_alvo(nome_alvo, "fullname", resultados)

        status_gratis_txt = ""
        if not usuario_ja_usou_gratis(user_id):
            status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

        texto_oferta = (
            f"🔍 BUSCA JUDICIAL E REGISTROS PÚBLICOS:\n"
            f"👤 {nome_alvo.upper()}\n"
            f"───────────────────────────────\n\n"
            f"Gere o Painel Web Interativo com consultas configuradas para:\n"
            f"• Jusbrasil | Escavador | Diários Oficiais | Portal Transparência\n\n"
            f"{status_gratis_txt}"
            f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Entre no nosso canal oficial: {CANAL_TAG_PUBLICO}"
        )
        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto_oferta, reply_markup=markup)

    @bot.message_handler(commands=['stats', 'statistics'])
    def handle_stats_command(message):
        if message.from_user.id != ADMIN_ID:
            return

        res_users = db_execute("SELECT COUNT(*) FROM users", fetchone=True)
        total_users = res_users[0] if res_users else 0

        res_searches = db_execute("SELECT value FROM metrics WHERE key = 'total_searches'", fetchone=True)
        searches = res_searches[0] if res_searches else 0

        res_reports = db_execute("SELECT value FROM metrics WHERE key = 'total_reports'", fetchone=True)
        reports = res_reports[0] if res_reports else 0

        vendas = db_execute("SELECT COUNT(*), SUM(amount) FROM payments WHERE status = 'approved' AND amount > 0", fetchone=True)
        qtd_vendas = vendas[0] if (vendas and vendas[0] is not None) else 0
        faturamento = vendas[1] if (vendas and vendas[1] is not None) else 0.0

        data_hora_solicitacao = datetime.now(TIMEZONE_BR).strftime('%d/%m/%Y às %H:%M:%S')

        relatorio_financeiro = (
            f"📊 RELATÓRIO FINANCEIRO E MÉTRICAS DE USO\n"
            f"───────────────────────────────\n"
            f"👤 Usuários Totais Registrados: {total_users}\n"
            f"🔎 Total de Buscas Executadas: {searches}\n"
            f"📄 Relatórios VIP Gerados: {reports}\n"
            f"💰 Vendas Aprovadas (Pix): {qtd_vendas}\n"
            f"💵 Faturamento Total Adquirido: R$ {faturamento:.2f}\n"
            f"───────────────────────────────\n"
            f"📅 Solicitado em: {data_hora_solicitacao}"
        )

        grupo_target = obter_grupo_logs_id()
        try:
            bot.send_message(grupo_target, relatorio_financeiro)
            if message.chat.type == 'private':
                bot.reply_to(message, "✅ Relatório de estatísticas enviado diretamente para o grupo de logs/financeiro.")
        except Exception as e:
            logger.error("Falha ao enviar relatório para o grupo (%s): %s", grupo_target, str(e))
            bot.reply_to(message, f"⚠️ Erro ao enviar para o grupo ({grupo_target}).")

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

        qtype = "username"
        if e_email_valido(alvo): qtype = "email"
        elif e_nome_completo(alvo): qtype = "fullname"
        elif RE_CNPJ.match(re.sub(r'\D', '', alvo)): qtype = "cnpj"
        elif RE_FONE.match(re.sub(r'\D', '', alvo)): qtype = "fone"

        resultados = executar_varredura_osint(alvo, query_type=qtype)
        results_json = json.dumps(resultados)
        token_relatorio = secrets.token_urlsafe(16)
        pid_cortesia = f"cortesia_{secrets.token_hex(6)}"

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

    @bot.message_handler(func=lambda message: True)
    def handle_search(message):
        if not message.text:
            return

        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        if not limite_busca_ok(user_id):
            responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
            return

        registrar_acesso(user_id)

        if message.chat.type in ['group', 'supergroup']:
            return

        texto = message.text.replace("\n", " ").strip()
        target = texto.replace("@", "").strip()

        if e_url(target) and not ("." in target and "/" not in target):
            responder_seguro(message, "⚠️ Comando Inválido!\nUtilize os comandos específicos como /user, /email, /nome, /fone, /cnpj, /placa ou /dominio.")
            orientar_uso_correto(message.chat.id)
            return

        if len(target) < 2:
            responder_seguro(message, "⚠️ Termo de busca muito curto.")
            return

        qtype = "username"
        if e_email_valido(target): qtype = "email"
        elif e_nome_completo(target): qtype = "fullname"
        elif RE_CNPJ.match(re.sub(r'\D', '', target)): qtype = "cnpj"
        elif RE_FONE.match(re.sub(r'\D', '', target)): qtype = "fone"
        elif RE_PLACA.match(target.upper().replace("-", "")): qtype = "placa"

        parece_alvo = (
            e_email_valido(target) or RE_CNPJ.match(re.sub(r'\D', '', target))
            or RE_FONE.match(re.sub(r'\D', '', target))
            or (RE_USERNAME.match(target) and len(target) >= 4 and " " not in target)
        )
        if qtype == "username" and not parece_alvo:
            orientar_uso_correto(message.chat.id)
            return

        notificar_uso_grupo_logs(message.from_user, f"Busca Automática ({qtype.upper()})")

        resultados = executar_varredura_osint(target, query_type=qtype)
        encontrados = [p for p, data in resultados.items() if isinstance(data, dict) and data.get("exists") is True]

        if encontrados or qtype != "username":
            hash_alvo = registrar_hash_alvo(target, qtype, resultados)
            status_gratis_txt = ""
            if not usuario_ja_usou_gratis(user_id):
                status_gratis_txt = "🎁 BÓNUS GRATUITO DISPONÍVEL: Resgate o seu relatório SEM CUSTO por ser membro do canal oficial!\n\n"

            texto_resultado = (
                f"🎯 CONSULTA OSINT DE ALVO ({qtype.upper()}):\n"
                f"👤 {target}\n"
                f"───────────────────────────────\n\n"
                f"Gere o seu Painel Web Interativo completo para acessar todos os atalhos e resultados mapeados.\n\n"
                f"{status_gratis_txt}"
                f"💳 Valor da consulta: R$ {PRECO_PADRAO:.2f} no Pix\n\n"
                f"👉 Faça parte do nosso canal oficial: {CANAL_TAG_PUBLICO}"
            )

            markup = construir_markup_oferta(hash_alvo, user_id)
            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
        else:
            bot.send_message(
                message.chat.id,
                f"ℹ️ Varredura concluída: Nenhum registro público localizado para @{target}.\n\n"
                f"👉 Fique por dentro de novas técnicas de OSINT no nosso canal: {CANAL_TAG_PUBLICO}"
            )

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("claimfree_"):
            hash_curto = call.data.split("claimfree_")[1]
            target, qtype, results_json_str = obter_alvo_por_hash(hash_curto)
            user_id = call.from_user.id

            if usuario_esta_banido(user_id):
                bot.answer_callback_query(call.id, "Acesso suspenso.", show_alert=True)
                return

            if not target or not results_json_str:
                bot.answer_callback_query(call.id, "Sessão expirada. Envie a busca novamente.", show_alert=True)
                return

            if not usuario_e_membro_canal(user_id):
                bot.answer_callback_query(call.id, "⚠️ Você precisa entrar no nosso canal oficial para liberar o teste grátis!", show_alert=True)
                
                msg_aviso = (
                    f"🔒 RESGATE DO RELATÓRIO GRATUITO\n\n"
                    f"Para liberar a sua consulta gratuita, você precisa estar inscrito no nosso canal oficial!\n\n"
                    f"1. Clique no botão abaixo e entre no canal {CANAL_TAG_PUBLICO}.\n"
                    f"2. Após entrar, volte aqui e clique novamente em RESGATAR RELATÓRIO GRATUITO."
                )
                markup = InlineKeyboardMarkup(row_width=1)
                markup.add(InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}"))
                bot.send_message(call.message.chat.id, msg_aviso, reply_markup=markup)
                return

            ok = db_execute(
                "INSERT INTO free_claims (user_id, claimed_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING RETURNING user_id",
                (user_id, datetime.now(TIMEZONE_BR).isoformat()), fetchone=True, commit=True
            )
            if not ok:
                bot.answer_callback_query(call.id, "⚠️ Você já utilizou o seu relatório gratuito!", show_alert=True)
                return

            bot.answer_callback_query(call.id, "🎉 Membro validado! Gerando seu relatório gratuito...")
            resultados = json.loads(results_json_str)
            link_web = gerar_painel_gratuito_membro(user_id, target, qtype, resultados)

            markup = InlineKeyboardMarkup(row_width=1)
            markup.add(InlineKeyboardButton("🌐 Acessar Seu Painel VIP (GRÁTIS)", url=link_web))

            bot.send_message(
                call.message.chat.id,
                f"🎉 PARABÉNS! SEU RELATÓRIO GRATUITO FOI LIBERADO!\n\n"
                f"Obrigado por fazer parte da comunidade Kronos Intel.\n"
                f"Clique no botão abaixo para acessar o painel completo do alvo {target}:",
                reply_markup=markup
            )

        elif call.data.startswith("b_"):
            hash_curto = call.data.split("b_")[1]
            target, qtype, results_json_str = obter_alvo_por_hash(hash_curto)

            user_id = call.from_user.id
            if usuario_esta_banido(user_id):
                bot.answer_callback_query(call.id, "Acesso suspenso.", show_alert=True)
                return

            if not target or not results_json_str:
                bot.answer_callback_query(call.id, "Sessão expirada. Envie a busca novamente.", show_alert=True)
                return

            bot.answer_callback_query(call.id, f"Gerando Chave Pix de R$ {PRECO_PADRAO:.2f}...")
            
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(
                user_id, target, valor=PRECO_PADRAO, query_type=qtype, results_json_str=results_json_str
            )

            if qr_pix:
                texto_oferta = (
                    f"🔒 CONSULTA KRONOS INTEL VIP\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Interativo Web Exclusivo ({qtype.upper()})\n"
                    f"2. Relatório Executivo Profissional (.PDF)\n"
                    f"3. Compilação Completa de Dados (.TXT)\n\n"
                    f"💰 Valor: R$ {PRECO_PADRAO:.2f} no Pix (Válido por 30 minutos)\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O painel interativo será liberado automaticamente após a confirmação do pagamento.\n\n"
                    f"👉 Acesse nosso canal oficial para dúvidas e avisos: {CANAL_TAG_PUBLICO}"
                )

                markup = InlineKeyboardMarkup(row_width=1)
                btn_copiar = InlineKeyboardButton("📋 Copiar Chave Pix (Texto)", callback_data=f"getkey_{token}")
                btn_canal = InlineKeyboardButton("📢 Entrar no Grupo/Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}")
                markup.add(btn_copiar, btn_canal)

                if qr_img_bytes:
                    bot.send_photo(call.message.chat.id, photo=qr_img_bytes, caption=texto_oferta, reply_markup=markup)
                else:
                    bot.send_message(call.message.chat.id, text=texto_oferta, reply_markup=markup)
            else:
                bot.send_message(call.message.chat.id, "⚠️ Não consegui gerar o Pix agora. Tente novamente.")

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta finalizada.")
            bot.edit_message_text(
                chat_id=call.message.chat.id, 
                message_id=call.message.message_id, 
                text=f"👍 Entendido! Digite um comando como /user, /email, /nome ou /fone para iniciar uma nova busca.\n\n👉 Acompanhe as novidades no canal: {CANAL_TAG_PUBLICO}"
            )

        elif call.data.startswith("getkey_"):
            try:
                token_pix = call.data.split("getkey_")[1]
                row = db_execute("SELECT pix_code FROM payments WHERE token = ? AND status = 'pending'", (token_pix,), fetchone=True)
                if row and row[0]:
                    bot.answer_callback_query(call.id, "Enviando chave...")
                    bot.send_message(call.message.chat.id, text=f"<code>{escapar_html(row[0])}</code>", parse_mode="HTML")
                else:
                    bot.answer_callback_query(call.id, "Chave Pix não encontrada ou já expirada.")
            except Exception as e:
                logger.error("Erro ao buscar pix_code no banco: %s", str(e))
                bot.answer_callback_query(call.id, "Erro ao recuperar chave Pix.")

@app.route(f"/telegram/{WEBHOOK_SECRET_PATH}", methods=["POST"])
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

def validar_assinatura_mp(req, segredo: str, data_id: str) -> bool:
    if not segredo:
        logger.error("MERCADOPAGO_WEBHOOK_SECRET ausente: webhook rejeitando por padrão")
        return False
    partes = dict(p.split("=", 1) for p in req.headers.get("x-signature", "").split(",") if "=" in p)
    ts, v1 = partes.get("ts"), partes.get("v1")
    if not ts or not v1 or not data_id:
        return False
    manifest = f"id:{data_id};request-id:{req.headers.get('x-request-id','')};ts:{ts};"
    esperado = hmac.new(segredo.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(esperado, v1):
        logger.warning("Assinatura MP inválida para %s", data_id)
        return False
    try:
        if abs(time.time() - int(ts) / 1000) > 600:
            return False
    except ValueError:
        return False
    return True

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

        # Validação de Assinatura HMAC Mercado Pago
        if MERCADOPAGO_WEBHOOK_SECRET:
            if not validar_assinatura_mp(request, MERCADOPAGO_WEBHOOK_SECRET, pid_str):
                return jsonify({"status": "error", "detail": "assinatura invalida"}), 401
        else:
            logger.warning("MERCADOPAGO_WEBHOOK_SECRET ausente: assinatura NÃO validada")
        
        row = db_execute(
            "SELECT user_id, target_username, query_type, token FROM payments WHERE payment_id = ? AND status = 'pending'",
            (pid_str,), fetchone=True
        )

        if not row or row[1].startswith("("):
            with _orphan_lock:
                if len(_orphan_alerts_sent) > 10000:
                    _orphan_alerts_sent.clear()
                    
                if pid_str not in _orphan_alerts_sent:
                    _orphan_alerts_sent.add(pid_str)
                    existe = db_execute("SELECT 1 FROM payments WHERE payment_id = ?", (pid_str,), fetchone=True)
                    if (not existe or row) and sdk:
                        try:
                            info = sdk.payment().get(pid_str).get("response", {})
                            meta = info.get("metadata") or {}
                            if info.get("status") == "approved" and meta.get("token"):
                                grupo_logs_id = obter_grupo_logs_id()
                                if bot and grupo_logs_id:
                                    bot.send_message(
                                        grupo_logs_id,
                                        f"<b>⚠️ Pix aprovado SEM registro utilizável</b>\n"
                                        f"• <b>Pagamento ID:</b> {pid_str}\n"
                                        f"• <b>Comprador ID:</b> {meta.get('telegram_user_id')}\n"
                                        f"• <b>Valor:</b> R$ {info.get('transaction_amount', 0.0):.2f}",
                                        parse_mode="HTML"
                                    )
                        except Exception:
                            logger.exception("Falha ao alertar pagamento órfão no grupo de logs")
            return jsonify({"status": "ok"}), 200

        telegram_id, target, query_type, token_relatorio = row

        if payment_id and sdk:
            try:
                payment_info = sdk.payment().get(str(payment_id)).get("response", {})
                if payment_info.get("status") == "approved":
                    
                    _valor = float(payment_info.get("transaction_amount") or 0.0)
                    _meta = payment_info.get("metadata") or {}

                    if _valor + 1e-6 < PRECO_PADRAO:
                        logger.error("Pagamento %s rejeitado: valor pago R$ %.2f < R$ %.2f", pid_str, _valor, PRECO_PADRAO)
                        return jsonify({"status": "ok"}), 200

                    if _meta.get("telegram_user_id") and int(_meta.get("telegram_user_id")) != int(telegram_id):
                        logger.error("Pagamento %s rejeitado: telegram_user_id divergente", pid_str)
                        return jsonify({"status": "ok"}), 200

                    claimed = db_execute(
                        "UPDATE payments SET status='approved' WHERE payment_id=? AND status='pending' RETURNING payment_id",
                        (pid_str,), fetchone=True, commit=True
                    )

                    if not claimed:
                        return jsonify({"status": "ok"}), 200

                    link_web = f"{WEB_BASE_URL}/relatorio/{token_relatorio}"
                    grupo_logs_id = obter_grupo_logs_id()

                    if telegram_id and bot:
                        markup = InlineKeyboardMarkup(row_width=1)
                        markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web", url=link_web))
                        markup.add(InlineKeyboardButton("📄 Baixar Relatório PDF VIP", url=f"{WEB_BASE_URL}/download/pdf/{token_relatorio}"))
                        markup.add(InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CANAL_TAG_PUBLICO.replace('@','')}") )

                        try:
                            bot.send_message(
                                telegram_id,
                                f"⚡ PAGAMENTO CONFIRMADO — KRONOS INTEL VIP\n\n"
                                f"Sua consulta ({query_type.upper()}) foi liberada com sucesso!\n\n"
                                f"🔗 Clique nos botões abaixo para acessar o painel e baixar o relatório executivo em PDF:\n\n"
                                f"👉 Faça parte do nosso canal oficial: {CANAL_TAG_PUBLICO}",
                                reply_markup=markup
                            )
                            registrar_relatorio()
                        except Exception:
                            logger.exception("Falha ao entregar relatório")

                    if bot and grupo_logs_id:
                        try:
                            msg_venda_log = (
                                f"<b>💰 NOVA VENDA APROVADA!</b>\n\n"
                                f"• <b>Valor:</b> R$ {payment_info.get('transaction_amount', 0.0):.2f}\n"
                                f"• <b>Módulo:</b> {escapar_html(query_type.upper())}\n"
                                f"• <b>Comprador ID:</b> {telegram_id}"
                            )
                            bot.send_message(grupo_logs_id, msg_venda_log, parse_mode="HTML")
                        except Exception as log_err:
                            logger.error("Erro ao enviar log no grupo financeiro: %s", str(log_err))

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v34.1 VIP Active.", 200

if __name__ == "__main__":
    setup_webhook()
    Thread(target=worker_divulgacao_diaria, daemon=True).start()
    Thread(target=worker_background, daemon=True).start()
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
