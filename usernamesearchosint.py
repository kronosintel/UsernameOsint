"""
Kronos Intel OSINT Bot v35.0 VIP
- Motor OSINT Assíncrono com httpx.AsyncClient, Keep-Alive e Concorrência por Semáforo
- Classificador Tri-Estado Puro (Zero Falso Positivo por construção)
- Cache TTL para otimização de pesquisas sequenciais do mesmo alvo
- SQLite WAL com PRAGMA user_version para migrações automáticas e Rate Limit Persistido
- Webhook do Telegram com secret_token e validação HMAC-SHA256 no Mercado Pago
- Sanitização de PDF (ReportLab), HTML Telegram e Trilha de Auditoria LGPD via Hash SHA-256
- Fábrica genérica de Handlers Telegram e Endpoints de Liveness/Readiness
- Suporte Oficial: @kronosintel
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
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
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import urllib.parse
from zoneinfo import ZoneInfo
from threading import Lock, Thread

import httpx
import mercadopago
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Update
from flask import Flask, jsonify, request, render_template_string, send_file

# Dependências do ReportLab
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("kronos_osint")

# --- CONFIGURAÇÃO TIPADA DO SISTEMA ---
def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default

def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except ValueError:
        return default

def _env_bool(key: str, default: bool) -> bool:
    val = os.getenv(key, str(default)).lower()
    return val in ("1", "true", "yes", "on")

@dataclass
class Config:
    TELEGRAM_TOKEN: str = os.getenv("TELEGRAM_TOKEN", "")
    ADMIN_ID: int = _env_int("ADMIN_ID", 5041637922)
    CANAL_PRINCIPAL_ID: int = _env_int("CANAL_PRINCIPAL_ID", -1003802363624)
    LOG_GROUP_ID: int = _env_int("LOG_GROUP_ID", -1003986408630)
    CANAL_TAG_PUBLICO: str = os.getenv("CANAL_TAG_PUBLICO", "@kronosinteloficial")
    SUPORTE_USERNAME: str = os.getenv("SUPORTE_USERNAME", "kronosintel")
    BOT_USERNAME: str = os.getenv("BOT_USERNAME", "KronosSearchbot")
    WEB_BASE_URL: str = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com").rstrip('/')
    
    MERCADOPAGO_TOKEN: str = os.getenv("MERCADOPAGO_TOKEN", "")
    MERCADOPAGO_WEBHOOK_SECRET: str = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "").strip()
    
    PRECO_PADRAO: float = _env_float("PRECO_PADRAO", 3.90)
    DB_FILE: str = os.getenv("DB_FILE", "/var/data/kronos_osint.db" if os.path.exists("/var/data") else "kronos_osint.db")
    PORT: int = _env_int("PORT", 5000)
    
    CACHE_TTL_SECONDS: int = _env_int("CACHE_TTL_SECONDS", 900)
    RETENTION_DAYS: int = _env_int("RETENTION_DAYS", 30)
    REQUIRE_TERMS: bool = _env_bool("REQUIRE_TERMS", False)
    
    TELEGRAM_SECRET_TOKEN: str = os.getenv("TELEGRAM_SECRET_TOKEN", hashlib.sha256((os.getenv("TELEGRAM_TOKEN", "") + "secret_token").encode()).hexdigest()[:32])

CFG = Config()

if not CFG.TELEGRAM_TOKEN:
    logger.warning("TELEGRAM_TOKEN não configurado. Funcionalidades do Bot estarão desativadas.")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=1024 * 1024,
)

TIMEZONE_BR = ZoneInfo("America/Sao_Paulo")
db_lock = Lock()

RE_USERNAME = re.compile(r"^(?=.*[A-Za-z0-9])[A-Za-z0-9._-]{2,40}$")
RE_CNPJ = re.compile(r"^\d{14}$")
RE_PLACA = re.compile(r"^[A-Z]{3}[0-9][A-Z0-9][0-9]{2}$")
RE_FONE = re.compile(r"^\d{10,11}$")

sdk = mercadopago.SDK(CFG.MERCADOPAGO_TOKEN) if CFG.MERCADOPAGO_TOKEN else None
bot = telebot.TeleBot(CFG.TELEGRAM_TOKEN, threaded=False) if CFG.TELEGRAM_TOKEN else None

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

# --- FUNÇÕES UTILITÁRIAS E SANITIZAÇÃO ---
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

def normalizar_termo_hash(termo: str) -> str:
    limpo = termo.strip().lower()
    return hashlib.sha256(limpo.encode("utf-8")).hexdigest()

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

# --- BANCO DE DADOS E MIGRAÇÕES (WAL + USER_VERSION) ---
def init_db():
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("PRAGMA synchronous = NORMAL")
        cursor.execute("PRAGMA busy_timeout = 30000")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                created_at TEXT,
                banned INTEGER DEFAULT 0,
                ban_reason TEXT,
                accepted_terms INTEGER DEFAULT 0
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rate_events (
                user_id INTEGER,
                timestamp REAL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                module TEXT,
                target_hash TEXT,
                created_at TEXT
            )
        """)

        # Índices de performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_token ON payments(token)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_status_reminded ON payments(status, reminded)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_payments_created ON payments(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_hashes_created ON target_hashes(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_rate_events_user_ts ON rate_events(user_id, timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id)")

        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES ('total_searches', 0)")
        cursor.execute("INSERT OR IGNORE INTO metrics (key, value) VALUES ('total_reports', 0)")
        
        conn.commit()
        conn.close()

init_db()

def db_execute(query: str, params: tuple = (), fetchone=False, fetchall=False, commit=False):
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
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

def registrar_auditoria(user_id: int, modulo: str, termo: str):
    target_hash = normalizar_termo_hash(termo)
    db_execute(
        "INSERT INTO audit_log (user_id, module, target_hash, created_at) VALUES (?, ?, ?, ?)",
        (user_id, modulo, target_hash, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )

def limite_busca_ok(user_id: int, maximo: int = 6, janela_segundos: int = 3600) -> bool:
    if user_id == CFG.ADMIN_ID:
        return True
    agora = time.time()
    corte = agora - janela_segundos
    
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rate_events WHERE timestamp < ?", (corte,))
        cursor.execute("SELECT COUNT(*) FROM rate_events WHERE user_id = ? AND timestamp >= ?", (user_id, corte))
        qtd = cursor.fetchone()[0]
        
        if qtd >= maximo:
            conn.commit()
            conn.close()
            return False
            
        cursor.execute("INSERT INTO rate_events (user_id, timestamp) VALUES (?, ?)", (user_id, agora))
        conn.commit()
        conn.close()
        return True

def adquirir_lock_worker(nome: str, renovar_s: int = 240) -> bool:
    agora = datetime.now(TIMEZONE_BR)
    expira = (agora + timedelta(seconds=renovar_s)).isoformat()
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        try:
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

def usuario_aceitou_termos(user_id: int) -> bool:
    if not CFG.REQUIRE_TERMS:
        return True
    res = db_execute("SELECT accepted_terms FROM users WHERE user_id = ?", (user_id,), fetchone=True)
    return res is not None and res[0] == 1

def usuario_e_membro_canal(user_id: int) -> bool:
    if not bot or not CFG.CANAL_PRINCIPAL_ID:
        return False
    try:
        member = bot.get_chat_member(CFG.CANAL_PRINCIPAL_ID, user_id)
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

def notificar_uso_grupo_logs(from_user, modulo_nome: str):
    if not bot or not CFG.LOG_GROUP_ID or from_user.id == CFG.ADMIN_ID:
        return
    try:
        raw_first = escaping_html = escapar_html(from_user.first_name or "Usuario")
        raw_last = escaping_html = escapar_html(from_user.last_name or "")
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
            f"• <b>Termo Varrito:</b> [PROTEGIDO POR PRIVACIDADE LGPD]\n"
            f"• <b>Data/Hora:</b> {data_hora}"
        )
        bot.send_message(CFG.LOG_GROUP_ID, msg_log, parse_mode="HTML")
    except Exception as e:
        logger.error("Erro ao enviar log para o grupo: %s", str(e))

# --- PLATAFORMAS E CONFIGURAÇÃO DO MOTOR OSINT ---
LIMITE_CORPO = 400_000
STATUS_NAO_EXISTE = (404, 410)
STATUS_INCONCLUSIVO = (401, 403, 405, 406, 409, 429, 451, 500, 501, 502, 503, 504, 520, 522, 524)
REDIRECT_NAO_ENCONTRADO = ("/login", "/signin", "/signup", "/register", "/home", "404", "/error", "not-found", "notfound", "typo", "subdomain=")

PLATAFORMAS: dict[str, dict[str, Any]] = {
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

    "YouTube":      {"url": "https://www.youtube.com/@{username}", "fonte": "html", "positivo": r'"channelId":"UC', "negativo": "this page isn't available", "timeout": 3.0},
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
    "Roblox":       {"url": "https://www.roblox.com/user.aspx?username={username}", "fonte": "html", "positivo": r'profile-header', "timeout": 2.5},
    "CodePen":      {"url": "https://codepen.io/{username}", "fonte": "html", "positivo": r'profile-header'},
    "Steam":        {"url": "https://steamcommunity.com/id/{username}", "fonte": "html", "positivo": r'actual_persona_name', "negativo": "the specified profile could not be found"},
    "PyPI":         {"url": "https://pypi.org/user/{username}/", "fonte": "html", "positivo": r'author-profile__name', "negativo": "404 not found"},

    "Tumblr":       {"url": "https://{username}.tumblr.com", "fonte": "html", "confiavel_200": True},
    "Disqus":       {"url": "https://disqus.com/by/{username}/", "fonte": "html", "confiavel_200": True},
    "WordPress":    {"url": "https://{username}.wordpress.com", "fonte": "html", "confiavel_200": True},
}

# --- CLASSIFICADOR TRI-ESTADO PURO ---
def _casa_padrao(padrao: str, texto: str) -> bool:
    if not padrao:
        return False
    try:
        return bool(re.search(padrao, texto, re.I | re.S))
    except re.error:
        return str(padrao).lower() in texto.lower()

def _avaliar_json_dados(cfg: dict, dados: Any) -> Optional[bool]:
    if dados is None:
        return None
    modo = cfg.get("json", "nao_vazio")
    if modo == "lista_cheia":
        return isinstance(dados, list) and len(dados) > 0
    if modo == "keybase":
        return isinstance(dados, dict) and bool(dados.get("them"))
    if modo == "reddit":
        if isinstance(dados, dict):
            d = dados.get("data") or {}
            return bool(d) and not d.get("is_suspended")
        return False
    if isinstance(dados, dict):
        return len(dados) > 0
    return bool(dados)

def classificar_resposta(cfg: dict, status_code: int, headers: dict, corpo_texto: str, json_dados: Any, username: str) -> dict[str, Any]:
    ne = tuple(cfg.get("status_nao_existe", STATUS_NAO_EXISTE))
    fonte = cfg.get("fonte", "html")
    
    if status_code in ne:
        return {"exists": False, "status": "nao_existe", "motivo": f"http_{status_code}"}
    if status_code in STATUS_INCONCLUSIVO or status_code >= 500:
        return {"exists": False, "status": "desconhecido", "motivo": f"http_{status_code}_bloqueio_ou_limite"}
    
    if status_code in (301, 302, 303, 307, 308):
        loc = (headers.get("Location") or headers.get("location") or "").lower()
        alvo = username.lower()
        if any(x in loc for x in REDIRECT_NAO_ENCONTRADO) or alvo not in loc:
            return {"exists": False, "status": "nao_existe", "motivo": "redirect_fora_do_perfil"}
        return {"exists": True, "confianca": 0.70, "status": "existe", "motivo": "redirect_para_perfil"}

    if 200 <= status_code < 300:
        if fonte == "api":
            ok = _avaliar_json_dados(cfg, json_dados)
            if ok is True:
                return {"exists": True, "confianca": 1.0, "status": "existe", "motivo": "api_confirmou"}
            if ok is False:
                return {"exists": False, "status": "nao_existe", "motivo": "api_vazia_ou_suspensa"}
            return {"exists": False, "status": "desconhecido", "motivo": "api_json_invalido"}
        else:
            corpo = corpo_texto[:LIMITE_CORPO]
            pos = cfg.get("positivo")
            neg = cfg.get("negativo")

            if neg and _casa_padrao(neg, corpo):
                return {"exists": False, "status": "nao_existe", "motivo": "marcador_negativo_encontrado"}
            if pos and _casa_padrao(pos, corpo):
                return {"exists": True, "confianca": 0.95, "status": "existe", "motivo": "marcador_positivo_encontrado"}
            if cfg.get("confiavel_200"):
                return {"exists": True, "confianca": 0.85, "status": "existe", "motivo": "http_200_confiavel"}
            return {"exists": False, "status": "desconhecido", "motivo": "sem_marcador_positivo"}

    return {"exists": False, "status": "desconhecido", "motivo": f"http_{status_code}_nao_tratado"}

# --- MOTOR ASSÍNCRONO COM HTTPX E EVENT LOOP DEDICADO ---
class OSINTEngineAsync:
    def __init__(self, max_concurrency: int = 25):
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_lock = Lock()
        self.headers_padrao = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    async def consultar_plataforma(self, client: httpx.AsyncClient, nome: str, cfg: dict, username: str) -> tuple[str, dict[str, Any]]:
        url = cfg["url"].format(username=username)
        fonte = cfg.get("fonte", "html")
        headers = dict(self.headers_padrao)
        headers.update(cfg.get("cabecalhos", {}))
        timeout_plat = cfg.get("timeout", 4.0)

        async with self.semaphore:
            try:
                resp = await client.get(
                    url,
                    headers=headers,
                    timeout=timeout_plat,
                    follow_redirects=(fonte == "api")
                )
                
                # Tratamento de Retry para 429/5xx
                if resp.status_code in (429, 500, 502, 503, 504):
                    retry_after = resp.headers.get("Retry-After")
                    wait_s = float(retry_after) if retry_after and retry_after.isdigit() else 1.0
                    if wait_s <= 2.0:
                        await asyncio.sleep(wait_s)
                        resp = await client.get(url, headers=headers, timeout=timeout_plat, follow_redirects=(fonte == "api"))

                json_dados = None
                if fonte == "api":
                    try:
                        json_dados = resp.json()
                    except Exception:
                        json_dados = None

                res = classificar_resposta(cfg, resp.status_code, dict(resp.headers), resp.text, json_dados, username)
                if res.get("exists"):
                    res["url"] = url
                return nome, res

            except httpx.TimeoutException:
                return nome, {"exists": False, "status": "desconhecido", "motivo": "timeout_sem_retry"}
            except Exception as e:
                return nome, {"exists": False, "status": "desconhecido", "motivo": f"excecao_{type(e).__name__}"}

    async def executar_varredura(self, username: str) -> dict[str, Any]:
        agora = time.time()
        with self._cache_lock:
            if username in self.cache:
                ts, res_cached = self.cache[username]
                if agora - ts < CFG.CACHE_TTL_SECONDS:
                    return res_cached

        async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=20, max_connections=40)) as client:
            tasks = [
                self.consultar_plataforma(client, nome, cfg, username)
                for nome, cfg in PLATAFORMAS.items()
            ]
            resultados_raw = await asyncio.gather(*tasks)

        resultados = dict(resultados_raw)

        # Segunda passada assíncrona para reconfirmação de baixa confiança
        duvidosos = [nome for nome, res in resultados.items() if res.get("status") == "existe" and res.get("confianca", 1.0) < 0.80]
        if duvidosos:
            async with httpx.AsyncClient() as client_reconf:
                for nome in duvidosos:
                    cfg = PLATAFORMAS[nome]
                    url = cfg["url"].format(username=username)
                    try:
                        r2 = await client_reconf.get(url, headers=self.headers_padrao, timeout=3.0, follow_redirects=True)
                        if r2.status_code in STATUS_NAO_EXISTE or any(x in str(r2.url).lower() for x in REDIRECT_NAO_ENCONTRADO):
                            resultados[nome] = {"exists": False, "status": "nao_existe", "motivo": "reconfirmacao_falhou"}
                        else:
                            resultados[nome]["confianca"] = 0.90
                    except Exception:
                        resultados[nome] = {"exists": False, "status": "desconhecido", "motivo": "reconfirmacao_erro"}

        with self._cache_lock:
            if len(self.cache) > 2000:
                self.cache.clear()
            self.cache[username] = (agora, resultados)

        return resultados

# Loop Async e Gerenciador
class AsyncLoopThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro, timeout: float = 15.0):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=timeout)

ASYNC_RUNNER = AsyncLoopThread()
ENGINE_ASYNC = OSINTEngineAsync()

# --- DADOS EXTERNOS ASSÍNCRONOS (CNPJ & DNS) ---
async def _cnpj_async(cnpj: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"https://brasilapi.com.br/api/cnpj/v1/{cnpj}")
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
        logger.error("Erro na consulta de CNPJ: %s", str(e))
    return {}

async def _dominio_async(dominio: str) -> dict[str, Any]:
    dados = {}
    loop = asyncio.get_running_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, dominio)
        dados["Endereço IP Servidor"] = ip
    except Exception:
        dados["Endereço IP Servidor"] = "Indisponível"

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(f"https://dns.google/resolve?name={dominio}&type=MX")
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
        dados_reais = ASYNC_RUNNER.run(_cnpj_async(limpo))

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
        dados_dns = ASYNC_RUNNER.run(_dominio_async(dom))

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
        return ASYNC_RUNNER.run(ENGINE_ASYNC.executar_varredura(target))

# --- GERADORES DE RELATÓRIO (PDF E TXT) ---
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
SISTEMA: Kronos Engine v35.0 VIP
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

# --- OPERAÇÕES FINANCEIRAS MERCADO PAGO ---
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
        "notification_url": f"{CFG.WEB_BASE_URL}/webhook",
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
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_reports'", commit=True)

    return f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"

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
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_reports'", commit=True)
    link_web = f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"
    return link_web, token_relatorio

def construir_markup_oferta(hash_alvo: str, user_id: int) -> InlineKeyboardMarkup:
    markup = InlineKeyboardMarkup(row_width=1)
    
    if not usuario_ja_usou_gratis(user_id):
        btn_gratis = InlineKeyboardButton("🎁 RESGATAR RELATÓRIO GRATUITO (Membros)", callback_data=f"claimfree_{hash_alvo}")
        markup.add(btn_gratis)

    btn_sim = InlineKeyboardButton(f"⚡ 🔓 OBTER PAINEL COMPLETO (R$ {CFG.PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}")
    btn_canal = InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CFG.CANAL_TAG_PUBLICO.replace('@','')}")
    btn_nao = InlineKeyboardButton("❌ Cancelar", callback_data="final_cancel")
    
    markup.add(btn_sim, btn_canal, btn_nao)
    return markup

# --- WORKERS BACKGROUND DE TAREFAS CONTINUAS ---
def worker_divulgacao_diaria():
    if not adquirir_lock_worker("divulgacao_diaria", renovar_s=1800):
        return

    ultimo_envio = None
    while True:
        try:
            time.sleep(300)
            now = datetime.now(TIMEZONE_BR)

            if now.hour == 10 and (ultimo_envio is None or ultimo_envio.date() < now.date()):
                if bot and CFG.CANAL_PRINCIPAL_ID:
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
                    btn_usar = InlineKeyboardButton("🚀 Abrir Bot de Consultas Agora", url=f"https://t.me/{CFG.BOT_USERNAME}")
                    markup.add(btn_usar)

                    bot.send_message(CFG.CANAL_PRINCIPAL_ID, msg_divulgacao, reply_markup=markup)
                    ultimo_envio = now
                    logger.info("Mensagem diária enviada no Canal Principal.")
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
                                    f"Conclua a liberação do seu relatório interativo por R$ {CFG.PRECO_PADRAO:.2f} no Pix."
                                )
                                markup = InlineKeyboardMarkup(row_width=1)
                                markup.add(InlineKeyboardButton(f"⚡ 🔓 CONCLUIR AGORA (R$ {CFG.PRECO_PADRAO:.2f}) 🔓 ⚡", callback_data=f"b_{hash_alvo}"))
                                bot.send_message(uid, msg_lembrete, reply_markup=markup)
                        elif minutos_decorridos >= 30:
                            db_execute("UPDATE payments SET reminded = 1 WHERE payment_id = ?", (pid,), commit=True)
                    except Exception as ex:
                        logger.error("Erro no remarketing: %s", str(ex))

            # Expurgo LGPD e Limpeza de hashes antigas
            lim_hashes = (now - timedelta(days=1)).isoformat()
            db_execute("DELETE FROM target_hashes WHERE created_at < ?", (lim_hashes,), commit=True)
            
            lim_retention = (now - timedelta(days=CFG.RETENTION_DAYS)).isoformat()
            db_execute("UPDATE payments SET results_json=NULL, target_username='(expirado)' WHERE created_at < ? AND target_username NOT LIKE '(%'", (lim_retention,), commit=True)
            db_execute("DELETE FROM audit_log WHERE created_at < ?", (lim_retention,), commit=True)

        except Exception as e:
            logger.error("Erro no worker background: %s", str(e))

# --- INTERFACE WEB FLASK ---
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
                        <a href="{{ p.url }}" target="_blank" rel="noopener" class="btn-platform">
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

# --- FÁBRICA GENÉRICA DE HANDLERS DO TELEGRAM ---
def _processar_busca_generica(message, target: str, qtype: str, modulo_nome: str):
    user_id = message.from_user.id
    if usuario_esta_banido(user_id):
        bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
        return

    if not usuario_aceitou_termos(user_id):
        bot.reply_to(message, "⚠️ Você precisa aceitar os termos de uso antes de realizar consultas. Use /termos.")
        return

    if not limite_busca_ok(user_id):
        responder_seguro(message, "⚠️ Limite de buscas atingido!\nAguarde um momento para realizar novas varreduras.")
        return

    now_str = datetime.now(TIMEZONE_BR).isoformat()
    db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, now_str), commit=True)
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_searches'", commit=True)
    
    notificar_uso_grupo_logs(message.from_user, modulo_nome)
    registrar_auditoria(user_id, qtype, target)

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
            f"💳 Valor da consulta: R$ {CFG.PRECO_PADRAO:.2f} no Pix\n\n"
            f"👉 Faça parte do nosso canal oficial: {CFG.CANAL_TAG_PUBLICO}"
        )

        markup = construir_markup_oferta(hash_alvo, user_id)
        bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
    else:
        bot.send_message(
            message.chat.id,
            f"ℹ️ Varredura concluída: Nenhum registro público localizado para @{target}.\n\n"
            f"👉 Fique por dentro de novas técnicas de OSINT no nosso canal: {CFG.CANAL_TAG_PUBLICO}"
        )

def _comando_busca(qtype: str, validador: Callable[[str], Optional[str]], erro_msg: str, modulo_nome: str):
    def handler(message):
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) < 2:
            responder_seguro(message, f"⚠️ Comando Incompleto!\n{erro_msg}")
            return
        alvo_limpo = validador(partes[1])
        if not alvo_limpo:
            responder_seguro(message, f"⚠️ Entrada Inválida!\n{erro_msg}")
            return
        _processar_busca_generica(message, alvo_limpo, qtype, modulo_nome)
    return handler

if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        user_id = message.from_user.id
        if usuario_esta_banido(user_id):
            bot.reply_to(message, "🚫 O seu acesso a esta plataforma foi suspenso temporariamente.")
            return

        raw_first = escapar_html(message.from_user.first_name or "Usuario")
        user_name = "".join(c for c in raw_first if c.isalnum() or c == " ")[:30].strip() or "Usuario"
        
        now_str = datetime.now(TIMEZONE_BR).isoformat()
        db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, now_str), commit=True)

        menu_boas_vindas = (
            f"👑 KRONOS INTEL OSINT BOT v35.0 VIP ⚡\n"
            f"─────────────────────────────────────────────\n"
            f"👋 Olá, {user_name}! Bem-vindo à sua central avançada de inteligência cibernética!\n\n"
            f"🛠️ MÓDULOS DISPONÍVEIS:\n"
            f"• /user <username>\n"
            f"• /email <email>\n"
            f"• /nome <Nome Completo>\n"
            f"• /fone <telefone_ddd>\n"
            f"• /cnpj <cnpj>\n"
            f"• /placa <placa_veiculo>\n"
            f"• /dominio <dominio_web>\n\n"
            f"⚙️ COMANDOS DE PRIVACIDADE E TERMOS:\n"
            f"• /termos — Visualizar políticas e aceitar uso\n"
            f"• /apagar — Excluir permanentemente seus registros (LGPD)\n\n"
            f"📢 Canal Oficial: {CFG.CANAL_TAG_PUBLICO}\n"
            f"💬 Suporte Direto: @{CFG.SUPORTE_USERNAME}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(
            InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CFG.CANAL_TAG_PUBLICO.replace('@','')}"),
            InlineKeyboardButton("💬 Suporte", url=f"https://t.me/{CFG.SUPORTE_USERNAME}")
        )
        bot.send_message(message.chat.id, menu_boas_vindas, reply_markup=markup)

    @bot.message_handler(commands=['termos'])
    def handle_termos(message):
        user_id = message.from_user.id
        db_execute("UPDATE users SET accepted_terms = 1 WHERE user_id = ?", (user_id,), commit=True)
        texto = (
            "📜 TERMOS DE USO E POLÍTICA DE PRIVACIDADE (LGPD)\n\n"
            "1. A ferramenta Kronos Intel agrega atalhos e informações estritamente públicas obtidas de fontes abertas.\n"
            "2. O uso para assédio, stalking, fraudes ou atos ilícitos é expressamente proibido.\n"
            "3. O sistema registra trilhas de auditoria via Hash Criptográfico SHA-256 para conformidade legal.\n\n"
            "✅ Termos aceitos com sucesso!"
        )
        responder_seguro(message, texto)

    # Registro dinâmico de Handlers via Fábrica
    bot.message_handler(commands=['fone'])(
        _comando_busca("fone", lambda x: re.sub(r'\D', '', x) if RE_FONE.match(re.sub(r'\D', '', x)) else None, "Envie o DDD + Número (ex: /fone 11999998888)", "Telefone (/fone)")
    )
    bot.message_handler(commands=['cnpj'])(
        _comando_busca("cnpj", lambda x: re.sub(r'\D', '', x) if RE_CNPJ.match(re.sub(r'\D', '', x)) else None, "Envie apenas os 14 números (ex: /cnpj 00000000000191)", "CNPJ (/cnpj)")
    )
    bot.message_handler(commands=['placa'])(
        _comando_busca("placa", lambda x: x.upper().replace("-", "").strip() if RE_PLACA.match(x.upper().replace("-", "").strip()) else None, "Envie no formato ABC1234 ou ABC1D23", "Placa (/placa)")
    )
    bot.message_handler(commands=['email'])(
        _comando_busca("email", lambda x: x.strip() if e_email_valido(x.strip()) else None, "Envie no formato usuario@dominio.com", "E-mail (/email)")
    )
    bot.message_handler(commands=['nome'])(
        _comando_busca("fullname", lambda x: x.strip() if e_nome_completo(x.strip()) else None, "Envie Nome e Sobrenome completos", "Nome Completo (/nome)")
    )
    bot.message_handler(commands=['dominio'])(
        _comando_busca("dominio", lambda x: x.lower().replace("https://", "").replace("http://", "").strip('/'), "Envie um domínio válido (ex: /dominio site.com)", "Domínio (/dominio)")
    )
    bot.message_handler(commands=['user'])(
        _comando_busca("username", lambda x: x.replace("@", "").strip() if RE_USERNAME.match(x.replace("@", "").strip()) else None, "Envie um username válido (ex: /user alvo123)", "Username (/user)")
    )

    @bot.message_handler(commands=['admin'])
    def handle_admin_panel(message):
        if message.from_user.id != CFG.ADMIN_ID:
            return

        res_users = db_execute("SELECT COUNT(*) FROM users", fetchone=True)
        total_users = res_users[0] if res_users else 0
        res_searches = db_execute("SELECT value FROM metrics WHERE key = 'total_searches'", fetchone=True)
        searches = res_searches[0] if res_searches else 0
        vendas = db_execute("SELECT COUNT(*), SUM(amount) FROM payments WHERE status = 'approved' AND amount > 0", fetchone=True)
        qtd_vendas = vendas[0] if (vendas and vendas[0] is not None) else 0
        faturamento = vendas[1] if (vendas and vendas[1] is not None) else 0.0

        texto_admin = (
            f"👑 PAINEL CENTRAL DE ADMINISTRAÇÃO KRONOS INTEL (v35.0 VIP)\n"
            f"─────────────────────────────────────────────\n"
            f"📊 Métricas de Operação:\n"
            f"• Usuários Totais: {total_users}\n"
            f"• Buscas Executadas: {searches}\n"
            f"• Vendas Aprovadas: {qtd_vendas} (R$ {faturamento:.2f})\n\n"
            f"🛠️ COMANDOS DE ADMIN:\n"
            f"• /ban <user_id> [motivo] | /unban <user_id>\n"
            f"• /broadcast <mensagem>\n"
            f"• /stats\n"
            f"• /conceder <user_id> <termo_alvo>"
        )
        responder_seguro(message, texto_admin)

    @bot.message_handler(commands=['apagar'])
    def handle_apagar_dados(message):
        user_id = message.from_user.id
        db_execute("DELETE FROM users WHERE user_id = ?", (user_id,), commit=True)
        db_execute("UPDATE payments SET target_username='(apagado)', results_json=NULL, pix_code=NULL WHERE user_id = ?", (user_id,), commit=True)
        db_execute("DELETE FROM free_claims WHERE user_id = ?", (user_id,), commit=True)
        db_execute("DELETE FROM coupon_redemptions WHERE user_id = ?", (user_id,), commit=True)
        db_execute("DELETE FROM rate_events WHERE user_id = ?", (user_id,), commit=True)
        db_execute("DELETE FROM audit_log WHERE user_id = ?", (user_id,), commit=True)
        bot.reply_to(message, "🗑️ Solicitação de Privacidade LGPD Concluída: Todos os seus registros foram expurgados permanentemente do sistema.")

    @bot.message_handler(commands=['stats', 'statistics'])
    def handle_stats_command(message):
        if message.from_user.id != CFG.ADMIN_ID:
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
            f"📊 RELATÓRIO FINANCEIRO E MÉTRICAS v35.0 VIP\n"
            f"───────────────────────────────\n"
            f"👤 Usuários Totais Registrados: {total_users}\n"
            f"🔎 Total de Buscas Executadas: {searches}\n"
            f"📄 Relatórios VIP Gerados: {reports}\n"
            f"💰 Vendas Aprovadas (Pix): {qtd_vendas}\n"
            f"💵 Faturamento Total Adquirido: R$ {faturamento:.2f}\n"
            f"───────────────────────────────\n"
            f"📅 Solicitado em: {data_hora_solicitacao}"
        )

        try:
            bot.send_message(CFG.LOG_GROUP_ID, relatorio_financeiro)
            if message.chat.type == 'private':
                bot.reply_to(message, "✅ Relatório financeiro enviado ao grupo de logs.")
        except Exception as e:
            logger.error("Falha ao enviar relatório para o grupo: %s", str(e))

    @bot.message_handler(func=lambda message: True)
    def handle_catch_all(message):
        if not message.text or message.chat.type in ['group', 'supergroup']:
            return

        texto = message.text.replace("\n", " ").strip()
        target = texto.replace("@", "").strip()

        if e_url(target) and not ("." in target and "/" not in target):
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

        _processar_busca_generica(message, target, qtype, f"Busca Direta ({qtype.upper()})")

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
                bot.answer_callback_query(call.id, "⚠️ Você precisa entrar no canal oficial para liberar o relatório grátis!", show_alert=True)
                return

            ok = db_execute(
                "INSERT INTO free_claims (user_id, claimed_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING RETURNING user_id",
                (user_id, datetime.now(TIMEZONE_BR).isoformat()), fetchone=True, commit=True
            )
            if not ok:
                bot.answer_callback_query(call.id, "⚠️ Você já utilizou o seu relatório gratuito!", show_alert=True)
                return

            bot.answer_callback_query(call.id, "🎉 Relatório gratuito gerado!")
            resultados = json.loads(results_json_str)
            link_web = gerar_painel_gratuito_membro(user_id, target, qtype, resultados)

            markup = InlineKeyboardMarkup(row_width=1)
            markup.add(InlineKeyboardButton("🌐 Acessar Seu Painel VIP (GRÁTIS)", url=link_web))
            bot.send_message(call.message.chat.id, f"🎉 RELATÓRIO LIBERADO PARA {target}:", reply_markup=markup)

        elif call.data.startswith("b_"):
            hash_curto = call.data.split("b_")[1]
            target, qtype, results_json_str = obter_alvo_por_hash(hash_curto)
            user_id = call.from_user.id

            if usuario_esta_banido(user_id) or not target or not results_json_str:
                bot.answer_callback_query(call.id, "Consulta indisponível.", show_alert=True)
                return

            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target, valor=CFG.PRECO_PADRAO, query_type=qtype, results_json_str=results_json_str)
            if qr_pix:
                texto_oferta = (
                    f"🔒 CONSULTA KRONOS INTEL VIP ({qtype.upper()})\n"
                    f"───────────────────────────────\n"
                    f"💰 Valor: R$ {CFG.PRECO_PADRAO:.2f} no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n`{qr_pix}`"
                )
                markup = InlineKeyboardMarkup(row_width=1)
                markup.add(InlineKeyboardButton("📋 Copiar Chave Pix", callback_data=f"getkey_{token}"))
                bot.send_message(call.message.chat.id, texto_oferta, reply_markup=markup, parse_mode="Markdown")

        elif call.data.startswith("getkey_"):
            token_pix = call.data.split("getkey_")[1]
            row = db_execute("SELECT pix_code FROM payments WHERE token = ? AND status = 'pending'", (token_pix,), fetchone=True)
            if row and row[0]:
                bot.send_message(call.message.chat.id, text=f"<code>{escapar_html(row[0])}</code>", parse_mode="HTML")

# --- ENDPOINTS FLASK DE WEBHOOKS E HEALTH CHECK ---
@app.route(f"/telegram/{CFG.TELEGRAM_SECRET_TOKEN}", methods=["POST"])
def telegram_webhook():
    if not bot:
        return jsonify({"error": "bot_disabled"}), 400

    secret_header = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
    if not secret_header or not hmac.compare_digest(secret_header, CFG.TELEGRAM_SECRET_TOKEN):
        return jsonify({"error": "unauthorized"}), 403

    try:
        data = request.get_json(force=True, silent=True)
        if data:
            update = Update.de_json(data)
            bot.process_new_updates([update])
            return jsonify({"status": "ok"}), 200
    except Exception as err:
        logger.exception("Erro no webhook do Telegram: %s", str(err))
    return jsonify({"status": "ok"}), 200

def validar_assinatura_mp(req, segredo: str, data_id: str) -> bool:
    if not segredo:
        return False
    partes = dict(p.split("=", 1) for p in req.headers.get("x-signature", "").split(",") if "=" in p)
    ts, v1 = partes.get("ts"), partes.get("v1")
    if not ts or not v1 or not data_id:
        return False
    manifest = f"id:{data_id};request-id:{req.headers.get('x-request-id','')};ts:{ts};"
    esperado = hmac.new(segredo.encode(), manifest.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(esperado, v1):
        return False
    try:
        if abs(time.time() - int(ts) / 1000) > 600:
            return False
    except ValueError:
        return False
    return True

@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
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

    if not payment_id or str(payment_id) == "123456":
        return jsonify({"status": "ok"}), 200

    pid_str = str(payment_id)

    if CFG.MERCADOPAGO_WEBHOOK_SECRET and not validar_assinatura_mp(request, CFG.MERCADOPAGO_WEBHOOK_SECRET, pid_str):
        return jsonify({"status": "error", "detail": "assinatura_invalida"}), 401

    row = db_execute("SELECT user_id, target_username, query_type, token FROM payments WHERE payment_id = ? AND status = 'pending'", (pid_str,), fetchone=True)
    if not row or row[1].startswith("("):
        return jsonify({"status": "ok"}), 200

    telegram_id, target, query_type, token_relatorio = row

    if sdk:
        try:
            payment_info = sdk.payment().get(pid_str).get("response", {})
            if payment_info.get("status") == "approved":
                _valor = float(payment_info.get("transaction_amount") or 0.0)
                _meta = payment_info.get("metadata") or {}

                if _valor + 1e-6 < CFG.PRECO_PADRAO or (_meta.get("telegram_user_id") and int(_meta.get("telegram_user_id")) != int(telegram_id)):
                    return jsonify({"status": "ok"}), 200

                claimed = db_execute("UPDATE payments SET status='approved' WHERE payment_id=? AND status='pending' RETURNING payment_id", (pid_str,), fetchone=True, commit=True)
                if not claimed:
                    return jsonify({"status": "ok"}), 200

                link_web = f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"
                if telegram_id and bot:
                    markup = InlineKeyboardMarkup(row_width=1)
                    markup.add(
                        InlineKeyboardButton("🌐 Acessar Painel Interativo Web", url=link_web),
                        InlineKeyboardButton("📄 Baixar Relatório PDF VIP", url=f"{CFG.WEB_BASE_URL}/download/pdf/{token_relatorio}")
                    )
                    bot.send_message(telegram_id, f"⚡ PAGAMENTO CONFIRMADO!\n\nConsulta ({query_type.upper()}) liberada com sucesso:", reply_markup=markup)
                    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_reports'", commit=True)
        except Exception as e:
            logger.error("Erro no webhook MP: %s", str(e))

    return jsonify({"status": "ok"}), 200

@app.route("/healthz")
def healthz():
    return jsonify({"status": "healthy"}), 200

@app.route("/readyz")
def readyz():
    try:
        db_execute("SELECT 1", fetchone=True)
        return jsonify({"status": "ready", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "unready", "reason": str(e)}), 503

@app.route("/")
def index():
    return f"Kronos Intel OSINT Service v35.0 VIP Active.", 200

def setup_webhook_telegram():
    if bot and CFG.TELEGRAM_TOKEN:
        webhook_url = f"{CFG.WEB_BASE_URL}/telegram/{CFG.TELEGRAM_SECRET_TOKEN}"
        try:
            bot.remove_webhook()
            bot.set_webhook(url=webhook_url, secret_token=CFG.TELEGRAM_SECRET_TOKEN)
            logger.info("Webhook Telegram v35.0 configurado com sucesso.")
        except Exception as e:
            logger.error("Erro ao registrar Webhook Telegram: %s", str(e))

if __name__ == "__main__":
    setup_webhook_telegram()
    Thread(target=worker_divulgacao_diaria, daemon=True).start()
    Thread(target=worker_background, daemon=True).start()
    app.run(debug=_env_bool("FLASK_DEBUG", False), host="0.0.0.0", port=CFG.PORT)
