"""
Kronos Intel OSINT Bot v35.1 VIP
- Resposta Ultra-Rápida com Timeout Reduzido por Plataforma (2.0s max)
- Motor OSINT Assíncrono Otimizado
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

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("kronos_osint")

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
    LOG_GROUP_ID: int = _env_int("GRUPO_LOGS_ID", _env_int("LOG_GROUP_ID", -1003986408630))
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

def escaping_html(texto: str) -> str:
    return html.escape(str(texto or ""))

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
        except Exception:
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
    except Exception:
        pass

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

def limpar_comando_string(texto: str) -> str:
    t = texto.strip()
    t = re.sub(r'^/?[a-zA-Z0-9_]+\s+', '', t)
    return t.replace("@", "").strip()

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
        except Exception:
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
    except Exception:
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
        raw_first = escaping_html(from_user.first_name or "Usuario")
        raw_last = escaping_html(from_user.last_name or "")
        nome_completo = f"{raw_first} {raw_last}".strip()
        username_str = f"@{escaping_html(from_user.username)}" if from_user.username else "Sem @username"
        data_hora = datetime.now(TIMEZONE_BR).strftime('%d/%m/%Y às %H:%M:%S')

        msg_log = (
            f"<b>🔎 NOVA CONSULTA EXECUTADA</b>\n"
            f"───────────────────────────────\n"
            f"• <b>ID do Usuário:</b> <code>{from_user.id}</code>\n"
            f"• <b>Nome:</b> {nome_completo}\n"
            f"• <b>Username:</b> {username_str}\n"
            f"• <b>Módulo Solicitado:</b> {escaping_html(modulo_nome.upper())}\n"
            f"• <b>Data/Hora:</b> {data_hora}"
        )
        bot.send_message(CFG.LOG_GROUP_ID, msg_log, parse_mode="HTML")
    except Exception:
        pass

# --- PLATAFORMAS E CONFIGURAÇÃO DO MOTOR OSINT ---
PLATAFORMAS: dict[str, dict[str, Any]] = {
    "GitHub":       {"url": "https://api.github.com/users/{username}", "fonte": "api", "json": "nao_vazio", "cabecalhos": {"Accept": "application/vnd.github+json"}},
    "GitLab":       {"url": "https://gitlab.com/api/v4/users?username={username}", "fonte": "api", "json": "lista_cheia"},
    "Codeberg":     {"url": "https://codeberg.org/api/v1/users/{username}", "fonte": "api", "json": "nao_vazio"},
    "Docker Hub":   {"url": "https://hub.docker.com/v2/users/{username}/", "fonte": "api", "json": "nao_vazio"},
    "Reddit":       {"url": "https://www.reddit.com/user/{username}/about.json", "fonte": "api", "json": "reddit", "cabecalhos": {"User-Agent": "kronos-osint/1.0"}},
    "Lichess":      {"url": "https://lichess.org/api/user/{username}", "fonte": "api", "json": "nao_vazio"},
    "Chess.com":    {"url": "https://api.chess.com/pub/player/{username}", "fonte": "api", "json": "nao_vazio"},
    "Medium":       {"url": "https://medium.com/@{username}", "fonte": "html", "positivo": r'property="og:type" content="profile"'},
    "SoundCloud":   {"url": "https://soundcloud.com/{username}", "fonte": "html", "positivo": r'soundcloud:users:'},
    "Linktree":     {"url": "https://linktr.ee/{username}", "fonte": "html", "positivo": r'profile_title'},
    "Steam":        {"url": "https://steamcommunity.com/id/{username}", "fonte": "html", "positivo": r'actual_persona_name'},
}

class OSINTEngineAsync:
    def __init__(self, max_concurrency: int = 30):
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._cache_lock = Lock()
        self.headers_padrao = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
        }

    async def consultar_plataforma(self, client: httpx.AsyncClient, nome: str, cfg: dict, username: str) -> tuple[str, dict[str, Any]]:
        url = cfg["url"].format(username=username)
        async with self.semaphore:
            try:
                resp = await client.get(url, headers=self.headers_padrao, timeout=2.0, follow_redirects=True)
                if resp.status_code == 200:
                    return nome, {"exists": True, "url": url}
            except Exception:
                pass
            return nome, {"exists": False}

    async def executar_varredura(self, username: str) -> dict[str, Any]:
        agora = time.time()
        with self._cache_lock:
            if username in self.cache:
                ts, res_cached = self.cache[username]
                if agora - ts < CFG.CACHE_TTL_SECONDS:
                    return res_cached

        async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=20, max_connections=40)) as client:
            tasks = [self.consultar_plataforma(client, nome, cfg, username) for nome, cfg in PLATAFORMAS.items()]
            resultados_raw = await asyncio.gather(*tasks)

        resultados = dict(resultados_raw)

        encoded_user = urllib.parse.quote(username)
        resultados["Google Search (Redes & Perfis)"] = {"exists": True, "url": f"https://www.google.com/search?q=%22{encoded_user}%22"}
        resultados["Instagram Profile Direct"] = {"exists": True, "url": f"https://www.instagram.com/{encoded_user}/"}
        resultados["TikTok Profile Direct"] = {"exists": True, "url": f"https://www.tiktok.com/@{encoded_user}"}
        resultados["X / Twitter Profile Direct"] = {"exists": True, "url": f"https://x.com/{encoded_user}"}
        resultados["WhatsMyName Username Enum"] = {"exists": True, "url": f"https://whatsmyname.app/?q={encoded_user}"}

        with self._cache_lock:
            if len(self.cache) > 2000:
                self.cache.clear()
            self.cache[username] = (agora, resultados)

        return resultados

class AsyncLoopThread:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro, timeout: float = 8.0):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=timeout)

ASYNC_RUNNER = AsyncLoopThread()
ENGINE_ASYNC = OSINTEngineAsync()

def executar_varredura_osint(target: str, query_type: str = "username") -> dict[str, dict[str, Any]]:
    target_limpo = limpar_comando_string(target)

    if query_type == "email":
        encoded_email = urllib.parse.quote(target_limpo)
        return {
            "Have I Been Pwned (Base de Vazamentos)": {"exists": True, "url": f"https://haveibeenpwned.com/account/{encoded_email}"},
            "DeHashed CyberIntelligence": {"exists": True, "url": f"https://dehashed.com/search?query={encoded_email}"},
            "Intelligence X (IntelX)": {"exists": True, "url": f"https://intelx.io/?s={encoded_email}"},
            "BreachDirectory Engine": {"exists": True, "url": f"https://breachdirectory.org/search?query={encoded_email}"}
        }
    elif query_type == "fullname":
        encoded_name = urllib.parse.quote(f'"{target_limpo}"')
        return {
            "Jusbrasil (Processos e Diários)": {"exists": True, "url": f"https://www.jusbrasil.com.br/busca?q={encoded_name}"},
            "Escavador (Publicações Judiciais)": {"exists": True, "url": f"https://www.escavador.com/busca?q={encoded_name}"},
            "Portal da Transparência Federal": {"exists": True, "url": f"https://www.portaltransparencia.gov.br/busca?termo={urllib.parse.quote(target_limpo)}"}
        }
    elif query_type == "fone":
        limpo = re.sub(r'\D', '', target_limpo)
        ddd = limpo[:2] if len(limpo) >= 10 else "N/A"
        regiao = DDD_ESTADOS.get(ddd, "Região Não Mapeada")

        res = {
            "WhatsApp Direct Chat": {"exists": True, "url": f"https://wa.me/55{limpo}"},
            "Truecaller Directory": {"exists": True, "url": f"https://www.truecaller.com/search/br/{limpo}"},
            "Google Search (Vazamentos)": {"exists": True, "url": f"https://www.google.com/search?q=%22{limpo}%22"}
        }
        res["Região Geográfica / UF"] = {"exists": True, "url": "#", "detalhes": regiao}
        return res
    else:
        return ASYNC_RUNNER.run(ENGINE_ASYNC.executar_varredura(target_limpo))

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

    meta_data = [
        [Paragraph("<b>ALVO ANALISADO:</b>", cell_style), Paragraph(f"<b>{sanitizar_pdf(target)}</b>", cell_style)],
        [Paragraph("<b>MÓDULO DE BUSCA:</b>", cell_style), Paragraph(query_type.upper(), cell_style)],
        [Paragraph("<b>DATA DA AUDITORIA:</b>", cell_style), Paragraph(data_atual, cell_style)]
    ]
    t_meta = Table(meta_data, colWidths=[160, 380])
    t_meta.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f3f4f6')), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e5e7eb')), ('PADDING', (0,0), (-1,-1), 6)]))
    story.append(t_meta)
    story.append(Spacer(1, 15))

    table_data = [[Paragraph("PLATAFORMA / CAMPO", header_table_style), Paragraph("INFORMAÇÃO / LINK DIRETO", header_table_style)]]

    for p, v in resultados.items():
        if isinstance(v, dict) and v.get("exists") is True:
            url_str = v.get('url', '')
            table_data.append([Paragraph(f"<b>{sanitizar_pdf(p)}</b>", cell_style), Paragraph(link_pdf(url_str), cell_url_style)])

    t_results = Table(table_data, colWidths=[180, 360])
    t_results.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')), ('PADDING', (0,0), (-1,-1), 6)]))
    story.append(t_results)

    doc.build(story)
    buffer.seek(0)
    return buffer

def construir_relatorio_osint(target: str, resultados: dict[str, dict[str, Any]], query_type: str = "username") -> io.BytesIO:
    data_atual = datetime.now(TIMEZONE_BR).strftime("%d/%m/%Y %H:%M:%S")
    corpo = f"KRONOS INTEL — RELATÓRIO OSINT\nALVO: {target}\nDATA: {data_atual}\n\n"
    for p, v in resultados.items():
        if isinstance(v, dict) and v.get("exists") is True:
            corpo += f"[+] {p} : {v.get('url', '')}\n"
    buf = io.BytesIO(corpo.encode('utf-8'))
    buf.name = f"Relatorio_OSINT_{target}.txt"
    return buf

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
    return f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"

def _processar_busca_generica(message, raw_target: str, qtype: str, modulo_nome: str):
    user_id = message.from_user.id
    target = limpar_comando_string(raw_target)

    if not target or len(target) < 2:
        responder_seguro(message, "⚠️ Termo de busca muito curto.")
        return

    now_str = datetime.now(TIMEZONE_BR).isoformat()
    db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, now_str), commit=True)

    resultados = executar_varredura_osint(target, query_type=qtype)

    if user_id == CFG.ADMIN_ID:
        link_web = gerar_painel_gratuito_membro(user_id, target, qtype, resultados)
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(
            InlineKeyboardButton("🌐 Acessar Seu Painel VIP (ADMIN)", url=link_web),
            InlineKeyboardButton("📄 Baixar Relatório PDF VIP", url=f"{CFG.WEB_BASE_URL}/download/pdf/{link_web.split('/')[-1]}")
        )
        bot.send_message(
            message.chat.id,
            f"👑 **MODO ADMINISTRADOR - CONSULTA LIBERADA**\n\n"
            f"• **Alvo:** `{target}`\n"
            f"• **Modalidade:** {qtype.upper()}\n\n"
            f"Relatório processado e disponível abaixo:",
            reply_markup=markup,
            parse_mode="Markdown"
        )
        return

if bot:
    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        user_id = message.from_user.id
        menu_boas_vindas = f"👑 KRONOS INTEL OSINT BOT VIP ⚡️\n\nUtilize /user <username> para consultar."
        bot.send_message(message.chat.id, menu_boas_vindas)

    @bot.message_handler(commands=['user', 'admin_user'])
    def handle_user_cmd(message):
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) >= 2:
            _processar_busca_generica(message, partes[1], "username", "Username (/user)")
        else:
            responder_seguro(message, "⚠️ Uso: `/user <username>`", parse_mode="Markdown")

    @bot.message_handler(func=lambda message: True)
    def handle_catch_all(message):
        if not message.text or message.chat.type in ['group', 'supergroup']:
            return
        target = limpar_comando_string(message.text)
        if len(target) >= 2:
            _processar_busca_generica(message, target, "username", "Busca Direta")

@app.route(f"/telegram/{CFG.TELEGRAM_SECRET_TOKEN}", methods=["POST"])
def telegram_webhook():
    if not bot:
        return jsonify({"error": "bot_disabled"}), 400
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            update = Update.de_json(data)
            bot.process_new_updates([update])
            return jsonify({"status": "ok"}), 200
    except Exception as err:
        logger.exception("Erro no webhook do Telegram: %s", str(err))
    return jsonify({"status": "ok"}), 200

@app.route("/healthz")
def healthz():
    return jsonify({"status": "healthy"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Service Active.", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=CFG.PORT)
