"""
Kronos Intel OSINT Bot v35.3 VIP (Versão Leve)
- Fluxo simplificado sem bloqueios no catch_all
- Resposta imediata para /start, /user e /admin_user
- Motor OSINT assíncrono leve com timeout de 2.0s
- Suporte Oficial: @kronosintel
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import html
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, Optional, Tuple
import urllib.parse
from zoneinfo import ZoneInfo
from threading import Lock

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

@dataclass
class Config:
    TELEGRAM_TOKEN: str = os.getenv("TELEGRAM_TOKEN", "")
    ADMIN_ID: int = _env_int("ADMIN_ID", 5041637922)
    CANAL_PRINCIPAL_ID: int = _env_int("CANAL_PRINCIPAL_ID", -1003802363624)
    LOG_GROUP_ID: int = _env_int("GRUPO_LOGS_ID", -1003986408630)
    CANAL_TAG_PUBLICO: str = os.getenv("CANAL_TAG_PUBLICO", "@kronosinteloficial")
    SUPORTE_USERNAME: str = os.getenv("SUPORTE_USERNAME", "kronosintel")
    BOT_USERNAME: str = os.getenv("BOT_USERNAME", "KronosSearchbot")
    WEB_BASE_URL: str = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com").rstrip('/')
    
    MERCADOPAGO_TOKEN: str = os.getenv("MERCADOPAGO_TOKEN", "")
    MERCADOPAGO_WEBHOOK_SECRET: str = os.getenv("MERCADOPAGO_WEBHOOK_SECRET", "").strip()
    
    PRECO_PADRAO: float = _env_float("PRECO_PADRAO", 3.90)
    DB_FILE: str = os.getenv("DB_FILE", "/var/data/kronos_osint.db" if os.path.exists("/var/data") else "kronos_osint.db")
    PORT: int = _env_int("PORT", 5000)
    TELEGRAM_SECRET_TOKEN: str = os.getenv("TELEGRAM_SECRET_TOKEN", "secret_token_kronos")

CFG = Config()

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

TIMEZONE_BR = ZoneInfo("America/Sao_Paulo")
db_lock = Lock()

sdk = mercadopago.SDK(CFG.MERCADOPAGO_TOKEN) if CFG.MERCADOPAGO_TOKEN else None
bot = telebot.TeleBot(CFG.TELEGRAM_TOKEN, threaded=False) if CFG.TELEGRAM_TOKEN else None

def escaping_html(texto: str) -> str:
    return html.escape(str(texto or ""))

def sanitizar_pdf(texto: str) -> str:
    s = str(texto if texto is not None else "")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def limpar_comando_string(texto: str) -> str:
    t = texto.strip()
    t = re.sub(r'^/?[a-zA-Z0-9_]+\s*', '', t)
    return t.replace("@", "").strip()

def init_db():
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL")

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
                token TEXT,
                results_json TEXT,
                query_type TEXT DEFAULT 'username',
                created_at TEXT
            )
        """)
        conn.commit()
        conn.close()

init_db()

def db_execute(query: str, params: tuple = (), fetchone=False, commit=False):
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute(query, params)
        res = cursor.fetchone() if fetchone else None
        if commit:
            conn.commit()
        conn.close()
        return res

# --- PLATAFORMAS LEVES DE CONSULTA ---
PLATAFORMAS = {
    "GitHub": "https://api.github.com/users/{username}",
    "GitLab": "https://gitlab.com/api/v4/users?username={username}",
    "Reddit": "https://www.reddit.com/user/{username}/about.json",
    "Medium": "https://medium.com/@{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
}

async def consultar_alvo_async(username: str) -> dict[str, Any]:
    username_limpo = limpar_comando_string(username)
    resultados = {}
    
    headers = {"User-Agent": "Mozilla/5.0"}
    async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)) as client:
        for nome, url_template in PLATAFORMAS.items():
            url = url_template.format(username=username_limpo)
            try:
                resp = await client.get(url, headers=headers, timeout=2.0)
                if resp.status_code == 200:
                    resultados[nome] = {"exists": True, "url": url}
            except Exception:
                pass

    encoded_user = urllib.parse.quote(username_limpo)
    resultados["Google Search"] = {"exists": True, "url": f"https://www.google.com/search?q=%22{encoded_user}%22"}
    resultados["Instagram"] = {"exists": True, "url": f"https://www.instagram.com/{encoded_user}/"}
    resultados["TikTok"] = {"exists": True, "url": f"https://www.tiktok.com/@{encoded_user}"}
    resultados["X / Twitter"] = {"exists": True, "url": f"https://x.com/{encoded_user}"}
    
    return resultados

def executar_varredura(target: str) -> dict[str, Any]:
    return asyncio.run(consultar_alvo_async(target))

def gerar_painel_gratuito(user_id: int, target: str, resultados: dict) -> str:
    results_json = json.dumps(resultados)
    token_relatorio = secrets.token_urlsafe(16)
    pid_free = f"free_{user_id}_{secrets.token_hex(4)}"

    db_execute(
        "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at) "
        "VALUES (?, ?, ?, 0.0, 'approved', ?, ?, 'username', ?)",
        (pid_free, user_id, target, token_relatorio, results_json, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )
    return f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"

def processar_busca(message, raw_target: str):
    user_id = message.from_user.id
    target = limpar_comando_string(raw_target)

    if not target or len(target) < 2:
        bot.reply_to(message, "⚠️ Termo muito curto.")
        return

    db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, datetime.now(TIMEZONE_BR).isoformat()), commit=True)

    resultados = executar_varredura(target)

    if user_id == CFG.ADMIN_ID:
        link_web = gerar_painel_gratuito(user_id, target, resultados)
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(
            InlineKeyboardButton("🌐 Acessar Painel VIP (ADMIN)", url=link_web),
            InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{CFG.WEB_BASE_URL}/download/pdf/{link_web.split('/')[-1]}")
        )
        bot.send_message(
            message.chat.id,
            f"👑 **MODO ADMINISTRADOR - CONSULTA LIBERADA**\n\n"
            f"• **Alvo:** `{target}`\n"
            f"• **Modalidade:** USERNAME\n\n"
            f"Relatório processado e disponível abaixo:",
            reply_markup=markup,
            parse_mode="Markdown"
        )
        return

    link_web = gerar_painel_gratuito(user_id, target, resultados)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("🌐 Acessar Seu Painel Web", url=link_web),
        InlineKeyboardButton("📢 Canal Oficial", url=f"https://t.me/{CFG.CANAL_TAG_PUBLICO.replace('@','')}")
    )
    bot.send_message(message.chat.id, f"🎯 **CONSULTA DE ALVO:** `{target}`\n\nAcesse o relatório abaixo:", reply_markup=markup, parse_mode="Markdown")

if bot:
    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        user_id = message.from_user.id
        raw_first = escaping_html(message.from_user.first_name or "Usuario")
        
        db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, datetime.now(TIMEZONE_BR).isoformat()), commit=True)

        menu = (
            f"👑 KRONOS INTEL OSINT BOT VIP ⚡️\n"
            f"─────────────────────────────\n"
            f"👋 Olá, {raw_first}!\n\n"
            f"🛠️ COMANDOS DISPONÍVEIS:\n"
            f"• `/user <username>` — Consultar presença digital\n"
            f"• `/admin_user <username>` — Consulta direta de Admin\n\n"
            f"📢 Canal Oficial: {CFG.CANAL_TAG_PUBLICO}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(
            InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CFG.CANAL_TAG_PUBLICO.replace('@','')}"),
            InlineKeyboardButton("💬 Suporte", url=f"https://t.me/{CFG.SUPORTE_USERNAME}")
        )
        bot.send_message(message.chat.id, menu, reply_markup=markup, parse_mode="Markdown")

    @bot.message_handler(commands=['user', 'admin_user'])
    def handle_user_cmd(message):
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) >= 2:
            processar_busca(message, partes[1])
        else:
            bot.reply_to(message, "⚠️ Uso correto: `/user <username>`", parse_mode="Markdown")

@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, created_at FROM payments WHERE token = ?", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404
    return f"Relatório do alvo: {p[0]}", 200

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
        logger.exception("Erro no webhook: %s", str(err))
    return jsonify({"status": "ok"}), 200

@app.route("/healthz")
def healthz():
    return jsonify({"status": "healthy"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Active.", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=CFG.PORT)
