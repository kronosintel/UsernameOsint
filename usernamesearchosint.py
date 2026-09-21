"""
Kronos Intel OSINT Bot v35.5 VIP
- Correção Crítica do Webhook (Processamento Não-Bloqueante)
- Resposta Instantânea para /start, /user e /admin_user
- Motor OSINT Assíncrono com Timeout Seguro
- Painel Web e Download de PDF VIP Ativo
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
    PRECO_PADRAO: float = _env_float("PRECO_PADRAO", 3.90)
    DB_FILE: str = os.getenv("DB_FILE", "/var/data/kronos_osint.db" if os.path.exists("/var/data") else "kronos_osint.db")
    PORT: int = _env_int("PORT", 5000)
    CACHE_TTL_SECONDS: int = _env_int("CACHE_TTL_SECONDS", 900)
    TELEGRAM_SECRET_TOKEN: str = os.getenv("TELEGRAM_SECRET_TOKEN", "secret_token_kronos")

CFG = Config()

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

TIMEZONE_BR = ZoneInfo("America/Sao_Paulo")
db_lock = Lock()

sdk = mercadopago.SDK(CFG.MERCADOPAGO_TOKEN) if CFG.MERCADOPAGO_TOKEN else None
# Habilitado threaded=True para processamento simultâneo sem travar o Flask
bot = telebot.TeleBot(CFG.TELEGRAM_TOKEN, threaded=True) if CFG.TELEGRAM_TOKEN else None

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

PLATAFORMAS = {
    "GitHub": "https://api.github.com/users/{username}",
    "GitLab": "https://gitlab.com/api/v4/users?username={username}",
    "Codeberg": "https://codeberg.org/api/v1/users/{username}",
    "Docker Hub": "https://hub.docker.com/v2/users/{username}/",
    "Reddit": "https://www.reddit.com/user/{username}/about.json",
    "Lichess": "https://lichess.org/api/user/{username}",
    "Chess.com": "https://api.chess.com/pub/player/{username}",
    "Medium": "https://medium.com/@{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
}

async def consultar_alvo_async(username: str) -> dict[str, Any]:
    username_limpo = limpar_comando_string(username)
    resultados = {}
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)) as client:
        tasks = []
        for nome, url_template in PLATAFORMAS.items():
            url = url_template.format(username=username_limpo)
            tasks.append(client.get(url, headers=headers, timeout=1.5, follow_redirects=True))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for (nome, _), resp in zip(PLATAFORMAS.items(), responses):
            if isinstance(resp, httpx.Response) and resp.status_code == 200:
                resultados[nome] = {"exists": True, "url": str(resp.url)}

    encoded_user = urllib.parse.quote(username_limpo)
    resultados["Google Search (Redes & Perfis)"] = {"exists": True, "url": f"https://www.google.com/search?q=%22{encoded_user}%22"}
    resultados["Instagram Profile Direct"] = {"exists": True, "url": f"https://www.instagram.com/{encoded_user}/"}
    resultados["TikTok Profile Direct"] = {"exists": True, "url": f"https://www.tiktok.com/@{encoded_user}"}
    resultados["X / Twitter Profile Direct"] = {"exists": True, "url": f"https://x.com/{encoded_user}"}
    resultados["WhatsMyName Username Enum"] = {"exists": True, "url": f"https://whatsmyname.app/?q={encoded_user}"}
    
    return resultados

def executar_varredura(target: str) -> dict[str, Any]:
    return asyncio.run(consultar_alvo_async(target))

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

    link_web = gerar_painel_gratuito(user_id, target, resultados)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("🌐 Acessar Painel VIP", url=link_web),
        InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{CFG.WEB_BASE_URL}/download/pdf/{link_web.split('/')[-1]}")
    )

    if user_id == CFG.ADMIN_ID:
        bot.send_message(
            message.chat.id,
            f"👑 **MODO ADMINISTRADOR - CONSULTA LIBERADA**\n\n"
            f"• **Alvo:** `{target}`\n"
            f"• **Modalidade:** USERNAME\n\n"
            f"Relatório processado e disponível abaixo:",
            reply_markup=markup,
            parse_mode="Markdown"
        )
    else:
        bot.send_message(
            message.chat.id,
            f"🎯 **CONSULTA OSINT CONCLUÍDA**\n\n"
            f"• **Alvo:** `{target}`\n\n"
            f"Clique abaixo para ver o painel:",
            reply_markup=markup,
            parse_mode="Markdown"
        )

if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        user_id = message.from_user.id
        raw_first = escaping_html(message.from_user.first_name or "Usuario")
        user_name = "".join(c for c in raw_first if c.isalnum() or c == " ")[:30].strip() or "Usuario"

        db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, datetime.now(TIMEZONE_BR).isoformat()), commit=True)

        menu_boas_vindas = (
            f"👑 KRONOS INTEL OSINT BOT v35.5 VIP ⚡️\n"
            f"─────────────────────────────────────────────\n"
            f"👋 Olá, {user_name}! Bem-vindo à sua central avançada de inteligência cibernética!\n\n"
            f"🛠️ MÓDULOS DE CONSULTA DISPONÍVEIS:\n\n"
            f"1️⃣ 👤 USERNAME / REDES SOCIAIS:\n"
            f"   • `/user alvo123`\n"
            f"   • `/admin_user alvo123` (Admin)\n\n"
            f"📢 Canal Oficial: {CFG.CANAL_TAG_PUBLICO}\n"
            f"💬 Suporte Direto: @{CFG.SUPORTE_USERNAME}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(
            InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CFG.CANAL_TAG_PUBLICO.replace('@','')}"),
            InlineKeyboardButton("💬 Suporte", url=f"https://t.me/{CFG.SUPORTE_USERNAME}")
        )
        bot.send_message(message.chat.id, menu_boas_vindas, reply_markup=markup, parse_mode="Markdown")

    @bot.message_handler(commands=['admin_user'])
    def handle_admin_user_cmd(message):
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) >= 2:
            processar_busca(message, partes[1])
        else:
            bot.reply_to(message, "⚠️ Uso correto: `/admin_user <username>`", parse_mode="Markdown")

    @bot.message_handler(commands=['user'])
    def handle_user_cmd(message):
        partes = message.text.strip().split(maxsplit=1)
        if len(partes) >= 2:
            processar_busca(message, partes[1])
        else:
            bot.reply_to(message, "⚠️ Uso correto: `/user <username>`", parse_mode="Markdown")

    @bot.message_handler(func=lambda message: True)
    def handle_catch_all(message):
        if not message.text or message.chat.type in ['group', 'supergroup']:
            return
        target = limpar_comando_string(message.text)
        if len(target) >= 2:
            processar_busca(message, target)

@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, created_at FROM payments WHERE token = ?", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou expirado.", 404

    target, results_json_str, created_at = p[0], p[1], p[2]
    try:
        results_json = json.loads(results_json_str) if isinstance(results_json_str, str) else results_json_str
    except Exception:
        results_json = {}

    encontrados = []
    if isinstance(results_json, dict):
        for k, v in results_json.items():
            if isinstance(v, dict) and v.get("exists") is True and v.get("url") != "#":
                encontrados.append({"nome": k, "url": v.get("url")})

    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <title>Kronos Intel — Relatório OSINT ({target})</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background-color: #0f172a; color: #f8fafc; font-family: sans-serif; padding: 20px; }}
            .card-custom {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
            .btn-link-custom {{ background: #334155; color: #38bdf8; text-decoration: none; padding: 10px 15px; border-radius: 8px; display: block; margin-bottom: 10px; }}
            .btn-link-custom:hover {{ background: #475569; color: #f8fafc; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card-custom">
                <h2>🔎 Relatório OSINT: {target}</h2>
                <p class="text-muted">Data: {created_at}</p>
            </div>
            <div class="card-custom">
                <h4>Fontes e Redes Localizadas:</h4>
                <div class="mt-3">
    """
    for item in encontrados:
        html_content += f'<a href="{item["url"]}" target="_blank" class="btn-link-custom">🔗 {item["nome"]} — {item["url"]}</a>'
    
    html_content += """
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(html_content)

@app.route("/download/pdf/<token>")
def download_pdf(token):
    p = db_execute("SELECT target_username, results_json FROM payments WHERE token = ?", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

    target, results_json_str = p[0], p[1]
    try:
        results_json = json.loads(results_json_str) if isinstance(results_json_str, str) else results_json_str
    except Exception:
        results_json = {}
    
    pdf_buf = gerar_pdf_osint(target, results_json)
    return send_file(
        pdf_buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"Relatorio_VIP_{target}.pdf"
    )

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
