"""
Kronos Intel OSINT Bot v35.8 VIP
- Correção na extração de argumentos para /admin_user e /user
- Prevenção do erro 'Termo de busca muito curto' em comandos com prefixo
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
import queue
import re
import secrets
import sqlite3
import time
from typing import Any, Dict
import urllib.parse
from zoneinfo import ZoneInfo
from threading import Lock, Thread
from io import BytesIO

import httpx
import requests
import telebot
try:
    import qrcode
except ImportError:
    qrcode = None
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Update
from flask import Flask, jsonify, request, render_template_string, send_file
from maigret_lookup import consultar_username
from email_tools import consultar_email
from plate_tools import consultar_placa
from domain_tools import consultar_dominio
from name_tools import consultar_nome_completo
from cnpj_tools import consultar_cnpj

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
        return float(os.getenv(key, str(default)).replace(",", "."))
    except ValueError:
        return default

@dataclass
class Config:
    TELEGRAM_TOKEN: str = os.getenv("TELEGRAM_TOKEN", "")
    ADMIN_ID: int = _env_int("ADMIN_ID", 0)
    CANAL_TAG_PUBLICO: str = os.getenv("CANAL_TAG_PUBLICO", "@kronosinteloficial")
    CANAL_PRINCIPAL_ID: str = os.getenv("CANAL_PRINCIPAL_ID", "").strip()
    GRUPO_LOGS_ID: str = os.getenv("GRUPO_LOGS_ID", "").strip()
    CONSULTA_PRECO: float = _env_float("CONSULTA_PRECO", 5.90)
    MERCADOPAGO_ACCESS_TOKEN: str = os.getenv("MERCADOPAGO_ACCESS_TOKEN", os.getenv("MERCADOPAGO_TOKEN", "")).strip()
    PAGAMENTO_EXPIRACAO_MINUTOS: int = _env_int("PAGAMENTO_EXPIRACAO_MINUTOS", 30)
    ADMIN_BYPASS_PAYMENT: bool = os.getenv("ADMIN_BYPASS_PAYMENT", "1").lower() in {"1", "true", "yes"}
    MAIGRET_TIMEOUT: int = _env_int("MAIGRET_TIMEOUT", 45)
    MAIGRET_ENABLED: bool = os.getenv("MAIGRET_ENABLED", "0").lower() in {"1", "true", "yes"}
    CONSULTA_TIMEOUT: int = _env_int("CONSULTA_TIMEOUT", 35)
    SUPORTE_USERNAME: str = os.getenv("SUPORTE_USERNAME", "kronosintel")
    WEB_BASE_URL: str = os.getenv("WEB_BASE_URL", "https://usernameosint-1-vcj4.onrender.com").rstrip('/')
    DB_FILE: str = os.getenv("DB_FILE", "/var/data/kronos_osint.db" if os.path.exists("/var/data") else "kronos_osint.db")
    PORT: int = _env_int("PORT", 5000)
    TELEGRAM_SECRET_TOKEN: str = os.getenv("TELEGRAM_SECRET_TOKEN", "")

CFG = Config()

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)

TIMEZONE_BR = ZoneInfo("America/Sao_Paulo")
db_lock = Lock()

bot = telebot.TeleBot(CFG.TELEGRAM_TOKEN, threaded=False) if CFG.TELEGRAM_TOKEN else None

ADMIN_COMMANDS = {
    "/admin_user": "username",
    "/admin_email": "email",
    "/admin_nome": "fullname",
    "/admin_fone": "fone",
    "/admin_cnpj": "cnpj",
    "/admin_placa": "placa",
    "/admin_dominio": "dominio",
}

ADMIN_MODULES = {
    "user": "username",
    "username": "username",
    "email": "email",
    "nome": "fullname",
    "fullname": "fullname",
    "fone": "fone",
    "cnpj": "cnpj",
    "placa": "placa",
    "dominio": "dominio",
}

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

def resumo_resultado(item: dict[str, Any]) -> str:
    status = str(item.get("status") or ("found" if item.get("exists") is True else "not_found"))
    partes = [f"Status: {status}"]
    if item.get("breach_count") is not None:
        partes.append(f"violações: {item['breach_count']}")
    if item.get("breaches"):
        partes.append("fontes: " + ", ".join(str(x) for x in item["breaches"][:10]))
    if item.get("note"):
        partes.append(str(item["note"]))
    if item.get("text"):
        partes.append(str(item["text"]))
    return " — ".join(partes)

def extrair_alvo_limpo(texto: str, preservar_arroba: bool = False) -> str:
    """ Extrai o termo de busca ignorando comandos e o caractere @. """
    partes = texto.strip().split(maxsplit=1)
    if len(partes) > 1 and partes[0].startswith('/'):
        alvo = partes[1].strip()
    else:
        alvo = texto.strip()
    return alvo.strip() if preservar_arroba else alvo.replace("@", "").strip()

def _preco_formatado() -> str:
    return f"R$ {CFG.CONSULTA_PRECO:.2f}".replace(".", ",")

def enviar_notificacao_evento(evento: str, message, consulta: str = "-", alvo: str = "-", valor: str | None = None) -> None:
    """Envia um log operacional ao canal principal e ao grupo opcional."""
    if not bot:
        return
    destinos = [destino for destino in (CFG.CANAL_PRINCIPAL_ID, CFG.GRUPO_LOGS_ID) if destino]
    if not destinos:
        logger.warning("Nenhum destino de log configurado para o evento %s", evento)
        return

    usuario = message.from_user
    nome = " ".join(part for part in (usuario.first_name, usuario.last_name) if part).strip() or "Sem nome"
    username = f"@{usuario.username}" if usuario.username else "sem username"
    valor = valor or (_preco_formatado() if consulta != "-" else "-")
    texto = (
        f"📣 *{evento}*\n"
        f"• Usuário: {escaping_html(nome)} ({username})\n"
        f"• ID: `{usuario.id}`\n"
        f"• Consulta: `{consulta}`\n"
        f"• Alvo: `{escaping_html(alvo)}`\n"
        f"• Valor: *{valor}*\n"
        f"• Horário: `{datetime.now(TIMEZONE_BR).strftime('%d/%m/%Y %H:%M:%S')}`"
    )
    for destino in destinos:
        try:
            bot.send_message(destino, texto, parse_mode="Markdown", disable_web_page_preview=True)
        except Exception as exc:
            logger.warning("Falha ao enviar log para %s: %s", destino, exc)

def usuario_esta_no_canal(user_id: int) -> bool:
    if not bot or not CFG.CANAL_PRINCIPAL_ID:
        return False
    try:
        membro = bot.get_chat_member(CFG.CANAL_PRINCIPAL_ID, user_id)
        return membro.status in {"member", "administrator", "creator"}
    except Exception as exc:
        logger.warning("Não foi possível validar entrada no canal: %s", exc)
        return False

def reivindicar_consulta_gratis(user_id: int) -> bool:
    """Consome uma única consulta grátis de forma atômica."""
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cur = conn.cursor()
        cur.execute("UPDATE users SET free_used = 1 WHERE user_id = ? AND COALESCE(free_used, 0) = 0", (user_id,))
        consumida = cur.rowcount == 1
        conn.commit()
        conn.close()
        return consumida

def enviar_checkout_com_qr(chat_id: int, checkout_url: str, target: str, qtype: str) -> None:
    """Envia QR do link de checkout e o botão de pagamento."""
    if qrcode is None:
        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(InlineKeyboardButton("💳 Abrir pagamento Mercado Pago", url=checkout_url))
        bot.send_message(
            chat_id,
            f"🧾 Consulta `{qtype.upper()}` criada.\n"
            f"Valor: *{_preco_formatado()}*\n"
            f"Link para copiar: `{checkout_url}`",
            reply_markup=markup,
            parse_mode="Markdown",
        )
        logger.warning("Pacote qrcode não instalado; checkout enviado sem imagem QR")
        return
    qr = qrcode.make(checkout_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    buffer.name = "pagamento.png"
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(InlineKeyboardButton("💳 Abrir pagamento Mercado Pago", url=checkout_url))
    bot.send_photo(
        chat_id,
        buffer,
        caption=(
            f"🧾 Consulta `{qtype.upper()}` criada\n"
            f"Alvo: `{target}`\n"
            f"Valor: *{_preco_formatado()}*\n\n"
            "Escaneie o QR ou abra o botão abaixo.\n"
            f"Link para copiar manualmente: `{checkout_url}`\n"
            f"O pagamento expira em {CFG.PAGAMENTO_EXPIRACAO_MINUTOS} minutos."
        ),
        reply_markup=markup,
        parse_mode="Markdown",
    )

def init_db():
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                created_at TEXT,
                free_used INTEGER DEFAULT 0
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
        for column, definition in (
            ("external_reference", "TEXT"),
            ("provider_payment_id", "TEXT"),
            ("expires_at", "TEXT"),
            ("reminder_at", "TEXT"),
            ("reminder_sent", "INTEGER DEFAULT 0"),
            ("checkout_url", "TEXT"),
        ):
            try:
                cursor.execute(f"ALTER TABLE payments ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN free_used INTEGER DEFAULT 0")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
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

def criar_preferencia_pagamento(message, target: str, qtype: str) -> tuple[str, str] | None:
    """Cria um checkout do Mercado Pago para uma consulta individual."""
    if not CFG.MERCADOPAGO_ACCESS_TOKEN:
        logger.error("MERCADOPAGO_ACCESS_TOKEN não configurado")
        return None

    reference = secrets.token_urlsafe(18)
    agora = datetime.now(TIMEZONE_BR)
    expira = agora.timestamp() + (CFG.PAGAMENTO_EXPIRACAO_MINUTOS * 60)
    expires_at = datetime.fromtimestamp(expira, TIMEZONE_BR).isoformat()
    payment_id = f"mp_{reference}"
    db_execute(
        "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at, external_reference, expires_at, reminder_at, reminder_sent) "
        "VALUES (?, ?, ?, ?, 'pending', NULL, NULL, ?, ?, ?, ?, ?, 0)",
        (payment_id, message.from_user.id, target, CFG.CONSULTA_PRECO, qtype, agora.isoformat(), reference, expires_at, datetime.fromtimestamp(agora.timestamp() + 600, TIMEZONE_BR).isoformat()),
        commit=True,
    )

    amount = round(CFG.CONSULTA_PRECO, 2)
    payload = {
        "items": [{
            "title": f"Consulta OSINT — {qtype}",
            "description": f"Consulta autorizada de {target[:80]}",
            "quantity": 1,
            "currency_id": "BRL",
            "unit_price": amount,
        }],
        "external_reference": reference,
        "notification_url": f"{CFG.WEB_BASE_URL}/webhooks/mercadopago",
        "back_urls": {
            "success": CFG.WEB_BASE_URL,
            "failure": CFG.WEB_BASE_URL,
            "pending": CFG.WEB_BASE_URL,
        },
        "auto_return": "approved",
    }
    try:
        response = requests.post(
            "https://api.mercadopago.com/checkout/preferences",
            headers={
                "Authorization": f"Bearer {CFG.MERCADOPAGO_ACCESS_TOKEN}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=20,
        )
        response.raise_for_status()
        data = response.json()
        checkout_url = data.get("init_point") or data.get("sandbox_init_point")
        if not checkout_url:
            raise RuntimeError("Mercado Pago não retornou o link de checkout.")
        db_execute("UPDATE payments SET checkout_url = ? WHERE external_reference = ?", (checkout_url, reference), commit=True)
        return reference, checkout_url
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        logger.exception("Falha ao criar checkout Mercado Pago: %s", exc)
        db_execute("UPDATE payments SET status = 'creation_error' WHERE external_reference = ?", (reference,), commit=True)
        return None

def liberar_consulta_paga(reference: str, provider_payment_id: str, status: str) -> bool:
    """Confirma um pagamento e gera o relatório somente após aprovação."""
    row = db_execute(
        "SELECT user_id, target_username, query_type, status, expires_at FROM payments WHERE external_reference = ?",
        (reference,), fetchone=True,
    )
    if not row or row[3] in {"approved", "processing"}:
        return False
    if status != "approved":
        db_execute("UPDATE payments SET status = ?, provider_payment_id = ? WHERE external_reference = ?", (status, provider_payment_id, reference), commit=True)
        return False

    user_id, target, qtype, _, expires_at = row
    if expires_at and datetime.fromisoformat(expires_at) < datetime.now(TIMEZONE_BR):
        db_execute("UPDATE payments SET status = 'expired', provider_payment_id = ? WHERE external_reference = ?", (provider_payment_id, reference), commit=True)
        return False

    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cur = conn.cursor()
        cur.execute(
            "UPDATE payments SET status = 'processing', provider_payment_id = ? "
            "WHERE external_reference = ? AND status = 'pending'",
            (provider_payment_id, reference),
        )
        claimed = cur.rowcount == 1
        conn.commit()
        conn.close()
    if not claimed:
        return False

    try:
        resultados = executar_varredura(target, query_type=qtype)
        results_json = json.dumps(resultados, ensure_ascii=False)
    except Exception as exc:
        logger.exception("Falha ao gerar relatório pago %s: %s", reference, exc)
        db_execute("UPDATE payments SET status = 'report_error' WHERE external_reference = ?", (reference,), commit=True)
        return False
    token_relatorio = secrets.token_urlsafe(16)
    db_execute(
        "UPDATE payments SET status = 'approved', provider_payment_id = ?, token = ?, results_json = ? WHERE external_reference = ?",
        (provider_payment_id, token_relatorio, results_json, reference), commit=True,
    )
    if bot:
        link = f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"
        bot.send_message(
            user_id,
            f"✅ Pagamento aprovado. Seu relatório de `{qtype}` está pronto:\n{link}",
            parse_mode="Markdown",
            disable_web_page_preview=True,
        )
    return True

def buscar_e_marcar_lembretes() -> list[tuple]:
    agora = datetime.now(TIMEZONE_BR).isoformat()
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        rows = cur.execute(
            "SELECT payment_id, user_id, target_username, query_type, amount, checkout_url "
            "FROM payments WHERE status = 'pending' AND reminder_at <= ? AND reminder_sent = 0",
            (agora,),
        ).fetchall()
        for row in rows:
            cur.execute("UPDATE payments SET reminder_sent = 1 WHERE payment_id = ?", (row[0],))
        conn.commit()
        conn.close()
    return rows

def loop_lembretes() -> None:
    """Worker leve: verifica apenas o lembrete persistido no SQLite."""
    while True:
        try:
            for _, user_id, target, qtype, amount, checkout_url in buscar_e_marcar_lembretes():
                if bot and checkout_url:
                    markup = InlineKeyboardMarkup(row_width=1)
                    markup.add(InlineKeyboardButton("💳 Continuar pagamento", url=checkout_url))
                    bot.send_message(
                        user_id,
                        f"⏰ Lembrete: sua consulta `{qtype}` de `{target}` ainda está pendente.\n"
                        f"Valor: *R$ {float(amount):.2f}*\n"
                        "Este é o único lembrete automático desta cobrança.",
                        reply_markup=markup,
                        parse_mode="Markdown",
                    )
        except Exception as exc:
            logger.warning("Erro no worker de lembretes: %s", exc)
        time.sleep(30)

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
    username_limpo = extrair_alvo_limpo(username)
    resultados = {}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)) as client:
        tasks = [client.get(url_template.format(username=username_limpo), headers=headers, timeout=1.5, follow_redirects=True) for nome, url_template in PLATAFORMAS.items()]
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
    
    resultados.update({
        "MyCred — referência manual": {
            "exists": None, "status": "reference_only", "url": "https://mycred.com/",
            "query": username_limpo,
            "note": "MyCred não é um enumerador universal; confirme qualquer ocorrência manualmente.",
        },
        "Google — presença do username": {"exists": None, "status": "reference_only", "url": f"https://www.google.com/search?q=%22{encoded_user}%22"},
        "Bing — presença do username": {"exists": None, "status": "reference_only", "url": f"https://www.bing.com/search?q=%22{encoded_user}%22"},
        "DuckDuckGo — presença do username": {"exists": None, "status": "reference_only", "url": f"https://duckduckgo.com/?q=%22{encoded_user}%22"},
    })
    return resultados

def resultados_username_rapidos(username: str) -> dict[str, dict[str, Any]]:
    encoded = urllib.parse.quote(username)
    return {
        "GitHub": {"exists": True, "url": f"https://github.com/{encoded}"},
        "GitLab": {"exists": True, "url": f"https://gitlab.com/{encoded}"},
        "Instagram": {"exists": True, "url": f"https://www.instagram.com/{encoded}/"},
        "X / Twitter": {"exists": True, "url": f"https://x.com/{encoded}"},
        "Reddit": {"exists": True, "url": f"https://www.reddit.com/user/{encoded}/"},
        "TikTok": {"exists": True, "url": f"https://www.tiktok.com/@{encoded}"},
        "YouTube": {"exists": True, "url": f"https://www.youtube.com/@{encoded}"},
        "Mastodon / pesquisa": {"exists": True, "url": f"https://www.google.com/search?q=%22{encoded}%22"},
        "MyCred — referência manual": {
            "exists": None, "status": "reference_only",
            "url": "https://mycred.com/", "query": username,
            "note": "MyCred não é um enumerador universal; a presença precisa ser confirmada manualmente.",
        },
        "Google — presença do username": {"exists": None, "status": "reference_only", "url": f"https://www.google.com/search?q=%22{encoded}%22"},
        "Bing — presença do username": {"exists": None, "status": "reference_only", "url": f"https://www.bing.com/search?q=%22{encoded}%22"},
        "DuckDuckGo — presença do username": {"exists": None, "status": "reference_only", "url": f"https://duckduckgo.com/?q=%22{encoded}%22"},
    }

def executar_varredura(target: str, query_type: str = "username") -> dict[str, Any]:
    target_limpo = extrair_alvo_limpo(target, preservar_arroba=query_type == "email")

    if query_type == "email":
        return consultar_email(target_limpo)
    elif query_type == "fullname":
        return consultar_nome_completo(target_limpo)
    elif query_type == "fone":
        limpo = re.sub(r'\D', '', target_limpo)
        ddd = limpo[:2] if len(limpo) >= 10 else "N/A"
        regiao = DDD_ESTADOS.get(ddd, "Região Não Mapeada")
        return {
            "WhatsApp Direct Chat": {"exists": True, "url": f"https://wa.me/55{limpo}"},
            "Truecaller Directory": {"exists": True, "url": f"https://www.truecaller.com/search/br/{limpo}"},
            "Google Search (Busca Numérica)": {"exists": True, "url": f"https://www.google.com/search?q=%22{limpo}%22"},
            "Região Geográfica / UF": {"exists": True, "url": "#", "detalhes": regiao}
        }
    elif query_type == "cnpj":
        return consultar_cnpj(target_limpo)
    elif query_type == "placa":
        return consultar_placa(target_limpo)
    elif query_type == "dominio":
        return consultar_dominio(target_limpo)
    else:
        if not CFG.MAIGRET_ENABLED:
            try:
                return asyncio.run(asyncio.wait_for(consultar_alvo_async(target_limpo), timeout=8))
            except Exception as exc:
                logger.warning("Catálogo online demorou ou falhou; usando relatório rápido: %s", exc)
                return resultados_username_rapidos(target_limpo)
        # Maigret amplia a busca para milhares de sites. A opção de todos os
        # sites pode ser ativada no ambiente sem alterar o código do bot.
        try:
            todos_os_sites = os.getenv("MAIGRET_ALL_SITES", "0").lower() in {"1", "true", "yes"}
            resultado_maigret = consultar_username(
                target_limpo,
                todos_os_sites=todos_os_sites,
                timeout=CFG.MAIGRET_TIMEOUT,
            )
            resultados_maigret = {}
            for item in resultado_maigret.encontrados:
                nome = item.get("site") or item.get("name") or item.get("title") or "Maigret"
                url = item.get("url") or item.get("link") or item.get("profile_url") or ""
                resultados_maigret[str(nome)] = {
                    "exists": True,
                    "status": item.get("status", "found"),
                    "url": url,
                    "source": "Maigret",
                }
            if resultados_maigret:
                return resultados_maigret
            if resultado_maigret.erro:
                logger.warning("Maigret sem resultados estruturados: %s", resultado_maigret.erro)
        except (RuntimeError, TimeoutError, ValueError) as exc:
            logger.warning("Maigret indisponível; usando catálogo interno: %s", exc)

        # Mantém o comportamento anterior quando a dependência não está
        # disponível, há timeout ou a versão instalada não retorna NDJSON.
        try:
            return asyncio.run(asyncio.wait_for(consultar_alvo_async(target_limpo), timeout=8))
        except Exception as exc:
            logger.warning("Fallback online demorou ou falhou; usando relatório rápido: %s", exc)
            return resultados_username_rapidos(target_limpo)

def executar_varredura_com_timeout(target: str, query_type: str) -> dict[str, Any]:
    """Executa qualquer módulo com limite para nunca deixar a consulta presa."""
    resultado_queue: queue.Queue = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            resultado_queue.put((True, executar_varredura(target, query_type)))
        except Exception as exc:
            resultado_queue.put((False, exc))

    consulta_thread = Thread(target=worker, daemon=True)
    consulta_thread.start()
    consulta_thread.join(max(1, CFG.CONSULTA_TIMEOUT))
    if consulta_thread.is_alive():
        raise TimeoutError(f"A consulta excedeu {CFG.CONSULTA_TIMEOUT} segundos.")
    try:
        sucesso, valor = resultado_queue.get_nowait()
    except queue.Empty as exc:
        raise RuntimeError("O módulo não retornou resultado.") from exc
    if not sucesso:
        raise valor
    return valor

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
        if isinstance(v, dict):
            url_str = v.get('url', '')
            detalhe = f"{link_pdf(url_str)}<br/>{sanitizar_pdf(resumo_resultado(v))}"
            table_data.append([Paragraph(f"<b>{sanitizar_pdf(p)}</b>", cell_style), Paragraph(detalhe, cell_url_style)])

    t_results = Table(table_data, colWidths=[180, 360])
    t_results.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')), ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')), ('PADDING', (0,0), (-1,-1), 6)]))
    story.append(t_results)

    doc.build(story)
    buffer.seek(0)
    return buffer

def gerar_painel_gratuito(user_id: int, target: str, qtype: str, resultados: dict) -> str:
    results_json = json.dumps(resultados)
    token_relatorio = secrets.token_urlsafe(16)
    pid_free = f"free_{user_id}_{secrets.token_hex(4)}"

    db_execute(
        "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, query_type, created_at) "
        "VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?, ?)",
        (pid_free, user_id, target, token_relatorio, results_json, qtype, datetime.now(TIMEZONE_BR).isoformat()),
        commit=True
    )
    return f"{CFG.WEB_BASE_URL}/relatorio/{token_relatorio}"

def atualizar_progresso(message, progress_id: int | None, texto: str) -> None:
    if not bot or not progress_id:
        return
    try:
        bot.edit_message_text(texto, message.chat.id, progress_id, parse_mode="Markdown")
    except Exception as exc:
        logger.debug("Não foi possível atualizar progresso: %s", exc)

def _processar_busca(message, raw_target: str, qtype: str = "username", progress_id: int | None = None):
    user_id = message.from_user.id
    target = extrair_alvo_limpo(raw_target, preservar_arroba=qtype == "email")

    if not target or len(target) < 2:
        bot.reply_to(message, "⚠️ Termo de busca muito curto.")
        return

    db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, datetime.now(TIMEZONE_BR).isoformat()), commit=True)

    membro_canal = usuario_esta_no_canal(user_id)
    consulta_gratis = membro_canal and reivindicar_consulta_gratis(user_id)
    atualizar_progresso(message, progress_id, "🔎 *Consulta recebida*\n\n`[██░░░░░░░░]` 20%\nVerificando acesso...")
    Thread(
        target=enviar_notificacao_evento,
        args=("CONSULTA GRÁTIS" if consulta_gratis else "NOVA CONSULTA", message, qtype, target, "GRÁTIS" if consulta_gratis else None),
        daemon=True,
    ).start()

    admin_bypass = user_id == CFG.ADMIN_ID and CFG.ADMIN_BYPASS_PAYMENT
    if not admin_bypass and not consulta_gratis:
        atualizar_progresso(message, progress_id, f"💳 *Gerando cobrança*\n\n`[████░░░░░░]` 40%\nValor: *{_preco_formatado()}*")
        bot.send_message(
            message.chat.id,
            f"⏳ Consulta `{qtype.upper()}` recebida. Gerando cobrança de *{_preco_formatado()}*...",
            parse_mode="Markdown",
        )
        checkout = criar_preferencia_pagamento(message, target, qtype)
        if not checkout:
            bot.send_message(
                message.chat.id,
                "⚠️ Não foi possível gerar o pagamento. O administrador precisa verificar "
                "MERCADOPAGO_TOKEN/MERCADOPAGO_ACCESS_TOKEN e os logs do Render.",
            )
            return
        _, checkout_url = checkout
        atualizar_progresso(message, progress_id, "💳 *Aguardando pagamento*\n\n`[█████░░░░░]` 50%\nQR code e botão enviados abaixo.")
        enviar_checkout_com_qr(message.chat.id, checkout_url, target, qtype)
        return

    if consulta_gratis:
        atualizar_progresso(message, progress_id, "🎁 *Consulta gratuita liberada*\n\n`[██████░░░░]` 60%\nBuscando informações públicas...")
        bot.send_message(message.chat.id, "🎁 Você está usando sua única consulta gratuita como membro do canal.")
    elif admin_bypass:
        atualizar_progresso(message, progress_id, "👑 *Acesso administrativo liberado*\n\n`[██████░░░░]` 60%\nBuscando informações públicas...")

    logger.info("Iniciando varredura: tipo=%s alvo=%s usuario=%s", qtype, target, user_id)
    resultados = executar_varredura_com_timeout(target, qtype)
    logger.info("Varredura concluída: tipo=%s alvo=%s usuario=%s itens=%s", qtype, target, user_id, len(resultados))
    atualizar_progresso(message, progress_id, "⚙️ *Organizando resultados*\n\n`[████████░░]` 80%\nGerando relatório...")

    link_web = gerar_painel_gratuito(user_id, target, qtype, resultados)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("🌐 Acessar Painel VIP", url=link_web),
        InlineKeyboardButton("📄 Baixar PDF VIP", url=f"{CFG.WEB_BASE_URL}/download/pdf/{link_web.split('/')[-1]}")
    )

    if admin_bypass or consulta_gratis:
        cabecalho = (
            "👑 **MODO ADMINISTRADOR - CONSULTA LIBERADA**\n\n"
            if admin_bypass
            else "🎁 **CONSULTA GRÁTIS PARA MEMBRO DO CANAL**\n\n"
        )
        bot.send_message(
            message.chat.id,
            cabecalho +
            f"• **Alvo:** `{target}`\n"
            f"• **Modalidade:** {qtype.upper()}\n\n"
            f"Relatório processado e disponível abaixo:",
            reply_markup=markup,
            parse_mode="Markdown"
        )
    else:
        bot.send_message(
            message.chat.id,
            f"🎯 **CONSULTA OSINT CONCLUÍDA ({qtype.upper()})**\n\n"
            f"• **Alvo:** `{target}`\n\n"
            f"Clique abaixo para ver o painel:",
            reply_markup=markup,
            parse_mode="Markdown"
        )
    atualizar_progresso(message, progress_id, "✅ *Relatório pronto*\n\n`[██████████]` 100%\nO link foi enviado acima.")

def processar_busca(message, raw_target: str, qtype: str = "username", progress_id: int | None = None):
    """Executa a consulta e informa falhas que ocorram na thread."""
    try:
        _processar_busca(message, raw_target, qtype, progress_id)
    except Exception as exc:
        logger.exception("Falha ao gerar relatório (%s): %s", qtype, exc)
        atualizar_progresso(message, progress_id, "❌ *Falha na consulta*\n\nO relatório não pôde ser gerado. Consulte os logs do Render.")
        if bot:
            try:
                bot.send_message(
                    message.chat.id,
                    "⚠️ A consulta foi recebida, mas ocorreu um erro ao gerar o relatório. "
                    "O administrador foi avisado nos logs. Tente novamente.",
                )
            except Exception:
                logger.exception("Falha ao avisar o usuário sobre erro de relatório")

def iniciar_busca(message, raw_target: str, qtype: str = "username") -> None:
    """Inicia a consulta fora do handler do webhook para não bloquear o bot."""
    progress = bot.send_message(
        message.chat.id,
        "⏳ *Recebi sua consulta*\n\n`[█░░░░░░░░░]` 10%\nIniciando...",
        parse_mode="Markdown",
    ) if bot else None
    progress_id = progress.message_id if progress else None
    Thread(target=processar_busca, args=(message, raw_target, qtype, progress_id), daemon=True).start()

def gerar_resumo_admin() -> str:
    """Monta um resumo administrativo sem expor resultados no chat."""
    with db_lock:
        conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
        cur = conn.cursor()
        usuarios = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        relatorios = cur.execute("SELECT COUNT(*) FROM payments").fetchone()[0]
        aprovados = cur.execute("SELECT COUNT(*) FROM payments WHERE status = 'approved'").fetchone()[0]
        por_tipo = cur.execute(
            "SELECT query_type, COUNT(*) FROM payments GROUP BY query_type ORDER BY COUNT(*) DESC"
        ).fetchall()
        ultimos = cur.execute(
            "SELECT target_username, query_type, created_at, token FROM payments "
            "ORDER BY created_at DESC LIMIT 8"
        ).fetchall()
        conn.close()

    linhas = [
        "👑 *PAINEL ADMINISTRATIVO*",
        "",
        f"• Usuários cadastrados: `{usuarios}`",
        f"• Relatórios: `{relatorios}`",
        f"• Relatórios aprovados: `{aprovados}`",
        "",
        "*Consultas por módulo:*",
    ]
    linhas.extend(f"• `{tipo}`: `{quantidade}`" for tipo, quantidade in por_tipo)
    linhas.extend(["", "*Últimos relatórios:*"])
    for alvo, tipo, criado_em, token in ultimos:
        link = f"{CFG.WEB_BASE_URL}/relatorio/{token}"
        linhas.append(f"• `{tipo}` — `{alvo}` — [{criado_em}]({link})")
    if not ultimos:
        linhas.append("• Nenhum relatório encontrado.")
    return "\n".join(linhas)

if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        user_id = message.from_user.id
        raw_first = escaping_html(message.from_user.first_name or "Usuario")
        user_name = "".join(c for c in raw_first if c.isalnum() or c == " ")[:30].strip() or "Usuario"

        db_execute("INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING", (user_id, datetime.now(TIMEZONE_BR).isoformat()), commit=True)
        Thread(target=enviar_notificacao_evento, args=("NOVO /START", message), daemon=True).start()

        menu_boas_vindas = (
            f"👑 **KRONOS INTEL OSINT BOT v35.8 VIP** ⚡️\n"
            f"─────────────────────────────────────────────\n"
            f"👋 Olá, {user_name}! Bem-vindo à sua central de inteligência cibernética!\n\n"
            f"🎁 Entre no canal oficial e ganhe **1 consulta gratuita**. Depois dela, cada consulta custa **{_preco_formatado()}**.\n\n"
            f"🛠️ **MÓDULOS DE CONSULTA DISPONÍVEIS:**\n\n"
            f"1️⃣ 👤 **USERNAME / REDES SOCIAIS:**\n"
            f"   • `/user alvo123`\n"
            f"   • `/admin_user alvo123` (Admin)\n\n"
            f"2️⃣ 📧 **E-MAIL & VAZAMENTOS:**\n"
            f"   • `/email exemplo@dominio.com`\n\n"
            f"3️⃣ ⚖️ **NOME COMPLETO (JUDICIAL):**\n"
            f"   • `/nome João da Silva`\n\n"
            f"4️⃣ 📱 **TELEFONE & WHATSAPP:**\n"
            f"   • `/fone 11999998888`\n\n"
            f"5️⃣ 🏢 **CNPJ EMPRESARIAL:**\n"
            f"   • `/cnpj 00000000000191`\n\n"
            f"6️⃣ 🚗 **VEÍCULOS (PLACA):**\n"
            f"   • `/placa ABC1D23`\n\n"
            f"7️⃣ 🌐 **DOMÍNIOS & DNS:**\n"
            f"   • `/dominio site.com`\n\n"
            f"📢 **Canal Oficial:** {CFG.CANAL_TAG_PUBLICO}\n"
            f"💬 **Suporte Direto:** @{CFG.SUPORTE_USERNAME}"
        )

        markup = InlineKeyboardMarkup(row_width=1)
        markup.add(
            InlineKeyboardButton("📢 Entrar no Canal Oficial", url=f"https://t.me/{CFG.CANAL_TAG_PUBLICO.replace('@','')}"),
            InlineKeyboardButton("✅ Já entrei — verificar consulta grátis", callback_data="verificar_gratis"),
            InlineKeyboardButton("💬 Suporte", url=f"https://t.me/{CFG.SUPORTE_USERNAME}")
        )
        bot.send_message(message.chat.id, menu_boas_vindas, reply_markup=markup, parse_mode="Markdown")

    @bot.callback_query_handler(func=lambda call: call.data == "verificar_gratis")
    def verificar_consulta_gratis(call):
        user_id = call.from_user.id
        bot.answer_callback_query(call.id)
        if not usuario_esta_no_canal(user_id):
            bot.send_message(
                call.message.chat.id,
                "Ainda não consegui confirmar sua entrada no canal. Entre pelo botão e toque em verificar novamente.",
            )
            return
        with db_lock:
            conn = sqlite3.connect(CFG.DB_FILE, timeout=30.0)
            usado = conn.execute("SELECT COALESCE(free_used, 0) FROM users WHERE user_id = ?", (user_id,)).fetchone()
            conn.close()
        if usado and usado[0]:
            bot.send_message(call.message.chat.id, f"Sua consulta gratuita já foi usada. As próximas consultas custam {_preco_formatado()}.")
        else:
            bot.send_message(call.message.chat.id, "✅ Entrada confirmada. Sua próxima consulta será gratuita. Use, por exemplo: /user nome_de_usuario")

    @bot.message_handler(commands=['admin', 'admin_user', 'admin_email', 'admin_nome', 'admin_fone', 'admin_cnpj', 'admin_placa', 'admin_dominio', 'user', 'email', 'nome', 'fone', 'cnpj', 'placa', 'dominio'])
    def handle_commands(message):
        cmd = message.text.split()[0].split("@")[0].lower()
        partes = message.text.strip().split(maxsplit=1)

        if cmd == "/admin":
            if message.from_user.id != CFG.ADMIN_ID:
                bot.reply_to(message, "⛔ Comando restrito ao administrador.")
                return
            if len(partes) == 2:
                admin_partes = partes[1].split(maxsplit=1)
                modulo = admin_partes[0].lower().lstrip("/")
                if modulo in ADMIN_MODULES and len(admin_partes) == 2:
                    iniciar_busca(message, admin_partes[1], ADMIN_MODULES[modulo])
                    return
                bot.reply_to(message, "Use: `/admin user alvo` ou `/admin email alvo`", parse_mode="Markdown")
                return
            bot.send_message(message.chat.id, gerar_resumo_admin(), parse_mode="Markdown", disable_web_page_preview=True)
            return

        if cmd in ADMIN_COMMANDS and message.from_user.id != CFG.ADMIN_ID:
            bot.reply_to(message, "⛔ Comando administrativo restrito ao administrador.")
            return

        if len(partes) < 2:
            bot.reply_to(message, f"⚠️ Por favor, insira o termo de busca após o comando `{cmd}`.", parse_mode="Markdown")
            return

        alvo = partes[1]
        
        if cmd in ADMIN_COMMANDS:
            iniciar_busca(message, alvo, ADMIN_COMMANDS[cmd])
        elif cmd == '/user':
            iniciar_busca(message, alvo, "username")
        elif 'email' in cmd:
            iniciar_busca(message, alvo, "email")
        elif 'nome' in cmd:
            iniciar_busca(message, alvo, "fullname")
        elif 'fone' in cmd:
            iniciar_busca(message, alvo, "fone")
        elif 'cnpj' in cmd:
            iniciar_busca(message, alvo, "cnpj")
        elif 'placa' in cmd:
            iniciar_busca(message, alvo, "placa")
        elif 'dominio' in cmd:
            iniciar_busca(message, alvo, "dominio")

    @bot.message_handler(func=lambda message: True)
    def handle_catch_all(message):
        if not message.text or message.chat.type in ['group', 'supergroup']:
            return
        if message.text.startswith('/'):
            bot.reply_to(
                message,
                "❌ Comando inválido. Use /start para ver os comandos disponíveis.\n\n"
                "Consultas: /user, /email, /nome, /fone, /cnpj, /placa e /dominio.",
            )
            return
        target = extrair_alvo_limpo(message.text)
        if len(target) >= 2:
            iniciar_busca(message, target, "username")

@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, query_type, created_at FROM payments WHERE token = ?", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou expirado.", 404

    target, results_json_str, query_type, created_at = p[0], p[1], p[2], p[3]
    try:
        results_json = json.loads(results_json_str) if isinstance(results_json_str, str) else results_json_str
    except Exception:
        results_json = {}

    fontes = []
    if isinstance(results_json, dict):
        for k, v in results_json.items():
            if isinstance(v, dict):
                fontes.append({"nome": k, "url": v.get("url", ""), "resumo": resumo_resultado(v)})

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
                <h2>🔎 Relatório OSINT ({query_type.upper()}): {target}</h2>
                <p class="text-muted">Data: {created_at}</p>
            </div>
            <div class="card-custom">
                <h4>Fontes e Bases Localizadas:</h4>
                <div class="mt-3">
    """
    for item in fontes:
        nome = html.escape(str(item["nome"]))
        url = html.escape(str(item["url"]))
        resumo = html.escape(str(item["resumo"]))
        if url.startswith(("http://", "https://")):
            html_content += f'<a href="{url}" target="_blank" class="btn-link-custom">🔗 {nome} — abrir fonte</a>'
        else:
            html_content += f'<div class="btn-link-custom">🔎 {nome}</div>'
        html_content += f'<p class="text-muted">{resumo}</p>'
    
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
    p = db_execute("SELECT target_username, results_json, query_type FROM payments WHERE token = ?", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

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
        download_name=f"Relatorio_VIP_{target}.pdf"
    )

@app.route("/webhooks/mercadopago", methods=["POST"])
def webhook_mercadopago():
    """Recebe a notificação e confirma o pagamento consultando a API oficial."""
    if not CFG.MERCADOPAGO_ACCESS_TOKEN:
        return jsonify({"ok": False, "error": "payment_not_configured"}), 503

    payload = request.get_json(silent=True) or {}
    payment_id = (payload.get("data") or {}).get("id") or request.args.get("data.id") or request.args.get("id")
    event_type = payload.get("type") or request.args.get("type")
    if not payment_id or event_type not in (None, "payment"):
        return jsonify({"ok": True, "ignored": True}), 200

    try:
        response = requests.get(
            f"https://api.mercadopago.com/v1/payments/{payment_id}",
            headers={"Authorization": f"Bearer {CFG.MERCADOPAGO_ACCESS_TOKEN}"},
            timeout=15,
        )
        response.raise_for_status()
        payment = response.json()
        reference = payment.get("external_reference")
        status = payment.get("status")
        if not reference:
            return jsonify({"ok": True, "ignored": True}), 200
        liberado = liberar_consulta_paga(str(reference), str(payment_id), str(status))
        if liberado and bot:
            row = db_execute(
                "SELECT user_id, target_username, query_type, amount FROM payments WHERE external_reference = ?",
                (reference,), fetchone=True,
            )
            if row:
                destinos = [destino for destino in (CFG.CANAL_PRINCIPAL_ID, CFG.GRUPO_LOGS_ID) if destino]
                valor = f"R$ {float(row[3]):.2f}".replace(".", ",")
                aviso = (
                    "✅ *PAGAMENTO APROVADO*\n"
                    f"• Usuário ID: `{row[0]}`\n"
                    f"• Consulta: `{row[2]}`\n"
                    f"• Alvo: `{row[1]}`\n"
                    f"• Valor: *{valor}*\n"
                    f"• Pagamento Mercado Pago: `{payment_id}`"
                )
                for destino in destinos:
                    try:
                        bot.send_message(destino, aviso, parse_mode="Markdown")
                    except Exception as exc:
                        logger.warning("Falha ao notificar pagamento aprovado: %s", exc)
        return jsonify({"ok": True, "processed": liberado}), 200
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Falha ao confirmar webhook Mercado Pago: %s", exc)
        return jsonify({"ok": False}), 200

def _processar_update_async(update_json):
    try:
        logger.info("Update Telegram recebido: update_id=%s", update_json.get("update_id"))
        update = Update.de_json(update_json)
        if bot:
            if update.message and update.message.text:
                comando = update.message.text.split()[0].split("@")[0].lower()
                if comando in {"/start", "/help", "/ajuda", "/suporte"}:
                    send_welcome(update.message)
                    logger.info("Comando inicial respondido diretamente: %s", comando)
                    return
            bot.process_new_updates([update])
            logger.info("Update Telegram processado: update_id=%s", update_json.get("update_id"))
    except Exception as e:
        logger.error(f"Erro ao processar mensagem do Telegram: {e}")

@app.route("/telegram", methods=["POST"])
def telegram_webhook():
    if not bot:
        return jsonify({"error": "bot_disabled"}), 400
    if CFG.TELEGRAM_SECRET_TOKEN:
        recebido = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if not secrets.compare_digest(recebido, CFG.TELEGRAM_SECRET_TOKEN):
            return jsonify({"error": "forbidden"}), 403
    try:
        data = request.get_json(force=True, silent=True)
        if data:
            logger.info("Webhook Telegram aceitou update_id=%s", data.get("update_id"))
            raw_message = data.get("message") or {}
            raw_text = str(raw_message.get("text") or "")
            raw_command = raw_text.split()[0].split("@")[0].lower() if raw_text else ""
            if raw_command in {"/start", "/help", "/ajuda", "/suporte"}:
                update = Update.de_json(data)
                if update.message:
                    send_welcome(update.message)
                    logger.info("Comando inicial respondido no webhook: %s", raw_command)
                return jsonify({"status": "ok"}), 200
            Thread(target=_processar_update_async, args=(data,), daemon=True).start()
    except Exception as err:
        logger.exception("Erro no webhook: %s", str(err))
    return jsonify({"status": "ok"}), 200

@app.route("/healthz")
def healthz():
    return jsonify({
        "status": "healthy",
        "telegram_configured": bool(CFG.TELEGRAM_TOKEN),
        "mercadopago_configured": bool(CFG.MERCADOPAGO_ACCESS_TOKEN),
        "channel_configured": bool(CFG.CANAL_PRINCIPAL_ID),
        "maigret_enabled": CFG.MAIGRET_ENABLED,
        "qrcode_available": qrcode is not None,
    }), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Active.", 200

def configurar_webhook_telegram() -> None:
    """Registra o webhook usando somente variáveis protegidas do Render."""
    logger.info(
        "Configuração: telegram=%s mercado_pago=%s canal=%s qrcode=%s",
        bool(CFG.TELEGRAM_TOKEN),
        bool(CFG.MERCADOPAGO_ACCESS_TOKEN),
        bool(CFG.CANAL_PRINCIPAL_ID),
        qrcode is not None,
    )
    if not bot or not CFG.WEB_BASE_URL:
        return
    url = f"{CFG.WEB_BASE_URL}/telegram"
    try:
        if CFG.TELEGRAM_SECRET_TOKEN:
            bot.set_webhook(url=url, secret_token=CFG.TELEGRAM_SECRET_TOKEN)
        else:
            bot.set_webhook(url=url)
        logger.info("Webhook do Telegram configurado em %s", url)
    except Exception as exc:
        # Não impedir o Gunicorn de subir se o Telegram estiver temporariamente
        # indisponível; o próximo deploy tentará novamente.
        logger.warning("Não foi possível configurar o webhook do Telegram: %s", exc)

configurar_webhook_telegram()
Thread(target=loop_lembretes, daemon=True, name="payment-reminders").start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=CFG.PORT)
