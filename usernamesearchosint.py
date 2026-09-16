"""
Kronos Intel OSINT Bot v5.2
- Entrega EXCLUSIVA via Painel Web Interativo (Sem arquivos anexos no chat)
- Opções de Download em PDF e TXT mantidas diretamente no Painel Web
- URL Base configurada: https://usernameosint-1-vcj4.onrender.com
- Sem cota diária (Prévia em texto pura com gatilho)
- Botão VIP Promocional (R$ 3,90 no Pix via Mercado Pago)
- Módulo de Leaks e Vazamentos (HIBP, IntelX, DeHashed, LeakCheck, Pastebin, Jusbrasil)
- Banco de Dados SQLite & Histórico de Vendas
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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Lock, Thread
from typing import Any

import requests
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Update
import mercadopago
from flask import Flask, jsonify, request, render_template_string, Response

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

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

def valid_username(value: str | None) -> bool:
    return bool(value and USERNAME_RE.fullmatch(value))

def registrar_acesso(user_id: int):
    now_str = datetime.now().isoformat()
    db_execute(
        "INSERT INTO users (user_id, created_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING",
        (user_id, now_str), commit=True
    )
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_searches'", commit=True)

def registrar_relatorio():
    db_execute("UPDATE metrics SET value = value + 1 WHERE key = 'total_reports'", commit=True)

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

def executar_varredura_osint(username: str) -> dict[str, dict[str, Any]]:
    return FastOSINTChecker(username).run()

# --- GERADORES DE RELATÓRIO ---
def calcular_score_exposicao(encontrados_count: int, total_auditado: int) -> tuple[int, str]:
    if total_auditado == 0:
        return 0, "BAIXA"
    score = min(100, int((encontrados_count / total_auditado) * 350))
    nivel = "ELEVADA" if score >= 65 else ("MODERADA" if score >= 30 else "BAIXA")
    return score, nivel

def construir_relatorio_osint(username: str, resultados: dict[str, dict[str, Any]]) -> io.BytesIO:
    encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    score, nivel_exposicao = calcular_score_exposicao(len(encontrados), len(resultados))

    hibp_link = f"https://haveibeenpwned.com/account/{username}"
    intelx_link = f"https://intelx.io/?s={username}"
    dehashed_link = f"https://dehashed.com/search?query={username}"
    leakcheck_link = f"https://leakcheck.io/search?type=username&query={username}"
    pastebin_dork = f"https://www.google.com/search?q=site:pastebin.com+%22{username}%22"
    jusbrasil_dork = f"https://www.google.com/search?q=site:jusbrasil.com.br+%22{username}%22"
    escavador_dork = f"https://www.google.com/search?q=site:escavador.com+%22{username}%22"
    google_dork = f"https://www.google.com/search?q=%22{username}%22"

    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO OSINT EXECUTIVO
===================================================================
ALVO ANALISADO: @{username}
DATA DA CONSULTA: {data_atual}
SISTEMA DE MAPEAMENTO: Kronos Engine v5.2
===================================================================

1. RESUMO EXECUTIVO E MÉTRICA DE RISCO
-------------------------------------------------------------------
- Total de plataformas auditadas: {len(resultados)}
- Perfis confirmados: {len(encontrados)}
- Score de Exposição Digital: {score}/100 ({nivel_exposicao})

2. PLATAFORMAS E PERFIS MAPEADOS
-------------------------------------------------------------------
"""
    if encontrados:
        for p in encontrados:
            url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=username))
            corpo += f"[+] {p.ljust(18)} : {url}\n"
    else:
        corpo += "[-] Nenhum perfil público indexado nas bases padrão.\n"

    corpo += f"""
3. VARREDURA DE VAZAMENTOS, PASTES E DORKS JUDICIAIS
-------------------------------------------------------------------
[+] Have I Been Pwned      : {hibp_link}
[+] Intelligence X (IntelX): {intelx_link}
[+] DeHashed Database      : {dehashed_link}
[+] LeakCheck Search       : {leakcheck_link}
[+] Pastes & Dump Text     : {pastebin_dork}
[+] Diários Oficiais (Jus) : {jusbrasil_dork}
[+] Processos (Escavador)  : {escavador_dork}
[+] Google Exact Match     : {google_dork}

===================================================================
Documento confidencial gerado por Kronos Intel OSINT Service.
===================================================================
"""
    buf = io.BytesIO(corpo.encode('utf-8'))
    buf.name = f"Relatorio_OSINT_{username}.txt"
    return buf

def construir_relatorio_pdf(username: str, resultados: dict[str, dict[str, Any]]) -> io.BytesIO | None:
    if not HAS_REPORTLAB:
        return None
    try:
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
        data_atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        score, nivel_exposicao = calcular_score_exposicao(len(encontrados), len(resultados))

        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle('TStyle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, textColor=colors.HexColor('#0F172A'), spaceAfter=6)
        heading_style = ParagraphStyle('HStyle', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, textColor=colors.HexColor('#0F172A'), spaceBefore=10, spaceAfter=6)
        body_style = ParagraphStyle('BStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#334155'), leading=12)

        elements = [
            Paragraph("KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT", title_style),
            Paragraph(f"<b>Alvo:</b> @{username} | <b>Data:</b> {data_atual}", body_style),
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=12),
            Paragraph(f"<b>Score de Exposição Digital:</b> {score}/100 ({nivel_exposicao})", body_style),
            Spacer(1, 10),
        ]

        if encontrados:
            elements.append(Paragraph("Perfis Confirmados e URLs Diretas", heading_style))
            p_data = [[Paragraph("<b>Plataforma</b>", body_style), Paragraph("<b>URL do Perfil</b>", body_style)]]
            for p in encontrados:
                url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=username))
                p_data.append([Paragraph(p, body_style), Paragraph(f"<a href='{url}' color='#2563EB'>{url}</a>", body_style)])
            t = Table(p_data, colWidths=[140, 360])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(t)

        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Links Diretos de Varredura Profunda e Vazamentos", heading_style))

        dorks_text = (
            f"• <b>Have I Been Pwned:</b> <a href='https://haveibeenpwned.com/account/{username}' color='#2563EB'>Checar Vazamento HIBP</a><br/>"
            f"• <b>Intelligence X (IntelX):</b> <a href='https://intelx.io/?s={username}' color='#2563EB'>Buscar Base Deep Web</a><br/>"
            f"• <b>DeHashed Search:</b> <a href='https://dehashed.com/search?query={username}' color='#2563EB'>Pesquisar Credenciais</a><br/>"
            f"• <b>LeakCheck:</b> <a href='https://leakcheck.io/search?type=username&query={username}' color='#2563EB'>Verificar Bases Comprometidas</a><br/>"
            f"• <b>Diários Oficiais:</b> <a href='https://www.google.com/search?q=site:jusbrasil.com.br+%22{username}%22' color='#2563EB'>Consultar Jusbrasil</a>"
        )
        elements.append(Paragraph(dorks_text, body_style))

        doc.build(elements)
        pdf_buffer.seek(0)
        pdf_buffer.name = f"Relatorio_OSINT_{username}.pdf"
        return pdf_buffer
    except Exception as e:
        logger.error("Erro ao gerar PDF: %s", str(e))
        return None

def gerar_pix_mercadopago(user_id: int, target_username: str, valor: float = PRECO_VIP) -> tuple[str | None, bytes | None, str | None]:
    if not sdk:
        return None, None, None
    token_relatorio = secrets.token_urlsafe(16)
    payment_data = {
        "transaction_amount": float(valor),
        "description": f"Relatorio OSINT - @{target_username}",
        "payment_method_id": "pix",
        "payer": {"email": f"user_{user_id}@telegram.com", "first_name": "Usuario", "last_name": str(user_id)},
        "metadata": {"telegram_user_id": user_id, "target_username": target_username, "token": token_relatorio}
    }
    try:
        res = sdk.payment().create(payment_data).get("response", {})
        tx = res.get("point_of_interaction", {}).get("transaction_data", {})
        qr_code = tx.get("qr_code")
        qr_base64 = tx.get("qr_code_base64")
        img_bytes = base64.b64decode(qr_base64) if qr_base64 else None
        
        pid = str(res.get("id"))
        db_execute("INSERT INTO payments (payment_id, user_id, target_username, amount, status, reminded, token, created_at) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)",
                   (pid, user_id, target_username, valor, token_relatorio, datetime.now().isoformat()), commit=True)
        return qr_code, img_bytes, token_relatorio
    except Exception as e:
        logger.error("Erro ao gerar Pix: %s", str(e))
        return None, None, None

def enviar_relatorio_espelho_admin(username: str, documento: io.BytesIO, user_id: int, tipo_consulta: str):
    if bot and ADMIN_ID and user_id != ADMIN_ID:
        try:
            documento.seek(0)
            captura_legenda = f"👁‍🗨 [ESPELHO OSINT]\n• Tipo: {tipo_consulta}\n• Usuário Solicitante: {user_id}\n• Alvo: @{username}"
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
                                f"⏳ SUA CHAVE PIX PARA @{target} ESTÁ QUASE EXPIRANDO!\n\n"
                                f"Notamos que você gerou a liberação do Relatório VIP OSINT, mas o pagamento ainda não foi concluído.\n\n"
                                f"💡 Aproveite a promoção de R$ 19,90 por apenas R$ 3,90!\n"
                                f"Clique no botão abaixo para concluir no Pix ou tirar dúvidas com nosso suporte."
                            )
                            markup = InlineKeyboardMarkup(row_width=1)
                            markup.add(InlineKeyboardButton(f"⚡ 🔓 SIM, QUERO O RELATÓRIO DE @{target} (R$ 3,90) 🔓 ⚡", callback_data=f"buy_{target}"))
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
    <title>Kronos Intel — Relatório OSINT Executivo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.0/font/bootstrap-icons.css">
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .navbar { background-color: #161b22; border-bottom: 1px solid #30363d; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 12px; margin-bottom: 20px; }
        .card-header { background-color: #21262d; border-bottom: 1px solid #30363d; font-weight: bold; color: #58a6ff; }
        .badge-score { font-size: 1.2rem; padding: 8px 16px; border-radius: 20px; }
        .btn-platform { background-color: #21262d; border: 1px solid #30363d; color: #f0f6fc; text-align: left; transition: 0.2s; }
        .btn-platform:hover { background-color: #238636; border-color: #2ea043; color: #fff; transform: translateY(-2px); }
        .btn-dork { background-color: #1f6feb; color: #fff; }
        .btn-dork:hover { background-color: #388bfd; color: #fff; }
        .btn-download { background-color: #238636; color: #fff; font-weight: bold; }
        .btn-download:hover { background-color: #2ea043; color: #fff; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark mb-4 py-3">
        <div class="container">
            <span class="navbar-brand mb-0 h1 text-primary"><i class="bi bi-shield-lock-fill me-2"></i>KRONOS INTEL OSINT</span>
            <div class="d-flex gap-2">
                <a href="/download/pdf/{{ token }}" class="btn btn-download btn-sm"><i class="bi bi-file-earmark-pdf-fill me-1"></i> Baixar PDF</a>
                <a href="/download/txt/{{ token }}" class="btn btn-outline-light btn-sm"><i class="bi bi-file-earmark-text-fill me-1"></i> Baixar TXT</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-body d-flex justify-content-between align-items-center flex-wrap">
                        <div>
                            <h3 class="card-title text-white mb-1"><i class="bi bi-person-circle me-2"></i>Target: @{{ username }}</h3>
                            <p class="text-secondary mb-0"><i class="bi bi-clock-history me-1"></i> Varredura realizada em {{ data_atual }}</p>
                        </div>
                        <div class="mt-2 mt-md-0">
                            <span class="badge bg-danger badge-score"><i class="bi bi-exclamation-triangle-fill me-1"></i> Risco: {{ nivel_exposicao }} ({{ score }}/100)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-7">
                <div class="card">
                    <div class="card-header"><i class="bi bi-grid-3x3-gap-fill me-2"></i>Perfis Mapeados ({{ encontrados|length }} Encontrados)</div>
                    <div class="card-body">
                        {% if encontrados %}
                        <div class="row g-2">
                            {% for p in encontrados %}
                            <div class="col-sm-6">
                                <a href="{{ p.url }}" target="_blank" class="btn btn-platform w-100 d-flex justify-content-between align-items-center py-2 px-3">
                                    <span><i class="bi bi-globe me-2"></i>{{ p.nome }}</span>
                                    <i class="bi bi-box-arrow-up-right"></i>
                                </a>
                            </div>
                            {% endfor %}
                        </div>
                        {% else %}
                        <p class="text-secondary mb-0">Nenhum perfil público indexado nas bases padrão.</p>
                        {% endif %}
                    </div>
                </div>
            </div>

            <div class="col-md-5">
                <div class="card">
                    <div class="card-header text-warning"><i class="bi bi-incognito me-2"></i>Vazamentos & Leaks</div>
                    <div class="card-body d-grid gap-2">
                        <a href="https://haveibeenpwned.com/account/{{ username }}" target="_blank" class="btn btn-dork"><i class="bi bi-search me-2"></i>Have I Been Pwned</a>
                        <a href="https://intelx.io/?s={{ username }}" target="_blank" class="btn btn-dork"><i class="bi bi-cpu me-2"></i>Intelligence X (IntelX)</a>
                        <a href="https://dehashed.com/search?query={{ username }}" target="_blank" class="btn btn-dork"><i class="bi bi-database-check me-2"></i>DeHashed Search</a>
                        <a href="https://leakcheck.io/search?type=username&query={{ username }}" target="_blank" class="btn btn-dork"><i class="bi bi-shield-exclamation me-2"></i>LeakCheck Base</a>
                        <a href="https://www.google.com/search?q=site:pastebin.com+%22{{ username }}%22" target="_blank" class="btn btn-dork"><i class="bi bi-file-code me-2"></i>Pastebin Dork Search</a>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header text-info"><i class="bi bi-briefcase-fill me-2"></i>Diários Oficiais & Justiça</div>
                    <div class="card-body d-grid gap-2">
                        <a href="https://www.google.com/search?q=site:jusbrasil.com.br+%22{{ username }}%22" target="_blank" class="btn btn-outline-info"><i class="bi bi-journal-text me-2"></i>Jusbrasil Search</a>
                        <a href="https://www.google.com/search?q=site:escavador.com+%22{{ username }}%22" target="_blank" class="btn btn-outline-info"><i class="bi bi-file-earmark-person me-2"></i>Escavador Processos</a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""

# --- ROTAS FLASK PARA WEB DASHBOARD E DOWNLOADS ---
@app.route("/relatorio/<token>")
def ver_relatorio_web(token):
    p = db_execute("SELECT target_username, results_json, created_at FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado ou pagamento pendente.", 404

    username, results_json, created_at = p[0], json.loads(p[1]), p[2]
    encontrados_raw = [plat for plat, data in results_json.items() if data.get("exists") is True]
    
    encontrados = []
    for plat in encontrados_raw:
        url = results_json[plat].get("url", PLATFORM_URLS.get(plat, "").format(username=username))
        encontrados.append({"nome": plat, "url": url})

    score, nivel_exposicao = calcular_score_exposicao(len(encontrados), len(results_json))
    data_formatada = datetime.fromisoformat(created_at).strftime("%d/%m/%Y %H:%M:%S")

    return render_template_string(
        HTML_DASHBOARD_TEMPLATE,
        username=username,
        token=token,
        encontrados=encontrados,
        score=score,
        nivel_exposicao=nivel_exposicao,
        data_atual=data_formatada
    )

@app.route("/download/pdf/<token>")
def download_pdf(token):
    p = db_execute("SELECT target_username, results_json FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

    username, results_json = p[0], json.loads(p[1])
    pdf_buf = construir_relatorio_pdf(username, results_json)
    if not pdf_buf:
        return "Erro ao gerar PDF.", 500

    return Response(
        pdf_buf.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename=Relatorio_OSINT_{username}.pdf"}
    )

@app.route("/download/txt/<token>")
def download_txt(token):
    p = db_execute("SELECT target_username, results_json FROM payments WHERE token = ? AND status = 'approved'", (token,), fetchone=True)
    if not p:
        return "Relatório não encontrado.", 404

    username, results_json = p[0], json.loads(p[1])
    txt_buf = construir_relatorio_osint(username, results_json)

    return Response(
        txt_buf.getvalue(),
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename=Relatorio_OSINT_{username}.txt"}
    )

# --- HANDLERS TELEGRAM ---
if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        bot.reply_to(
            message,
            f"👋 Kronos Intel — OSINT Bot v5.2\n\n"
            f"Envie o nome de usuário desejado para verificar em quais plataformas ele está cadastrado.\n"
            f"Exemplo: nome_do_alvo\n\n"
            f"🛠 Suporte: @{SUPORTE_USERNAME}"
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
            f"💰 Vendas Aprovadas: {qtd_vendas} (R$ {faturamento:.2f})\n"
            f"📦 ReportLab PDF: {'Ativo' if HAS_REPORTLAB else 'Inativo'}"
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
            username = texto.lower().replace("admin", "").replace("@", "").strip()
        else:
            username = texto.replace("@", "").strip()

        if not valid_username(username):
            bot.reply_to(message, "⚠️ Nome de usuário inválido.")
            return

        # FLUXO ADMIN (ENTREGA EXCLUSIVA DO BOTÃO PAINEL WEB)
        if eh_admin_mode:
            msg_status = bot.reply_to(message, f"👑 [ADMIN VIP] Processando @{username}...")
            resultados = executar_varredura_osint(username)
            results_json = json.dumps(resultados)
            token_relatorio = secrets.token_urlsafe(16)
            pid_admin = f"admin_{int(time.time())}"

            db_execute(
                "INSERT INTO payments (payment_id, user_id, target_username, amount, status, token, results_json, created_at) VALUES (?, ?, ?, 0.0, 'approved', ?, ?, ?)",
                (pid_admin, user_id, username, token_relatorio, results_json, datetime.now().isoformat()),
                commit=True
            )
            registrar_relatorio()

            try:
                bot.edit_message_text(f"✅ Varredura concluída para @{username}!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

            link_web = f"{WEB_BASE_URL.rstrip('/')}/relatorio/{token_relatorio}"
            markup = InlineKeyboardMarkup(row_width=1)
            markup.add(InlineKeyboardButton("🌐 Acessar Painel Interativo Web (ADMIN)", url=link_web))

            bot.send_message(
                message.chat.id,
                f"👑 [MODO ADMIN] Painel Interativo Web gerado para @{username}:",
                reply_markup=markup
            )
            return

        # FLUXO PRINCIPAL (PRÉVIA ILIMITADA COM GATILHO)
        msg_status = bot.reply_to(message, f"🔎 Mapeando plataformas para @{username}...")
        resultados = executar_varredura_osint(username)
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]

        try:
            bot.edit_message_text(f"✅ Mapeamento concluído para @{username}!", chat_id=message.chat.id, message_id=msg_status.message_id)
        except Exception:
            pass

        if encontrados:
            lista_plataformas = "\n".join([f"• {p}" for p in encontrados])

            texto_resultado = (
                f"🎯 PLATAFORMAS ENCONTRADAS PARA @{username}\n"
                f"───────────────────────────────\n\n"
                f"{lista_plataformas}\n\n"
                f"⚠️ O usuário possui {len(encontrados)} contas ativas identificadas nas redes acima.\n\n"
                f"Deseja obter o Relatório Interativo Web com links clicáveis de cada perfil, Dorks Judiciais e Checagem de Vazamentos?\n\n"
                f"🔥 OFERTA LIMITADA: De R$ 19,90 por apenas R$ 3,90 no Pix!"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("⚡ 🔓 SIM, QUERO O RELATÓRIO COMPLETO 🔓 ⚡", callback_data=f"buy_{username}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data=f"confirm_cancel_{username}")
            btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
            markup.add(btn_sim, btn_nao, btn_suporte)

            bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
        else:
            bot.send_message(message.chat.id, f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{username}.")

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("buy_"):
            target_username = call.data.split("buy_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, "Gerando Chave Pix de R$ 3,90...")
            qr_pix, qr_img_bytes, token = gerar_pix_mercadopago(user_id, target_username, valor=PRECO_VIP)

            if qr_pix:
                texto_oferta = (
                    f"🔒 PACOTE KRONOS INTEL VIP — @{target_username}\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. Painel Interativo Web (HTML) com links diretos clicáveis\n"
                    f"2. Opção de Download em PDF Executivo e TXT na Web\n"
                    f"3. Dorks Judiciais (Jusbrasil / Processos)\n"
                    f"4. Checagem de Vazamentos (Have I Been Pwned / IntelX / DeHashed)\n"
                    f"5. Guia Bônus de Proteção Digital\n\n"
                    f"💰 Valor: De R$ 19,90 por R$ 3,90 no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O painel interativo será entregue automaticamente assim que o pagamento for confirmado."
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

        elif call.data.startswith("confirm_cancel_"):
            target_username = call.data.split("confirm_cancel_")[1]
            
            texto_atencao = (
                f"🚨 TEM CERTEZA QUE NÃO DESEJA O RELATÓRIO COMPLETO?\n\n"
                f"O perfil @{target_username} tem rastros ativos na internet que podem conter dados de contato e vazamentos.\n\n"
                f"💰 Desbloqueie agora por apenas R$ 3,90 no Pix!"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("⚡ 🔓 SIM, QUERO O RELATÓRIO COMPLETO (R$ 3,90) 🔓 ⚡", callback_data=f"buy_{target_username}")
            btn_nao = InlineKeyboardButton("❌ Confirmar Cancelamento", callback_data="final_cancel")
            markup.add(btn_sim, btn_nao)

            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=texto_atencao, reply_markup=markup)

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta finalizada.")
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text="👍 Entendido! Envie outro nome de usuário quando quiser realizar uma nova pesquisa.")

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
                    target_username = metadata.get("target_username", "alvo")
                    token_relatorio = metadata.get("token") or secrets.token_urlsafe(16)

                    resultados = executar_varredura_osint(target_username)
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
                            f"Seu relatório executivo para @{target_username} foi gerado com sucesso!\n\n"
                            f"🔗 Clique no botão abaixo para acessar o painel completo no seu navegador:",
                            reply_markup=markup
                        )

                        doc_txt = construir_relatorio_osint(target_username, resultados)
                        registrar_relatorio()
                        enviar_relatorio_espelho_admin(target_username, doc_txt, telegram_id, "VENDA PIX APROVADA")

                    if bot and ADMIN_ID:
                        bot.send_message(ADMIN_ID, f"💰 NOVA VENDA APROVADA!\n• Valor: R$ 3,90 (Pix)\n• Alvo: @{target_username}\n• Comprador: {telegram_id}")

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v5.2 Active.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
