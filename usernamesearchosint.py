"""
Kronos Intel OSINT Bot v3.8 (Estável, Rápido e Sem Erros de Envio)
- Resposta instantânea e envio garantido de mensagens e botões
- Varredura otimizada com limite de tempo rigoroso por requisição
- Banco de Dados SQLite (kronos_osint.db)
- Valor promocional de R$ 3,90 no Pix
"""
from __future__ import annotations

import base64
import io
import logging
import os
import re
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, date
from threading import Lock, Thread
from typing import Any

import requests
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Update
import mercadopago
from flask import Flask, jsonify, request

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
DEFAULT_TIMEOUT = 3.0  # Tempo limite baixo para varredura rápida
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
                last_free_date TEXT,
                credits INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                referrer_id INTEGER,
                referred_id INTEGER,
                PRIMARY KEY (referrer_id, referred_id)
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

def verificar_e_consumir_cota(user_id: int) -> bool:
    hoje_str = date.today().isoformat()
    user = db_execute("SELECT credits, last_free_date FROM users WHERE user_id = ?", (user_id,), fetchone=True)
    
    if not user:
        db_execute("INSERT INTO users (user_id, last_free_date, credits, created_at) VALUES (?, ?, 0, ?)",
                   (user_id, hoje_str, datetime.now().isoformat()), commit=True)
        return True

    credits, last_free_date = user[0], user[1]

    if credits > 0:
        db_execute("UPDATE users SET credits = credits - 1 WHERE user_id = ?", (user_id,), commit=True)
        return True

    if last_free_date != hoje_str:
        db_execute("UPDATE users SET last_free_date = ? WHERE user_id = ?", (hoje_str, user_id), commit=True)
        return True

    return False

def registrar_indicacao(referrer_id: int, new_user_id: int):
    if referrer_id == new_user_id:
        return

    db_execute("INSERT OR IGNORE INTO referrals (referrer_id, referred_id) VALUES (?, ?)",
               (referrer_id, new_user_id), commit=True)
    
    count = db_execute("SELECT COUNT(*) FROM referrals WHERE referrer_id = ?", (referrer_id,), fetchone=True)[0]
    if count > 0 and count % 3 == 0:
        db_execute("UPDATE users SET credits = credits + 1 WHERE user_id = ?", (referrer_id,), commit=True)
        if bot:
            try:
                bot.send_message(referrer_id, "🎉 Você indicou 3 amigos e ganhou +1 consulta gratuita no Kronos Intel!")
            except Exception:
                pass

# --- MOTOR OSINT PARALELO RÁPIDO ---
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

    jusbrasil_dork = f"https://www.google.com/search?q=site:jusbrasil.com.br+%22{username}%22"
    escavador_dork = f"https://www.google.com/search?q=site:escavador.com+%22{username}%22"
    google_dork = f"https://www.google.com/search?q=%22{username}%22"
    pastebin_dork = f"https://www.google.com/search?q=site:pastebin.com+%22{username}%22"
    breach_dork = f"https://www.google.com/search?q=%22{username}%22+db+OR+leak+OR+password"

    corpo = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO OSINT EXECUTIVO
===================================================================
ALVO ANALISADO: @{username}
DATA DA CONSULTA: {data_atual}
SISTEMA DE MAPEAMENTO: Kronos Engine v3.8
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
3. DORKS JUDICIAIS E VARREDURA DE VAZAMENTOS (LEAKS)
-------------------------------------------------------------------
[+] Busca em Diários Oficiais (Jusbrasil) : {jusbrasil_dork}
[+] Mapeamento de Processos (Escavador)  : {escavador_dork}
[+] Checagem de Vazamento de Senhas      : {breach_dork}
[+] Google Exact Match                   : {google_dork}
[+] Registros em Pastes / Vazamentos      : {pastebin_dork}

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
        body_style = ParagraphStyle('BStyle', parent=styles['Normal'], fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#334155'), leading=12)

        elements = [
            Paragraph("KRONOS INTEL — RELATÓRIO EXECUTIVO OSINT", title_style),
            Paragraph(f"<b>Alvo:</b> @{username} | <b>Data:</b> {data_atual}", body_style),
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=12),
            Paragraph(f"<b>Score de Exposição:</b> {score}/100 ({nivel_exposicao})", body_style),
            Spacer(1, 10),
        ]

        if encontrados:
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

        doc.build(elements)
        pdf_buffer.seek(0)
        pdf_buffer.name = f"Relatorio_OSINT_{username}.pdf"
        return pdf_buffer
    except Exception as e:
        logger.error("Erro ao gerar PDF: %s", str(e))
        return None

def construir_guia_protecao_pdf() -> io.BytesIO | None:
    if not HAS_REPORTLAB:
        return None
    try:
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        elements = [
            Paragraph("GUIA KRONOS: SANITIZAÇÃO DE PEGADA DIGITAL", ParagraphStyle('T', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#0F172A'))),
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#10B981'), spaceAfter=10),
            Paragraph("1. Desvincule usernames repetidos em fóruns e redes públicas.", ParagraphStyle('B', parent=styles['Normal'], fontSize=10, leading=14)),
            Paragraph("2. Remova registros antigos no Jusbrasil/Escavador através dos painéis de privacidade.", ParagraphStyle('B', parent=styles['Normal'], fontSize=10, leading=14)),
            Paragraph("3. Ative a Autenticação em Duas Etapas (2FA) em todas as contas ativas.", ParagraphStyle('B', parent=styles['Normal'], fontSize=10, leading=14)),
        ]
        doc.build(elements)
        pdf_buffer.seek(0)
        pdf_buffer.name = "Guia_Protecao_Pegada_Digital_Kronos.pdf"
        return pdf_buffer
    except Exception:
        return None

def gerar_pix_mercadopago(user_id: int, target_username: str, valor: float = PRECO_VIP) -> tuple[str | None, bytes | None]:
    if not sdk:
        return None, None
    payment_data = {
        "transaction_amount": float(valor),
        "description": f"Relatorio OSINT - @{target_username}",
        "payment_method_id": "pix",
        "payer": {"email": f"user_{user_id}@telegram.com", "first_name": "Usuario", "last_name": str(user_id)},
        "metadata": {"telegram_user_id": user_id, "target_username": target_username}
    }
    try:
        res = sdk.payment().create(payment_data).get("response", {})
        tx = res.get("point_of_interaction", {}).get("transaction_data", {})
        qr_code = tx.get("qr_code")
        qr_base64 = tx.get("qr_code_base64")
        img_bytes = base64.b64decode(qr_base64) if qr_base64 else None
        
        pid = str(res.get("id"))
        db_execute("INSERT INTO payments (payment_id, user_id, target_username, amount, status, reminded, created_at) VALUES (?, ?, ?, ?, 'pending', 0, ?)",
                   (pid, user_id, target_username, valor, datetime.now().isoformat()), commit=True)
        return qr_code, img_bytes
    except Exception as e:
        logger.error("Erro ao gerar Pix: %s", str(e))
        return None, None

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
                            markup.add(InlineKeyboardButton(f"⚡ Liberar Relatório de @{target} (R$ 3,90)", callback_data=f"buy_{target}"))
                            markup.add(InlineKeyboardButton("💬 Suporte", url=f"https://t.me/{SUPORTE_USERNAME}"))
                            bot.send_message(uid, msg_lembrete, reply_markup=markup)
                except Exception as ex:
                    logger.error("Erro no remarketing: %s", str(ex))

        except Exception as e:
            logger.error("Erro no worker de remarketing: %s", str(e))

Thread(target=worker_remarketing_pix, daemon=True).start()

# --- HANDLERS TELEGRAM ---
if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        user_id = message.from_user.id
        registrar_acesso(user_id)

        args = message.text.strip().split()
        if len(args) > 1 and args[1].startswith("ref_"):
            try:
                referrer_id = int(args[1].replace("ref_", ""))
                registrar_indicacao(referrer_id, user_id)
            except ValueError:
                pass

        bot.reply_to(
            message,
            f"👋 Kronos Intel — OSINT Bot v3.8\n\n"
            f"Você tem direito a 1 consulta gratuita por dia.\n"
            f"Envie o nome de usuário desejado para pesquisar a pegada digital.\n"
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

    @bot.message_handler(commands=['conceder'])
    def handle_conceder_credit(message):
        if message.from_user.id != ADMIN_ID:
            return
        parts = message.text.strip().split()
        if len(parts) < 3:
            bot.reply_to(message, "⚠️ Uso correto: /conceder <user_id> <quantidade>")
            return
        try:
            target_id = int(parts[1])
            qtd = int(parts[2])
            db_execute("UPDATE users SET credits = credits + ? WHERE user_id = ?", (qtd, target_id), commit=True)
            bot.reply_to(message, f"✅ Concedidos {qtd} crédito(s) para o usuário {target_id}.")
        except Exception as e:
            bot.reply_to(message, f"⚠️ Erro ao conceder créditos: {str(e)}")

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

        # FLUXO ADMIN
        if eh_admin_mode:
            msg_status = bot.reply_to(message, f"👑 [ADMIN VIP] Processando @{username}...")
            resultados = executar_varredura_osint(username)
            doc_txt = construir_relatorio_osint(username, resultados)
            doc_pdf = construir_relatorio_pdf(username, resultados)
            guia_pdf = construir_guia_protecao_pdf()
            registrar_relatorio()

            try:
                bot.edit_message_text(f"✅ Varredura concluída para @{username}!", chat_id=message.chat.id, message_id=msg_status.message_id)
            except Exception:
                pass

            if doc_pdf:
                bot.send_document(message.chat.id, doc_pdf, caption=f"📄 [ADMIN VIP] Relatório PDF — @{username}")
            bot.send_document(message.chat.id, doc_txt, caption=f"📝 [ADMIN VIP] Texto Bruto — @{username}")
            if guia_pdf:
                bot.send_document(message.chat.id, guia_pdf, caption="📘 Guia de Proteção Digital")
            return

        # FLUXO USUÁRIO COMUM (COTA DIÁRIA)
        tem_cota = verificar_e_consumir_cota(user_id)

        if tem_cota:
            msg_status = bot.reply_to(message, f"🔎 Mapeando pegada digital de @{username}...")
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
                    f"⚠️ O usuário possui {len(encontrados)} contas ativas identificadas.\n\n"
                    f"Deseja liberar o Relatório Completo com todas as URLs diretas, Dorks Judiciais (Jusbrasil/Processos) e Checagem de Vazamentos?\n\n"
                    f"🔥 OFERTA ESPECIAL: De R$ 19,90 por apenas R$ 3,90!"
                )

                markup = InlineKeyboardMarkup(row_width=1)
                btn_sim = InlineKeyboardButton("🔓 Sim, quero o relatório completo (R$ 3,90)", callback_data=f"buy_{username}")
                btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data=f"confirm_cancel_{username}")
                btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
                markup.add(btn_sim, btn_nao, btn_suporte)

                bot.send_message(message.chat.id, texto_resultado, reply_markup=markup)
            else:
                bot.send_message(message.chat.id, f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{username}.")
            return

        # COTA EXPIRADA
        bot.reply_to(message, f"🔎 Mapeando plataformas para @{username}...")
        resultados = executar_varredura_osint(username)
        encontrados = [p for p, data in resultados.items() if data.get("exists") is True]

        if encontrados:
            lista_plataformas = "\n".join([f"• {p}" for p in encontrados[:5]])
            ref_link = f"https://t.me/{BOT_USERNAME}?start=ref_{user_id}"

            texto_expirado = (
                f"📊 PRÉVIA DA VARREDURA OSINT — @{username}\n"
                f"───────────────────────────────\n"
                f"⚠️ Sua cota diária gratuita expirou.\n\n"
                f"O usuário foi localizado em {len(encontrados)} plataformas, incluindo:\n"
                f"{lista_plataformas}\n"
                f"• ... e outras!\n\n"
                f"Deseja desbloquear as URLs diretas e o Relatório Executivo em PDF por apenas R$ 3,90?"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("🔓 Sim, quero o relatório completo (R$ 3,90)", callback_data=f"buy_{username}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data=f"confirm_cancel_{username}")
            btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
            markup.add(btn_sim, btn_nao, btn_suporte)

            bot.send_message(message.chat.id, texto_expirado, reply_markup=markup)
        else:
            bot.send_message(message.chat.id, f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{username}.")

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("buy_"):
            target_username = call.data.split("buy_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, "Gerando Chave Pix de R$ 3,90...")
            qr_pix, qr_img_bytes = gerar_pix_mercadopago(user_id, target_username, valor=PRECO_VIP)

            if qr_pix:
                texto_oferta = (
                    f"🔒 PACOTE KRONOS INTEL VIP — @{target_username}\n"
                    f"───────────────────────────────\n"
                    f"Você está liberando:\n"
                    f"1. URLs Diretas de todas as plataformas\n"
                    f"2. Relatório Executivo Formatado em PDF\n"
                    f"3. Relatório em Texto Bruto (.TXT)\n"
                    f"4. Dorks Judiciais (Jusbrasil / Processos)\n"
                    f"5. Checagem de Vazamentos de Senhas / Leaks\n"
                    f"6. Guia Bônus em PDF de Proteção Digital\n\n"
                    f"💰 Valor: De R$ 19,90 por R$ 3,90 no Pix\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ Os arquivos serão entregues automaticamente assim que o pagamento for confirmado."
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
            user_id = call.from_user.id
            ref_link = f"https://t.me/{BOT_USERNAME}?start=ref_{user_id}"

            texto_atencao = (
                f"🚨 TEM CERTEZA QUE NÃO DESEJA O RELATÓRIO COMPLETO?\n\n"
                f"O perfil @{target_username} tem rastros ativos na internet que podem conter dados de contato e vazamentos.\n\n"
                f"💰 Adquira por apenas R$ 3,90 no Pix ou indique 3 amigos usando este link para desbloquear 100% grátis:\n{ref_link}"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("⚡ Sim! Liberar Pacote VIP (R$ 3,90)", callback_data=f"buy_{target_username}")
            btn_nao = InlineKeyboardButton("❌ Confirmar Cancelamento", callback_data="final_cancel")
            markup.add(btn_sim, btn_nao)

            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text=texto_atencao, reply_markup=markup)

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta finalizada.")
            bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, text="👍 Entendido! Se precisar de uma nova consulta, envie o comando novamente.")

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
        
        p_check = db_execute("SELECT status FROM payments WHERE payment_id = ?", (pid_str,), fetchone=True)
        if p_check and p_check[0] == "approved":
            return jsonify({"status": "ok"}), 200

        if payment_id and sdk:
            try:
                payment_info = sdk.payment().get(str(payment_id)).get("response", {})
                if payment_info.get("status") == "approved":
                    metadata = payment_info.get("metadata", {})
                    telegram_id = metadata.get("telegram_user_id")
                    target_username = metadata.get("target_username", "alvo")

                    db_execute("UPDATE payments SET status = 'approved' WHERE payment_id = ?", (pid_str,), commit=True)

                    if telegram_id and bot:
                        bot.send_message(telegram_id, f"⚡ PAGAMENTO CONFIRMADO — PACOTE KRONOS INTEL VIP\n\nGerando relatórios e extraindo URLs para @{target_username}...")
                        resultados = executar_varredura_osint(target_username)
                        doc_txt = construir_relatorio_osint(target_username, resultados)
                        doc_pdf = construir_relatorio_pdf(target_username, resultados)
                        guia_pdf = construir_guia_protecao_pdf()
                        registrar_relatorio()

                        enviar_relatorio_espelho_admin(target_username, doc_txt, telegram_id, "VENDA PIX APROVADA")

                        if doc_pdf:
                            bot.send_document(telegram_id, doc_pdf, caption=f"📄 Relatório Executivo PDF — @{target_username}")
                        bot.send_document(telegram_id, doc_txt, caption=f"📝 Relatório Texto Bruto — @{target_username}")
                        if guia_pdf:
                            bot.send_document(telegram_id, guia_pdf, caption="📘 Guia de Proteção Digital")

                    if bot and ADMIN_ID:
                        bot.send_message(ADMIN_ID, f"💰 NOVA VENDA APROVADA!\n• Valor: R$ 3,90 (Pix)\n• Alvo: @{target_username}\n• Comprador: {telegram_id}")

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook v3.8 Active.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
