"""Username OSINT Checker com Busca Expandida, Cota Diária Única, Notificações e Monetização Pix."""
from __future__ import annotations

import base64
import io
import logging
import os
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, date
from threading import Lock
from typing import Any

import requests
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, Update
import mercadopago
from flask import Flask, jsonify, request

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
DEFAULT_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8"))
MAX_WORKERS = max(1, min(int(os.getenv("MAX_WORKERS", "20")), 30))
PORT = int(os.getenv("PORT", "5000"))

# --- SISTEMA DE MÉTRICAS E COTA DIÁRIA ---
STATS_LOCK = Lock()
UNIQUE_USERS: set[int] = set()
TOTAL_SEARCHES: int = 0
TOTAL_REPORTS_GENERATED: int = 0

FREE_DAILY_USAGE: dict[int, date] = {}
PROCESSED_PAYMENTS: set[str] = set()
payments_lock = Lock()

# --- CONFIGURAÇÃO DE ADMINISTRADOR E SUPORTE ---
ADMIN_ID = int(os.getenv("ADMIN_ID", "5041637922"))
SUPORTE_USERNAME = os.getenv("SUPORTE_USERNAME", "kronos_intel")

MERCADOPAGO_TOKEN = os.getenv("MERCADOPAGO_TOKEN")
sdk = mercadopago.SDK(MERCADOPAGO_TOKEN) if MERCADOPAGO_TOKEN else None

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8625009528:AAHfx5Te-ngeeNMnlB_8hbP40wrpx6_1wIA")
bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=False) if TELEGRAM_TOKEN else None

# --- BASE EXPANDIDA DE PLATAFORMAS ---
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

def verificar_e_consumir_cota_gratis(user_id: int) -> bool:
    hoje = date.today()
    with STATS_LOCK:
        ultima_consulta = FREE_DAILY_USAGE.get(user_id)
        if ultima_consulta != hoje:
            FREE_DAILY_USAGE[user_id] = hoje
            return True
        return False

def registrar_acesso_usuario(user_id: int):
    global TOTAL_SEARCHES
    with STATS_LOCK:
        UNIQUE_USERS.add(user_id)
        TOTAL_SEARCHES += 1

def registrar_relatorio_gerado():
    global TOTAL_REPORTS_GENERATED
    with STATS_LOCK:
        TOTAL_REPORTS_GENERATED += 1

def gerar_pix_mercadopago(user_id: int, target_username: str, valor: float = 9.99) -> tuple[str | None, bytes | None]:
    if not sdk:
        logger.error("SDK do Mercado Pago não inicializada.")
        return None, None
        
    payment_data = {
        "transaction_amount": float(valor),
        "description": f"Relatorio OSINT Completo - @{target_username}",
        "payment_method_id": "pix",
        "payer": {
            "email": f"user_{user_id}@telegram.com",
            "first_name": "Usuario",
            "last_name": str(user_id)
        },
        "metadata": {
            "telegram_user_id": user_id,
            "target_username": target_username
        }
    }
    try:
        result = sdk.payment().create(payment_data).get("response", {})
        tx_data = result.get("point_of_interaction", {}).get("transaction_data", {})
        
        qr_copia_cola = tx_data.get("qr_code")
        qr_base64 = tx_data.get("qr_code_base64")
        
        img_bytes = base64.b64decode(qr_base64) if qr_base64 else None
        
        return qr_copia_cola, img_bytes
    except Exception as e:
        logger.error("Erro ao gerar Pix: %s", str(e))
        return None, None

class OSINTTool:
    def __init__(self, username: str, timeout: float = DEFAULT_TIMEOUT):
        self.username = username
        self.timeout = timeout
        self.results: dict[str, dict[str, Any]] = {}
        self._lock = Lock()
        self.headers = {
            "User-Agent": "UsernameSearchOSINT/2.0 (public-profile-checker)",
            "Accept": "application/json, text/html;q=0.9",
        }
        self.platforms = {
            name: template.format(username=username)
            for name, template in PLATFORM_URLS.items()
        }

    def _save(self, platform: str, result: dict[str, Any]) -> None:
        with self._lock:
            self.results[platform] = result

    def validate_profile(self, platform: str, url: str) -> None:
        try:
            response = requests.get(
                url, headers=self.headers, timeout=self.timeout, allow_redirects=True
            )
            status = response.status_code
            if status == 404:
                result = {"status": "not_found", "exists": False}
            elif 200 <= status < 400:
                body = response.text[:200_000].lower()
                markers = NOT_FOUND_MARKERS.get(platform.lower(), ())
                if any(marker in body for marker in markers):
                    result = {"status": "not_found", "exists": False}
                else:
                    result = {"status": "found", "exists": True, "url": url}
            else:
                result = {"status": "error", "exists": None, "http_status": status}
            self._save(platform, result)
        except Exception:
            self._save(platform, {"status": "unavailable", "exists": None})

    def run_checks(self) -> dict[str, dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(self.platforms))) as executor:
            futures = [executor.submit(self.validate_profile, p, u) for p, u in self.platforms.items()]
            for future in as_completed(futures):
                future.result()
        return {p: self.results[p] for p in self.platforms if p in self.results}

def construir_relatorio_osint(username: str, resultados: dict[str, dict[str, Any]]) -> io.BytesIO:
    encontrados = [p for p, data in resultados.items() if data.get("exists") is True]
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    google_dork_exact = f"https://www.google.com/search?q=%22{username}%22"
    bing_dork_exact = f"https://www.bing.com/search?q=%22{username}%22"
    ddg_dork_exact = f"https://duckduckgo.com/?q=%22{username}%22"
    
    reddit_dork = f"https://www.google.com/search?q=site:reddit.com+%22{username}%22"
    pastebin_dork = f"https://www.google.com/search?q=site:pastebin.com+%22{username}%22"
    forum_dork = f"https://www.google.com/search?q=inurl:forum+%22{username}%22"

    corpo_relatorio = f"""===================================================================
                   KRONOS INTEL — RELATÓRIO OSINT
===================================================================
ALVO ANALISADO: @{username}
DATA DA CONSULTA: {data_atual}
SISTEMA DE MAPEAMENTO: Kronos Intelligence Engine v2.0
===================================================================

1. RESUMO EXECUTIVO
-------------------------------------------------------------------
- Total de plataformas auditadas: {len(resultados)}
- Perfis e marcadores ativos confirmados: {len(encontrados)}
- Nível de pegada digital (Exposição): {"ELEVADO" if len(encontrados) > 5 else "MODERADO"}

2. PLATAFORMAS E PERFIS ENCONTRADOS DIRETAMENTE
-------------------------------------------------------------------
"""
    if encontrados:
        for p in encontrados:
            url = resultados[p].get("url", PLATFORM_URLS.get(p, "").format(username=username))
            corpo_relatorio += f"[+] {p.ljust(18)} : {url}\n"
    else:
        corpo_relatorio += "[-] Nenhum perfil público indexado nas bases padrão.\n"

    corpo_relatorio += f"""
3. ANÁLISE DE FÓRUNS, MENÇÕES E INDEXAÇÃO DE BUSCA (EXACT MATCH)
-------------------------------------------------------------------
Abaixo estão os links de varredura profunda contendo a busca exata entre
aspas ("{username}") nos motores de busca e comunidades:

[+] Google (Exact Match)     : {google_dork_exact}
[+] Bing (Exact Match)       : {bing_dork_exact}
[+] DuckDuckGo (Exact Match) : {ddg_dork_exact}

Mapeamento em Fóruns e Texto Colado (Dorks Específicos):
[+] Menções no Reddit        : {reddit_dork}
[+] Registros no Pastebin    : {pastebin_dork}
[+] Mapeamento em Fóruns     : {forum_dork}

4. RECOMENDAÇÕES DE PRIVACIDADE
-------------------------------------------------------------------
- Alterar nomes de usuário repetidos em plataformas críticas.
- Remover links cruzados entre perfis pessoais e fóruns técnicos.
- Monitorar os links de busca acima periodicamente para identificar menções não autorizadas.

===================================================================
Documento confidencial gerado por Kronos Intel OSINT Service.
===================================================================
"""
    file_buffer = io.BytesIO(corpo_relatorio.encode('utf-8'))
    file_buffer.name = f"Relatorio_OSINT_{username}.txt"
    return file_buffer

def enviar_relatorio_espelho_admin(username: str, documento: io.BytesIO, user_id: int, tipo_consulta: str):
    # SÓ ENVIA O ESPELHO SE O SOLICITANTE NÃO FOR O PRÓPRIO ADMIN
    if bot and ADMIN_ID and user_id != ADMIN_ID:
        try:
            documento.seek(0)
            captura_legenda = (
                f"👁‍🗨 [ESPELHO OSINT]\n"
                f"• Tipo: {tipo_consulta}\n"
                f"• Usuário Solicitante: {user_id}\n"
                f"• Alvo Pesquisado: @{username}"
            )
            bot.send_document(
                chat_id=ADMIN_ID,
                document=documento,
                caption=captura_legenda
            )
            documento.seek(0)
        except Exception as e:
            logger.error("Erro ao enviar cópia do relatório ao admin: %s", str(e))

if bot:
    @bot.message_handler(commands=['start', 'help', 'suporte', 'ajuda'])
    def send_welcome(message):
        registrar_acesso_usuario(message.from_user.id)
        bot.reply_to(
            message,
            f"👋 Kronos Intel — OSINT Bot\n\n"
            f"Você tem direito a 1 relatório completo gratuito por dia.\n"
            f"Envie o nome de usuário desejado para iniciar a consulta.\n"
            f"Exemplo: nome_do_alvo\n\n"
            f"🛠 Precisa de ajuda ou suporte?\nEntre em contato: @{SUPORTE_USERNAME}"
        )

    @bot.message_handler(commands=['stats'])
    def handle_stats_command(message):
        if message.from_user.id != ADMIN_ID:
            return

        with STATS_LOCK:
            total_unicos = len(UNIQUE_USERS)
            total_buscas = TOTAL_SEARCHES
            total_relatorios = TOTAL_REPORTS_GENERATED

        painel = (
            f"📊 PAINEL DE ESTATÍSTICAS DO BOT\n"
            f"───────────────────────────────\n"
            f"👤 Usuários Únicos: {total_unicos}\n"
            f"🔎 Total de Pesquisas: {total_buscas}\n"
            f"📄 Relatórios Gerados: {total_relatorios}\n"
            f"💰 Vendas Aprovadas: {len(PROCESSED_PAYMENTS)}"
        )
        bot.send_message(message.chat.id, painel)

    @bot.message_handler(commands=['admin'])
    def handle_admin_command(message):
        if message.from_user.id != ADMIN_ID:
            bot.reply_to(message, "⛔ Acesso negado. Comando exclusivo para o Administrador.")
            return

        parts = message.text.strip().split()
        if len(parts) < 2:
            bot.reply_to(message, "⚠️ Uso correto: /admin <username>")
            return

        username = parts[1].replace("@", "")
        bot.reply_to(message, f"⚡ Modo Admin Ativo! Gerando relatório para @{username}...")

        tool = OSINTTool(username)
        resultados = tool.run_checks()
        documento = construir_relatorio_osint(username, resultados)
        registrar_relatorio_gerado()

        bot.send_document(
            chat_id=message.chat.id,
            document=documento,
            caption=f"👑 [ADMIN ACCESS] Relatório OSINT Completo — @{username}"
        )

    @bot.message_handler(func=lambda message: True)
    def handle_search(message):
        user_id = message.from_user.id
        registrar_acesso_usuario(user_id)
        username = message.text.strip().replace("@", "")

        if not valid_username(username):
            bot.reply_to(message, "⚠️ Nome de usuário inválido.")
            return

        # VERIFICA A COTA GRATUITA (RÍGIDO: APENAS 1 POR DIA PARA QUALQUER USUÁRIO)
        tem_cota_gratis = verificar_e_consumir_cota_gratis(user_id)

        if tem_cota_gratis:
            bot.reply_to(message, f"🎁 Cota diária gratuita ativada! Processando relatório para @{username}...")
            tool = OSINTTool(username)
            resultados = tool.run_checks()
            documento = construir_relatorio_osint(username, resultados)
            registrar_relatorio_gerado()

            enviar_relatorio_espelho_admin(username, documento, user_id, "COTA GRATUITA DIÁRIA")

            bot.send_document(
                chat_id=message.chat.id,
                document=documento,
                caption=f"📄 Relatório OSINT Completo — @{username}\n\n✨ Sua cota diária gratuita de hoje foi utilizada."
            )
            return

        # A PARTIR DA 2ª CONSULTA DO DIA, EXIGE PAGAMENTO
        bot.reply_to(message, f"🔎 Iniciando varredura OSINT para @{username}...")

        tool = OSINTTool(username)
        results = tool.run_checks()
        encontrados = [p for p, data in results.items() if data.get("exists") is True]

        if encontrados:
            preview_plataformas = "\n".join([f"• {p}" for p in encontrados[:5]])
            texto_gratuito = (
                f"📊 PRÉVIA DA VARREDURA OSINT — @{username}\n"
                f"───────────────────────────────\n"
                f"⚠️ Sua cota gratuita de hoje já foi utilizada.\n\n"
                f"✅ Perfis Encontrados ({len(encontrados)}):\n{preview_plataformas}\n\n"
                f"🔒 Deseja liberar o relatório completo por apenas R$ 9,99?"
            )
            
            markup = InlineKeyboardMarkup(row_width=2)
            btn_sim = InlineKeyboardButton("✅ Sim, quero o relatório!", callback_data=f"buy_{username}")
            btn_nao = InlineKeyboardButton("❌ Não, obrigado", callback_data=f"confirm_cancel_{username}")
            btn_suporte = InlineKeyboardButton("💬 Falar com Suporte", url=f"https://t.me/{SUPORTE_USERNAME}")
            markup.add(btn_sim, btn_nao)
            markup.add(btn_suporte)

            bot.send_message(message.chat.id, texto_gratuito, reply_markup=markup)
        else:
            bot.send_message(message.chat.id, f"ℹ️ Varredura concluída: Nenhum perfil público localizado para @{username}.")

    @bot.callback_query_handler(func=lambda call: True)
    def callback_listener(call):
        if call.data.startswith("buy_"):
            target_username = call.data.split("buy_")[1]
            user_id = call.from_user.id
            
            bot.answer_callback_query(call.id, "Gerando QR Code e Chave Pix...")

            qr_pix, qr_img_bytes = gerar_pix_mercadopago(user_id, target_username, valor=9.99)

            if qr_pix:
                texto_oferta = (
                    f"🔒 RELATÓRIO COMPLETO — @{target_username}\n"
                    f"───────────────────────────────\n"
                    f"• Todas as URLs diretas mapeadas\n"
                    f"• Mapeamento de fóruns e comunidades\n"
                    f"• Análise de exposição e recomendações\n"
                    f"• Relatório em formato de documento (.TXT)\n\n"
                    f"💰 Valor: R$ 9,99\n\n"
                    f"Copie a chave Pix abaixo:\n\n"
                    f"{qr_pix}\n\n"
                    f"⚡ O relatório será enviado automaticamente assim que o pagamento for confirmado."
                )
                
                markup = InlineKeyboardMarkup(row_width=1)
                btn_copiar = InlineKeyboardButton("📋 Obter Apenas Chave Pix (Texto)", callback_data=f"getkey_{user_id}")
                btn_suporte = InlineKeyboardButton("💬 Precisa de Ajuda?", url=f"https://t.me/{SUPORTE_USERNAME}")
                markup.add(btn_copiar, btn_suporte)

                if qr_img_bytes:
                    bot.send_photo(
                        chat_id=call.message.chat.id,
                        photo=qr_img_bytes,
                        caption=texto_oferta,
                        reply_markup=markup
                    )
                else:
                    bot.send_message(
                        chat_id=call.message.chat.id,
                        text=texto_oferta,
                        reply_markup=markup
                    )
            else:
                bot.send_message(call.message.chat.id, "⚠️ Erro ao gerar a chave Pix. Tente novamente mais tarde.")

        elif call.data.startswith("confirm_cancel_"):
            target_username = call.data.split("confirm_cancel_")[1]
            bot.answer_callback_query(call.id, "Atenção...")

            texto_atencao = (
                f"⚠️ Tem certeza de que deseja cancelar a consulta de @{target_username}?\n\n"
                f"O relatório completo revela todas as menções do username em:\n"
                f"• Motores de busca avançados (Google Exact Match)\n"
                f"• Fóruns técnicos e comunidades (Reddit, Pastebin)\n"
                f"• Histórico de cadastros e registros públicos\n\n"
                f"💡 Aproveite por apenas R$ 9,99 e receba o documento na hora!"
            )

            markup = InlineKeyboardMarkup(row_width=1)
            btn_sim = InlineKeyboardButton("✅ Mudei de ideia, quero o relatório!", callback_data=f"buy_{target_username}")
            btn_nao = InlineKeyboardButton("❌ Sim, quero cancelar mesmo", callback_data="final_cancel")
            markup.add(btn_sim, btn_nao)

            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text=texto_atencao,
                reply_markup=markup
            )

        elif call.data == "final_cancel":
            bot.answer_callback_query(call.id, "Consulta cancelada.")
            bot.edit_message_text(
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                text="👍 Entendido! Se precisar de uma nova consulta, aguarde o reset diário ou realize o pagamento Pix."
            )

        elif call.data.startswith("getkey_"):
            bot.answer_callback_query(call.id, "Enviando chave em texto...")
            msg_texto = call.message.caption or call.message.text
            lines = msg_texto.split("\n\n") if msg_texto else []
            
            pix_key = None
            for l in lines:
                if len(l) > 50 and not l.startswith("🔒") and not l.startswith("⚡"):
                    pix_key = l.strip()
                    break

            if pix_key:
                bot.send_message(
                    chat_id=call.message.chat.id,
                    text=f"`{pix_key}`",
                    parse_mode="Markdown"
                )
            else:
                bot.send_message(call.message.chat.id, "⚠️ Toque e segure no texto do Pix na mensagem acima para copiar.")

# --- ROTA RECEPTORA DO TELEGRAM ---
@app.route(f"/telegram/{TELEGRAM_TOKEN}", methods=["POST"])
def telegram_webhook():
    if bot:
        data = request.get_json(force=True, silent=True)
        if data:
            update = Update.de_json(data)
            bot.process_new_updates([update])
            return jsonify({"status": "ok"}), 200
    return jsonify({"error": "unauthorized"}), 403

# --- ROTA WEBHOOK MERCADO PAGO ---
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    try:
        if request.method == "GET" or request.args.get("id") == "123456":
            return jsonify({"status": "ok"}), 200

        payment_id = None
        topic = request.args.get("topic") or request.args.get("type")
        if topic == "payment":
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
        with payments_lock:
            if pid_str in PROCESSED_PAYMENTS:
                logger.info("Notificação duplicada ignorada para o pagamento: %s", pid_str)
                return jsonify({"status": "ok"}), 200

        if payment_id and sdk:
            try:
                payment_info = sdk.payment().get(str(payment_id)).get("response", {})
                if payment_info.get("status") == "approved":
                    metadata = payment_info.get("metadata", {})
                    telegram_id = metadata.get("telegram_user_id")
                    target_username = metadata.get("target_username", "alvo")

                    with payments_lock:
                        PROCESSED_PAYMENTS.add(pid_str)

                    if telegram_id and bot:
                        bot.send_message(
                            telegram_id,
                            f"✅ Pagamento de R$ 9,99 Confirmado via Pix!\n\nGerando relatório avançado para @{target_username}..."
                        )

                        tool = OSINTTool(target_username)
                        resultados = tool.run_checks()
                        documento = construir_relatorio_osint(target_username, resultados)
                        registrar_relatorio_gerado()

                        enviar_relatorio_espelho_admin(target_username, documento, telegram_id, "VENDA PIX APROVADA")

                        bot.send_document(
                            chat_id=telegram_id,
                            document=documento,
                            caption=f"📄 Relatório OSINT Completo — @{target_username}\nObrigado por utilizar o Kronos Intel Bot!"
                        )

                    if bot and ADMIN_ID:
                        notificacao_admin = (
                            f"💰 NOVA VENDA APROVADA!\n"
                            f"───────────────────────────────\n"
                            f"• Valor: R$ 9,99 (Pix)\n"
                            f"• ID Pagamento: {payment_id}\n"
                            f"• Alvo Pesquisado: @{target_username}\n"
                            f"• ID do Comprador: {telegram_id}"
                        )
                        bot.send_message(ADMIN_ID, notificacao_admin)

            except Exception as e:
                logger.error("Erro no processamento do pagamento %s: %s", payment_id, str(e))

    except Exception as general_err:
        logger.error("Erro generico no webhook do Mercado Pago: %s", str(general_err))

    return jsonify({"status": "ok"}), 200

@app.route("/")
def index():
    return "Kronos Intel OSINT Bot & Webhook Ativos.", 200

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
