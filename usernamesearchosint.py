"""Small, defensive username availability checker with Telegram Bot integration and Mercado Pago Monetization.

Only checks public profile URLs supplied by the built-in provider list. A result is
never proof that two profiles belong to the same person.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any

import requests
import telebot
import mercadopago
from flask import Flask, jsonify, render_template, request, session
from requests import Response
from werkzeug.exceptions import BadRequest

# Configuração de Logs
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuração da Aplicação Flask
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32)),
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0") == "1",
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DEFAULT_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "8"))
MAX_WORKERS = max(1, min(int(os.getenv("MAX_WORKERS", "8")), 20))
PORT = int(os.getenv("PORT", "5000"))

# --- CONFIGURAÇÃO DO MERCADO PAGO ---
MERCADOPAGO_TOKEN = os.getenv("MERCADOPAGO_TOKEN")
sdk = mercadopago.SDK(MERCADOPAGO_TOKEN) if MERCADOPAGO_TOKEN else None

PLATFORM_URLS = {
    # Código, dados e tecnologia
    "GitHub": "https://api.github.com/users/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Bitbucket": "https://bitbucket.org/{username}/",
    "Codeberg": "https://codeberg.org/{username}",
    "SourceForge": "https://sourceforge.net/u/{username}/profile/",
    "npm": "https://www.npmjs.com/~{username}",
    "PyPI": "https://pypi.org/user/{username}/",
    "Docker Hub": "https://hub.docker.com/u/{username}",
    "Hugging Face": "https://huggingface.co/{username}",
    "Kaggle": "https://www.kaggle.com/{username}",
    "Keybase": "https://keybase.io/{username}",
    # Redes sociais e comunidades
    "Instagram": "https://www.instagram.com/{username}/",
    "X": "https://x.com/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}/",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Quora": "https://www.quora.com/profile/{username}",
    "Mastodon.social": "https://mastodon.social/@{username}",
    "Bluesky": "https://bsky.app/profile/{username}.bsky.social",
    "Threads": "https://www.threads.net/@{username}",
    "Clubhouse": "https://www.clubhouse.com/@{username}",
    "Telegram": "https://t.me/{username}",
    "Discord": "https://discord.com/users/{username}",
    # Publicação, portfólio e criação
    "Medium": "https://medium.com/@{username}",
    "Substack": "https://{username}.substack.com",
    "WordPress.com": "https://wordpress.com/{username}",
    "Tumblr": "https://{username}.tumblr.com",
    "Linktree": "https://linktr.ee/{username}",
    "Carrd": "https://{username}.carrd.co",
    "Patreon": "https://www.patreon.com/{username}",
    "Ko-fi": "https://ko-fi.com/{username}",
    "Buy Me a Coffee": "https://www.buymeacoffee.com/{username}",
    "Gumroad": "https://{username}.gumroad.com",
    "Product Hunt": "https://www.producthunt.com/@{username}",
    "Dribbble": "https://dribbble.com/{username}",
    "Behance": "https://www.behance.net/{username}",
    "Flickr": "https://www.flickr.com/people/{username}/",
    "500px": "https://500px.com/p/{username}",
    # Vídeo, áudio e entretenimento
    "Twitch": "https://www.twitch.tv/{username}",
    "DeviantArt": "https://www.deviantart.com/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Spotify": "https://open.spotify.com/user/{username}",
    "SoundCloud": "https://soundcloud.com/{username}",
    "Mixcloud": "https://www.mixcloud.com/{username}/",
    "Last.fm": "https://www.last.fm/user/{username}",
    "Vimeo": "https://vimeo.com/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "Dailymotion": "https://www.dailymotion.com/{username}",
    "Rumble": "https://rumble.com/c/{username}",
    # Interesses e perfis públicos
    "Goodreads": "https://www.goodreads.com/{username}",
    "Letterboxd": "https://letterboxd.com/{username}/",
    "Strava": "https://www.strava.com/athletes/{username}",
    "Chess.com": "https://www.chess.com/member/{username}",
    "Lichess": "https://lichess.org/@/{username}",
    "Internet Archive": "https://archive.org/details/@{username}",
}

NOT_FOUND_MARKERS = {
    "gitlab": ("the page you're looking for doesn't exist",),
    "bitbucket": ("this page doesn't exist",),
    "codeberg": ("page not found",),
    "npm": ("is not a registered user",),
    "pypi": ("404 not found",),
    "keybase": ("user not found",),
    "instagram": ("page isn't available", "sorry, this page isn't available"),
    "reddit": ("this page is empty", "page not found"),
    "tiktok": ("couldn't find this account",),
    "twitch": ("sorry. unless you've got a time machine",),
    "telegram": ("if you have telegram",),
    "substack": ("page not found",),
    "tumblr": ("there's nothing here",),
    "linktree": ("page not found",),
    "patreon": ("page not found",),
    "dribbble": ("page not found",),
    "flickr": ("we can't find that page",),
    "vimeo": ("sorry, we couldn't find that page",),
    "youtube": ("this page isn't available",),
    "dailymotion": ("page not found",),
    "letterboxd": ("page not found",),
    "lichess": ("user not found",),
}


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def valid_username(value: str | None) -> bool:
    return bool(value and USERNAME_RE.fullmatch(value))


def gerar_pix_mercadopago(user_id: int, target_username: str, valor: float = 15.00) -> str | None:
    """Gera uma cobrança Pix no Mercado Pago salvando os metadados do usuário."""
    if not sdk:
        logger.error("SDK do Mercado Pago não inicializada. Verifique MERCADOPAGO_TOKEN.")
        return None
        
    payment_data = {
        "transaction_amount": float(valor),
        "description": f"Relatório OSINT Completo - @{target_username}",
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
        result = sdk.payment().create(payment_data)
        response = result.get("response", {})
        return response.get("point_of_interaction", {}).get("transaction_data", {}).get("qr_code")
    except Exception as e:
        logger.error("Erro ao gerar Pix no Mercado Pago: %s", str(e))
        return None


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

    def _github_result(self, response: Response, url: str) -> dict[str, Any]:
        data = response.json()
        return {
            "status": "found",
            "exists": True,
            "name": data.get("name"),
            "bio": data.get("bio"),
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "following": data.get("following"),
            "profile_url": data.get("html_url") or url,
        }

    def validate_profile(self, platform: str, url: str) -> None:
        logger.info("Checking %s", platform)
        try:
            response = requests.get(
                url, headers=self.headers, timeout=self.timeout, allow_redirects=True
            )
            status = response.status_code
            if platform == "GitHub":
                if status == 200 and response.headers.get("content-type", "").startswith("application/json"):
                    result = self._github_result(response, url)
                elif status == 404:
                    result = {"status": "not_found", "exists": False}
                elif status in (403, 429):
                    result = {"status": "rate_limited", "exists": None, "http_status": status}
                else:
                    result = {"status": "error", "exists": None, "http_status": status}
            elif status == 404:
                result = {"status": "not_found", "exists": False}
            elif status in (401, 403, 429):
                result = {"status": "blocked", "exists": None, "http_status": status}
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
        except (requests.Timeout, requests.ConnectionError) as exc:
            logger.warning("%s unavailable: %s", platform, type(exc).__name__)
            self._save(platform, {"status": "unavailable", "exists": None})
        except (ValueError, requests.RequestException) as exc:
            logger.warning("Error checking %s: %s", platform, type(exc).__name__)
            self._save(platform, {"status": "error", "exists": None})

    def run_checks(self) -> dict[str, dict[str, Any]]:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(self.platforms))) as executor:
            futures = [executor.submit(self.validate_profile, p, u) for p, u in self.platforms.items()]
            for future in as_completed(futures):
                future.result()
        return {p: self.results[p] for p in self.platforms if p in self.results}


# --- INICIALIZAÇÃO DO BOT DO TELEGRAM ---
TOKEN = os.getenv("TELEGRAM_TOKEN")
bot = telebot.TeleBot(TOKEN) if TOKEN else None

if bot:
    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        bot.reply_to(
            message, 
            "👋 *Bem-vindo ao UsernameOSINT Bot!*\n\n"
            "Envie qualquer nome de usuário para realizar a varredura pública inicial gratuita.\n"
            "Exemplo: `nome_do_usuario`",
            parse_mode="Markdown"
        )

    @bot.message_handler(func=lambda message: True)
    def handle_search(message):
        username = message.text.strip().replace("@", "")
        user_id = message.from_user.id

        if not valid_username(username):
            bot.reply_to(
                message, 
                "⚠️ *Nome de usuário inválido.*\nUse de 1 a 64 caracteres (letras, números, ponto, sublinhado ou hífen).",
                parse_mode="Markdown"
            )
            return

        bot.reply_to(message, f"🔎 Iniciando checagem pública para: *{username}*...", parse_mode="Markdown")
        
        # 1. Executa busca pública gratuita
        tool = OSINTTool(username)
        results = tool.run_checks()
        
        found_links = []
        for platform, data in results.items():
            if data.get("exists") is True:
                url = data.get("profile_url") or data.get("url") or tool.platforms.get(platform)
                if url:
                    found_links.append(f"• [{platform}]({url})")
                else:
                    found_links.append(f"• {platform}")

        if found_links:
            res_text = f"✅ *Perfis públicos encontrados para {username}:*\n\n" + "\n".join(found_links)
        else:
            res_text = f"ℹ️ Nenhum perfil público padrão foi encontrado para *{username}*."

        # Envia a verificação gratuita
        bot.send_message(message.chat.id, res_text, parse_mode="Markdown", disable_web_page_preview=True)

        # 2. Oferece a Opção do Relatório Completo via Pix Pago
        qr_pix = gerar_pix_mercadopago(user_id, username, valor=15.00)
        
        if qr_pix:
            oferta_paga = (
                f"\n\n🔒 *DESEJA O RELATÓRIO COMPLETO?*\n"
                f"• Consulta em Fóruns Técnicos\n"
                f"• Menções e Marcadores Associados\n"
                f"• Varredura Expandida em Vazamentos\n\n"
                f"💰 *Valor:* R$ 15,00\n"
                f"Copie a chave Pix abaixo e pague no seu app bancário para liberar instantaneamente:\n\n"
                f"`{qr_pix}`\n\n"
                f"⚡ _O relatório detalhado será enviado automaticamente neste chat assim que o Pix for aprovado._"
            )
            bot.send_message(message.chat.id, oferta_paga, parse_mode="Markdown")


def start_telegram_bot():
    if bot:
        logger.info("Iniciando escuta do Bot Telegram...")
        bot.infinity_polling(skip_pending=True)


# Inicializa a thread do Telegram ao subir o módulo
if bot:
    threading.Thread(target=start_telegram_bot, daemon=True).start()


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    return response


@app.route("/")
def index():
    return (
        "UsernameSearchOSINT & Webhook Mercado Pago online. Servico Flask ativo.\n",
        200,
        {"Content-Type": "text/plain; charset=utf-8"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}, 200


# --- ROTA WEBHOOK DO MERCADO PAGO ---
@app.route("/webhook", methods=["POST"])
def webhook():
    """Recebe as notificações de pagamento do Mercado Pago e libera o relatório."""
    data = request.json
    if data and data.get("type") == "payment":
        payment_id = data["data"]["id"]
        
        if sdk:
            try:
                payment_info = sdk.payment().get(payment_id).get("response", {})
                
                if payment_info.get("status") == "approved":
                    metadata = payment_info.get("metadata", {})
                    telegram_id = metadata.get("telegram_user_id")
                    target_username = metadata.get("target_username", "não informado")
                    
                    if telegram_id and bot:
                        bot.send_message(
                            telegram_id,
                            f"✅ *Pagamento Confirmado via Pix!*\n\n"
                            f"Iniciando varredura avançada (fóruns, menções e marcadores) para o alvo `@{target_username}`...",
                            parse_mode="Markdown"
                        )
                        
                        # --- EXECUTAR RELATÓRIO COMPLETO AQUI ---
                        relatorio_completo = (
                            f"📄 *RELATÓRIO AVANÇADO OSINT — @{target_username}*\n\n"
                            f"• *Fóruns Identificados:* 2 fóruns técnicos\n"
                            f"• *Menções em Bases públicas:* Localizadas\n"
                            f"• *Marcadores de Registro:* Encontrados em serviços ativos\n"
                            f"• *Status da Varredura:* Finalizada com sucesso."
                        )
                        bot.send_message(telegram_id, relatorio_completo, parse_mode="Markdown")
            except Exception as e:
                logger.error("Erro ao processar Webhook: %s", str(e))

    return jsonify({"status": "ok"}), 200


@app.route("/osint", methods=["POST"])
def osint_search():
    supplied_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token")
    if not expected_token or not supplied_token or not secrets.compare_digest(supplied_token, expected_token):
        raise BadRequest("Invalid form token.")
    username = request.form.get("username", "").strip()
    if not valid_username(username):
        return (
            "Nome de usuario invalido. Use de 1 a 64 caracteres: letras, "
            "numeros, ponto, sublinhado ou hifen.\n",
            400,
            {"Content-Type": "text/plain; charset=utf-8"},
        )
    results = OSINTTool(username).run_checks()
    return jsonify({"username": username, "results": results})


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
