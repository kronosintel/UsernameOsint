"""Small, defensive username availability checker.

Only checks public profile URLs supplied by the built-in provider list. A result is
never proof that two profiles belong to the same person.
"""
from __future__ import annotations

import logging
import os
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any

import requests
from flask import Flask, render_template, request, session
from requests import Response
from werkzeug.exceptions import BadRequest

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

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

# Common provider pages returned for unknown/removed accounts. These markers help
# avoid declaring every CDN/SPA 200 page as an account match.
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


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
    return response


@app.route("/")
def index():
    return render_template("index.html", csrf_token=csrf_token())


@app.get("/health")
def health():
    """Lightweight health endpoint used by Render and uptime monitors."""
    return {"status": "ok"}, 200


@app.route("/osint", methods=["POST"])
def osint_search():
    supplied_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token")
    if not expected_token or not supplied_token or not secrets.compare_digest(supplied_token, expected_token):
        raise BadRequest("Invalid form token.")
    username = request.form.get("username", "").strip()
    if not valid_username(username):
        return render_template(
            "index.html",
            error="Use 1–64 characters: letters, numbers, dot, underscore or hyphen.",
            csrf_token=csrf_token(),
        ), 400
    results = OSINTTool(username).run_checks()
    return render_template("results.html", username=username, results=results)


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1", host="0.0.0.0", port=PORT)
