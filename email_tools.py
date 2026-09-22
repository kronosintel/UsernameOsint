"""Consulta defensiva de exposição de e-mail.

O módulo nunca retorna senhas, tokens ou dados privados. A API do HIBP exige
uma chave própria; IntelX e DeHashed aparecem como fontes oficiais para
verificação manual ou integração autorizada quando o usuário configurar suas
credenciais.
"""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

import requests

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")


def _resultado(nome: str, url: str, status: str, **extra: Any) -> dict[str, Any]:
    return {nome: {"exists": status == "found", "status": status, "url": url, **extra}}


def consultar_email(email: str, timeout: int = 12) -> dict[str, dict[str, Any]]:
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Informe um endereço de e-mail válido.")

    encoded = quote(email, safe="")
    resultados: dict[str, dict[str, Any]] = {}
    hibp_url = "https://haveibeenpwned.com/account/" + encoded
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        resultados.update(_resultado(
            "Have I Been Pwned",
            hibp_url,
            "api_key_required",
            note="Configure HIBP_API_KEY para obter automaticamente os nomes das violações.",
        ))
    else:
        try:
            response = requests.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/" + encoded,
                headers={"hibp-api-key": api_key, "user-agent": "UsernameOsint/1.0"},
                params={"truncateResponse": "true"},
                timeout=timeout,
            )
            if response.status_code == 200:
                breaches = response.json()
                resultados.update(_resultado(
                    "Have I Been Pwned", hibp_url, "found",
                    breach_count=len(breaches) if isinstance(breaches, list) else 0,
                    breaches=[item.get("Name") for item in breaches if isinstance(item, dict) and item.get("Name")],
                ))
            elif response.status_code == 404:
                resultados.update(_resultado("Have I Been Pwned", hibp_url, "not_found", breach_count=0))
            elif response.status_code in (401, 403):
                resultados.update(_resultado("Have I Been Pwned", hibp_url, "invalid_api_key"))
            elif response.status_code == 429:
                resultados.update(_resultado("Have I Been Pwned", hibp_url, "rate_limited"))
            else:
                resultados.update(_resultado("Have I Been Pwned", hibp_url, "inconclusive"))
        except requests.RequestException as exc:
            resultados.update(_resultado("Have I Been Pwned", hibp_url, "unavailable", error=str(exc)))

    resultados.update({
        "Intelligence X (IntelX)": {
            "exists": None,
            "status": "reference_only",
            "url": "https://intelx.io/",
            "query": email,
            "note": "Abra a fonte oficial e pesquise o e-mail. Resultados dependem da licença e dos limites da conta.",
        },
        "DeHashed": {
            "exists": None,
            "status": "reference_only",
            "url": "https://dehashed.com/search",
            "query": email,
            "note": "Pesquisa manual/API exige conta e autorização; o relatório não coleta credenciais ou senhas.",
        },
        "Mozilla Monitor": {
            "exists": None,
            "status": "reference_only",
            "url": "https://monitor.mozilla.org/scan",
            "query": email,
        },
    })
    resultados["observacao"] = {
        "status": "safe_summary",
        "text": "O resultado indica nomes/metadados de exposição. Senhas, tokens e conteúdo de vazamentos nunca são exibidos.",
    }
    return resultados
