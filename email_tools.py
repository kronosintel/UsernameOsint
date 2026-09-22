"""Consultas públicas e autorizadas relacionadas a um endereço de e-mail.

A integração usa a API oficial do Have I Been Pwned quando HIBP_API_KEY está
configurada. Ela retorna nomes e metadados de violações, não senhas nem dados
expostos.
"""
from __future__ import annotations

import os
import re
from typing import Any

import requests

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")


def _resultado(nome: str, url: str, status: str, **extra: Any) -> dict[str, Any]:
    return {nome: {"exists": status == "found", "status": status, "url": url, **extra}}


def consultar_email(email: str, timeout: int = 12) -> dict[str, dict[str, Any]]:
    """Consulta ocorrência do e-mail em serviços públicos/legítimos."""
    email = email.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Informe um endereço de e-mail válido.")

    resultados: dict[str, dict[str, Any]] = {}
    hibp_url = "https://haveibeenpwned.com/account/" + email
    api_key = os.getenv("HIBP_API_KEY", "").strip()
    if not api_key:
        resultados.update(_resultado("Have I Been Pwned", hibp_url, "api_key_required"))
    else:
        try:
            response = requests.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/" + email,
                headers={"hibp-api-key": api_key, "user-agent": "UsernameOsint/1.0"},
                params={"truncateResponse": "true"},
                timeout=timeout,
            )
            if response.status_code == 200:
                breaches = response.json()
                resultados.update(_resultado(
                    "Have I Been Pwned", hibp_url, "found",
                    breach_count=len(breaches) if isinstance(breaches, list) else None,
                    breaches=breaches if isinstance(breaches, list) else [],
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

    resultados.update(_resultado(
        "Mozilla Monitor",
        "https://monitor.mozilla.org/scan",
        "reference_only",
        note="Use o site oficial para uma consulta manual adicional.",
    ))
    resultados["observacao"] = {
        "status": "safe_summary",
        "text": "Nenhuma senha ou dado privado é coletado por este módulo; apenas metadados públicos de violações.",
    }
    return resultados
