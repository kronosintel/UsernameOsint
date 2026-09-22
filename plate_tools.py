"""Consulta defensiva de placa.

Não consulta proprietário, CPF, endereço ou qualquer dado pessoal. Para dados
veiculares autorizados, configure um provedor contratado em PLACA_API_URL,
com o placeholder {placa}; a resposta do provedor deve ser pública e legal.
"""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

import requests

OLD_PLATE = re.compile(r"^[A-Z]{3}\d{4}$")
MERCOSUL_PLATE = re.compile(r"^[A-Z]{3}\d[A-Z]\d{2}$")


def consultar_placa(placa: str, timeout: int = 12) -> dict[str, dict[str, Any]]:
    placa = re.sub(r"[^A-Za-z0-9]", "", placa).upper()
    if not (OLD_PLATE.fullmatch(placa) or MERCOSUL_PLATE.fullmatch(placa)):
        raise ValueError("Placa inválida. Use ABC1234 ou ABC1D23.")

    resultados: dict[str, dict[str, Any]] = {
        "Sinesp Cidadão": {
            "exists": True,
            "status": "reference_only",
            "url": "https://www.gov.br/pt-br/servicos/consultar-online-os-dados-de-placa-de-veiculo",
            "note": "Consulta manual no canal oficial; disponibilidade depende de autenticação e regras do serviço.",
        },
        "Observação de privacidade": {
            "exists": True,
            "status": "safe_summary",
            "note": "Este módulo não retorna proprietário, CPF, endereço ou outros dados pessoais.",
        },
    }

    provider = os.getenv("PLACA_API_URL", "").strip()
    if not provider:
        resultados["Provedor veicular autorizado"] = {
            "exists": None,
            "status": "provider_not_configured",
            "note": "Defina PLACA_API_URL somente para uma API contratada e autorizada.",
        }
        return resultados

    url = provider.replace("{placa}", quote(placa, safe=""))
    headers = {"user-agent": "UsernameOsint/1.0"}
    token = os.getenv("PLACA_API_KEY", "").strip()
    if token:
        headers["authorization"] = f"Bearer {token}"
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            resultados["Provedor veicular autorizado"] = {
                "exists": True,
                "status": "found",
                "url": url,
                "data": response.json(),
            }
        elif response.status_code == 404:
            resultados["Provedor veicular autorizado"] = {"exists": False, "status": "not_found", "url": url}
        else:
            resultados["Provedor veicular autorizado"] = {"exists": None, "status": "inconclusive", "url": url}
    except (requests.RequestException, ValueError) as exc:
        resultados["Provedor veicular autorizado"] = {"exists": None, "status": "unavailable", "url": url, "error": str(exc)}
    return resultados
