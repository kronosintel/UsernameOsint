"""Consulta cadastral pública de CNPJ."""
from __future__ import annotations

from typing import Any

import requests


def _somente_digitos(valor: str) -> str:
    return "".join(ch for ch in valor if ch.isdigit())


def _validar_cnpj(cnpj: str) -> bool:
    cnpj = _somente_digitos(cnpj)
    if len(cnpj) != 14 or len(set(cnpj)) == 1:
        return False
    pesos_a = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    pesos_b = [6] + pesos_a
    for indice, pesos in enumerate((pesos_a, pesos_b)):
        total = sum(int(digito) * peso for digito, peso in zip(cnpj, pesos))
        digito = (total * 10) % 11
        if digito == 10:
            digito = 0
        if digito != int(cnpj[12 + indice]):
            return False
    return True


def consultar_cnpj(cnpj: str, timeout: int = 12) -> dict[str, dict[str, Any]]:
    cnpj = _somente_digitos(cnpj)
    if not _validar_cnpj(cnpj):
        raise ValueError("CNPJ inválido.")
    url = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj}"
    try:
        response = requests.get(url, timeout=timeout, headers={"user-agent": "UsernameOsint/1.0"})
        if response.status_code == 200:
            data = response.json()
            return {
                "BrasilAPI CNPJ": {
                    "exists": True,
                    "status": "found",
                    "url": url,
                    "data": data,
                }
            }
        if response.status_code == 404:
            return {"BrasilAPI CNPJ": {"exists": False, "status": "not_found", "url": url}}
        return {"BrasilAPI CNPJ": {"exists": None, "status": "inconclusive", "url": url}}
    except requests.RequestException as exc:
        return {"BrasilAPI CNPJ": {"exists": None, "status": "unavailable", "url": url, "error": str(exc)}}
