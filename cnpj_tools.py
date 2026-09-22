"""Consulta cadastral pública e defensiva de CNPJ."""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

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
    resultados: dict[str, dict[str, Any]] = {}
    try:
        response = requests.get(url, timeout=timeout, headers={"user-agent": "UsernameOsint/1.0"})
        if response.status_code == 200:
            resultados["BrasilAPI CNPJ"] = {"exists": True, "status": "found", "url": url, "data": response.json()}
        elif response.status_code == 404:
            resultados["BrasilAPI CNPJ"] = {"exists": False, "status": "not_found", "url": url}
        else:
            resultados["BrasilAPI CNPJ"] = {"exists": None, "status": "inconclusive", "url": url}
    except requests.RequestException as exc:
        resultados["BrasilAPI CNPJ"] = {"exists": None, "status": "unavailable", "url": url, "error": str(exc)}

    resultados.update({
        "CNPJá — referência complementar": {
            "exists": None,
            "status": "reference_only",
            "url": "https://cnpja.com/",
            "query": cnpj,
            "note": "Fonte complementar de dados cadastrais e atividades; confirme sempre na Receita Federal.",
        },
        "Receita Federal — comprovante oficial": {
            "exists": None,
            "status": "reference_only",
            "url": "https://solucoes.receita.fazenda.gov.br/servicos/cnpjreva/cnpjreva_solicitacao.asp",
            "query": cnpj,
            "note": "Fonte oficial para situação cadastral do CNPJ.",
        },
    })
    return resultados
