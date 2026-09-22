"""Busca defensiva e pública para nome completo.

Os links são fontes de referência e podem conter homônimos. O módulo não
confirma identidade nem acessa bases privadas ou restritas.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote


def _busca(nome: str, texto: str) -> str:
    return quote(f'"{nome}" {texto}')


def consultar_nome_completo(nome: str) -> dict[str, dict[str, Any]]:
    nome = " ".join(nome.strip().split())
    if len(nome) < 5 or len(nome.split()) < 2:
        raise ValueError("Informe nome e sobrenome para reduzir homônimos.")

    return {
        "Jusbrasil — processos e publicações": {
            "exists": None, "status": "reference_only",
            "url": f"https://www.jusbrasil.com.br/busca?q={_busca(nome, 'processo')}",
            "note": "Verifique homônimos, tribunal e número do processo.",
        },
        "Escavador — processos e publicações": {
            "exists": None, "status": "reference_only",
            "url": f"https://www.escavador.com/busca?q={_busca(nome, 'processo')}",
        },
        "Google — processos": {
            "exists": None, "status": "reference_only",
            "url": f"https://www.google.com/search?q={_busca(nome, 'processo')}",
        },
        "Bing — presença digital": {
            "exists": None, "status": "reference_only",
            "url": f"https://www.bing.com/search?q={_busca(nome, '')}",
        },
        "DuckDuckGo — presença digital": {
            "exists": None, "status": "reference_only",
            "url": f"https://duckduckgo.com/?q={_busca(nome, '')}",
        },
        "Yandex — presença digital": {
            "exists": None, "status": "reference_only",
            "url": f"https://yandex.com/search/?text={_busca(nome, '')}",
        },
        "Google News — menções públicas": {
            "exists": None, "status": "reference_only",
            "url": f"https://news.google.com/search?q={quote(nome)}",
        },
        "Observação": {
            "exists": None, "status": "safe_summary",
            "note": "Buscas de nome não confirmam identidade. Confirme por dados públicos adicionais e meios legais autorizados.",
        },
    }
