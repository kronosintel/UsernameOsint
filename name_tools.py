"""Links e consultas públicas de nome completo.

A busca não confirma identidade. Evita scraping de páginas protegidas e não
retorna dados pessoais não públicos.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote


def consultar_nome_completo(nome: str) -> dict[str, dict[str, Any]]:
    nome = " ".join(nome.strip().split())
    if len(nome) < 5 or len(nome.split()) < 2:
        raise ValueError("Informe nome e sobrenome para reduzir homônimos.")
    termo = quote(f'"{nome}"')
    return {
        "Jusbrasil": {
            "exists": True,
            "status": "reference_only",
            "url": f"https://www.jusbrasil.com.br/busca?q={termo}",
        },
        "Escavador": {
            "exists": True,
            "status": "reference_only",
            "url": f"https://www.escavador.com/busca?q={termo}",
        },
        "Google — processos e publicações": {
            "exists": True,
            "status": "reference_only",
            "url": f"https://www.google.com/search?q={quote(f'"{nome}" processo')}",
        },
        "Observação": {
            "exists": True,
            "status": "safe_summary",
            "note": "Resultados podem conter homônimos; confirme identidade por meios legais e autorizados.",
        },
    }
