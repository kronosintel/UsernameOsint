"""Adaptador do Sherlock Project para consultas de username no bot.

O scanner roda em processo separado para que um timeout total encerre também
as requisições internas em paralelo, sem deixar threads órfãs no Gunicorn.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class ResultadoSherlock:
    username: str
    encontrados: list[dict[str, Any]]
    total_encontrados: int
    erro: str | None = None

    def para_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validar_username(username: str) -> str:
    username = username.strip().lstrip("@")
    if not username:
        raise ValueError("Informe um username.")
    if len(username) > 100 or re.search(r"[\x00-\x1f\x7f]", username):
        raise ValueError("Username inválido.")
    return username


def _ler_resultados(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict) and item.get("url")]


def consultar_username(
    username: str,
    *,
    timeout: int = 15,
    site_timeout: int = 2,
) -> ResultadoSherlock:
    """Consulta Sherlock e retorna somente perfis que a ferramenta marcou como encontrados.

    ``timeout`` limita o processo inteiro; ``site_timeout`` limita cada site.
    Se o limite total vencer, achados já confirmados são preservados.
    """
    username = _validar_username(username)
    if timeout <= 0 or site_timeout <= 0:
        raise ValueError("Os timeouts devem ser maiores que zero.")

    worker = Path(__file__).with_name("sherlock_worker.py")
    with tempfile.TemporaryDirectory(prefix="kronos-sherlock-") as temp_dir:
        partial_results = Path(temp_dir) / "found.json"
        command = [
            sys.executable,
            str(worker),
            username,
            str(int(site_timeout)),
            str(partial_results),
        ]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            encontrados = _ler_resultados(partial_results)
            if encontrados:
                return ResultadoSherlock(
                    username=username,
                    encontrados=encontrados,
                    total_encontrados=len(encontrados),
                    erro=f"Sherlock excedeu o limite de {timeout}s; retornando achados parciais.",
                )
            raise TimeoutError(f"A pesquisa Sherlock excedeu {timeout} segundos.") from exc

        try:
            payload = json.loads(process.stdout.strip() or "{}")
            encontrados = payload.get("encontrados", []) if isinstance(payload, dict) else []
            encontrados = [item for item in encontrados if isinstance(item, dict) and item.get("url")]
        except json.JSONDecodeError:
            encontrados = _ler_resultados(partial_results)

        if process.returncode != 0 and not encontrados:
            detalhe = process.stderr.strip()[-500:]
            raise RuntimeError(detalhe or f"Sherlock terminou com código {process.returncode}.")

        return ResultadoSherlock(
            username=username,
            encontrados=encontrados,
            total_encontrados=len(encontrados),
            erro=None,
        )
