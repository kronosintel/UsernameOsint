"""Integração reutilizável do Maigret para bots.

Instalação:
    python -m pip install maigret

Uso:
    from maigret_lookup import consultar_username
    resultado = consultar_username("nome_do_usuario")
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class ResultadoMaigret:
    """Resultado normalizado para ser enviado pelo bot."""

    username: str
    encontrados: list[dict[str, Any]]
    total_encontrados: int
    comando: list[str]
    erro: str | None = None

    def para_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validar_username(username: str) -> str:
    username = username.strip().lstrip('@')
    if not username:
        raise ValueError("Informe um username.")
    if len(username) > 100 or re.search(r"[\x00\r\n]", username):
        raise ValueError("Username inválido.")
    return username


def _encontrados_do_stdout(stdout: str) -> list[dict[str, Any]]:
    """Lê NDJSON quando o Maigret o imprime no terminal.

    Algumas versões podem misturar mensagens de progresso com o NDJSON;
    por isso cada linha é analisada independentemente.
    """
    encontrados: list[dict[str, Any]] = []
    for linha in stdout.splitlines():
        linha = linha.strip()
        if not linha.startswith("{"):
            continue
        try:
            item = json.loads(linha)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            encontrados.append(item)
    return encontrados


def consultar_username(
    username: str,
    *,
    todos_os_sites: bool = False,
    tags: list[str] | None = None,
    timeout: int = 180,
    executavel: str = "maigret",
) -> ResultadoMaigret:
    """Pesquisa um username no Maigret.

    Args:
        username: Nome a consultar; um ``@`` inicial é removido.
        todos_os_sites: Se True, usa ``-a``; caso contrário usa os sites padrão.
        tags: Filtros opcionais, por exemplo ``["social", "coding"]``.
        timeout: Tempo máximo da pesquisa em segundos.
        executavel: Caminho do executável, útil em venv ou Docker.

    Returns:
        ResultadoMaigret, que pode ser convertido para JSON com ``para_dict()``.
    """
    username = _validar_username(username)
    if timeout <= 0:
        raise ValueError("timeout deve ser maior que zero.")

    caminho = shutil.which(executavel) or executavel
    comando = [caminho, username, "--json", "ndjson"]
    if todos_os_sites:
        comando.append("-a")
    if tags:
        comando.extend(["--tags", ",".join(tags)])

    try:
        processo = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Maigret não foi encontrado. Instale com: python -m pip install maigret"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"A pesquisa excedeu {timeout} segundos.") from exc

    encontrados = _encontrados_do_stdout(processo.stdout)
    erro = processo.stderr.strip() or None
    if processo.returncode != 0 and not encontrados:
        erro = erro or f"Maigret terminou com código {processo.returncode}."

    return ResultadoMaigret(
        username=username,
        encontrados=encontrados,
        total_encontrados=len(encontrados),
        comando=comando,
        erro=erro,
    )


def formatar_para_bot(resultado: ResultadoMaigret, limite: int = 20) -> str:
    """Gera uma resposta curta, adequada para Telegram, Discord ou outro bot."""
    if resultado.erro and not resultado.encontrados:
        return f"Não foi possível consultar @{resultado.username}: {resultado.erro}"
    if not resultado.encontrados:
        return f"Nenhum resultado estruturado encontrado para @{resultado.username}."

    linhas = [
        f"Resultados para @{resultado.username}:",
        f"Encontrados: {resultado.total_encontrados}",
    ]
    for item in resultado.encontrados[:limite]:
        nome = item.get("site", item.get("name", "Site"))
        url = item.get("url", item.get("link", ""))
        status = item.get("status", "encontrado")
        linhas.append(f"- {nome}: {url} ({status})" if url else f"- {nome} ({status})")
    if resultado.total_encontrados > limite:
        linhas.append(f"... e mais {resultado.total_encontrados - limite} resultado(s).")
    return "\n".join(linhas)
