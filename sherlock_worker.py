"""Worker isolado para a API Python oficial de sherlock-project."""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any


class ColetorResultados:
    def __init__(self, arquivo_parcial: Path, query_notify: Any, query_status: Any):
        self._arquivo_parcial = arquivo_parcial
        self._query_status = query_status
        self._lock = threading.Lock()
        self._encontrados: dict[str, dict[str, Any]] = {}
        self._base = query_notify

    def start(self, message=None) -> None:
        self._base.start(message)

    def update(self, result) -> None:
        if result.status is not self._query_status.CLAIMED:
            return
        item = {
            "site": str(result.site_name),
            "url": str(result.site_url_user or ""),
            "status": "found",
            "query_time": result.query_time,
        }
        with self._lock:
            self._encontrados[item["site"]] = item
            self._persistir()

    def finish(self, message=None) -> None:
        self._base.finish(message)

    def _persistir(self) -> None:
        temp_path = self._arquivo_parcial.with_suffix(".tmp")
        try:
            temp_path.write_text(
                json.dumps(list(self._encontrados.values()), ensure_ascii=False),
                encoding="utf-8",
            )
            os.replace(temp_path, self._arquivo_parcial)
        except OSError:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def encontrados(self) -> list[dict[str, Any]]:
        with self._lock:
            return sorted(self._encontrados.values(), key=lambda item: item["site"].casefold())


def main() -> int:
    if len(sys.argv) != 4:
        print("Uso interno inválido.", file=sys.stderr)
        return 2

    username = sys.argv[1]
    site_timeout = float(sys.argv[2])
    arquivo_parcial = Path(sys.argv[3])

    from importlib.resources import as_file, files
    from sherlock_project.notify import QueryNotify
    from sherlock_project.result import QueryStatus
    from sherlock_project.sherlock import sherlock
    from sherlock_project.sites import SitesInformation

    recurso = files("sherlock_project").joinpath("resources", "data.json")
    with as_file(recurso) as data_path:
        sites = SitesInformation(data_file_path=str(data_path))
        site_data = {site.name: site.information for site in sites}

    notify = ColetorResultados(arquivo_parcial, QueryNotify(), QueryStatus)
    sherlock(username, site_data, notify, timeout=site_timeout)
    print(json.dumps({"encontrados": notify.encontrados()}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
