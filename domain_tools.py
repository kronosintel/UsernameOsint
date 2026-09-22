"""Verificações defensivas de domínio e reputação."""
from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

import requests

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def consultar_dominio(dominio: str, timeout: int = 12) -> dict[str, dict[str, Any]]:
    dominio = dominio.strip().lower().replace("https://", "").replace("http://", "").split("/", 1)[0]
    if not DOMAIN_RE.fullmatch(dominio):
        raise ValueError("Informe um domínio válido, como exemplo.com.")

    resultados: dict[str, dict[str, Any]] = {
        "Google Safe Browsing": {
            "exists": True,
            "status": "reference_only",
            "url": "https://transparencyreport.google.com/safe-browsing/search?url=" + quote(dominio),
        },
        "VirusTotal": {
            "exists": True,
            "status": "api_key_required" if not os.getenv("VT_API_KEY") else "pending",
            "url": "https://www.virustotal.com/gui/domain/" + dominio,
        },
        "URLScan": {
            "exists": True,
            "status": "reference_only",
            "url": "https://urlscan.io/search/#domain:" + dominio,
        },
        "WHOIS": {
            "exists": True,
            "status": "reference_only",
            "url": "https://lookup.icann.org/en/lookup?name=" + quote(dominio),
        },
    }

    vt_key = os.getenv("VT_API_KEY", "").strip()
    if vt_key:
        try:
            response = requests.get(
                "https://www.virustotal.com/api/v3/domains/" + dominio,
                headers={"x-apikey": vt_key, "user-agent": "UsernameOsint/1.0"},
                timeout=timeout,
            )
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = int(stats.get("malicious", 0) or 0)
                suspicious = int(stats.get("suspicious", 0) or 0)
                resultados["VirusTotal"].update(
                    status="found" if malicious or suspicious else "clean_signal",
                    malicious=malicious,
                    suspicious=suspicious,
                    harmless=int(stats.get("harmless", 0) or 0),
                )
            elif response.status_code == 429:
                resultados["VirusTotal"]["status"] = "rate_limited"
            elif response.status_code in (401, 403):
                resultados["VirusTotal"]["status"] = "invalid_api_key"
            else:
                resultados["VirusTotal"]["status"] = "inconclusive"
        except requests.RequestException as exc:
            resultados["VirusTotal"].update(status="unavailable", error=str(exc))
    return resultados
