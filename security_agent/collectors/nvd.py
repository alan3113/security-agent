from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True, slots=True)
class NvdEnrichment:
    cvss: float | None
    severity: str | None
    references: list[str]


class NvdCollector:
    URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self.client = client
        self.api_key = api_key

    async def collect(self, cves: set[str]) -> dict[str, NvdEnrichment]:
        semaphore = asyncio.Semaphore(5)

        async def fetch(cve: str) -> tuple[str, NvdEnrichment | None]:
            async with semaphore:
                response = await self.client.get(self.URL, params={"cveId": cve},
                                                 headers={"apiKey": self.api_key})
                response.raise_for_status()
                vulnerabilities = response.json().get("vulnerabilities", [])
                if not vulnerabilities:
                    return cve, None
                item = vulnerabilities[0]["cve"]
                cvss, severity = self._metrics(item.get("metrics", {}))
                references = [reference["url"] for reference in item.get("references", [])
                              if reference.get("url")]
                return cve, NvdEnrichment(cvss, severity, references)

        pairs = await asyncio.gather(*(fetch(cve) for cve in sorted(cves)))
        return {cve: value for cve, value in pairs if value is not None}

    @staticmethod
    def _metrics(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if not entries:
                continue
            primary = next((entry for entry in entries if entry.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or primary.get("baseSeverity")
            try:
                return float(score), str(severity).upper() if severity else None
            except (TypeError, ValueError):
                continue
        return None, None
