from __future__ import annotations

import httpx


class EpssCollector:
    URL = "https://api.first.org/data/v1/epss"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def collect(self, cves: set[str]) -> dict[str, float]:
        result: dict[str, float] = {}
        ordered = sorted(cves)
        for offset in range(0, len(ordered), 100):
            chunk = ordered[offset:offset + 100]
            if not chunk:
                continue
            response = await self.client.get(self.URL, params={"cve": ",".join(chunk)})
            response.raise_for_status()
            for item in response.json().get("data", []):
                try:
                    result[item["cve"]] = float(item["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        return result

