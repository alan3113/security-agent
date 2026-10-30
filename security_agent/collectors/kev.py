from __future__ import annotations

import httpx


class KevCollector:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def collect(self) -> set[str]:
        response = await self.client.get(self.URL)
        response.raise_for_status()
        return {item["cveID"] for item in response.json().get("vulnerabilities", []) if item.get("cveID")}

