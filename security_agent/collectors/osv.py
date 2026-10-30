from __future__ import annotations

import asyncio
from typing import Any

import httpx

from security_agent.models import Advisory, Dependency


class OsvCollector:
    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def match(self, dependencies: list[Dependency]) -> list[tuple[Dependency, Advisory]]:
        matches: list[tuple[Dependency, Advisory]] = []
        for offset in range(0, len(dependencies), 1000):
            batch = dependencies[offset:offset + 1000]
            response = await self.client.post(f"{self.BASE_URL}/querybatch",
                                              json={"queries": [item.osv_query() for item in batch]})
            response.raise_for_status()
            results = response.json().get("results", [])
            ids_by_dependency = [(dependency, [vuln["id"] for vuln in result.get("vulns", [])])
                                 for dependency, result in zip(batch, results, strict=False)]
            unique_ids = sorted({item for _, ids in ids_by_dependency for item in ids})
            details = await self._details(unique_ids)
            for dependency, ids in ids_by_dependency:
                matches.extend((dependency, self._parse(details[identifier], dependency))
                               for identifier in ids if identifier in details)
        return matches

    async def _details(self, identifiers: list[str]) -> dict[str, dict[str, Any]]:
        semaphore = asyncio.Semaphore(10)

        async def fetch(identifier: str) -> tuple[str, dict[str, Any]]:
            async with semaphore:
                response = await self.client.get(f"{self.BASE_URL}/vulns/{identifier}")
                response.raise_for_status()
                return identifier, response.json()

        return dict(await asyncio.gather(*(fetch(identifier) for identifier in identifiers)))

    @staticmethod
    def _parse(data: dict[str, Any], dependency: Dependency | None = None) -> Advisory:
        fixed = []
        for affected in data.get("affected", []):
            package = affected.get("package", {})
            if dependency is not None and (
                package.get("name") != dependency.name
                or package.get("ecosystem") != dependency.ecosystem
            ):
                continue
            for version_range in affected.get("ranges", []):
                fixed.extend(event["fixed"] for event in version_range.get("events", []) if "fixed" in event)
        references = [item["url"] for item in data.get("references", []) if item.get("url")]
        database = data.get("database_specific", {})
        severity = str(database.get("severity", "UNKNOWN")).upper()
        cvss = OsvCollector._cvss_score(data, database)
        return Advisory(
            id=data["id"], summary=data.get("summary", "No summary supplied"),
            details=data.get("details", ""), aliases=list(data.get("aliases", [])),
            severity=severity, cvss=cvss, fixed_versions=sorted(set(fixed)),
            references=references, published=data.get("published"), modified=data.get("modified"),
        )

    @staticmethod
    def _cvss_score(data: dict[str, Any], database: dict[str, Any]) -> float | None:
        for key in ("cvss_score", "cvssScore"):
            if key in database:
                try:
                    return float(database[key])
                except (TypeError, ValueError):
                    pass
        # OSV severity entries commonly contain vectors, not calculated base scores.
        # Preserve correctness by using only an explicitly supplied numeric score.
        for entry in data.get("severity", []):
            score = entry.get("score")
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
        return None

