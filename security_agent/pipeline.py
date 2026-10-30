from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

import httpx

from security_agent.collectors import EpssCollector, KevCollector, NvdCollector, OsvCollector
from security_agent.collectors.rss import RssCollector
from security_agent.config import AgentConfig
from security_agent.inventory import InventoryScanner
from security_agent.models import Dependency, Finding, Reachability, Triage
from security_agent.notify import GoogleChatNotifier
from security_agent.prioritize import prioritize
from security_agent.store import StateStore
from security_agent.triage import LlmTriager, find_evidence


LOGGER = logging.getLogger(__name__)


class SecurityPipeline:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.store = StateStore(config.database)
        self.inventory = InventoryScanner()

    async def run(self, *, use_syft: bool = False, dry_run: bool = False,
                  package_names: set[str] | None = None,
                  advisory_ids: set[str] | None = None,
                  trigger: dict | None = None) -> list[Finding]:
        inventory_by_repo: list[tuple[Path, Dependency]] = []
        for repository in self.config.repositories:
            dependencies = self.inventory.scan(repository, use_syft=use_syft)
            inventory_by_repo.extend((repository, dependency) for dependency in dependencies)
        if package_names is not None:
            normalized = {item.casefold() for item in package_names}
            inventory_by_repo = [
                item for item in inventory_by_repo if item[1].name.casefold() in normalized
            ]
        dependencies = [dependency for _, dependency in inventory_by_repo]
        if not dependencies:
            LOGGER.warning("No pinned dependencies were found")
            self._write_report([], trigger=trigger)
            return []

        timeout = httpx.Timeout(self.config.request_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     headers={"User-Agent": "security-monitor-agent/0.1"}) as client:
            matches = await OsvCollector(client).match(dependencies)
            if advisory_ids:
                wanted = {item.upper() for item in advisory_ids}
                matches = [
                    (dependency, advisory) for dependency, advisory in matches
                    if wanted.intersection({advisory.id.upper(), *(item.upper() for item in advisory.aliases)})
                ]
            findings = [Finding(dependency=dependency, advisory=advisory)
                        for dependency, advisory in matches]
            cves = {cve for finding in findings for cve in finding.advisory.cves}
            kev_task = asyncio.create_task(self._safe_kev(client))
            epss_task = asyncio.create_task(self._safe_epss(client, cves))
            nvd_task = asyncio.create_task(self._safe_nvd(client, cves))
            kev, epss, nvd = await asyncio.gather(kev_task, epss_task, nvd_task)
            repo_by_purl = {dependency.purl: repository for repository, dependency in inventory_by_repo}

            for finding in findings:
                finding.kev = any(cve in kev for cve in finding.advisory.cves)
                finding.epss = max((epss[cve] for cve in finding.advisory.cves if cve in epss), default=None)
                enrichments = [nvd[cve] for cve in finding.advisory.cves if cve in nvd]
                if enrichments:
                    best = max(enrichments, key=lambda item: item.cvss or 0)
                    if best.cvss is not None:
                        finding.advisory.cvss = best.cvss
                    if best.severity:
                        finding.advisory.severity = best.severity
                    finding.advisory.references = list(dict.fromkeys(
                        [*finding.advisory.references, *best.references]
                    ))
                await self._triage(finding, repo_by_purl[finding.dependency.purl])
                prioritize(finding, self.config.thresholds)
                is_new = self.store.upsert(finding)
                if (is_new and finding.disposition == "immediate" and self.config.google_chat_webhook
                        and not dry_run):
                    await GoogleChatNotifier(client, self.config.google_chat_webhook).send(finding)
                    self.store.mark_notified(finding.key)
        self._write_report(findings, trigger=trigger)
        return sorted(findings, key=lambda item: item.priority, reverse=True)

    async def run_if_new_intelligence(self, *, dry_run: bool = False) -> list[Finding]:
        """Poll lightweight feeds and scan only when at least one unseen item appears."""
        if not self.config.rss_feeds:
            LOGGER.debug("No RSS intelligence feeds are configured")
            return []
        items = RssCollector().collect(self.config.rss_feeds)
        new_items = [item for item in items if self.store.record_feed_item(item.url, item.title)]
        if not new_items:
            LOGGER.info("No new vulnerability intelligence; dependency scan skipped")
            return []
        LOGGER.info("%d new intelligence item(s); starting dependency scan", len(new_items))
        return await self.run(
            dry_run=dry_run,
            trigger={"type": "internet_feed", "items": [item.url for item in new_items[:25]]},
        )

    async def _triage(self, finding: Finding, repository: Path) -> None:
        cache_key = f"{finding.key}|{finding.advisory.modified or ''}"
        cached = self.store.get_triage(cache_key)
        if cached:
            finding.triage = cached
            return
        evidence = find_evidence(repository, finding.dependency)
        fallback = Triage(
            reachability=Reachability.POSSIBLE if evidence else Reachability.UNKNOWN,
            impact=finding.advisory.summary,
            fix=(f"Upgrade to {finding.advisory.fixed_versions[0]}"
                 if finding.advisory.fixed_versions else "Review the advisory; no fixed version is listed"),
            fixed_version=finding.advisory.fixed_versions[0] if finding.advisory.fixed_versions else None,
            evidence=evidence,
        )
        finding.triage = fallback
        if self.config.enable_llm and os.getenv("OPENAI_API_KEY"):
            try:
                triager = LlmTriager(self.config.openai_model)
                finding.triage = triager.triage(finding.dependency, finding.advisory, evidence)
            except Exception as exc:  # A failed enhancement must not fail deterministic scanning.
                LOGGER.warning("LLM triage failed for %s: %s", finding.key, exc)
        self.store.cache_triage(cache_key, finding.triage)

    async def _safe_kev(self, client: httpx.AsyncClient) -> set[str]:
        try:
            return await KevCollector(client).collect()
        except (httpx.HTTPError, ValueError) as exc:
            LOGGER.warning("CISA KEV enrichment failed: %s", exc)
            return set()

    async def _safe_epss(self, client: httpx.AsyncClient, cves: set[str]) -> dict[str, float]:
        try:
            return await EpssCollector(client).collect(cves)
        except (httpx.HTTPError, ValueError) as exc:
            LOGGER.warning("EPSS enrichment failed: %s", exc)
            return {}

    async def _safe_nvd(self, client: httpx.AsyncClient, cves: set[str]):
        api_key = os.getenv("NVD_API_KEY")
        if not api_key or not cves:
            return {}
        try:
            return await NvdCollector(client, api_key).collect(cves)
        except (httpx.HTTPError, ValueError) as exc:
            LOGGER.warning("NVD enrichment failed: %s", exc)
            return {}

    def _write_report(self, findings: list[Finding], *, trigger: dict | None = None) -> Path:
        self.config.report_directory.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        path = self.config.report_directory / f"scan-{stamp}.json"
        payload = {
            "generated_at": datetime.now(UTC).isoformat(),
            "trigger": trigger or {"type": "manual"},
            "finding_count": len(findings),
            "findings": [item.to_dict() for item in findings],
        }
        path.write_text(json.dumps(payload, indent=2) + "\n")
        return path
