from __future__ import annotations

import httpx

from security_agent.models import Finding


class GoogleChatNotifier:
    def __init__(self, client: httpx.AsyncClient, webhook_url: str):
        self.client = client
        self.webhook_url = webhook_url

    async def send(self, finding: Finding) -> None:
        dependency = finding.dependency
        advisory = finding.advisory
        marker = "🔴" if finding.disposition == "immediate" else "🟠"
        context = ["CISA KEV" if finding.kev else "", f"EPSS {finding.epss:.1%}" if finding.epss is not None else ""]
        fix = finding.triage.fix or (
            f"Upgrade to {advisory.fixed_versions[0]} or later"
            if advisory.fixed_versions else "No verified fixed version is listed; review the advisory"
        )
        reference = advisory.references[0] if advisory.references else f"https://osv.dev/vulnerability/{advisory.id}"
        text = (
            f"{marker} *{advisory.severity} | {advisory.id} in {dependency.name}@{dependency.version}*\n"
            f"Priority {finding.priority}/100 · {', '.join(item for item in context if item) or 'No active exploitation signal'}\n"
            f"{advisory.summary}\n"
            f"Reachability: {finding.triage.reachability.value}\n"
            f"Fix: {fix}\n"
            f"Ref: {reference}"
        )
        response = await self.client.post(self.webhook_url, json={"text": text})
        response.raise_for_status()

    async def send_digest(self, findings: list[dict]) -> None:
        lines = [f"🛡️ *Security dependency digest — {len(findings)} new finding(s)*"]
        for finding in findings[:20]:
            advisory = finding["advisory"]
            dependency = finding["dependency"]
            lines.append(
                f"• *{advisory['id']}* · {dependency['name']}@{dependency['version']} · "
                f"priority {finding['priority']}/100 — {advisory['summary'][:180]}"
            )
        if len(findings) > 20:
            lines.append(f"…and {len(findings) - 20} more; see the JSON report.")
        response = await self.client.post(self.webhook_url, json={"text": "\n".join(lines)[:4000]})
        response.raise_for_status()

