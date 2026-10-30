from security_agent.models import Dependency
from security_agent.triage.email_intel import EmailIntelligenceExtractor


def test_deterministic_email_extraction_never_needs_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    result = EmailIntelligenceExtractor("unused", enabled=False).extract(
        "Critical vulnerability CVE-2026-12345",
        "lodash versions before the fix are affected. https://example.test/advisory",
        [Dependency("lodash", "4.17.15", "npm")],
    )
    assert result.is_security_advisory is True
    assert result.cve_ids == ["CVE-2026-12345"]
    assert result.packages[0].name == "lodash"


def test_unrelated_email_is_not_an_advisory():
    result = EmailIntelligenceExtractor("unused", enabled=False).extract(
        "Weekly meeting", "The agenda is attached.", []
    )
    assert result.is_security_advisory is False
    assert result.cve_ids == []


def test_llm_failure_falls_back_to_deterministic_extraction():
    class FailingCompletions:
        def parse(self, **kwargs):
            raise RuntimeError("offline")

    class Client:
        class Chat:
            completions = FailingCompletions()
        chat = Chat()

    result = EmailIntelligenceExtractor("unused", client=Client()).extract(  # type: ignore[arg-type]
        "CVE-2026-9999 advisory", "A vulnerability was found.", []
    )
    assert result.cve_ids == ["CVE-2026-9999"]
