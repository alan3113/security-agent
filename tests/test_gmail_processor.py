import asyncio
from pathlib import Path

from security_agent.collectors.gmail import SecurityEmail
from security_agent.config import AgentConfig, GmailConfig
from security_agent.gmail_processor import GmailSecurityProcessor


class FakeGmail:
    def __init__(self, message: SecurityEmail):
        self.message = message
        self.statuses: list[str] = []

    def apply_status(self, message_id: str, status: str) -> None:
        assert message_id == self.message.message_id
        self.statuses.append(status)

    def get_security_email(self, message_id: str) -> SecurityEmail:
        assert message_id == self.message.message_id
        return self.message


def test_unverified_sender_is_labeled_for_review_and_deduplicated(tmp_path: Path):
    config = AgentConfig(
        repositories=[tmp_path],
        database=tmp_path / "state.db",
        report_directory=tmp_path / "reports",
        enable_llm=False,
        gmail=GmailConfig(
            enabled=True,
            approved_senders=["security@example.com"],
            require_authentication_pass=True,
        ),
    )
    message = SecurityEmail(
        "message-1", "thread-1", "attacker@example.net", "Urgent CVE",
        "spf=fail; dkim=fail; dmarc=fail", "CVE-2026-1234",
    )
    gmail = FakeGmail(message)
    processor = GmailSecurityProcessor(config, gmail=gmail)  # type: ignore[arg-type]
    assert asyncio.run(processor.process_message("message-1")) == "review"
    assert gmail.statuses == [config.gmail.processing_label, config.gmail.review_label]
    assert asyncio.run(processor.process_message("message-1")) == "duplicate"
