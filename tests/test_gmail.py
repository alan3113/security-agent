import json

from security_agent.collectors.gmail import (
    SecurityEmail,
    parse_pubsub_notification,
    validate_security_email,
)
from security_agent.config import GmailConfig


def test_sender_and_authentication_must_both_pass():
    config = GmailConfig(
        approved_senders=["security@example.com"], require_authentication_pass=True
    )
    valid = SecurityEmail("1", "t", "security@example.com", "Alert",
                          "mx.google.com; dkim=pass; spf=pass; dmarc=pass", "CVE-2026-1234")
    spoofed = SecurityEmail("2", "t", "security@example.com", "Alert",
                            "mx.google.com; dkim=fail; spf=fail; dmarc=fail", "CVE-2026-1234")
    assert validate_security_email(valid, config)[0] is True
    assert validate_security_email(spoofed, config)[0] is False


def test_approved_domain_and_pubsub_payload():
    config = GmailConfig(approved_domains=["example.com"], require_authentication_pass=False)
    message = SecurityEmail("1", "t", "alerts@example.com", "Alert", "", "body")
    assert validate_security_email(message, config)[0] is True
    assert parse_pubsub_notification(json.dumps({
        "emailAddress": "Mailbox@Example.com", "historyId": "123"
    }).encode()) == ("mailbox@example.com", "123")
