from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class Thresholds:
    immediate: float = 70
    digest: float = 35


@dataclass(slots=True)
class GmailConfig:
    enabled: bool = False
    mailbox: str = "me"
    pubsub_topic: str = ""
    pubsub_subscription: str = ""
    credentials_file: Path | None = None
    oauth_client_file: Path | None = None
    service_account_file: Path | None = None
    incoming_label: str = "Security/Incoming"
    processing_label: str = "Security/Processing"
    matched_label: str = "Security/Matched"
    no_match_label: str = "Security/NoMatch"
    review_label: str = "Security/NeedsReview"
    error_label: str = "Security/Error"
    approved_senders: list[str] = field(default_factory=list)
    approved_domains: list[str] = field(default_factory=list)
    require_authentication_pass: bool = True
    max_content_bytes: int = 100_000


@dataclass(slots=True)
class AgentConfig:
    repositories: list[Path] = field(default_factory=lambda: [Path.cwd()])
    database: Path = Path(".security-agent.db")
    report_directory: Path = Path("reports")
    intelligence_poll_minutes: int = 15
    gmail_poll_minutes: int = 5
    digest_hour_local: int = 9
    thresholds: Thresholds = field(default_factory=Thresholds)
    openai_model: str = "gpt-4o-mini"
    enable_llm: bool = True
    google_chat_webhook: str | None = None
    rss_feeds: list[str] = field(default_factory=list)
    request_timeout_seconds: float = 30
    gmail: GmailConfig = field(default_factory=GmailConfig)

    @classmethod
    def load(cls, path: str | Path) -> "AgentConfig":
        config_path = Path(path).resolve()
        raw: dict[str, Any] = yaml.safe_load(config_path.read_text()) or {}
        base = config_path.parent

        def local_path(value: str) -> Path:
            candidate = Path(value).expanduser()
            return candidate if candidate.is_absolute() else (base / candidate).resolve()

        threshold_data = raw.get("thresholds", {})
        gmail_data = raw.get("gmail", {})
        repositories = [local_path(item) for item in raw.get("repositories", ["."])]

        def optional_path(value: str | None) -> Path | None:
            return local_path(value) if value else None

        return cls(
            repositories=repositories,
            database=local_path(raw.get("database", ".security-agent.db")),
            report_directory=local_path(raw.get("report_directory", "reports")),
            intelligence_poll_minutes=int(raw.get("intelligence_poll_minutes", 15)),
            gmail_poll_minutes=int(raw.get("gmail_poll_minutes", 5)),
            digest_hour_local=int(raw.get("digest_hour_local", 9)),
            thresholds=Thresholds(
                immediate=float(threshold_data.get("immediate", 70)),
                digest=float(threshold_data.get("digest", 35)),
            ),
            openai_model=str(raw.get("openai_model", "gpt-4o-mini")),
            enable_llm=bool(raw.get("enable_llm", True)),
            google_chat_webhook=os.getenv("GOOGLE_CHAT_WEBHOOK_URL"),
            rss_feeds=list(raw.get("rss_feeds", [])),
            request_timeout_seconds=float(raw.get("request_timeout_seconds", 30)),
            gmail=GmailConfig(
                enabled=bool(gmail_data.get("enabled", False)),
                mailbox=str(gmail_data.get("mailbox", "me")),
                pubsub_topic=str(gmail_data.get("pubsub_topic", "")),
                pubsub_subscription=str(gmail_data.get("pubsub_subscription", "")),
                credentials_file=optional_path(gmail_data.get("credentials_file")),
                oauth_client_file=optional_path(gmail_data.get("oauth_client_file")),
                service_account_file=optional_path(gmail_data.get("service_account_file")),
                incoming_label=str(gmail_data.get("incoming_label", "Security/Incoming")),
                processing_label=str(gmail_data.get("processing_label", "Security/Processing")),
                matched_label=str(gmail_data.get("matched_label", "Security/Matched")),
                no_match_label=str(gmail_data.get("no_match_label", "Security/NoMatch")),
                review_label=str(gmail_data.get("review_label", "Security/NeedsReview")),
                error_label=str(gmail_data.get("error_label", "Security/Error")),
                approved_senders=[str(item).lower() for item in gmail_data.get("approved_senders", [])],
                approved_domains=[str(item).lower().lstrip("@")
                                  for item in gmail_data.get("approved_domains", [])],
                require_authentication_pass=bool(gmail_data.get("require_authentication_pass", True)),
                max_content_bytes=int(gmail_data.get("max_content_bytes", 100_000)),
            ),
        )

