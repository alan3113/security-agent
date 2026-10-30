from __future__ import annotations

import logging
from typing import Any

from security_agent.collectors.gmail import (
    GmailClient,
    GmailConfigurationError,
    parse_pubsub_notification,
    validate_security_email,
)
from security_agent.config import AgentConfig
from security_agent.inventory import InventoryScanner
from security_agent.pipeline import SecurityPipeline
from security_agent.store import StateStore
from security_agent.triage import EmailIntelligenceExtractor


LOGGER = logging.getLogger(__name__)
HISTORY_CURSOR_KEY = "gmail.history_id"


class GmailSecurityProcessor:
    def __init__(self, config: AgentConfig, gmail: GmailClient | None = None):
        if not config.gmail.enabled:
            raise RuntimeError("Gmail integration is disabled in config.yaml")
        self.config = config
        self.gmail = gmail or GmailClient(config.gmail)
        self.store = StateStore(config.database)

    def setup(self) -> dict[str, Any]:
        if not self.config.gmail.approved_senders and not self.config.gmail.approved_domains:
            raise GmailConfigurationError(
                "Configure at least one gmail.approved_senders or gmail.approved_domains entry"
            )
        self.gmail.ensure_labels()
        filters_created = self.gmail.ensure_sender_filters()
        watch = self.gmail.start_watch()
        self.store.set_metadata(HISTORY_CURSOR_KEY, str(watch["historyId"]))
        return {**watch, "filters_created": filters_created}

    async def process_pending(self) -> dict[str, int]:
        results: dict[str, int] = {}
        for message_id in self.gmail.list_pending_message_ids():
            status = await self.process_message(message_id)
            results[status] = results.get(status, 0) + 1
        return results

    async def process_notification(self, data: bytes) -> dict[str, int]:
        email_address, notification_history = parse_pubsub_notification(data)
        configured = self.config.gmail.mailbox.lower()
        if configured != "me" and email_address != configured:
            raise ValueError(f"Pub/Sub notification was for unexpected mailbox {email_address}")
        cursor = self.store.get_metadata(HISTORY_CURSOR_KEY)
        if cursor is None:
            self.store.set_metadata(HISTORY_CURSOR_KEY, notification_history)
            LOGGER.info("Initialized Gmail history cursor; no messages processed")
            return {}
        message_ids, latest = self.gmail.message_ids_since(cursor)
        results: dict[str, int] = {}
        for message_id in message_ids:
            status = await self.process_message(message_id)
            results[status] = results.get(status, 0) + 1
        self.store.set_metadata(HISTORY_CURSOR_KEY, latest)
        return results

    async def process_message(self, message_id: str) -> str:
        if not self.store.claim_email(message_id):
            return "duplicate"
        sender = ""
        subject = ""
        extraction: dict | None = None
        try:
            self.gmail.apply_status(message_id, self.config.gmail.processing_label)
            message = self.gmail.get_security_email(message_id)
            sender, subject = message.sender, message.subject
            valid, reason = validate_security_email(message, self.config.gmail)
            if not valid:
                LOGGER.warning("Rejected Gmail security trigger %s: %s", message_id, reason)
                return self._finish(message_id, "review", self.config.gmail.review_label,
                                    sender, subject, {"rejection_reason": reason})

            inventory = []
            for repository in self.config.repositories:
                inventory.extend(InventoryScanner().scan(repository))
            extractor = EmailIntelligenceExtractor(
                self.config.openai_model, enabled=self.config.enable_llm
            )
            intel = extractor.extract(subject, message.content, inventory)
            extraction = intel.model_dump()
            if not intel.is_security_advisory:
                return self._finish(message_id, "review", self.config.gmail.review_label,
                                    sender, subject, extraction)

            inventory_names = {dependency.name.casefold(): dependency.name for dependency in inventory}
            mentioned = {package.name.casefold() for package in intel.packages}
            matched_names = {inventory_names[name] for name in mentioned if name in inventory_names}
            if mentioned and not matched_names and not intel.cve_ids:
                return self._finish(message_id, "no_match", self.config.gmail.no_match_label,
                                    sender, subject, extraction)

            package_filter = matched_names if matched_names else None
            findings = await SecurityPipeline(self.config).run(
                package_names=package_filter,
                advisory_ids=set(intel.cve_ids) or None,
                trigger={
                    "type": "gmail",
                    "message_id": message_id,
                    "sender": sender,
                    "cve_ids": intel.cve_ids,
                },
            )
            status = "matched" if findings else "no_match"
            label = self.config.gmail.matched_label if findings else self.config.gmail.no_match_label
            return self._finish(message_id, status, label, sender, subject, extraction)
        except Exception as exc:
            LOGGER.exception("Failed to process Gmail message %s", message_id)
            self.store.finish_email(message_id, "error", sender=sender, subject=subject,
                                    extraction=extraction, error=str(exc)[:2000])
            try:
                self.gmail.apply_status(message_id, self.config.gmail.error_label)
            except Exception:
                LOGGER.exception("Could not apply Gmail error label to %s", message_id)
            return "error"

    def _finish(self, message_id: str, status: str, label: str, sender: str, subject: str,
                extraction: dict) -> str:
        self.store.finish_email(message_id, status, sender=sender, subject=subject,
                                extraction=extraction)
        self.gmail.apply_status(message_id, label)
        return status
