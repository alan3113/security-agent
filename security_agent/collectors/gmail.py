from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from security_agent.config import GmailConfig


SCOPES = (
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
)
SAFE_CONTENT_TYPES = {"text/plain", "text/csv", "application/json"}


class GmailConfigurationError(RuntimeError):
    pass


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


@dataclass(frozen=True, slots=True)
class SecurityEmail:
    message_id: str
    thread_id: str
    sender: str
    subject: str
    authentication_results: str
    content: str


class GmailClient:
    """Small Gmail API adapter; message bodies are data and are never executed."""

    def __init__(self, config: GmailConfig, service: Any | None = None):
        self.config = config
        self.service = service or self._build_service(config)
        self._labels: dict[str, str] | None = None

    @staticmethod
    def _build_service(config: GmailConfig) -> Any:
        from google.auth import default
        from google.oauth2.credentials import Credentials
        from google.oauth2.service_account import Credentials as ServiceAccountCredentials
        from googleapiclient.discovery import build

        if config.service_account_file:
            credentials = ServiceAccountCredentials.from_service_account_file(
                str(config.service_account_file), scopes=SCOPES
            )
            if config.mailbox == "me":
                raise GmailConfigurationError(
                    "gmail.mailbox must be an email address when using a delegated service account"
                )
            credentials = credentials.with_subject(config.mailbox)
        elif config.credentials_file:
            credentials = Credentials.from_authorized_user_file(str(config.credentials_file), SCOPES)
        else:
            credentials, _ = default(scopes=SCOPES)
        return build("gmail", "v1", credentials=credentials, cache_discovery=False)

    @property
    def user_id(self) -> str:
        return self.config.mailbox

    def labels(self, *, refresh: bool = False) -> dict[str, str]:
        if self._labels is None or refresh:
            response = self.service.users().labels().list(userId=self.user_id).execute()
            self._labels = {item["name"]: item["id"] for item in response.get("labels", [])}
        return dict(self._labels)

    def ensure_labels(self) -> dict[str, str]:
        names = self.status_label_names
        labels = self.labels()
        for name in names:
            if name in labels:
                continue
            created = self.service.users().labels().create(
                userId=self.user_id,
                body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"},
            ).execute()
            labels[name] = created["id"]
        self._labels = labels
        return labels

    @property
    def status_label_names(self) -> tuple[str, ...]:
        return (
            self.config.incoming_label, self.config.processing_label, self.config.matched_label,
            self.config.no_match_label, self.config.review_label, self.config.error_label,
        )

    def ensure_sender_filters(self) -> int:
        """Create deterministic Gmail filters for approved senders/domains."""
        labels = self.ensure_labels()
        incoming_id = labels[self.config.incoming_label]
        existing = self.service.users().settings().filters().list(userId=self.user_id).execute().get("filter", [])
        existing_from = {
            item.get("criteria", {}).get("from")
            for item in existing
            if incoming_id in item.get("action", {}).get("addLabelIds", [])
        }
        sources = [*self.config.approved_senders, *(f"@{item}" for item in self.config.approved_domains)]
        created = 0
        for source in sources:
            if source in existing_from:
                continue
            self.service.users().settings().filters().create(
                userId=self.user_id,
                body={"criteria": {"from": source}, "action": {"addLabelIds": [incoming_id]}},
            ).execute()
            created += 1
        return created

    def start_watch(self) -> dict[str, str]:
        if not self.config.pubsub_topic:
            raise GmailConfigurationError("gmail.pubsub_topic is required for Gmail push notifications")
        labels = self.ensure_labels()
        return self.service.users().watch(
            userId=self.user_id,
            body={
                "topicName": self.config.pubsub_topic,
                "labelIds": [labels[self.config.incoming_label]],
                "labelFilterBehavior": "INCLUDE",
            },
        ).execute()

    def list_pending_message_ids(self) -> list[str]:
        excluded = " ".join(f'-label:"{name}"' for name in self.status_label_names[1:])
        query = f'label:"{self.config.incoming_label}" {excluded}'
        result: list[str] = []
        page_token = None
        while True:
            response = self.service.users().messages().list(
                userId=self.user_id, q=query, pageToken=page_token, maxResults=100
            ).execute()
            result.extend(item["id"] for item in response.get("messages", []))
            page_token = response.get("nextPageToken")
            if not page_token:
                return result

    def message_ids_since(self, history_id: str) -> tuple[list[str], str]:
        incoming_id = self.ensure_labels()[self.config.incoming_label]
        ids: set[str] = set()
        page_token = None
        latest = history_id
        while True:
            response = self.service.users().history().list(
                userId=self.user_id, startHistoryId=history_id, labelId=incoming_id,
                historyTypes=["messageAdded", "labelAdded"], pageToken=page_token,
            ).execute()
            latest = response.get("historyId", latest)
            for history in response.get("history", []):
                for item in history.get("messagesAdded", []):
                    message = item.get("message", {})
                    if incoming_id in message.get("labelIds", []):
                        ids.add(message["id"])
                for item in history.get("labelsAdded", []):
                    if incoming_id in item.get("labelIds", []):
                        ids.add(item["message"]["id"])
            page_token = response.get("nextPageToken")
            if not page_token:
                return sorted(ids), latest

    def get_security_email(self, message_id: str) -> SecurityEmail:
        message = self.service.users().messages().get(
            userId=self.user_id, id=message_id, format="full"
        ).execute()
        payload = message.get("payload", {})
        headers: dict[str, list[str]] = {}
        for item in payload.get("headers", []):
            headers.setdefault(item.get("name", "").lower(), []).append(item.get("value", ""))
        content = self._extract_content(message_id, payload)
        return SecurityEmail(
            message_id=message_id,
            thread_id=message.get("threadId", ""),
            sender=parseaddr(" ".join(headers.get("from", [])))[1].lower(),
            subject=" ".join(headers.get("subject", []))[:500],
            # Gmail prepends its own result; ignore sender-supplied results later in the header list.
            authentication_results=(headers.get("authentication-results", [""])[0]).lower(),
            content=content or message.get("snippet", ""),
        )

    def _extract_content(self, message_id: str, payload: dict[str, Any]) -> str:
        plain: list[str] = []
        html: list[str] = []
        total = 0

        def walk(part: dict[str, Any]) -> None:
            nonlocal total
            if total >= self.config.max_content_bytes:
                return
            mime_type = part.get("mimeType", "")
            body = part.get("body", {})
            raw = body.get("data")
            if not raw and body.get("attachmentId") and mime_type in SAFE_CONTENT_TYPES:
                attachment = self.service.users().messages().attachments().get(
                    userId=self.user_id, messageId=message_id, id=body["attachmentId"]
                ).execute()
                raw = attachment.get("data")
            if raw and (mime_type in SAFE_CONTENT_TYPES or mime_type == "text/html"):
                decoded = _decode(raw)[: self.config.max_content_bytes - total]
                total += len(decoded.encode(errors="ignore"))
                filename = part.get("filename", "")
                prefix = f"\n[SAFE TEXT ATTACHMENT: {filename}]\n" if filename else ""
                if mime_type == "text/html":
                    parser = _TextExtractor()
                    parser.feed(decoded)
                    html.append(prefix + " ".join(parser.parts))
                else:
                    plain.append(prefix + decoded)
            for child in part.get("parts", []):
                walk(child)

        walk(payload)
        return "\n".join(plain or html)[: self.config.max_content_bytes]

    def apply_status(self, message_id: str, status_label: str) -> None:
        labels = self.ensure_labels()
        terminal_ids = [labels[name] for name in self.status_label_names if name != status_label]
        self.service.users().messages().modify(
            userId=self.user_id, id=message_id,
            body={"addLabelIds": [labels[status_label]], "removeLabelIds": terminal_ids},
        ).execute()


def validate_security_email(message: SecurityEmail, config: GmailConfig) -> tuple[bool, str]:
    sender = message.sender.lower()
    domain = sender.rsplit("@", 1)[-1] if "@" in sender else ""
    if sender not in config.approved_senders and domain not in config.approved_domains:
        return False, f"sender {sender or '<missing>'} is not approved"
    if config.require_authentication_pass:
        authentication = message.authentication_results
        trusted_evaluator = "mx.google.com" in authentication
        identity_passed = "dkim=pass" in authentication or "spf=pass" in authentication
        if not trusted_evaluator or not identity_passed or "dmarc=fail" in authentication:
            return False, "Google SPF/DKIM authentication did not pass or DMARC failed"
    return True, ""


def parse_pubsub_notification(data: bytes) -> tuple[str, str]:
    payload = json.loads(data.decode("utf-8"))
    return str(payload["emailAddress"]).lower(), str(payload["historyId"])


def authorize_user(oauth_client_file: Path, token_file: Path) -> None:
    """Run Google's installed-app OAuth flow and save a refreshable user token."""
    from google_auth_oauthlib.flow import InstalledAppFlow

    flow = InstalledAppFlow.from_client_secrets_file(str(oauth_client_file), SCOPES)
    credentials = flow.run_local_server(port=0)
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(credentials.to_json())


def _decode(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding).decode("utf-8", errors="replace")
