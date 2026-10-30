from __future__ import annotations

import argparse
import asyncio
import logging

import httpx

from apscheduler.schedulers.blocking import BlockingScheduler

from security_agent.config import AgentConfig
from security_agent.collectors.gmail import authorize_user
from security_agent.inventory import InventoryScanner
from security_agent.gmail_processor import GmailSecurityProcessor
from security_agent.pipeline import SecurityPipeline
from security_agent.notify import GoogleChatNotifier
from security_agent.store import StateStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-agent", description="Monitor dependencies for vulnerabilities")
    parser.add_argument("--config", default="config.yaml", help="YAML configuration path")
    parser.add_argument("--verbose", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run one vulnerability scan")
    scan.add_argument("--syft", action="store_true", help="Use Syft instead of built-in lockfile parsers")
    scan.add_argument("--dry-run", action="store_true", help="Write state/report but do not send notifications")
    scan.add_argument("--no-llm", action="store_true", help="Disable optional LLM triage")
    inventory = subparsers.add_parser("inventory", help="Print the normalized dependency inventory")
    inventory.add_argument("--syft", action="store_true")
    schedule = subparsers.add_parser("schedule", help="Run continuously on the configured interval")
    schedule.add_argument("--no-llm", action="store_true")
    subparsers.add_parser("digest", help="Send pending digest findings to Google Chat")
    subparsers.add_parser("gmail-setup", help="Create Gmail labels/filters and start Pub/Sub watch")
    subparsers.add_parser("gmail-auth", help="Create an authorized-user Gmail token")
    gmail_poll = subparsers.add_parser("gmail-poll", help="Process currently labeled security emails")
    gmail_poll.add_argument("--no-llm", action="store_true")
    gmail_listen = subparsers.add_parser("gmail-listen", help="Listen for Gmail Pub/Sub notifications")
    gmail_listen.add_argument("--no-llm", action="store_true")
    return parser


def run_once(config: AgentConfig, *, use_syft: bool = False, dry_run: bool = False) -> int:
    findings = asyncio.run(SecurityPipeline(config).run(use_syft=use_syft, dry_run=dry_run))
    for finding in findings:
        print(f"{finding.priority:5.1f} {finding.disposition:9} {finding.advisory.id:20} "
              f"{finding.dependency.name}@{finding.dependency.version}")
    print(f"Scan complete: {len(findings)} finding(s)")
    return 1 if any(item.disposition == "immediate" for item in findings) else 0


async def send_digest(config: AgentConfig) -> int:
    if not config.google_chat_webhook:
        logging.getLogger(__name__).warning("GOOGLE_CHAT_WEBHOOK_URL is not set; digest was not sent")
        return 0
    store = StateStore(config.database)
    pending = store.pending_digest()
    if not pending:
        logging.getLogger(__name__).info("No pending digest findings")
        return 0
    async with httpx.AsyncClient(timeout=config.request_timeout_seconds) as client:
        await GoogleChatNotifier(client, config.google_chat_webhook).send_digest(
            [payload for _, payload in pending]
        )
    for key, _ in pending:
        store.mark_notified(key)
    return len(pending)


def poll_internet_intelligence(config: AgentConfig) -> int:
    findings = asyncio.run(SecurityPipeline(config).run_if_new_intelligence())
    return len(findings)


def poll_gmail(config: AgentConfig) -> dict[str, int]:
    return asyncio.run(GmailSecurityProcessor(config).process_pending())


def listen_gmail(config: AgentConfig) -> None:
    from google.cloud import pubsub_v1

    if not config.gmail.pubsub_subscription:
        raise RuntimeError("gmail.pubsub_subscription is required for gmail-listen")
    subscriber = pubsub_v1.SubscriberClient()

    def callback(message) -> None:
        try:
            asyncio.run(GmailSecurityProcessor(config).process_notification(message.data))
            message.ack()
        except Exception:
            logging.getLogger(__name__).exception("Gmail Pub/Sub notification failed")
            message.nack()

    future = subscriber.subscribe(
        config.gmail.pubsub_subscription,
        callback=callback,
        flow_control=pubsub_v1.types.FlowControl(max_messages=1),
    )
    logging.getLogger(__name__).info("Listening on %s", config.gmail.pubsub_subscription)
    try:
        future.result()
    except KeyboardInterrupt:
        future.cancel()
        future.result(timeout=30)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = AgentConfig.load(args.config)
    if getattr(args, "no_llm", False):
        config.enable_llm = False
    if args.command == "inventory":
        scanner = InventoryScanner()
        for repository in config.repositories:
            for dependency in scanner.scan(repository, use_syft=args.syft):
                flags = ",".join(filter(None, ["direct" if dependency.direct else "transitive",
                                               "dev" if dependency.development else "production"]))
                print(f"{dependency.purl}\t{flags}\t{dependency.source}")
        return 0
    if args.command == "scan":
        return run_once(config, use_syft=args.syft, dry_run=args.dry_run)
    if args.command == "digest":
        count = asyncio.run(send_digest(config))
        print(f"Digest complete: {count} finding(s) sent")
        return 0
    if args.command == "gmail-setup":
        result = GmailSecurityProcessor(config).setup()
        print(f"Gmail watch active until {result.get('expiration', 'unknown')}; "
              f"{result['filters_created']} filter(s) created")
        return 0
    if args.command == "gmail-auth":
        if not config.gmail.oauth_client_file or not config.gmail.credentials_file:
            raise RuntimeError("gmail.oauth_client_file and gmail.credentials_file are required")
        authorize_user(config.gmail.oauth_client_file, config.gmail.credentials_file)
        print(f"Gmail token written to {config.gmail.credentials_file}")
        return 0
    if args.command == "gmail-poll":
        results = poll_gmail(config)
        print(f"Gmail processing complete: {results}")
        return 1 if results.get("error") else 0
    if args.command == "gmail-listen":
        listen_gmail(config)
        return 0
    scheduler = BlockingScheduler()
    if config.rss_feeds:
        scheduler.add_job(lambda: poll_internet_intelligence(config), "interval",
                          minutes=config.intelligence_poll_minutes, max_instances=1, coalesce=True)
    if config.gmail.enabled:
        scheduler.add_job(lambda: poll_gmail(config), "interval", minutes=config.gmail_poll_minutes,
                          max_instances=1, coalesce=True)
        scheduler.add_job(lambda: GmailSecurityProcessor(config).gmail.start_watch(), "cron",
                          hour=1, minute=0, max_instances=1, coalesce=True)
    scheduler.add_job(lambda: asyncio.run(send_digest(config)), "cron", hour=config.digest_hour_local,
                      minute=0, max_instances=1, coalesce=True)
    if config.rss_feeds:
        poll_internet_intelligence(config)
    if config.gmail.enabled:
        poll_gmail(config)
    scheduler.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

