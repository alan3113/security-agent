# Security Monitoring Agent

A runnable implementation of [plan.md](plan.md): it reacts to new vulnerability feeds or authenticated cybersecurity-team email, inventories pinned dependencies, asks OSV to perform ecosystem-correct version matching, enriches matches with CISA KEV, FIRST EPSS, and optionally NVD, uses an optional LLM for read-only reachability triage, deduplicates in SQLite, and sends new urgent findings to Google Chat.

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env                  # export values; .env is not auto-loaded
security-agent inventory
security-agent scan --dry-run --no-llm
```

Edit `config.yaml` to point at one or more repositories. Set `OPENAI_API_KEY` to enable LLM triage, `NVD_API_KEY` for NVD CVSS enrichment, and `GOOGLE_CHAT_WEBHOOK_URL` to deliver new immediate alerts. Secrets are never required in the YAML. The LLM is an optional enhancement: inventory, matching, scoring, state, and reporting remain deterministic without it.

The scan command exits `1` when it finds an immediate issue, making it suitable for CI. Every scan also writes a timestamped JSON report under `reports/`.

## Commands

```bash
security-agent inventory [--syft]
security-agent scan [--dry-run] [--no-llm] [--syft]
security-agent digest
security-agent schedule [--no-llm]
security-agent gmail-auth
security-agent gmail-setup
security-agent gmail-poll [--no-llm]
security-agent gmail-listen [--no-llm]
```

Built-in inventory supports `package-lock.json`, `requirements.txt`, `poetry.lock`, `go.sum`, `Cargo.lock`, and pinned Maven dependencies in `pom.xml`. `--syft` uses a locally installed Syft binary and its CycloneDX JSON output, which adds container and OS package coverage.

## Security boundaries

- OSV performs version-range matching; model output never decides whether a version is vulnerable.
- The model gets no tools and receives only bounded matching lines from source files.
- Advisory text is explicitly delimited as untrusted. Returned evidence must exactly match supplied snippets.
- A suggested upgrade is retained only when it exactly matches an OSV `fixed` event.
- API keys and the Chat webhook are read from environment variables and ignored by Git.
- LLM results are cached by advisory, package, and advisory modification time.

## Scheduling and CI

`security-agent schedule` does not run unconditional dependency scans. It checks configured RSS feeds for unseen items and checks Gmail for newly labeled messages; only a new trigger starts a scan. It also sends pending digest findings daily at `digest_hour_local`. The included GitHub Actions workflow still scans lockfile changes before merge.

Google Chat notifications are sent immediately for newly seen urgent findings. New medium-priority findings are bundled by `security-agent digest` or the daily scheduler. RSS items can be configured and are stored as untrusted metadata; they are not permitted to create a vulnerability match without a deterministic advisory source.

## Gmail cybersecurity-team intake

The Gmail path uses deterministic sender filters and labels. Email text is an untrusted hint: extracted package names and CVEs can narrow an OSV query, but they cannot create a finding without an OSV match.

1. Create a Google Cloud Pub/Sub topic and pull subscription. Grant Gmail's push service account publisher access to the topic.
2. Enable the Gmail API. For user OAuth, download a Desktop OAuth client JSON, configure `oauth_client_file` and `credentials_file`, then run `security-agent gmail-auth`. For Workspace automation, configure a service account with domain-wide delegation instead.
3. Complete the `gmail` block in `config.yaml`. Always populate `approved_senders` or `approved_domains`; authenticated mail is rejected otherwise.
4. Run `security-agent gmail-setup`. This creates the processing labels and sender filters, starts the Gmail watch, and stores its history cursor.
5. Run `security-agent gmail-listen` as a supervised service for Pub/Sub push processing. As a simpler fallback, `security-agent gmail-poll` or `security-agent schedule` checks the incoming label periodically.

Message states are visible as Gmail labels:

```text
Security/Incoming → Security/Processing → Security/Matched
                                      ├→ Security/NoMatch
                                      ├→ Security/NeedsReview
                                      └→ Security/Error
```

The watch is renewed daily by `security-agent schedule`. Pub/Sub listener credentials use Application Default Credentials; this may be separate from the delegated Gmail credential. Safe text attachments (`text/plain`, `text/csv`, and JSON) are bounded by `max_content_bytes`; executable and other attachment types are never downloaded.

## Tests

```bash
pytest
```

The tests do not call external services or the OpenAI API.

