# Security Vulnerability Monitoring Agent: Implementation Plan

The core design rule is this: **use deterministic tools for anything that has to be correct, and use the LLM for reading, judging, and explaining.** Checking whether `lodash 4.17.15` falls inside a vulnerable version range is exact logic, and an LLM will sometimes get it wrong. Summarizing an advisory, judging whether your code actually calls the vulnerable function, and writing a clear fix note are tasks where GPT works well.

## 1. Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│ Project Scanner │     │ Intel Collectors │     │  Unstructured    │
│ (SBOM/lockfiles)│     │ OSV, NVD, GHSA,  │     │  sources (RSS,   │
│                 │     │ CISA KEV, EPSS   │     │  blogs, news)    │
└────────┬────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                       │                        │ LLM extracts
         ▼                       ▼                        ▼ package/version
   ┌──────────────────────────────────────────────────────────┐
   │        Matcher (deterministic version-range matching)     │
   └───────────────────────────┬──────────────────────────────┘
                               ▼
   ┌──────────────────────────────────────────────────────────┐
   │  LLM Triage: relevance, reachability, severity, fix plan  │
   └───────────────────────────┬──────────────────────────────┘
                               ▼
   ┌──────────────┐    ┌──────────────────┐    ┌───────────────┐
   │ State DB     │◄──►│ Prioritizer/     │───►│ Google Chat   │
   │ (seen/sent)  │    │ Deduplicator     │    │ webhook/email │
   └──────────────┘    └──────────────────┘    └───────────────┘
```

## 2. Components

### 2.1 Project Inventory

Build a full list of what you actually ship. Parse lockfiles rather than manifests, because lockfiles include transitive dependencies with exact versions. Examples are `package-lock.json`, `poetry.lock`, `requirements.txt`, `go.sum`, `pom.xml`, and `Cargo.lock`.

The easiest route is to generate an SBOM with **Syft** (CycloneDX format), which also covers Docker images and OS packages. Tag each dependency as direct or transitive and as production or dev-only, since that affects priority later. Store everything as package URLs (purl), for example `pkg:npm/lodash@4.17.15`. Purl is the identifier the vulnerability databases use.

### 2.2 Structured Intelligence Sources

These are your primary sources, all free:

- **OSV.dev API** is the most useful. It aggregates GitHub advisories, PyPI, npm, Go, RustSec, and more, and offers a `querybatch` endpoint that checks your whole SBOM in one call.
- **NVD API 2.0** provides CVE details and CVSS scores. Request a free API key to get higher rate limits.
- **GitHub Advisory Database** (GraphQL API) is often the fastest source for ecosystem-specific advisories.
- **CISA KEV catalog** is a JSON feed of vulnerabilities known to be exploited in the wild. A match here is top priority.
- **FIRST EPSS** gives the probability that a CVE will be exploited soon, which helps rank alerts.

### 2.3 Unstructured Sources

This is where the LLM adds the most value. Poll RSS feeds and security news (vendor security bulletins, project release notes, security blogs, and optionally Reddit or Hacker News security threads). These often report problems before a CVE exists, such as a compromised npm package or a malicious release.

GPT extracts structured data from each item using a JSON schema: affected packages, ecosystems, version ranges, and whether a fix exists. Those results then go through the same deterministic matcher as everything else.

Cybersecurity-team email is an additional event-driven source. A deterministic Gmail sender filter applies a `Security/Incoming` label, and Gmail API push notifications through Pub/Sub trigger processing. The agent verifies the envelope sender and SPF/DKIM/DMARC results, extracts CVEs and packages from bounded text content, and uses those values only to narrow an OSV query. Email claims never create a finding without deterministic OSV confirmation. SQLite deduplicates Gmail message IDs, while Gmail labels expose `Processing`, `Matched`, `NoMatch`, `NeedsReview`, and `Error` states.

### 2.4 Matcher

Use **osv-scanner** or the OSV API to compare your SBOM against advisories using exact version-range semantics for each ecosystem. Do not hand this step to the LLM.

### 2.5 LLM Triage (GPT)

For each match, give the model the advisory text, the affected package, and relevant code context. You can find that context by grepping your repo for imports or calls of the vulnerable module or function. Ask for structured output covering:

- whether your code is plausibly affected (reachability: is the vulnerable function used?)
- a plain-language impact summary
- the fix: an upgrade target, a config change, or a workaround

Always validate the fix against the "fixed in" versions from the advisory data. Never accept an upgrade version the model invented.

### 2.6 Prioritization

Combine CVSS score, EPSS score, KEV status, direct vs. transitive, production vs. dev, and the reachability verdict into one score. Use it to decide whether to send an immediate alert, include the issue in a daily digest, or only log it.

### 2.7 State Store

SQLite is enough to start, and Postgres works later. Track which advisories you've already seen, which alerts you've sent, and which issues the team has suppressed or accepted. Without this, the agent will spam the channel with the same issue every run.

### 2.8 Notification

"Team chat in Gmail" is Google Chat. The simplest approach is a **Google Chat incoming webhook**: create it in the Space settings, then POST a JSON message or a Cards v2 payload. No OAuth is needed.

Note that webhooks require a Google Workspace account. If you're on personal Gmail, use the Gmail API to send email instead.

Sample alert:

```
🔴 CRITICAL | CVE-2026-XXXXX in jsonwebtoken@8.5.1 (direct, production)
Exploited in the wild (CISA KEV) · EPSS 0.87
Impact: Signature bypass allows forged tokens.
Affected in our code: auth/middleware.js uses jwt.verify() ✔
Fix: npm install jsonwebtoken@9.0.2 (no breaking changes for our usage)
Ref: https://osv.dev/vulnerability/...
```

## 3. Tech Stack

| Purpose         | Choice                               |
| --------------- | ------------------------------------ |
| Language        | Python 3.11+                         |
| LLM             | `openai` SDK with structured outputs |
| HTTP            | `httpx`                              |
| RSS             | `feedparser`                         |
| SBOM / matching | Syft, osv-scanner (CLI tools)        |
| Database        | SQLite via SQLAlchemy                |
| Scheduling      | APScheduler or cron                  |

A heavy agent framework isn't required, because a clear pipeline is easier to debug. If you later want the LLM to decide on its own which sources to dig into, LangGraph is a reasonable upgrade.

### Suggested Layout

```
sec-agent/
├── collectors/      # osv.py, nvd.py, ghsa.py, kev.py, epss.py, rss.py
├── inventory/       # sbom.py (runs syft, parses lockfiles)
├── matcher/         # osv_match.py
├── triage/          # llm.py, prompts/, reachability.py
├── notify/          # gchat.py, email.py
├── store/           # models.py, db.py
├── config.yaml      # repos, feeds, thresholds, webhook URL
└── main.py          # scheduler + pipeline
```

## 4. Execution Model

Run three triggers:

- **Scheduled scan:** poll intelligence sources every 1 to 6 hours and re-match against the latest SBOM.
- **Change-driven scan:** in CI (GitHub Actions or GitLab CI), regenerate the SBOM whenever a lockfile changes and scan immediately, so new dependencies are checked before merge.
- **Intelligence-driven scan:** poll lightweight advisory feeds and listen for labeled cybersecurity-team mail. Run dependency matching only when an unseen feed item or authenticated mail arrives; do not perform unconditional scheduled dependency scans.

Send critical and KEV-listed issues instantly, and send everything else in a daily digest.

## 5. Securing the Agent Itself

- **Prompt injection:** Scraped news and advisory text is untrusted input, and someone could plant instructions in it. Give the LLM no tools that execute commands or change code. Treat its output as data that you validate, and keep fetched content clearly separated from your instructions in the prompt.
- **Secrets:** Keep the OpenAI key, webhook URL, and NVD key in environment variables or a secrets manager, never in the repo.
- **Code sharing with OpenAI:** Send only the minimal code snippets needed for reachability checks, not whole files. Check that this fits your company's policy on sending code to OpenAI.
- **Cost control:** Cache LLM results per advisory and package pair, and only call GPT on actual matches, not on every advisory.
