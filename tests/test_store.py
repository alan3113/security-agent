from pathlib import Path

from security_agent.models import Advisory, Dependency, Finding, Reachability, Triage
from security_agent.store import StateStore


def test_deduplication_and_triage_cache(tmp_path: Path):
    store = StateStore(tmp_path / "state.db")
    finding = Finding(Dependency("demo", "1.0", "PyPI"), Advisory("ADV-1", "Example"))
    assert store.upsert(finding) is True
    assert store.upsert(finding) is False
    triage = Triage(Reachability.POSSIBLE, "impact", "fix", "2.0", ["a.py:1: import demo"], True)
    store.cache_triage("cache", triage)
    assert store.get_triage("cache") == triage


def test_pending_digest_excludes_immediate_findings(tmp_path: Path):
    store = StateStore(tmp_path / "state.db")
    digest = Finding(Dependency("digest", "1.0", "PyPI"), Advisory("ADV-1", "Digest"),
                     priority=50, disposition="digest")
    immediate = Finding(Dependency("urgent", "1.0", "PyPI"), Advisory("ADV-2", "Urgent"),
                        priority=90, disposition="immediate")
    store.upsert(digest)
    store.upsert(immediate)
    assert [key for key, _ in store.pending_digest()] == [digest.key]
    store.mark_notified(digest.key)
    assert store.pending_digest() == []


def test_email_deduplication_and_metadata(tmp_path: Path):
    store = StateStore(tmp_path / "state.db")
    store.set_metadata("gmail.history_id", "100")
    assert store.get_metadata("gmail.history_id") == "100"
    assert store.claim_email("message-1", "thread-1") is True
    assert store.claim_email("message-1", "thread-1") is False
    store.finish_email("message-1", "error", error="temporary")
    assert store.claim_email("message-1", "thread-1") is True

