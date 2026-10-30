from pathlib import Path

from security_agent.models import Dependency
from security_agent.triage.reachability import find_evidence


def test_evidence_is_bounded_and_ignores_dependency_directories(tmp_path: Path):
    (tmp_path / "app.py").write_text("import requests\nrequests.get('https://example.test')\n")
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / "bad.js").write_text("requests requests requests")
    evidence = find_evidence(tmp_path, Dependency("requests", "1", "PyPI"), max_snippets=1)
    assert evidence == ["app.py:1: import requests"]
