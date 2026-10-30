from __future__ import annotations

import re
from pathlib import Path

from security_agent.models import Dependency


TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java", ".kt",
    ".rb", ".php", ".cs", ".scala", ".vue", ".svelte",
}
IGNORED_PARTS = {".git", ".venv", "venv", "node_modules", "vendor", "target", "dist", "build"}


def find_evidence(repository: Path, dependency: Dependency, *, max_snippets: int = 8) -> list[str]:
    """Find small import/use snippets without sending entire source files downstream."""
    names = {dependency.name, dependency.name.split(":")[-1], dependency.name.split("/")[-1]}
    expressions = [re.compile(re.escape(name), re.IGNORECASE) for name in names if len(name) >= 2]
    evidence: list[str] = []
    for path in repository.rglob("*"):
        if len(evidence) >= max_snippets:
            break
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in IGNORED_PARTS for part in path.parts):
            continue
        try:
            for number, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
                if any(pattern.search(line) for pattern in expressions):
                    relative = path.relative_to(repository)
                    evidence.append(f"{relative}:{number}: {line.strip()[:300]}")
                    if len(evidence) >= max_snippets:
                        break
        except OSError:
            continue
    return evidence

