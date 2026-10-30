from security_agent.config import Thresholds
from security_agent.models import Advisory, Dependency, Finding, Reachability, Triage
from security_agent.prioritize import prioritize


def test_kev_is_always_immediate():
    finding = Finding(
        dependency=Dependency("demo", "1.0", "PyPI"),
        advisory=Advisory("CVE-2026-1", "test", severity="LOW", cvss=2.0),
        kev=True,
        triage=Triage(reachability=Reachability.UNKNOWN),
    )
    prioritize(finding, Thresholds(immediate=99, digest=50))
    assert finding.disposition == "immediate"


def test_unreachable_reduces_score():
    base = Finding(Dependency("demo", "1", "npm", direct=True),
                   Advisory("ADV-1", "test", severity="HIGH", cvss=8.0))
    possible = Finding(base.dependency, base.advisory, triage=Triage(reachability=Reachability.POSSIBLE))
    unreachable = Finding(base.dependency, base.advisory, triage=Triage(reachability=Reachability.UNREACHABLE))
    prioritize(possible, Thresholds())
    prioritize(unreachable, Thresholds())
    assert possible.priority - unreachable.priority == 15

