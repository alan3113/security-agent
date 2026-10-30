from security_agent.collectors.osv import OsvCollector
from security_agent.models import Dependency


def test_osv_advisory_extracts_only_authoritative_fixed_versions():
    advisory = OsvCollector._parse({
        "id": "GHSA-test",
        "aliases": ["CVE-2026-0001"],
        "summary": "Example",
        "database_specific": {"severity": "HIGH", "cvss_score": 8.1},
        "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}]}],
        "references": [{"url": "https://example.test/advisory"}],
    })
    assert advisory.fixed_versions == ["2.0.1"]
    assert advisory.cvss == 8.1
    assert advisory.cves == ["CVE-2026-0001"]


def test_fixed_versions_are_scoped_to_matched_package():
    data = {
        "id": "GHSA-multi",
        "summary": "Multi-package advisory",
        "affected": [
            {"package": {"ecosystem": "npm", "name": "alpha"},
             "ranges": [{"events": [{"fixed": "1.2.0"}]}]},
            {"package": {"ecosystem": "npm", "name": "beta"},
             "ranges": [{"events": [{"fixed": "9.0.0"}]}]},
        ],
    }
    advisory = OsvCollector._parse(data, Dependency("alpha", "1.0.0", "npm"))
    assert advisory.fixed_versions == ["1.2.0"]

