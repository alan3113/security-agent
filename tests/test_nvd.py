from security_agent.collectors.nvd import NvdCollector


def test_nvd_prefers_primary_modern_cvss():
    score, severity = NvdCollector._metrics({
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
        ]
    })
    assert score == 9.8
    assert severity == "CRITICAL"
