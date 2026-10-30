from security_agent.models import Dependency


def test_maven_purl_uses_namespace_and_artifact():
    dependency = Dependency("org.example:library", "1.2.3", "Maven")
    assert dependency.purl == "pkg:maven/org.example/library@1.2.3"
