import json
from pathlib import Path

from security_agent.inventory import InventoryScanner


def test_package_lock_inventory_marks_direct_and_dev(tmp_path: Path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"alpha": "1.0.0"}, "devDependencies": {"tool": "2.0.0"}},
            "node_modules/alpha": {"version": "1.0.0"},
            "node_modules/alpha/node_modules/child": {"version": "3.0.0"},
            "node_modules/tool": {"version": "2.0.0", "dev": True},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    dependencies = InventoryScanner().scan(tmp_path)
    by_name = {item.name: item for item in dependencies}
    assert by_name["alpha"].direct is True
    assert by_name["child"].direct is False
    assert by_name["tool"].development is True
    assert by_name["alpha"].purl == "pkg:npm/alpha@1.0.0"


def test_multiple_lockfile_formats(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nunpinned>=1\n")
    (tmp_path / "go.sum").write_text("golang.org/x/text v0.3.0 h1:x\ngolang.org/x/text v0.3.0/go.mod h1:y\n")
    (tmp_path / "Cargo.lock").write_text('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
    dependencies = InventoryScanner().scan(tmp_path)
    assert {(item.ecosystem, item.name, item.version) for item in dependencies} == {
        ("PyPI", "requests", "2.31.0"),
        ("Go", "golang.org/x/text", "v0.3.0"),
        ("crates.io", "serde", "1.0.0"),
    }

