"""The unwired CLI cannot certify a scan or produce clean artifacts."""

from pathlib import Path

import pytest

from netra.cli.main import main


@pytest.mark.parametrize("extra", [[], ["--fail-on", "high"], ["--dry-run"]])
def test_unavailable_scan_exits_nonzero(monkeypatch, capsys, extra):
    monkeypatch.setattr("sys.argv", ["netra", "scan", "--target", "example.org", *extra])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    output = capsys.readouterr().out.lower()
    assert "not available" in output
    assert "scan complete" not in output
    assert "pass:" not in output
    assert "config valid" not in output


def test_unavailable_scan_does_not_write_sarif(monkeypatch, tmp_path):
    artifact = tmp_path / "results.sarif"
    monkeypatch.setattr(
        "sys.argv",
        [
            "netra",
            "scan",
            "--target",
            "example.org",
            "--output-sarif",
            str(artifact),
            "--fail-on",
            "critical",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert not artifact.exists()


@pytest.mark.parametrize("workflow", ["netra-scan.yml", "netra-reusable.yml"])
def test_unavailable_workflows_fail_without_artifacts(workflow):
    content = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / workflow).read_text(
        encoding="utf-8"
    )
    assert "not available" in content
    assert "exit 2" in content
    assert "|| true" not in content
    assert "upload-sarif" not in content
    assert "upload-artifact" not in content
    assert "netra scan" not in content
