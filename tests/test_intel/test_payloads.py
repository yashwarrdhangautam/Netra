"""Payload parser: passages keep their topic, section and source, and skip non-topic folders."""

from pathlib import Path

from netra.intel.payloads import PAYLOADS_LICENCE, PAYLOADS_REF, load_payloads, parse_readme, search
from netra.scanner.tools.template_pin import PINNED_REF, template_args

README = """# SQL Injection

## Intro

Some prose.

## Union based

```sql
' UNION SELECT NULL--
```

## Error based

```
' AND extractvalue(1,concat(0x7e,version()))--
```
"""


def test_parse_readme_keeps_section_and_source():
    passages = parse_readme("SQL Injection", "SQL Injection/README.md", README)
    assert [p.section for p in passages] == ["Union based", "Error based"]
    assert passages[0].text == "' UNION SELECT NULL--"
    assert passages[0].topic == "SQL Injection"
    assert passages[0].source == "SQL Injection/README.md"
    assert passages[0].licence == PAYLOADS_LICENCE
    assert passages[0].commit == PAYLOADS_REF


def test_load_payloads_skips_hidden_and_methodology_folders(tmp_path: Path):
    (tmp_path / "SQL Injection").mkdir()
    (tmp_path / "SQL Injection" / "README.md").write_text(README, encoding="utf-8")
    (tmp_path / "_template").mkdir()
    (tmp_path / "_template" / "README.md").write_text(README, encoding="utf-8")
    (tmp_path / "Methodology and Resources").mkdir()
    (tmp_path / "Methodology and Resources" / "README.md").write_text(README, encoding="utf-8")
    passages = load_payloads(tmp_path)
    assert {p.topic for p in passages} == {"SQL Injection"}
    assert len(passages) == 2


def test_load_payloads_missing_root_is_empty(tmp_path: Path):
    assert load_payloads(tmp_path / "absent") == []


def test_search_filters_by_topic_and_text():
    passages = parse_readme("SQL Injection", "SQL Injection/README.md", README)
    assert len(search(passages, "union")) == 1
    assert search(passages, "union", topic="XSS") == []
    assert len(search(passages, "", limit=1)) == 1


def test_template_args_empty_without_pinned_checkout(tmp_path: Path):
    assert template_args(tmp_path) == []
    assert len(PINNED_REF) == 40
