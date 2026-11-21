"""Deployment exposure rules for the default stack (spec S8)."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "docker-compose.yml"
DEV_OVERRIDE = ROOT / "docker-compose.dev.yml"
DOCKERFILES = [
    ROOT / "docker" / "Dockerfile",
    ROOT / "docker" / "Dockerfile.worker",
    ROOT / "frontend" / "Dockerfile",
]
DATA_SERVICES = ("postgres", "redis", "ollama")
DEFAULT_SECRETS = re.compile(
    r"netra:netra\b|=netra$|PASSWORD=(netra|password|admin)$", re.IGNORECASE
)


def _services() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def _published_hosts(service: dict) -> list[str]:
    """Host IP for each published port. An entry without an IP binds every interface."""
    hosts = []
    for entry in service.get("ports", []) or []:
        # Entries may contain ${VAR:-default}, so only a leading IPv4 address counts as a host.
        text = str(entry)
        first = text.split(":")[0]
        is_ip = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", first) is not None
        hosts.append(first if is_ip and text.count(":") >= 2 else "")  # "" = every interface
    return hosts


@pytest.mark.parametrize("name", DATA_SERVICES)
def test_data_services_are_not_published_by_default(name):
    assert not _services()[name].get("ports"), f"{name} is published in the default stack"


def test_every_published_port_is_localhost_only():
    for name, service in _services().items():
        for host in _published_hosts(service):
            assert host == "127.0.0.1", f"{name} publishes beyond localhost ({host})"


def test_no_default_database_or_broker_password():
    text = COMPOSE.read_text(encoding="utf-8")
    assert not DEFAULT_SECRETS.search(text), "a default password is present in the compose file"


def test_passwords_are_required_from_the_environment():
    text = COMPOSE.read_text(encoding="utf-8")
    assert "${NETRA_DB_PASSWORD:?" in text
    assert "${NETRA_REDIS_PASSWORD:?" in text
    assert "${NETRA_FLOWER_BASIC_AUTH:?" in text


def test_every_image_is_pinned_by_digest():
    for name, service in _services().items():
        image = service.get("image")
        if image is None or "build" in service:
            continue  # locally built images are pinned through their Dockerfile
        assert "@sha256:" in image, f"{name} image is not pinned by digest: {image}"


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.parent.name + "/" + p.name)
def test_every_base_image_is_pinned_by_digest(dockerfile):
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        if line.startswith("FROM "):
            assert "@sha256:" in line, f"unpinned base image in {dockerfile.name}: {line}"


def test_developer_override_is_localhost_only_and_not_auto_loaded():
    assert DEV_OVERRIDE.exists()
    override = yaml.safe_load(DEV_OVERRIDE.read_text(encoding="utf-8"))["services"]
    for name in ("postgres", "redis"):
        for host in _published_hosts(override[name]):
            assert host == "127.0.0.1"
    # Compose loads docker-compose.override.yml automatically; the dev file must not use that name.
    assert not (ROOT / "docker-compose.override.yml").exists()
