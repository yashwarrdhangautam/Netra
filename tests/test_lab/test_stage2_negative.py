"""Stage 2 negative and safety checks, plus the Juice Shop product run.

Each check is a real run of product code against local fixtures. Checks that cannot be run
offline (worker restart against a live broker, cancel of a running tool) are NOT in this module;
see docs/validation/stage-2-lab-validation.md.
"""

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from netra.db.models.scan import Scan
from netra.db.models.target import Target
from netra.db.models.user import User, UserRole
from netra.scanner.tools.base import CliTool
from netra.scanner.tools.nuclei import NucleiTool
from netra.schemas.authorization import AuthorizationRequest
from netra.services.scan_authorization import (
    grant_authorization,
    prepare_scan_authorization,
    revoke_authorization,
)
from netra.worker import tasks

LAB_SERVER = Path(__file__).resolve().parents[1] / "fixtures" / "lab" / "vuln_server.py"
JUICE_SHOP = "http://127.0.0.1:3000"

pytestmark = pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei is not on PATH")


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _request(port: int) -> AuthorizationRequest:
    return AuthorizationRequest(
        evidence_reference="stage-2-negative-local-fixture",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        allowed_actions=["vulnerability_scan"],
        http_methods=["GET"],
        ports=[port],
        # Local lab hosts only. Nuclei is now held to the grant's rate; at 5 rps the full pinned
        # template set cannot finish inside the tool timeout.
        max_requests_per_second=150,
    )


async def _granted_scan(db, port: int, value: str) -> Scan:
    actor = User(
        id=uuid.uuid4(),
        email=f"neg-{uuid.uuid4().hex[:6]}@example.org",
        hashed_password="unused",
        role=UserRole.ADMIN,
    )
    target = Target(
        name="stage2-negative", target_type="url", value=value, scope_includes=["127.0.0.1"]
    )
    db.add_all([actor, target])
    await db.flush()
    await grant_authorization(db, target.id, _request(port), actor)
    snapshot = await prepare_scan_authorization(db, target.id)
    scan = Scan(
        name="stage2-negative",
        target_id=target.id,
        profile="standard",
        checkpoint_data={"authorization_snapshot": snapshot},
    )
    db.add(scan)
    await db.commit()
    return scan, actor, target


@pytest.fixture(scope="module")
def event_loop_policy():
    # Subprocess tools need the Proactor loop on Windows; the root conftest selects Selector.
    if os.name == "nt":
        return asyncio.WindowsProactorEventLoopPolicy()
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture(scope="module")
def lab_server():
    port = _free_port()
    server = subprocess.Popen([sys.executable, str(LAB_SERVER), "--port", str(port)])  # noqa: S603
    for _ in range(50):
        if _port_open(port):
            break
        time.sleep(0.1)
    yield port
    server.terminate()
    server.wait(timeout=10)


class _DecoyHandler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):  # noqa: N802
        type(self).hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>decoy</html>")

    def log_message(self, *args):  # silence the default stderr log
        return


@pytest.fixture
def decoy():
    """A host outside the granted scope. Any request it receives is a scope violation."""
    _DecoyHandler.hits = []
    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), _DecoyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", port, _DecoyHandler
    server.shutdown()
    server.server_close()


async def test_revoked_authorization_stops_before_any_tool(db_session, lab_server, monkeypatch):
    port = lab_server
    scan, actor, target = await _granted_scan(db_session, port, f"http://127.0.0.1:{port}")
    await revoke_authorization(db_session, target.id, actor)
    await db_session.commit()
    run = AsyncMock()
    monkeypatch.setattr(NucleiTool, "run", run)

    result = await tasks._execute_vuln_scan(
        db_session, scan.id, {"live_hosts": [f"http://127.0.0.1:{port}"]}
    )

    assert result["status"] == "failed"
    assert result.get("error") == "authorization_revoked"
    run.assert_not_awaited()


async def test_decoy_host_outside_grant_receives_zero_requests(db_session, lab_server, decoy):
    decoy_url, decoy_port, handler = decoy
    assert decoy_port != lab_server
    scan, _, _ = await _granted_scan(db_session, lab_server, f"http://127.0.0.1:{lab_server}")

    lab_url = f"http://127.0.0.1:{lab_server}"
    result = await tasks._execute_vuln_scan(
        db_session, scan.id, {"live_hosts": [lab_url, decoy_url]}
    )

    # Fail closed: a host outside the grant in the batch refuses the phase, so nothing runs.
    assert result["status"] == "failed", result
    assert result.get("error") or result.get("policy_denial"), result
    assert handler.hits == [], f"decoy received requests: {handler.hits}"


def test_tool_environment_does_not_expose_platform_secrets(tmp_path, monkeypatch):
    """A tool subprocess must not inherit platform secrets from the worker environment."""
    sentinel = "sentinel-" + uuid.uuid4().hex
    monkeypatch.setenv("NETRA_ANTHROPIC_API_KEY", sentinel)
    monkeypatch.setenv("NETRA_JWT_SECRET_KEY", sentinel)
    monkeypatch.setenv("NETRA_DB_PASSWORD", sentinel)
    dumper = tmp_path / "dump_env.py"
    dumper.write_text("import os\nprint('\\n'.join(f'{k}={v}' for k, v in os.environ.items()))\n")

    class EnvDumper(CliTool):
        binary = sys.executable
        tool_name = "env-dumper"

    result = asyncio.run(EnvDumper(work_dir=tmp_path)._exec([str(dumper)]))

    assert result.success, result.error
    assert sentinel not in result.raw_output
    assert "NETRA_" not in result.raw_output


async def test_juice_shop_product_run_reports_the_reviewed_baseline(db_session):
    """Product vuln scan against Juice Shop. The reviewed manual baseline has one
    prometheus-metrics finding (docs/validation/stage-2-baselines)."""
    if not _port_open(3000):
        pytest.skip("Juice Shop is not listening on 127.0.0.1:3000")
    scan, _, _ = await _granted_scan(db_session, 3000, JUICE_SHOP)

    result = await tasks._execute_vuln_scan(db_session, scan.id, {"live_hosts": [JUICE_SHOP]})

    assert result["status"] == "completed", result.get("error") or result.get("policy_denial")
    nuclei = [run for run in result["runs"] if run["tool"] == "nuclei"]
    assert nuclei and nuclei[0]["state"] == "completed"
    assert nuclei[0]["findings_count"] >= 1
