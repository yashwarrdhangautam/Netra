"""Schemathesis contract smoke for NETRA-BB OpenAPI routes."""
from __future__ import annotations

import pytest

schemathesis = pytest.importorskip("schemathesis")

from netra.api.app import create_app


schema = schemathesis.from_asgi("/openapi.json", create_app())


@schema.parametrize(endpoint="/api/v1/bb/doctor", method="GET")
def test_bb_doctor_contract(case):
    response = case.call_asgi()
    case.validate_response(response)

