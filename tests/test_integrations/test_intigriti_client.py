"""Intigriti researcher client: paging, handle resolution, and scope mapping. No live network."""

import httpx

from netra.db.models.bb_scope_rule import ScopeAssetType, ScopeRuleType
from netra.integrations.intigriti import IntigritiClient


def _client_with(handler) -> IntigritiClient:
    client = IntigritiClient(token="test-token")
    client._client = httpx.AsyncClient(
        base_url=IntigritiClient.BASE_URL, transport=httpx.MockTransport(handler)
    )
    return client


async def test_list_programs_pages_until_max_count():
    records = [{"id": f"id-{i}", "handle": f"h{i}"} for i in range(250)]

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        limit = int(request.url.params["limit"])
        return httpx.Response(
            200, json={"maxCount": len(records), "records": records[offset : offset + limit]}
        )

    client = _client_with(handler)
    assert len(await client.list_programs(page_size=100)) == 250
    await client._client.aclose()


async def test_resolve_handle_to_id():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"maxCount": 1, "records": [{"id": "abc", "handle": "acme"}]}
        )

    client = _client_with(handler)
    assert await client.resolve_id("acme") == "abc"
    assert await client.resolve_id("abc") == "abc"
    assert await client.resolve_id("unknown") == "unknown"
    await client._client.aclose()


async def test_get_scope_maps_domains_and_out_of_scope_tier():
    program = {
        "id": "abc",
        "handle": "acme",
        "domains": {
            "content": [
                {
                    "endpoint": "*.acme.test",
                    "type": {"value": "Wildcard"},
                    "tier": {"value": "Critical"},
                },
                {
                    "endpoint": "admin.acme.test",
                    "type": {"value": "Domain"},
                    "tier": {"value": "Out of scope"},
                },
                {
                    "endpoint": "https://app.acme.test",
                    "type": {"value": "Url"},
                    "tier": {"value": "High"},
                },
            ]
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/programs"):
            return httpx.Response(
                200, json={"maxCount": 1, "records": [{"id": "abc", "handle": "acme"}]}
            )
        return httpx.Response(200, json=program)

    client = _client_with(handler)
    rules = await client.get_scope("acme")
    await client._client.aclose()

    assert [r.rule_type for r in rules] == [ScopeRuleType.IN, ScopeRuleType.OUT, ScopeRuleType.IN]
    assert rules[0].asset_type == ScopeAssetType.WILDCARD
    assert rules[2].asset_type == ScopeAssetType.URL


async def test_client_only_issues_get_requests():
    methods: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(200, json={"maxCount": 0, "records": []})

    client = _client_with(handler)
    await client.list_programs()
    await client._client.aclose()
    assert set(methods) == {"GET"}
