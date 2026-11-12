"""Tests for the privacy gateway + vault (Sprint 4)."""

from netra.bugbounty.agentic.privacy_gateway import PrivacyGateway, PrivacyVault, strip_ansi


def test_ip_tokenized_and_stable():
    v = PrivacyVault()
    out = v.tokenize("connect to 192.168.56.10 then 192.168.56.10 again")
    assert "192.168.56.10" not in out
    assert out.count("IP_001") == 2  # same value -> same token


def test_url_masked_whole():
    v = PrivacyVault()
    out = v.tokenize("GET https://api.victim.test/invoices/1043")
    assert "victim.test" not in out and "https://" not in out
    assert "URL_001" in out


def test_registered_secret_masked():
    v = PrivacyVault()
    v.register_secret("s3cr3t-token-abc")
    out = v.tokenize("Authorization: Bearer s3cr3t-token-abc")
    assert "s3cr3t-token-abc" not in out and "CRED_001" in out


def test_rehydrate_round_trips():
    v = PrivacyVault()
    original = "scan 10.0.0.5 and https://app.test/x"
    masked = v.tokenize(original)
    assert v.rehydrate(masked) == original


def test_strip_ansi():
    assert strip_ansi("\x1b[1;92m192.168.56.10\x1b[0m") == "192.168.56.10"


def test_gateway_model_never_sees_real_values():
    gw = PrivacyGateway()
    gw.vault.register_secret("API-KEY-XYZ")
    # colourised tool output carrying an IP, a URL and a secret
    raw = "\x1b[1;92m10.1.2.3\x1b[0m hit https://tenant.corp.test/a key=API-KEY-XYZ"
    seen = gw.to_model(raw)
    for leak in ("10.1.2.3", "tenant.corp.test", "API-KEY-XYZ", "\x1b["):
        assert leak not in seen
    assert "IP_001" in seen and "URL_001" in seen and "CRED_001" in seen


def test_sanitize_output_retokenizes_leaks():
    gw = PrivacyGateway()
    gw.to_model("target 172.16.0.9")  # assigns IP_001
    again = gw.sanitize_output("\x1b[31m172.16.0.9\x1b[0m responded 200")
    assert "172.16.0.9" not in again and "IP_001" in again
