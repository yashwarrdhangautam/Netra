"""Privacy gateway + vault: the model only ever sees placeholders.

Derived from Darkmoon's privacy gateway (GPL-3.0), reimplemented NETRA-native.
NETRA is AGPL-3.0, into which GPL-3.0 combines. Two invariants:

  1. the model receives placeholders, never real targets or secrets;
  2. every byte of tool output is ANSI-stripped and re-tokenized before the
     model sees it, so colourised or reformatted output cannot leak a value.

Placeholders are stable per vault: the same real value always maps to the same
token (short, repeatable -> cheaper context, and safe to log or cache). Values
are rehydrated to their real form only on the way to local tool execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# CSI sequences + OSC-8 hyperlinks; strip before matching so colourised output
# (rich, impacket, nxc...) cannot hide a value behind an escape sequence.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_URL_RE = re.compile(r"https?://[^\s\"'<>`|\\]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text or "")


@dataclass
class PrivacyVault:
    """Bidirectional map between real sensitive values and stable placeholders."""

    _to_token: dict[str, str] = field(default_factory=dict)
    _to_real: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def _placeholder(self, category: str, real: str) -> str:
        if real in self._to_token:
            return self._to_token[real]
        n = self._counts.get(category, 0) + 1
        self._counts[category] = n
        token = f"{category}_{n:03d}"
        self._to_token[real] = token
        self._to_real[token] = real
        return token

    def register_secret(self, secret: str) -> str:
        """Pre-register a credential/secret so it is always masked as CRED_nnn."""
        if not secret:
            return ""
        return self._placeholder("CRED", secret)

    def tokenize(self, text: str) -> str:
        """Replace sensitive values with placeholders. Safe to call repeatedly."""
        if not text:
            return text
        out = text
        # registered secrets first (longest first so overlaps resolve correctly)
        secrets = sorted(
            (r for r, t in self._to_token.items() if t.startswith("CRED_")),
            key=len,
            reverse=True,
        )
        for real in secrets:
            out = out.replace(real, self._to_token[real])
        # URLs before IPs/domains so a URL is masked whole, not piecemeal
        out = _URL_RE.sub(lambda m: self._placeholder("URL", m.group(0)), out)
        out = _IP_RE.sub(lambda m: self._placeholder("IP", m.group(0)), out)
        out = _DOMAIN_RE.sub(lambda m: self._placeholder("DOMAIN", m.group(0)), out)
        return out

    def rehydrate(self, text: str) -> str:
        """Replace placeholders with their real values (for local execution)."""
        if not text:
            return text
        out = text
        # longest tokens first so e.g. IP_010 is restored before IP_01 could clash
        for token in sorted(self._to_real, key=len, reverse=True):
            out = out.replace(token, self._to_real[token])
        return out


class PrivacyGateway:
    """Mediates every crossing between the model and local execution."""

    def __init__(self, vault: PrivacyVault | None = None) -> None:
        self.vault = vault or PrivacyVault()

    def to_model(self, text: str) -> str:
        """Outbound to the model: strip ANSI, then mask every sensitive value."""
        return self.vault.tokenize(strip_ansi(text))

    def from_model(self, text: str) -> str:
        """Inbound from the model: rehydrate placeholders for local execution."""
        return self.vault.rehydrate(text)

    def sanitize_output(self, text: str) -> str:
        """Tool output -> model: strip ANSI and re-tokenize any leaked values."""
        return self.vault.tokenize(strip_ansi(text))
