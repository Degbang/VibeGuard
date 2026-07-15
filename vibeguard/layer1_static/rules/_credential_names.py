"""Shared credential-name heuristics for Layer 1 CWE rule modules.

Extracted out of ``cwe_798.py`` once ``cwe_287.py`` needed the same
"does this identifier look like it holds a credential" question - see
IMPLEMENTATION_LOG.md. Both rules care about *names* (password, secret,
api key, token, ...), just for different reasons: cwe_798.py asks
whether a literal *value* is assigned to one; cwe_287.py asks whether
one is being compared with Java's unsafe ``==``/``!=`` operators.
"""

from __future__ import annotations

import re

# Case-insensitive substring match against field/variable/parameter/
# config-key names. Deliberately permissive (e.g. "passwordHash" also
# matches): each rule module decides its own further narrowing (see
# cwe_798.py's reference-suffix exclusion, for one example) - this
# module only answers "does the name look credential-shaped at all."
CREDENTIAL_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "authtoken",
    "auth_token",
    "token",
    "privatekey",
    "private_key",
    "clientsecret",
    "client_secret",
    "credential",
    "secretkey",
    "secret_key",
    "encryptionkey",
    "encryption_key",
)

_WORD_PATTERN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z0-9]+")


def is_credential_name(name: str) -> bool:
    """Case-insensitive substring match against known credential keywords."""
    lowered = name.lower()
    return any(keyword in lowered for keyword in CREDENTIAL_KEYWORDS)


def last_word(identifier: str) -> str:
    """Extract an identifier's final word, splitting camelCase and ./_/- separators.

    "secretName" -> "name", "quarkus.kubernetes.env.secrets" -> "secrets",
    "APIKey" -> "key". Used to check *what kind of thing* the name's
    last component describes, without being fooled by where a
    credential keyword happens to sit earlier in the identifier.
    """
    normalized = re.sub(r"[._-]", " ", identifier)
    words = _WORD_PATTERN.findall(normalized)
    return words[-1].lower() if words else identifier.lower()
