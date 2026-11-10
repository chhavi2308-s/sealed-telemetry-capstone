"""Phase C1 offline issuer-attestation contract; no AWS or producer mutations.

An attestation is meaningful only after independently authenticated issuer collection.
This module validates structure and deterministic credential fingerprints, not origin.
"""

import hmac
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from typing import Any
from uuid import UUID

from sealed_telemetry.schema import canonical, pseudonym, timestamp

CONTRACT_VERSION = "four-stage-issuance-1"
FINGERPRINT_ALGORITHM = "HMAC-SHA256"
KEY_VERSION_PATTERN = re.compile(r"v[1-9][0-9]{0,5}\Z")
FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECORD_BYTES = 16384
SUPPORTED_OPERATION = "files:upload"


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError("invalid issuance identifier")
    return value


def _uuid(value: str) -> str:
    _identifier(value)
    parsed = UUID(value)
    if str(parsed) != value or parsed.version != 4:
        raise ValueError("canonical UUIDv4 required")
    return value


def _key_version(value: str) -> str:
    if not isinstance(value, str) or KEY_VERSION_PATTERN.fullmatch(value) is None:
        raise ValueError("invalid fingerprint key version")
    return value


def credential_fingerprint(*, token_id: str, key: bytes, key_version: str) -> str:
    """HMAC of a private issuer-generated token ID, never a bearer or action ID.

    Key version is a separately authenticated selector, not an HMAC input. Each
    key version MUST map to exactly one independently managed secret key.
    """
    _uuid(token_id)
    _key_version(key_version)
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("HMAC key must contain at least 256 bits")
    return pseudonym(key, token_id)


@dataclass(frozen=True, repr=False)
class IssuanceAttestation:
    """Private issuer record proposed for C2, not existing AWS evidence.

    Only to_evidence_dict() is an export projection. Generic asdict(), pickle or
    direct attribute access includes the private token ID and must stay internal.
    """

    issuance_id: str
    token_id: str
    action_id: str
    actor_pseudonym: str
    operation: str
    resource_pseudonym: str
    issued_at_utc: str
    expires_at_utc: str
    credential_fingerprint: str
    fingerprint_key_version: str
    authorization_native_id: str
    contract_version: str = CONTRACT_VERSION
    fingerprint_algorithm: str = FINGERPRINT_ALGORITHM

    def __post_init__(self) -> None:
        self.validate()

    def __repr__(self) -> str:
        return "IssuanceAttestation(<private issuer record>)"

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "IssuanceAttestation":
        """Parse a bounded private record; reject unknown/missing fields safely."""
        try:
            if (
                not isinstance(raw, dict)
                or set(raw) != {item.name for item in fields(cls)}
                or len(canonical(raw)) > MAX_RECORD_BYTES
            ):
                raise ValueError("invalid record shape or size")
            return cls(**raw)
        except (ValueError, TypeError, AttributeError, OverflowError):
            raise ValueError("invalid issuance record") from None

    def to_evidence_dict(self) -> dict[str, str]:
        """Redact the private token ID for independently authenticated collection.

        This projection is not complete IBER Evidence or a claim of source origin.
        It cannot be parsed back as a private attestation without registry access.
        """
        self.validate()
        return {name: value for name, value in asdict(self).items() if name != "token_id"}

    def validate(self) -> None:
        for value in (self.issuance_id, self.token_id, self.action_id):
            _uuid(value)
        if len({self.issuance_id, self.token_id, self.action_id}) != 3:
            raise ValueError("issuance, token and action IDs must be distinct")
        if self.authorization_native_id != self.action_id:
            raise ValueError("authorization native ID must match the gateway action key")
        for value in (self.actor_pseudonym, self.resource_pseudonym):
            _identifier(value)
            if FINGERPRINT_PATTERN.fullmatch(value) is None or value == "0" * 64:
                raise ValueError("HMAC pseudonym format required")
        if self.operation != SUPPORTED_OPERATION:
            raise ValueError("unsupported four-stage operation")
        if self.contract_version != CONTRACT_VERSION:
            raise ValueError("unsupported issuance contract version")
        if self.fingerprint_algorithm != FINGERPRINT_ALGORITHM:
            raise ValueError("unsupported fingerprint algorithm")
        _key_version(self.fingerprint_key_version)
        _identifier(self.credential_fingerprint)
        if (
            FINGERPRINT_PATTERN.fullmatch(self.credential_fingerprint) is None
            or self.credential_fingerprint == "0" * 64
        ):
            raise ValueError("invalid HMAC fingerprint format")
        try:
            issued: datetime = timestamp(_identifier(self.issued_at_utc))
            expires: datetime = timestamp(_identifier(self.expires_at_utc))
        except (ValueError, TypeError, AttributeError, OverflowError):
            raise ValueError("UTC issuance timestamps required") from None
        if expires <= issued:
            raise ValueError("issuance expiry must follow issuance")


def verify_attestation_fingerprint(
    attestation: IssuanceAttestation, *, keyring: Mapping[str, bytes]
) -> bool:
    """Verify under the attested version; never fall back to a different key."""
    attestation.validate()
    if attestation.fingerprint_key_version not in keyring:
        raise ValueError("unknown fingerprint key version")
    key = keyring[attestation.fingerprint_key_version]
    expected = credential_fingerprint(
        token_id=attestation.token_id,
        key=key,
        key_version=attestation.fingerprint_key_version,
    )
    return hmac.compare_digest(expected, attestation.credential_fingerprint)
