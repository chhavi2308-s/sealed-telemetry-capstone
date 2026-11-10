"""Offline Phase C1 contract and deterministic HMAC test vectors."""

import hashlib
import json
import logging
import traceback
from dataclasses import asdict, replace
from uuid import uuid4

import pytest

from sealed_telemetry.four_stage_issuance import (
    IssuanceAttestation,
    credential_fingerprint,
    verify_attestation_fingerprint,
)
from sealed_telemetry.schema import Evidence, pseudonym

TOKEN_ID = "11111111-1111-4111-8111-111111111111"  # noqa: S105 -- public test vector ID
ACTION_ID = "22222222-2222-4222-8222-222222222222"
ISSUANCE_ID = "33333333-3333-4333-8333-333333333333"
KEY_V1 = bytes(range(32))
KEY_V2 = bytes(range(32, 64))


def attestation(key: bytes = KEY_V1, version: str = "v1") -> IssuanceAttestation:
    return IssuanceAttestation(
        issuance_id=ISSUANCE_ID,
        token_id=TOKEN_ID,
        action_id=ACTION_ID,
        actor_pseudonym="a" * 64,
        operation="files:upload",
        resource_pseudonym="b" * 64,
        issued_at_utc="2026-11-09T10:00:00+00:00",
        expires_at_utc="2026-11-09T10:05:00+00:00",
        credential_fingerprint=credential_fingerprint(
            token_id=TOKEN_ID, key=key, key_version=version
        ),
        fingerprint_key_version=version,
        authorization_native_id=ACTION_ID,
    )


def test_v1_vector_is_stable():
    assert credential_fingerprint(token_id=TOKEN_ID, key=KEY_V1, key_version="v1") == (
        "37bb64cdc05bfac138ca1f21dd669b0403e2b83fccd5ae38be3a4a7922ef1964"
    )


def test_v2_vector_is_stable_and_differs():
    assert credential_fingerprint(token_id=TOKEN_ID, key=KEY_V2, key_version="v2") == (
        "f6bb11b62d0a672e6b437bbfb729f48bea8c257c5a0ea37456e0aa6ef80a818b"
    )
    assert (
        attestation(KEY_V1, "v1").credential_fingerprint
        != attestation(KEY_V2, "v2").credential_fingerprint
    )


def test_attestation_verifies_only_with_selected_key_version():
    assert verify_attestation_fingerprint(attestation(), keyring={"v1": KEY_V1, "v2": KEY_V2})
    assert not verify_attestation_fingerprint(attestation(), keyring={"v1": KEY_V2})
    with pytest.raises(ValueError, match="unknown fingerprint key version"):
        verify_attestation_fingerprint(attestation(), keyring={"v2": KEY_V2})


def test_fingerprint_cannot_be_relabelled_with_other_version():
    assert not verify_attestation_fingerprint(
        replace(attestation(), fingerprint_key_version="v2"), keyring={"v1": KEY_V1, "v2": KEY_V2}
    )


@pytest.mark.parametrize("version", ["", "1", "v0", "v01", "v-1", "V1", "v1:old", "v1000000"])
def test_invalid_key_version_rejected(version):
    with pytest.raises(ValueError, match="key version"):
        credential_fingerprint(token_id=TOKEN_ID, key=KEY_V1, key_version=version)


@pytest.mark.parametrize("key", [b"", b"short", b"a" * 31])
def test_short_keys_rejected(key):
    with pytest.raises(ValueError, match="256 bits"):
        credential_fingerprint(token_id=TOKEN_ID, key=key, key_version="v1")


def test_distinct_token_ids_and_existing_engine_helper_agree():
    other = str(uuid4())
    assert credential_fingerprint(
        token_id=TOKEN_ID, key=KEY_V1, key_version="v1"
    ) != credential_fingerprint(token_id=other, key=KEY_V1, key_version="v1")
    assert credential_fingerprint(token_id=TOKEN_ID, key=KEY_V1, key_version="v1") == pseudonym(
        KEY_V1, TOKEN_ID
    )


@pytest.mark.parametrize(
    "change",
    [
        {"expires_at_utc": "2026-11-09T09:00:00+00:00"},
        {"issued_at_utc": "2026-11-09T10:00:00+05:30"},
        {"fingerprint_algorithm": "SHA256"},
        {"contract_version": "legacy"},
        {"credential_fingerprint": "0" * 63},
        {"authorization_native_id": ""},
        {"token_id": "not-a-uuid"},
    ],
)
def test_malformed_attestations_rejected(change):
    with pytest.raises((ValueError, TypeError)):
        replace(attestation(), **change).validate()


def test_no_bearer_or_sha256_lookup_hash_in_attestation():
    record = attestation()
    assert "access_token" not in record.__dataclass_fields__
    assert "token_hash" not in record.__dataclass_fields__
    assert "invocation_id" not in record.__dataclass_fields__


@pytest.mark.parametrize(
    "fake",
    [
        pseudonym(KEY_V1, ACTION_ID),
        hashlib.sha256(b"synthetic-bearer-fixture").hexdigest(),
        hashlib.sha256(ACTION_ID.encode()).hexdigest(),
    ],
)
def test_action_based_or_plain_lookup_hash_forgery_does_not_verify(fake):
    forged = replace(attestation(), credential_fingerprint=fake)
    # Shape validation alone cannot distinguish an ordinary digest from an HMAC.
    forged.validate()
    assert not verify_attestation_fingerprint(forged, keyring={"v1": KEY_V1})


@pytest.mark.parametrize(
    "token_id",
    [
        "",
        None,
        "ABCDEFAB-1234-4ABC-8ABC-ABCDEFABCDEF",
        "{" + TOKEN_ID + "}",
        "00000000-0000-0000-0000-000000000000",
        TOKEN_ID.replace("-", ""),
        hashlib.sha256(b"synthetic-bearer-fixture").hexdigest(),
    ],
)
def test_noncanonical_or_lookup_hash_token_ids_rejected(token_id):
    with pytest.raises(ValueError):
        credential_fingerprint(token_id=token_id, key=KEY_V1, key_version="v1")


@pytest.mark.parametrize(
    "field,value",
    [
        ("token_id", ACTION_ID),
        ("token_id", ISSUANCE_ID),
        ("issuance_id", ACTION_ID),
        ("authorization_native_id", ""),
        ("authorization_native_id", ISSUANCE_ID),
        ("actor_pseudonym", "raw-principal"),
        ("resource_pseudonym", "private-file.pdf"),
        ("actor_pseudonym", "0" * 64),
        ("resource_pseudonym", None),
        ("operation", "records:export"),
        ("credential_fingerprint", None),
        ("credential_fingerprint", "0" * 64),
        ("expires_at_utc", "2026-11-09T10:00:00+00:00"),
        ("issued_at_utc", True),
    ],
)
def test_construction_fails_closed_for_missing_or_invalid_binding_fields(field, value):
    with pytest.raises(ValueError):
        replace(attestation(), **{field: value})


def test_private_parse_roundtrip_and_redacted_export_are_different_contracts():
    record = attestation()
    private = asdict(record)
    assert IssuanceAttestation.parse(private) == record
    evidence = record.to_evidence_dict()
    assert "token_id" not in evidence
    assert evidence["credential_fingerprint"] == record.credential_fingerprint
    assert TOKEN_ID not in json.dumps(evidence) + repr(record) + str(record)
    with pytest.raises(ValueError, match="invalid issuance record"):
        IssuanceAttestation.parse(evidence)
    with pytest.raises(ValueError):
        Evidence.parse(evidence, "issuer")


@pytest.mark.parametrize(
    "missing",
    [
        "token_id",
        "action_id",
        "authorization_native_id",
        "credential_fingerprint",
        "fingerprint_key_version",
        "issued_at_utc",
        "actor_pseudonym",
        "contract_version",
        "fingerprint_algorithm",
    ],
)
def test_private_parser_rejects_missing_fields(missing):
    raw = asdict(attestation())
    raw.pop(missing)
    with pytest.raises(ValueError, match="invalid issuance record"):
        IssuanceAttestation.parse(raw)


@pytest.mark.parametrize("name", ["access_token", "token_hash", "source_id", "invocation_id"])
def test_unknown_fields_and_rejection_tracebacks_do_not_disclose_values(name, caplog):
    private_fixture = "private-rejection-fixture-only"
    raw = {**asdict(attestation()), name: private_fixture}
    with pytest.raises(ValueError) as failure:
        IssuanceAttestation.parse(raw)
    rendered = "".join(traceback.format_exception(failure.value))
    assert private_fixture not in str(failure.value) + rendered + caplog.text


def test_malformed_timestamp_error_does_not_disclose_input():
    private_fixture = "private-invalid-timestamp-only"
    with pytest.raises(ValueError) as failure:
        replace(attestation(), issued_at_utc=private_fixture)
    assert private_fixture not in "".join(traceback.format_exception(failure.value))


def test_invalid_private_record_shape_and_size_are_rejected():
    for raw in (None, [], {**asdict(attestation()), "extra": "x" * 17000}):
        with pytest.raises(ValueError, match="invalid issuance record"):
            IssuanceAttestation.parse(raw)


def test_rotation_retains_old_version_and_does_not_fall_back():
    old, new = attestation(), attestation(KEY_V2, "v2")
    ring = {"v1": KEY_V1, "v2": KEY_V2}
    assert verify_attestation_fingerprint(old, keyring=ring)
    assert verify_attestation_fingerprint(new, keyring=ring)
    with pytest.raises(ValueError, match="unknown fingerprint key version"):
        verify_attestation_fingerprint(old, keyring={"v2": KEY_V2})
    assert old.fingerprint_key_version == "v1"
    # Version labels select keys; relabeling identical key bytes cannot change HMAC.
    assert (
        credential_fingerprint(token_id=TOKEN_ID, key=KEY_V1, key_version="v2")
        == old.credential_fingerprint
    )


@pytest.mark.parametrize("key", [None, "not-key-bytes", bytearray(32), b"x" * 31])
def test_keyring_with_invalid_key_material_is_rejected(key):
    with pytest.raises(ValueError, match="256 bits"):
        verify_attestation_fingerprint(attestation(), keyring={"v1": key})


def test_fingerprint_agreement_is_not_authorization_or_source_proof():
    different_action = str(uuid4())
    changed_claim = replace(
        attestation(), action_id=different_action, authorization_native_id=different_action
    )
    # The fingerprint authenticates no action fields. C2 must independently read
    # the issuer record and durable gateway authorization, not trust this Boolean.
    assert verify_attestation_fingerprint(changed_claim, keyring={"v1": KEY_V1})


def test_logging_the_record_does_not_disclose_identifiers_or_fingerprints(caplog):
    record = attestation()
    with caplog.at_level("INFO"):
        logging.getLogger(__name__).info("record=%s", record)
    assert "private issuer record" in caplog.text
    for value in (TOKEN_ID, ACTION_ID, ISSUANCE_ID, record.credential_fingerprint):
        assert value not in caplog.text
