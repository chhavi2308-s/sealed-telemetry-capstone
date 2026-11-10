"""Read-through AWS collection and persistent, fail-closed evidence state. No deployment."""

import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.aws_handlers import source_for_principal
from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.four_stage_binding import _condition
from sealed_telemetry.four_stage_c3_schema import ROLE_ARN, TABLE_ARN, InvalidRecord, normalize
from sealed_telemetry.schema import canonical, digest, timestamp, utcnow


class CollectionError(ValueError):
    """Fixed diagnostics only; SDK/producer values never cross this boundary."""


@dataclass(frozen=True)
class Source:
    source_id: str
    contract: str
    table_arn: str
    key: str


@dataclass(frozen=True)
class Configuration:
    collector_role_arn: str
    state_table_arn: str
    sources: tuple[Source, ...]
    max_records: int = 1000
    max_pages: int = 20
    health_functions: tuple[tuple[str, str], ...] = ()
    archive_roles: tuple[tuple[str, str], ...] = ()

    def validate(self) -> None:
        if (
            not isinstance(self.collector_role_arn, str)
            or not isinstance(self.state_table_arn, str)
            or type(self.max_records) is not int
            or type(self.max_pages) is not int
        ):
            raise CollectionError("INVALID_COLLECTION_CONFIGURATION")
        role = ROLE_ARN.fullmatch(self.collector_role_arn)
        state = TABLE_ARN.fullmatch(self.state_table_arn)
        if not role or not state or role[1] != state[1] or role[2] != state[3]:
            raise CollectionError("INVALID_COLLECTION_CONFIGURATION")
        if (
            not self.sources
            or len(self.sources) > 7
            or not 1 <= self.max_records <= 1000
            or not 1 <= self.max_pages <= 20
        ):
            raise CollectionError("INVALID_COLLECTION_CONFIGURATION")
        arns, identities = set(), set()
        for source in self.sources:
            if not isinstance(source, Source) or not all(
                isinstance(value, str) for value in asdict(source).values()
            ):
                raise CollectionError("INVALID_COLLECTION_CONFIGURATION")
            arn = TABLE_ARN.fullmatch(source.table_arn)
            expected = {
                "gateway": "action_id",
                "issuer": "issuance_id",
                "provider": "provider_request_id",
            }
            valid = (
                (source.contract == "c2" and expected.get(source.source_id) == source.key)
                or (
                    source.contract == "iber-1"
                    and source.source_id in {"gateway", "app", "provider", "health"}
                    and source.key == "event_id"
                )
                or (
                    source.contract == "c4"
                    and {
                        "gateway": "record_id",
                        "app": "record_id",
                        "provider": "provider_request_id",
                        "health": "event_id",
                    }.get(source.source_id)
                    == source.key
                )
                or (
                    source.contract == "aws-events-1"
                    and source.source_id == "archive"
                    and source.key == "event_id"
                )
            )
            identity = (source.source_id, source.contract)
            if (
                not arn
                or (arn[1], arn[2], arn[3]) != (state[1], state[2], state[3])
                or not valid
                or source.table_arn == self.state_table_arn
                or source.table_arn in arns
                or identity in identities
            ):
                raise CollectionError("AMBIGUOUS_SOURCE_CONFIGURATION")
            arns.add(source.table_arn)
            identities.add(identity)
        for contract, roles in (
            ("c2", {"gateway", "issuer", "provider"}),
            ("iber-1", {"gateway", "app", "provider", "health"}),
            ("c4", {"gateway", "app", "provider", "health"}),
        ):
            configured = {s.source_id for s in self.sources if s.contract == contract}
            if configured and configured != roles:
                raise CollectionError("INCOMPLETE_SOURCE_CONFIGURATION")
        if any(s.contract == "c4" for s in self.sources):
            from sealed_telemetry.four_stage_c4_schema import FUNCTION_PATTERN

            try:
                functions = dict(self.health_functions)
                if (
                    len(functions) != 4
                    or len(self.health_functions) != 4
                    or set(functions) != {"gateway", "app", "provider", "collector"}
                    or len(set(functions.values())) != 4
                    or not all(
                        re.fullmatch(FUNCTION_PATTERN, arn)
                        and arn.split(":")[1] == state[1]
                        and arn.split(":")[3:5] == [state[2], state[3]]
                        for arn in functions.values()
                    )
                    or not any(s.contract == "c2" for s in self.sources)
                    or any(s.contract == "iber-1" for s in self.sources)
                ):
                    raise ValueError("invalid C4 configuration")
            except (TypeError, ValueError):
                raise CollectionError("INVALID_C4_CONFIGURATION") from None
        elif self.health_functions:
            raise CollectionError("INVALID_C4_CONFIGURATION")
        if any(s.contract == "aws-events-1" for s in self.sources):
            try:
                roles_map = dict(self.archive_roles)
                if (
                    len(self.sources) != 1
                    or len(self.archive_roles) != 4
                    or set(roles_map) != {"gateway", "app", "provider", "health"}
                    or len(set(roles_map.values())) != 4
                    or not all(
                        isinstance(arn, str)
                        and ROLE_ARN.fullmatch(arn)
                        and arn.split(":")[1] == state[1]
                        and arn.split(":")[4] == state[3]
                        for arn in roles_map.values()
                    )
                ):
                    raise ValueError("ambiguous archive mapping")
            except (TypeError, ValueError):
                raise CollectionError("INVALID_ARCHIVE_CONFIGURATION") from None
        elif self.archive_roles:
            raise CollectionError("INVALID_ARCHIVE_CONFIGURATION")

    @property
    def policy_hash(self) -> str:
        return digest(asdict(self))


class Ledger:
    """Collector-private state interface; table creation/permissions are external gates."""

    def __init__(self, db: Any, config: Configuration):
        self.db, self.config = db, config
        self.table = db.Table(config.state_table_arn)
        try:
            self.table.put_item(
                Item={
                    "record_id": "CONTROL",
                    "kind": "control",
                    "revision": 0,
                    "policy_hash": config.policy_hash,
                    "collections": "{}",
                },
                ConditionExpression=Attr("record_id").not_exists(),
            )
        except self.table.meta.client.exceptions.ConditionalCheckFailedException:
            pass
        self.control()

    def control(self) -> dict[str, Any]:
        row: dict[str, Any] | None = self.table.get_item(
            Key={"record_id": "CONTROL"}, ConsistentRead=True
        ).get("Item")
        if not row or row.get("policy_hash") != self.config.policy_hash:
            raise CollectionError("STATE_POLICY_MISMATCH")
        return row

    def _put_control(self, previous: dict[str, Any], **changes: Any) -> dict[str, Any]:
        return {
            "Put": {
                "TableName": self.config.state_table_arn,
                "Item": {**previous, "revision": int(previous["revision"]) + 1, **changes},
                **_condition(
                    Attr("revision").eq(previous["revision"])
                    & Attr("policy_hash").eq(self.config.policy_hash)
                ),
            }
        }

    def remember(
        self,
        source: Source,
        native_id: str,
        normalized: dict[str, Any] | None,
        collected_at: str,
        invalid: bool = False,
    ) -> str:
        if normalized is None and not invalid:
            return "ignored"
        identity = digest([source.table_arn, native_id])
        record_id = "c:" + identity
        content_hash = digest(normalized["data"]) if normalized else "invalid"
        history_id = "h:" + identity + ":" + content_hash
        receipt = {
            "resource_arn": source.table_arn,
            "native_id": native_id if normalized else None,
            "collector_role_arn": self.config.collector_role_arn,
            "collected_at_utc": collected_at,
            "policy_hash": self.config.policy_hash,
            "payload_hash": content_hash if normalized else None,
        }
        body = (
            canonical({"normalized": normalized, "receipt": receipt}).decode()
            if normalized
            else None
        )
        for _ in range(4):
            control = self.control()
            old = self.table.get_item(Key={"record_id": record_id}, ConsistentRead=True).get("Item")
            if old and old.get("payload_hash") == content_hash and old["status"] == "accepted":
                return "duplicate"
            if self.table.get_item(Key={"record_id": history_id}, ConsistentRead=True).get("Item"):
                if old and old["status"] == "quarantined":
                    return "quarantined"
                raise CollectionError("STATE_HISTORY_INCONSISTENT")
            status = "accepted" if old is None and not invalid else "quarantined"
            reason = (
                "INVALID_SOURCE_RECORD"
                if invalid
                else "CONFLICTING_NATIVE_RECORD"
                if old
                else "ACCEPTED"
            )
            current = {
                "record_id": record_id,
                "kind": "current",
                "status": status,
                "reason_code": reason,
                "source_id": source.source_id,
                "contract": source.contract,
                "resource_arn": source.table_arn,
                "payload_hash": content_hash,
                "revision": int(control["revision"]) + 1,
                "policy_hash": self.config.policy_hash,
                "body": body if status == "accepted" else None,
                "normalization_hash": digest(normalized) if status == "accepted" else None,
            }
            history = {
                "record_id": history_id,
                "kind": "history",
                "status": status,
                "reason_code": reason,
                "body": body,
                "policy_hash": self.config.policy_hash,
            }
            condition = (
                Attr("revision").eq(old["revision"]) if old else Attr("record_id").not_exists()
            )
            try:
                self.db.meta.client.transact_write_items(
                    TransactItems=[
                        self._put_control(control),
                        {
                            "Put": {
                                "TableName": self.config.state_table_arn,
                                "Item": current,
                                **_condition(condition),
                            }
                        },
                        {
                            "Put": {
                                "TableName": self.config.state_table_arn,
                                "Item": history,
                                **_condition(Attr("record_id").not_exists()),
                            }
                        },
                    ]
                )
                return status
            except self.db.meta.client.exceptions.TransactionCanceledException:
                continue
        raise CollectionError("STATE_CONCURRENT_UPDATE")

    def mark_collection(self, source: Source, now: str, ok: bool, reason: str) -> None:
        for _ in range(4):
            control = self.control()
            markers = json.loads(control["collections"])
            previous = markers.get(source.table_arn)
            if previous and timestamp(now) < timestamp(previous["attempted_at_utc"]):
                ok, reason = False, "COLLECTOR_CLOCK_REGRESSION"
            markers[source.table_arn] = {"attempted_at_utc": now, "ok": ok, "reason_code": reason}
            try:
                put = self._put_control(control, collections=canonical(markers).decode())["Put"]
                self.table.put_item(
                    **{key: value for key, value in put.items() if key != "TableName"}
                )
                return
            except self.table.meta.client.exceptions.ConditionalCheckFailedException:
                continue
        raise CollectionError("STATE_CONCURRENT_UPDATE")

    def snapshot(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        control = self.control()
        rows = []
        paginator = self.db.meta.client.get_paginator("scan")
        for index, page in enumerate(
            paginator.paginate(
                TableName=self.config.state_table_arn,
                ConsistentRead=True,
                **{"FilterExpression": Attr("kind").eq("current")},
                PaginationConfig={"PageSize": 100},
            )
        ):
            rows.extend(page["Items"])
            if len(rows) > self.config.max_records or index >= self.config.max_pages:
                raise CollectionError("STATE_CAPACITY_EXCEEDED")
        if self.control()["revision"] != control["revision"]:
            raise CollectionError("STATE_CHANGED_DURING_SNAPSHOT")
        for row in rows:
            if row.get("policy_hash") != self.config.policy_hash:
                raise CollectionError("STATE_POLICY_MISMATCH")
            if row["status"] == "accepted":
                envelope = json.loads(row["body"])
                if (
                    digest(envelope["normalized"]) != row["normalization_hash"]
                    or digest(envelope["normalized"]["data"]) != row["payload_hash"]
                    or envelope["receipt"]["policy_hash"] != self.config.policy_hash
                ):
                    raise CollectionError("STATE_INTEGRITY_FAILURE")
                receipt = envelope["receipt"]
                configured = next(
                    (s for s in self.config.sources if s.table_arn == row["resource_arn"]), None
                )
                if (
                    configured is None
                    or configured.source_id != row["source_id"]
                    or configured.contract != row["contract"]
                    or receipt["resource_arn"] != configured.table_arn
                    or receipt["collector_role_arn"] != self.config.collector_role_arn
                    or receipt["payload_hash"] != row["payload_hash"]
                ):
                    raise CollectionError("STATE_PROVENANCE_MISMATCH")
                try:
                    timestamp(receipt["collected_at_utc"])
                    reproduced = normalize(
                        configured.source_id,
                        configured.contract,
                        configured.table_arn,
                        receipt["native_id"],
                        envelope["normalized"]["data"],
                        self.config.archive_roles,
                    )
                    if reproduced != envelope["normalized"]:
                        raise CollectionError("STATE_INTEGRITY_FAILURE")
                except InvalidRecord:
                    raise CollectionError("STATE_INTEGRITY_FAILURE") from None
        return control, rows

    def assessment(self, revision: int, body: dict[str, Any]) -> None:
        result = {
            "kind": "assessment",
            "snapshot_revision": revision,
            "body": canonical(body).decode(),
            "assessed_at_utc": body["assessed_at_utc"],
            "assessment_hash": digest(body),
            "policy_hash": self.config.policy_hash,
        }
        try:
            self.db.meta.client.transact_write_items(
                TransactItems=[
                    {
                        "ConditionCheck": {
                            "TableName": self.config.state_table_arn,
                            "Key": {"record_id": "CONTROL"},
                            **_condition(
                                Attr("revision").eq(revision)
                                & Attr("policy_hash").eq(self.config.policy_hash)
                            ),
                        }
                    },
                    {
                        "Put": {
                            "TableName": self.config.state_table_arn,
                            "Item": {**result, "record_id": "ASSESSMENT"},
                            **_condition(
                                Attr("assessed_at_utc").not_exists()
                                | Attr("assessed_at_utc").lte(body["assessed_at_utc"])
                            ),
                        }
                    },
                    {
                        "Put": {
                            "TableName": self.config.state_table_arn,
                            "Item": {
                                **result,
                                "record_id": "a:" + str(revision) + ":" + digest(body),
                            },
                        }
                    },
                ]
            )
        except self.db.meta.client.exceptions.TransactionCanceledException:
            raise CollectionError("STATE_CHANGED_BEFORE_ASSESSMENT") from None

    def latest_assessment(self, now: str) -> dict[str, Any] | None:
        before = self.control()
        row = self.table.get_item(Key={"record_id": "ASSESSMENT"}, ConsistentRead=True).get("Item")
        after = self.control()
        if (
            not row
            or before["revision"] != after["revision"]
            or row.get("snapshot_revision") != after["revision"]
        ):
            return None
        try:
            body: dict[str, Any] = json.loads(row["body"])
            if not isinstance(body, dict):
                raise CollectionError("ASSESSMENT_INTEGRITY_FAILURE")
            if (
                row.get("assessment_hash") != digest(body)
                or row.get("policy_hash") != self.config.policy_hash
            ):
                raise CollectionError("ASSESSMENT_INTEGRITY_FAILURE")
            if (
                not 0
                <= (timestamp(now) - timestamp(body["assessed_at_utc"])).total_seconds()
                <= 130
            ):
                return None
            return body
        except (KeyError, TypeError, ValueError):
            raise CollectionError("ASSESSMENT_INTEGRITY_FAILURE") from None


class Collector:
    """No public payload-ingestion API: source identity comes from authenticated AWS reads."""

    def __init__(self, config: Configuration, session: Any = None):
        config.validate()
        self.config = config
        arn = TABLE_ARN.fullmatch(config.state_table_arn)
        assert arn is not None
        self.region = arn[2]
        self.session = session or boto3.Session(region_name=self.region)
        self.sts = self.session.client("sts", region_name=self.region, config=SDK_CONFIG)
        self.db = self.session.resource("dynamodb", region_name=self.region, config=SDK_CONFIG)

    def _authorize(self) -> Ledger:
        identity = self.sts.get_caller_identity()
        role = ROLE_ARN.fullmatch(self.config.collector_role_arn)
        if not role or identity["Account"] != role[2]:
            raise CollectionError("COLLECTOR_IDENTITY_REJECTED")
        try:
            source_for_principal(identity["Arn"], {"collector": self.config.collector_role_arn})
        except ValueError:
            raise CollectionError("COLLECTOR_IDENTITY_REJECTED") from None
        configured_role = self.session.client("iam", config=SDK_CONFIG).get_role(
            RoleName=self.config.collector_role_arn.rsplit("/", 1)[1]
        )["Role"]
        if (
            configured_role["Arn"] != self.config.collector_role_arn
            or configured_role["RoleId"] != identity["UserId"].split(":", 1)[0]
        ):
            raise CollectionError("COLLECTOR_IDENTITY_REJECTED")
        iam = self.session.client("iam", config=SDK_CONFIG)
        for _, arn in self.config.archive_roles:
            if iam.get_role(RoleName=arn.rsplit("/", 1)[1])["Role"]["Arn"] != arn:
                raise CollectionError("ARCHIVE_SOURCE_ROLE_REJECTED")
        for arn, key in [(s.table_arn, s.key) for s in self.config.sources] + [
            (self.config.state_table_arn, "record_id")
        ]:
            description = self.db.meta.client.describe_table(TableName=arn)["Table"]
            if (
                description["TableArn"] != arn
                or description["TableStatus"] != "ACTIVE"
                or description["KeySchema"] != [{"AttributeName": key, "KeyType": "HASH"}]
                or description["AttributeDefinitions"]
                != [{"AttributeName": key, "AttributeType": "S"}]
            ):
                raise CollectionError("SOURCE_RESOURCE_IDENTITY_REJECTED")
        return Ledger(self.db, self.config)

    def collect_all(self, now: str | None = None) -> dict[str, Any]:
        observed = timestamp(now or utcnow()).isoformat()
        try:
            ledger = self._authorize()
            counts = {name: 0 for name in ("accepted", "duplicate", "quarantined", "ignored")}
            for source in self.config.sources:
                count, ok, reason = 0, True, "READ_COMPLETED_NOT_COMPLETENESS_ATTESTATION"
                try:
                    pages = self.db.meta.client.get_paginator("scan").paginate(
                        TableName=source.table_arn,
                        ConsistentRead=True,
                        PaginationConfig={"PageSize": 100},
                    )
                    for index, page in enumerate(pages):
                        if index >= self.config.max_pages:
                            ok, reason = False, "SOURCE_CAPACITY_EXCEEDED"
                            break
                        for item in page["Items"]:
                            count += 1
                            if count > self.config.max_records:
                                ok, reason = False, "SOURCE_CAPACITY_EXCEEDED"
                                break
                            native_id = item.get(source.key)
                            if not isinstance(native_id, str) or len(native_id) > 256:
                                ok, reason = False, "INVALID_NATIVE_ID"
                                break
                            try:
                                normalized = normalize(
                                    source.source_id,
                                    source.contract,
                                    source.table_arn,
                                    native_id,
                                    item,
                                    self.config.archive_roles,
                                )
                                result = ledger.remember(source, native_id, normalized, observed)
                            except InvalidRecord:
                                result = ledger.remember(
                                    source, native_id, None, observed, invalid=True
                                )
                            counts[result] += 1
                        if not ok:
                            break
                except (BotoCoreError, ClientError):
                    ok, reason = False, "SOURCE_READ_UNAVAILABLE"
                ledger.mark_collection(source, observed, ok, reason)
            return {
                "counts": counts,
                "coverage_complete": False,
                "coverage_scope": (
                    "observed ledger only; scan success is not a completeness attestation"
                ),
            }
        except (BotoCoreError, ClientError):
            raise CollectionError("COLLECTION_UNAVAILABLE") from None

    def reconcile(self, now: str | None = None) -> dict[str, Any]:
        from sealed_telemetry.four_stage_iber import prepare

        observed = timestamp(now or utcnow()).isoformat()
        self.collect_all(observed)
        try:
            ledger = self._authorize()
            control, rows = ledger.snapshot()
            result = prepare(self.config, control, rows, observed)
            ledger.assessment(int(control["revision"]), result)
            return result
        except (BotoCoreError, ClientError):
            raise CollectionError("STATE_UNAVAILABLE") from None

    def latest_assessment(self, now: str | None = None) -> dict[str, Any] | None:
        try:
            return self._authorize().latest_assessment(timestamp(now or utcnow()).isoformat())
        except (BotoCoreError, ClientError):
            raise CollectionError("STATE_UNAVAILABLE") from None


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """New opt-in entrypoint; no template wiring or public payload-ingestion route."""
    if (
        not isinstance(event, dict)
        or set(event) != {"operation"}
        or not isinstance(event["operation"], str)
        or event["operation"] not in {"collect", "reconcile"}
    ):
        raise CollectionError("INVALID_COLLECTION_REQUEST")
    try:
        encoded = os.environ["C3_COLLECTION_CONFIG"]
        if len(encoded) > 16384:
            raise ValueError("configuration bound exceeded")
        raw = json.loads(encoded)
        sources = tuple(Source(**item) for item in raw.pop("sources"))
        config = Configuration(sources=sources, **raw)
        collector = Collector(config)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise CollectionError("INVALID_COLLECTION_CONFIGURATION") from None
    return collector.collect_all() if event["operation"] == "collect" else collector.reconcile()
