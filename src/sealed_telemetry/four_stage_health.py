"""Independent operational observations, with missing metric data explicitly unknown."""

import json
import math
import os
from datetime import timedelta
from typing import Any
from uuid import uuid4

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.schema import timestamp, utcnow

SOURCES = {"gateway", "app", "provider", "collector"}


def classify(observation: dict[str, Any], now: str) -> str:
    if observation["diagnostic"] != "OBSERVED":
        return "unknown"
    if observation["function_state"] is None or observation["update_status"] is None:
        return "unknown"
    if observation["function_state"] != "Active" or observation["update_status"] != "Successful":
        return "unhealthy"
    metrics = observation["metrics"]
    if set(metrics) != {"Invocations", "Errors", "Throttles"}:
        return "unknown"
    times = {item["timestamp"] for item in metrics.values()}
    if len(times) != 1:
        return "unknown"
    # Preserve the AWS measurement time, never refresh an old datapoint with polling time.
    age = (timestamp(now) - timestamp(next(iter(times)))).total_seconds()
    if not 0 <= age <= 130:
        return "unknown"
    values = {name: item["sum"] for name, item in metrics.items()}
    if any(
        type(value) not in {int, float} or not math.isfinite(value) or value < 0
        for value in values.values()
    ):
        return "unknown"
    if values["Errors"] > 0 or values["Throttles"] > 0:
        return "unhealthy"
    return "healthy" if values["Invocations"] > 0 else "unknown"


def observe(functions: dict[str, str], now: str, session: Any = None) -> list[dict[str, Any]]:
    if set(functions) != SOURCES or len(set(functions.values())) != 4:
        raise ValueError("INVALID_HEALTH_CONFIGURATION")
    session = session or boto3.Session()
    client = session.client("lambda", config=SDK_CONFIG)
    cloudwatch = session.client("cloudwatch", config=SDK_CONFIG)
    records = []
    for source, arn in functions.items():
        observation: dict[str, Any] = {
            "event_id": str(uuid4()),
            "source_id": "health",
            "evidence_contract": "four-stage-health-4",
            "health_for_source": source,
            "function_arn": arn,
            "event_time_utc": now,
            "function_state": None,
            "update_status": None,
            "metrics": {},
            "diagnostic": "OBSERVATION_UNAVAILABLE",
        }
        try:
            state = client.get_function_configuration(FunctionName=arn)
            if state["FunctionArn"] != arn:
                raise ValueError("FUNCTION_IDENTITY_MISMATCH")
            observation.update(
                function_state=state.get("State"),
                update_status=state.get("LastUpdateStatus"),
                diagnostic="OBSERVED",
            )
            for metric in ("Invocations", "Errors", "Throttles"):
                result = cloudwatch.get_metric_statistics(
                    Namespace="AWS/Lambda",
                    MetricName=metric,
                    Dimensions=[{"Name": "FunctionName", "Value": arn.rsplit(":", 1)[1]}],
                    StartTime=timestamp(now) - timedelta(seconds=180),
                    EndTime=timestamp(now),
                    Period=60,
                    Statistics=["Sum"],
                )
                points = result["Datapoints"]
                if points:
                    latest = max(points, key=lambda point: point["Timestamp"])
                    observation["metrics"][metric] = {
                        "timestamp": latest["Timestamp"].isoformat(),
                        "sum": latest["Sum"],
                    }
        except (BotoCoreError, ClientError, KeyError, ValueError, TypeError):
            observation.update(diagnostic="OBSERVATION_UNAVAILABLE", metrics={})
        observation["source_health"] = classify(observation, now)
        records.append(observation)
    return records


def handler(event: dict[str, Any], context: Any) -> dict[str, str]:
    # No request-supplied statuses/functions/clocks. Separate monitor execution role.
    if event != {}:
        raise ValueError("INVALID_HEALTH_REQUEST")
    records = observe(json.loads(os.environ["C4_HEALTH_FUNCTIONS"]), utcnow())
    target = boto3.resource("dynamodb", config=SDK_CONFIG).Table(os.environ["C4_HEALTH_TABLE"])
    for record in records:
        # Native DynamoDB supports integral observations without float marshalling issues.
        from decimal import Decimal

        for item in record["metrics"].values():
            item["sum"] = Decimal(str(item["sum"]))
        target.put_item(Item=record, ConditionExpression=Attr("event_id").not_exists())
    return {record["health_for_source"]: record["source_health"] for record in records}
