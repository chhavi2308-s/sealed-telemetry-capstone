"""Independent operational health monitor; availability is not proof of completeness."""

import json
import os
from datetime import timedelta
from typing import Any
from uuid import uuid4

import boto3
from boto3.dynamodb.conditions import Key

from sealed_telemetry.aws_support import SDK_CONFIG
from sealed_telemetry.cloud_lab import emit
from sealed_telemetry.schema import new_event, timestamp, utcnow


def monitor(event: dict[str, Any], context: Any) -> dict[str, str]:
    now = utcnow()
    services = json.loads(os.environ["MONITORED_FUNCTIONS"])
    health = {"app": "healthy", "gateway": "healthy", "provider": "healthy", "collector": "healthy"}
    lambda_client = boto3.client("lambda", config=SDK_CONFIG)
    workload_client = lambda_client
    if os.environ.get("WORKLOAD_OBSERVATION_ROLE"):
        credentials = boto3.client("sts", config=SDK_CONFIG).assume_role(
            RoleArn=os.environ["WORKLOAD_OBSERVATION_ROLE"], RoleSessionName="sealed-health"
        )["Credentials"]
        workload_client = boto3.client(
            "lambda",
            config=SDK_CONFIG,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    for source, functions in services.items():
        for function in functions:
            client = workload_client if source == "app" else lambda_client
            status = client.get_function_configuration(FunctionName=function)
            if status.get("State") != "Active" or status.get("LastUpdateStatus") == "Failed":
                health[source] = "unhealthy"
    sqs = boto3.client("sqs", config=SDK_CONFIG)
    for name in ("DLQ_URL", "AUDIT_FAILURE_URL"):
        attributes = sqs.get_queue_attributes(
            QueueUrl=os.environ[name], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]
        if int(attributes["ApproximateNumberOfMessages"]) > 0:
            health["collector" if name == "DLQ_URL" else "provider"] = "unhealthy"
    age = boto3.client("cloudwatch", config=SDK_CONFIG).get_metric_statistics(
        Namespace="AWS/SQS",
        MetricName="ApproximateAgeOfOldestMessage",
        Dimensions=[{"Name": "QueueName", "Value": os.environ["QUEUE_NAME"]}],
        StartTime=timestamp(now) - timedelta(minutes=5),
        EndTime=timestamp(now),
        Period=60,
        Statistics=["Maximum"],
    )["Datapoints"]
    if age and max(point["Maximum"] for point in age) > 120:
        health["collector"] = "unhealthy"
    for queue in json.loads(os.environ.get("MONITORED_QUEUES", "[]")):
        dead = sqs.get_queue_attributes(
            QueueUrl=queue["dlq"], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]
        lag = boto3.client("cloudwatch", config=SDK_CONFIG).get_metric_statistics(
            Namespace="AWS/SQS",
            MetricName="ApproximateAgeOfOldestMessage",
            Dimensions=[{"Name": "QueueName", "Value": queue["name"]}],
            StartTime=timestamp(now) - timedelta(minutes=5),
            EndTime=timestamp(now),
            Period=60,
            Statistics=["Maximum"],
        )["Datapoints"]
        if int(dead["ApproximateNumberOfMessages"]) or any(p["Maximum"] > 120 for p in lag):
            health[queue["source"]] = "unhealthy"
    pending = (
        boto3.resource("dynamodb", config=SDK_CONFIG)
        .Table(os.environ["OUTBOX_TABLE"])
        .query(
            IndexName="PendingIndex",
            KeyConditionExpression=Key("pending_partition").eq("pending"),
            Limit=1,
            ScanIndexForward=True,
        )
    )
    if any(
        (timestamp(now) - timestamp(item["created_at"])).total_seconds() > 120
        for item in pending["Items"]
    ):
        health["provider"] = "unhealthy"
    for source, state in health.items():
        emit(
            new_event(
                "health",
                "SOURCE_HEALTH",
                run_id=str(uuid4()),
                scenario_id="lab-v1",
                event_time_utc=now,
                actor_pseudonym="security-monitor",
                credential_fingerprint="0" * 64,
                operation="health:check",
                resource_pseudonym="lab-telemetry",
                health_for_source=source,
                source_health=state,
            )
        )
    return health
