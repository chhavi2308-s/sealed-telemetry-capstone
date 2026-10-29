from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from scripts.cleanup import plan
from scripts.cloud_acceptance import run
from scripts.preflight import inspect


def test_preflight_account_mismatch_fails_before_other_checks():
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "wrong"}
    with pytest.raises(ValueError, match="Account mismatch"):
        inspect(session, Namespace(account="123456789012"))
    assert session.client.call_count == 1


def test_live_runner_never_calls_aws_without_approval_flag(tmp_path):
    with patch("scripts.cloud_acceptance.boto3.Session") as session:
        with pytest.raises(ValueError, match="execute-approved"):
            run(Namespace(execute_approved=False, output=tmp_path / "results"))
        session.assert_not_called()
        assert not (tmp_path / "results").exists()


def test_cleanup_reports_pending_data_and_retained_resources():
    session = MagicMock()
    clients = {name: MagicMock() for name in ["sts", "cloudformation", "sqs", "stepfunctions"]}
    session.client.side_effect = lambda name, **kw: clients[name]
    clients["sts"].get_caller_identity.return_value = {"Account": "123456789012"}
    cfn = clients["cloudformation"]
    cfn.describe_stacks.return_value = {
        "Stacks": [
            {
                "StackId": "stack-arn",
                "Tags": [{"Key": "Project", "Value": "SealedTelemetry"}],
                "Parameters": [{"ParameterKey": "Quiesce", "ParameterValue": "false"}],
            }
        ]
    }
    cfn.get_paginator.return_value.paginate.return_value = [
        {
            "StackResourceSummaries": [
                {
                    "LogicalResourceId": "DLQ",
                    "PhysicalResourceId": "queue",
                    "ResourceType": "AWS::SQS::Queue",
                }
            ]
        }
    ]
    cfn.get_template.return_value = {
        "TemplateBody": {"Resources": {"Archive": {"DeletionPolicy": "Retain"}, "DLQ": {}}}
    }
    clients["sqs"].get_queue_attributes.return_value = {
        "Attributes": {"ApproximateNumberOfMessages": "1"}
    }
    result = plan(session, "123456789012", "stack")
    assert result["retained"] == ["Archive"]
    assert len(result["blockers"]) == 2
    cfn.delete_stack.assert_not_called()
