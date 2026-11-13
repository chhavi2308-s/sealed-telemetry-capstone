"""Offline contracts for the version-controlled C2/C4 CloudFormation source."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

TEMPLATE = Path(__file__).parents[1] / "infra" / "four-stage-c2c4.yaml"
LEGACY_TEMPLATE = Path(__file__).parents[1] / "infra" / "four-stage.yaml"


class CloudFormationLoader(yaml.SafeLoader):
    """Accept CloudFormation short-form tags without resolving deployment values."""


def _intrinsic(loader: CloudFormationLoader, suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{suffix}": value}


CloudFormationLoader.add_multi_constructor("!", _intrinsic)


def template() -> dict[str, Any]:
    loader = CloudFormationLoader(TEMPLATE.read_text(encoding="utf-8"))
    try:
        document = loader.get_single_data()
        assert isinstance(document, dict)
        return document
    finally:
        loader.dispose()


def legacy_template() -> dict[str, Any]:
    document = json.loads(LEGACY_TEMPLATE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(flatten(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(flatten(item) for item in value)
    return str(value)


def policy_actions(resource: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for policy in resource["Properties"]["Policies"]:
        candidate = policy
        if isinstance(policy, dict) and "Fn::If" in policy:
            candidate = policy["Fn::If"][1]
        if not isinstance(candidate, dict) or "PolicyDocument" not in candidate:
            continue
        for statement in candidate["PolicyDocument"]["Statement"]:
            actions = statement["Action"]
            values.update(actions if isinstance(actions, list) else [actions])
    return values


def baseline_policy(resource: dict[str, Any]) -> dict[str, Any]:
    return next(
        policy["PolicyDocument"]
        for policy in resource["Properties"]["Policies"]
        if isinstance(policy, dict) and policy.get("PolicyName") == "FourStageOnly"
    )


def resource_text(value: Any) -> str:
    if isinstance(value, dict):
        if "Fn::GetAtt" in value:
            attribute = value["Fn::GetAtt"]
            return ".".join(attribute) if isinstance(attribute, list) else str(attribute)
        if "Fn::Sub" in value:
            return str(value["Fn::Sub"])
        if "Ref" in value:
            return f"Ref:{value['Ref']}"
        if "Fn::Ref" in value:
            return f"Ref:{value['Fn::Ref']}"
    return str(value)


def permission_pairs(policy: dict[str, Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for statement in policy["Statement"]:
        actions = statement["Action"]
        resources = statement["Resource"]
        for action in actions if isinstance(actions, list) else [actions]:
            for resource in resources if isinstance(resources, list) else [resources]:
                pairs.add((action, resource_text(resource)))
    return pairs


def tag_values(tags: list[dict[str, Any]]) -> dict[str, str]:
    return {tag["Key"]: resource_text(tag["Value"]) for tag in tags}


def test_safe_defaults_and_required_resource_contract() -> None:
    document = template()
    parameters = document["Parameters"]
    assert parameters["GrantProducerEvidencePermissions"]["Default"] == "false"
    assert parameters["EvidenceMode"]["Default"] == "legacy"
    assert parameters["ContextMode"]["Default"] == "disabled"
    resources = document["Resources"]
    required = {
        "UploadApi",
        "AuthorizationFunction",
        "ApplicationFunction",
        "IssuerFunction",
        "SaasFunction",
        "IssuanceEvidence",
        "C4GatewayContext",
        "C4ApplicationContext",
        "C4ProviderContext",
        "C4IndependentHealth",
        "C4EvidenceState",
        "C4CollectorFunction",
        "C4MonitorFunction",
    }
    assert required <= set(resources)


def test_context_mode_rule_rejects_c4_without_c2() -> None:
    rule = template()["Rules"]["ContextModeRequiresC2"]
    assert rule["RuleCondition"] == {"Fn::Equals": [{"Fn::Ref": "ContextMode"}, "c4"]}
    assert rule["Assertions"] == [
        {
            "Assert": {"Fn::Equals": [{"Fn::Ref": "EvidenceMode"}, "c2"]},
            "AssertDescription": "ContextMode c4 requires EvidenceMode c2.",
        }
    ]

    def permitted(context: str, evidence: str) -> bool:
        return context != "c4" or evidence == "c2"

    assert permitted("disabled", "legacy")
    assert permitted("disabled", "c2")
    assert permitted("c4", "c2")
    assert not permitted("c4", "legacy")


def test_new_evidence_tables_are_encrypted_and_retained() -> None:
    resources = template()["Resources"]
    names = {
        "IssuanceEvidence": "${AWS::StackName}-IssuanceEvidence",
        "C4GatewayContext": "${AWS::StackName}-C4GatewayContext",
        "C4ApplicationContext": "${AWS::StackName}-C4ApplicationContext",
        "C4ProviderContext": "${AWS::StackName}-C4ProviderContext",
        "C4IndependentHealth": "${AWS::StackName}-C4IndependentHealth",
        "C4EvidenceState": "${AWS::StackName}-C4EvidenceState",
    }
    for name, expected_name in names.items():
        resource = resources[name]
        assert resource["DeletionPolicy"] == "Retain"
        assert resource["UpdateReplacePolicy"] == "Retain"
        assert resource["Properties"]["DeletionProtectionEnabled"] is True
        assert resource["Properties"]["TableName"] == {"Fn::Sub": expected_name}
        assert resource["Properties"]["SSESpecification"] == {"SSEEnabled": True}
        assert tag_values(resource["Properties"]["Tags"]) == {
            "Project": "SealedTelemetryFourStage",
            "Owner": "Ref:Owner",
            "ExpiresOn": "Ref:ExpiresOn",
        }
    assert resources["ExpectedActions"]["Properties"]["SSESpecification"] == {"SSEEnabled": False}


def test_legacy_table_tags_are_preserved_exactly() -> None:
    legacy = legacy_template()["Resources"]
    current = template()["Resources"]
    for name in ("ExpectedActions", "OAuthTokens", "SaasAudit"):
        assert tag_values(current[name]["Properties"]["Tags"]) == tag_values(
            legacy[name]["Properties"]["Tags"]
        )
        for property_name in (
            "BillingMode",
            "AttributeDefinitions",
            "KeySchema",
            "SSESpecification",
            "TimeToLiveSpecification",
        ):
            assert (
                current[name]["Properties"][property_name]
                == legacy[name]["Properties"][property_name]
            )


def test_legacy_producer_permissions_are_exactly_preserved() -> None:
    legacy = legacy_template()["Resources"]
    current = template()["Resources"]
    for role in ("AuthorizationRole", "ApplicationRole", "IssuerRole", "SaasRole"):
        assert permission_pairs(baseline_policy(current[role])) == permission_pairs(
            legacy[role]["Properties"]["Policies"][0]["PolicyDocument"]
        )


def test_deployment_owned_table_arn_bindings_are_intrinsic() -> None:
    resources = template()["Resources"]
    application = resources["ApplicationFunction"]["Properties"]["Environment"]["Variables"]
    issuer = resources["IssuerFunction"]["Properties"]["Environment"]["Variables"]
    assert application["EXPECTED_TABLE_ARN"] == {"Fn::GetAtt": "ExpectedActions.Arn"}
    assert application["ISSUANCE_TABLE_ARN"] == {"Fn::GetAtt": "IssuanceEvidence.Arn"}
    assert issuer["EXPECTED_TABLE_ARN"] == {"Fn::GetAtt": "ExpectedActions.Arn"}


def test_private_observer_and_producer_environment_contracts() -> None:
    resources = template()["Resources"]
    handlers = {
        "AuthorizationFunction": "sealed_telemetry.four_stage.authorization",
        "ApplicationFunction": "sealed_telemetry.four_stage.app",
        "IssuerFunction": "sealed_telemetry.four_stage.issuer",
        "SaasFunction": "sealed_telemetry.four_stage.saas",
        "C4CollectorFunction": "sealed_telemetry.four_stage_collection.handler",
        "C4MonitorFunction": "sealed_telemetry.four_stage_health.handler",
    }
    for function, handler in handlers.items():
        assert resources[function]["Properties"]["Handler"] == handler
    collector = resources["C4CollectorFunction"]["Properties"]
    monitor = resources["C4MonitorFunction"]["Properties"]
    assert collector["ReservedConcurrentExecutions"] == 1
    assert monitor["ReservedConcurrentExecutions"] == 1
    config = collector["Environment"]["Variables"]["C3_COLLECTION_CONFIG"]
    for logical_id in (
        "ExpectedActions",
        "IssuanceEvidence",
        "SaasAudit",
        "C4GatewayContext",
        "C4ApplicationContext",
        "C4ProviderContext",
        "C4IndependentHealth",
        "C4EvidenceState",
    ):
        assert logical_id in flatten(config)
    assert "C4IndependentHealth" in flatten(monitor["Environment"])


def test_transaction_and_observer_permissions_are_explicit_and_bounded() -> None:
    resources = template()["Resources"]
    assert "dynamodb:TransactWriteItems" in policy_actions(resources["IssuerRole"])
    assert "dynamodb:TransactWriteItems" in policy_actions(resources["C4CollectorRole"])
    collector = flatten(resources["C4CollectorRole"])
    monitor = flatten(resources["C4MonitorRole"])
    assert "OAuthTokens" not in collector
    assert "secretsmanager:GetSecretValue" not in collector
    assert "secretsmanager:GetSecretValue" not in monitor
    assert "C4IndependentHealth" in monitor
    for role in ("C4CollectorRole", "C4MonitorRole"):
        assert tag_values(resources[role]["Properties"]["Tags"]) == {
            "Project": "SealedTelemetryFourStage",
            "Owner": "Ref:Owner",
            "ExpiresOn": "Ref:ExpiresOn",
        }


def test_secret_kms_decrypt_is_constrained_to_secrets_manager_contexts() -> None:
    resources = template()["Resources"]
    expected_contexts = {
        "AuthorizationRole": [{"Fn::Ref": "IdentitySecretArn"}],
        "ApplicationRole": [{"Fn::Ref": "ContextSecretArn"}],
        "IssuerRole": [{"Fn::Ref": "IdentitySecretArn"}, {"Fn::Ref": "CredentialSecretArn"}],
        "SaasRole": [{"Fn::Ref": "ContextSecretArn"}],
    }
    for role, expected_context in expected_contexts.items():
        conditional = next(
            entry["Fn::If"][1]
            for entry in resources[role]["Properties"]["Policies"]
            if "Fn::If" in entry
        )
        statements = conditional["PolicyDocument"]["Statement"]
        decrypt = next(
            statement for statement in statements if statement["Action"] == ["kms:Decrypt"]
        )
        assert decrypt["Resource"] == "*"
        conditions = decrypt["Condition"]
        assert conditions["StringEquals"]["kms:ViaService"] == {
            "Fn::Sub": "secretsmanager.${AWS::Region}.${AWS::URLSuffix}"
        }
        context = conditions.get("ForAnyValue:StringEquals", conditions["StringEquals"])[
            "kms:EncryptionContext:SecretARN"
        ]
        if len(expected_context) == 1:
            assert context == expected_context[0]
        else:
            assert context == expected_context


def test_private_observers_have_no_routes_function_urls_or_schedules() -> None:
    resources = template()["Resources"]
    for name in ("C4CollectorFunction", "C4MonitorFunction"):
        properties = resources[name]["Properties"]
        assert "Events" not in properties
        assert "FunctionUrlConfig" not in properties
    assert not any(
        resource["Type"] in {"AWS::Events::Rule", "AWS::Scheduler::Schedule"}
        for resource in resources.values()
    )
    assert set(resources["UploadApi"]["Properties"]["Auth"]) >= {
        "EnableIamAuthorizer",
        "DefaultAuthorizer",
    }
    assert not any(
        resource["Type"] in {"AWS::S3::Bucket", "AWS::SQS::Queue"}
        for resource in resources.values()
    )


def test_parameters_are_identifiers_not_deployment_specific_arns_or_secret_values() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "arn:aws:" not in text
    assert "AKIA" not in text
    assert "BEGIN PRIVATE KEY" not in text
    parameters = template()["Parameters"]
    for name in ("IdentitySecretArn", "CredentialSecretArn", "ContextSecretArn"):
        assert "Default" not in parameters[name]
        assert "secretsmanager" in parameters[name]["AllowedPattern"]


def test_producer_evidence_policies_remain_conditionally_gated() -> None:
    resources = template()["Resources"]
    for role in ("AuthorizationRole", "ApplicationRole", "IssuerRole", "SaasRole"):
        conditions = [
            entry for entry in resources[role]["Properties"]["Policies"] if "Fn::If" in entry
        ]
        assert len(conditions) == 1
        assert conditions[0]["Fn::If"][0] == "GrantProducerPermissions"


def test_legacy_logical_resources_and_api_shape_are_continuous() -> None:
    resources = template()["Resources"]
    for name in (
        "UploadApi",
        "ExpectedActions",
        "OAuthTokens",
        "SaasAudit",
        "UploadApiAccessLogs",
    ):
        assert name in resources
    access_log = resources["UploadApi"]["Properties"]["AccessLogSettings"]
    assert "UploadApiAccessLogs" in flatten(access_log["DestinationArn"])
    assert "requestId=" in access_log["Format"]
    assert "body" not in access_log["Format"].lower()
    authorization = resources["AuthorizationFunction"]["Properties"]
    assert authorization["Events"]["Upload"]["Properties"]["Path"] == "/upload"
    assert authorization["Events"]["Upload"]["Properties"]["Method"] == "POST"
