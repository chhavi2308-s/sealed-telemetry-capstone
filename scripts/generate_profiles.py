"""Generate explicit two-account SAM profiles from the tested canonical laboratory template."""

import copy
import json
from pathlib import Path
from typing import Any


def ref(name: str) -> dict[str, str]:
    return {"Ref": name}


def sub(value: str) -> dict[str, str]:
    return {"Fn::Sub": value}


def profiles(template: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    security = copy.deepcopy(template)
    resources = security["Resources"]
    parameters = security["Parameters"]
    parameters["WorkloadAccountId"] = {"Type": "String", "AllowedPattern": "[0-9]{12}"}
    parameters["WorkloadStackName"] = {
        "Type": "String",
        "AllowedPattern": "[a-zA-Z][a-zA-Z0-9-]{0,39}",
    }
    app_arn = sub(
        "arn:${AWS::Partition}:lambda:${AWS::Region}:${WorkloadAccountId}:function:${WorkloadStackName}-app"
    )
    app_role = sub("arn:${AWS::Partition}:iam::${WorkloadAccountId}:role/${WorkloadStackName}-app")
    observation_role = sub(
        "arn:${AWS::Partition}:iam::${WorkloadAccountId}:role/${WorkloadStackName}-observation"
    )
    workload_names = {
        "AppFunction",
        "AppRole",
        "AppPolicy",
        "AppLogs",
        "AppLogPolicy",
        "WorkloadBoundary",
    }
    workload_resources = {k: copy.deepcopy(resources.pop(k)) for k in sorted(workload_names)}
    resources.pop("AppErrorAlarm")
    resources.pop("PlatformPermissionAppLogs")
    resources.pop("SubscriptionAppLogs")
    for name in ["GatewayRole", "HealthRole"]:
        resources[name]["Properties"]["RoleName"] = sub(
            "${AWS::StackName}-" + name.removesuffix("Role").lower()
        )

    # Replace exact app references without allowing unbounded cross-account resources.
    def replace(value: Any) -> Any:
        if value == {"Ref": "AppFunction"} or value == {"Fn::GetAtt": ["AppFunction", "Arn"]}:
            return app_arn
        if value == {"Fn::GetAtt": ["AppRole", "Arn"]}:
            return app_role
        if isinstance(value, dict):
            return {k: replace(v) for k, v in value.items()}
        if isinstance(value, list):
            return [replace(v) for v in value]
        return value

    security = replace(security)
    resources = security["Resources"]
    deny = resources["ArchivePolicy"]["Properties"]["PolicyDocument"]["Statement"][1]
    deny["Principal"] = "*"
    deny["Condition"] = {"ArnEquals": {"aws:PrincipalArn": app_role}}
    variables = resources["PlatformIngestFunction"]["Properties"]["Environment"]["Variables"]
    bindings = variables["ALLOWED_LOG_GROUPS"]["Fn::Sub"]
    bindings[0] = bindings[0].replace('"${A}",', "")
    bindings[1].pop("A")
    # Security trail selects security-owned functions; workload has its own trail below.
    resources["SupportedApiTrail"]["Properties"]["AdvancedEventSelectors"][1]["FieldSelectors"][2][
        "Equals"
    ] = [
        v
        for v in resources["SupportedApiTrail"]["Properties"]["AdvancedEventSelectors"][1][
            "FieldSelectors"
        ][2]["Equals"]
        if v != app_arn
    ]
    hp = resources["HealthPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    hp[0]["Resource"] = [v for v in hp[0]["Resource"] if v != app_arn]
    hp.append({"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": observation_role})
    resources["HealthFunction"]["Properties"]["Environment"]["Variables"][
        "WORKLOAD_OBSERVATION_ROLE"
    ] = observation_role
    resources["IntakeApi"]["Properties"]["Auth"]["ResourcePolicy"] = {
        "CustomStatements": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": sub("arn:${AWS::Partition}:iam::${WorkloadAccountId}:root")},
                "Action": "execute-api:Invoke",
                "Resource": "execute-api:/lab/POST/evidence",
                "Condition": {"ArnEquals": {"aws:PrincipalArn": app_role}},
            }
        ]
    }
    resources["CrossAccountPlatformPolicy"] = {
        "Type": "AWS::SQS::QueuePolicy",
        "Properties": {
            "Queues": [ref("PlatformQueue")],
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": sub("arn:${AWS::Partition}:iam::${WorkloadAccountId}:root")
                        },
                        "Action": "sqs:SendMessage",
                        "Resource": {"Fn::GetAtt": ["PlatformQueue", "Arn"]},
                        "Condition": {
                            "ArnEquals": {
                                "aws:PrincipalArn": sub(
                                    "arn:${AWS::Partition}:iam::${WorkloadAccountId}:role/${WorkloadStackName}-telemetry"
                                )
                            }
                        },
                    }
                ],
            },
        },
    }
    # Merge resource grants into the queue's existing transport policy (one policy per queue).
    resources["PlatformQueueTransportPolicy"]["Properties"]["PolicyDocument"]["Statement"] += (
        resources.pop("CrossAccountPlatformPolicy")["Properties"]["PolicyDocument"]["Statement"]
    )
    outputs = security["Outputs"]
    outputs["WorkloadIntakeArn"] = {
        "Value": sub(
            "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${IntakeApi}/lab/POST/evidence"
        )
    }
    outputs["PlatformQueueUrl"] = {"Value": ref("PlatformQueue")}
    outputs["PlatformQueueArn"] = {"Value": {"Fn::GetAtt": ["PlatformQueue", "Arn"]}}
    outputs["SaasRecordsUrl"] = {
        "Value": sub("https://${SaasApi}.execute-api.${AWS::Region}.${AWS::URLSuffix}/lab/records")
    }
    workload = {
        k: copy.deepcopy(template[k]) for k in ["AWSTemplateFormatVersion", "Transform", "Globals"]
    }
    workload["Description"] = (
        "Sealed-Telemetry compromisable workload account; no security evidence write/delete access"
    )
    workload["Parameters"] = {
        k: copy.deepcopy(template["Parameters"][k])
        for k in ["Owner", "ExpiresOn", "EnableSupplementary", "LabExposureEnabled", "Quiesce"]
    }
    workload["Parameters"].update(
        {
            k: {"Type": "String"}
            for k in [
                "SecurityAccountId",
                "SecurityStackName",
                "IntakeUrl",
                "IntakeArn",
                "SaasRecordsUrl",
                "PlatformQueueUrl",
                "PlatformQueueArn",
            ]
        }
    )
    workload["Parameters"]["SecurityAccountId"]["AllowedPattern"] = "[0-9]{12}"
    workload["Conditions"] = {
        k: copy.deepcopy(template["Conditions"][k]) for k in ["SupplementaryEnabled"]
    }
    wr = workload["Resources"] = workload_resources
    wr["AppRole"]["Properties"]["RoleName"] = sub("${AWS::StackName}-app")
    wr["AppFunction"]["Properties"]["FunctionName"] = sub("${AWS::StackName}-app")
    wr["AppFunction"]["Properties"]["Environment"]["Variables"] = {
        "INTAKE_URL": ref("IntakeUrl"),
        "SAAS_URL": ref("SaasRecordsUrl"),
        "LAB_EXPOSURE_ENABLED": ref("LabExposureEnabled"),
        "QUIESCED": ref("Quiesce"),
    }
    wr["AppPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]["Resource"] = ref("IntakeArn")
    wr["WorkloadBoundary"]["Properties"]["PolicyDocument"]["Statement"][1]["Resource"] = ref(
        "IntakeArn"
    )
    wr["GatewayInvokePermission"] = {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": ref("AppFunction"),
            "Principal": sub(
                "arn:${AWS::Partition}:iam::${SecurityAccountId}:role/${SecurityStackName}-gateway"
            ),
        },
    }
    wr["ObservationRole"] = {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "RoleName": sub("${AWS::StackName}-observation"),
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "sts:AssumeRole",
                        "Principal": {
                            "AWS": sub("arn:${AWS::Partition}:iam::${SecurityAccountId}:root")
                        },
                        "Condition": {
                            "ArnEquals": {
                                "aws:PrincipalArn": sub(
                                    "arn:${AWS::Partition}:iam::${SecurityAccountId}:role/${SecurityStackName}-health"
                                )
                            }
                        },
                    }
                ],
            },
            "Policies": [
                {
                    "PolicyName": "ReadWorkloadAvailability",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["lambda:GetFunctionConfiguration"],
                                "Resource": {"Fn::GetAtt": ["AppFunction", "Arn"]},
                            }
                        ],
                    },
                }
            ],
        },
    }
    for name in [
        "PlatformIngestFunction",
        "PlatformIngestRole",
        "PlatformIngestPolicy",
        "PlatformIngestLogs",
        "PlatformPermissionAppLogs",
        "SubscriptionAppLogs",
    ]:
        wr[name] = copy.deepcopy(template["Resources"][name])
    wr["PlatformIngestRole"]["Properties"]["RoleName"] = sub("${AWS::StackName}-telemetry")
    pf = wr["PlatformIngestFunction"]["Properties"]
    pf.pop("EventInvokeConfig", None)
    pf["Environment"]["Variables"] = {
        "PLATFORM_QUEUE_URL": ref("PlatformQueueUrl"),
        "ALLOWED_LOG_GROUPS": {"Fn::Sub": ['["${A}"]', {"A": ref("AppLogs")}]},
    }
    wr["PlatformIngestPolicy"]["Properties"]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": ref("PlatformQueueArn")},
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": {"Fn::GetAtt": ["PlatformIngestLogs", "Arn"]},
        },
    ]
    workload["Parameters"]["SecurityTrailBucketName"] = {"Type": "String"}
    workload["Conditions"]["TrailEnabled"] = copy.deepcopy(template["Conditions"]["TrailEnabled"])
    workload["Conditions"]["Quiesced"] = copy.deepcopy(template["Conditions"]["Quiesced"])
    trail = copy.deepcopy(template["Resources"]["SupportedApiTrail"])
    trail.pop("DependsOn", None)
    trail["Properties"]["S3BucketName"] = ref("SecurityTrailBucketName")
    trail["Properties"]["AdvancedEventSelectors"][1]["FieldSelectors"][2]["Equals"] = [
        {"Fn::GetAtt": ["AppFunction", "Arn"]}
    ]
    wr["WorkloadTrail"] = trail
    # Only CloudTrail service delivery from the exact workload trail can append native logs.
    statements = resources["TrailBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    for statement in list(statements):
        if (
            statement.get("Effect") == "Allow"
            and statement.get("Principal", {}).get("Service") == "cloudtrail.amazonaws.com"
        ):
            cross = copy.deepcopy(statement)
            cross["Condition"]["StringEquals"]["aws:SourceArn"] = sub(
                "arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${WorkloadAccountId}:trail/${WorkloadStackName}-aws-api"
            )
            if isinstance(cross["Resource"], dict) and "Fn::Sub" in cross["Resource"]:
                cross["Resource"]["Fn::Sub"] = cross["Resource"]["Fn::Sub"].replace(
                    "${AWS::AccountId}", "${WorkloadAccountId}"
                )
            statements.append(cross)
    notifications = resources["TrailBucket"]["Properties"]["NotificationConfiguration"][
        "LambdaConfigurations"
    ]
    notification = copy.deepcopy(notifications[0])
    for rule in notification["Filter"]["S3Key"]["Rules"]:
        if rule["Name"] == "prefix":
            rule["Value"] = sub("AWSLogs/${WorkloadAccountId}/CloudTrail/")
    notifications.append(notification)
    return security, workload


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    security, workload = profiles(
        json.loads((root / "infra/template.yaml").read_text(encoding="utf-8"))
    )
    for name, template in [("security", security), ("workload", workload)]:
        (root / f"infra/{name}.yaml").write_text(
            json.dumps(template, indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
