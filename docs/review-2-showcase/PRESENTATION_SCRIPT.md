# Review-2 presentation script

Target duration14minutes including three-minute demonstration. Read the spoken paragraphs and pause at each evidence view. Replace local status only after recorded AWS acceptance.

## 0:00–1:00 Introduction

My project is Sealed-Telemetry. It asks whether independent provider evidence can reveal unauthorized OAuth-token use when a compromised serverless application omits its own security logs. I will distinguish what runs locally from what has been verified in AWS.

## 1:00–2:00 Problem

OAuth bearer tokens can be reused by anyone who possesses them while they remain valid. A successful API response tells the provider that the credential was accepted; it does not establish that the intended application made the request. Application-only logs are weak evidence if that application is compromised.

## 2:00–3:00 Threat model

The attacker controls disposable workload code and a copied synthetic credential. The security evidence owner and provider control plane remain outside that compromise. We do not attack real services. Separate accounts are the final isolation candidate; same-account sandbox roles share an administrator boundary.

## 3:00–4:00 Research question

The gap investigated here is incomplete invocation-bound reconstruction under missing and delayed evidence. I do not claim that event correlation is new. The evaluated mechanism combines expected actions, independent observations, deadlines, health and explicit uncertainty. A novelty claim needs further literature and comparative evidence.

## 4:00–5:30 IBER

The gateway records intent. Provider observations carry request identifiers and credential pseudonyms. The detector searches bounded identifiers and time windows, waits for deadlines and produces pending, consistent, suspicious, corroborated or inconclusive states. Missing app logs alone do not prove token theft. Late observations append revisions rather than overwrite the historical explanation.

## 5:30–7:00 Architecture

API Gateway invokes Lambda; the application calls the synthetic OAuth-protected SaaS API. Provider audits enter a separate outbox and queue. Authenticated intake, SQS buffering, DynamoDB indexing and versioned encrypted S3 preserve evidence. CloudTrail supplies supported AWS API observations, not arbitrary SaaS requests. Platform telemetry is supplementary and not tamperproof.

## 7:00–8:00 Implemented controls

The implementation includes source-bound authentication, idempotent archive/index repair, DLQ recovery, health monitoring, decision history and operator-gated response. Approval must reference the current decision. Revocation success is established by probing the provider, not by trusting a function return value.

## 8:00–11:00 Demonstration

First I show a normal request and matching evidence. Next I replay a disposable test token while suppressing the application security event. I show the independent provider record and the evidence-backed finding. Finally I show benign logging failure as inconclusive. Until AWS acceptance is recorded I explicitly present this as a local synthetic demonstration and use the saved reports, not an invented AWS recording. During each step I pause to identify request IDs, evidence IDs, state and integrity verification.

## 11:00–12:00 Results

The current full suite reports107 passing tests. The primary synthetic study has180 unique test runs. IBER observes45 true positives,15 false negatives, no false positives and120 true negatives: recall0.75 and F1 approximately0.857. Simulator detection medians are40seconds calibrated and45fixed; these are not cloud timings.

## 12:00–13:00 Limitations

Copied identifiers can make replay indistinguishable from legitimate retries. All15 misses are retained in the results. Source availability is not completeness, hashes are not truth and security-admin compromise is outside the threat model. Finite scenario families do not prove production performance or zero false positives.

## 13:00–14:00 Roadmap and conclusion

Remaining acceptance includes approved AWS deployment, real cross-account IAM denial, delivery outages, response/recovery, performance and billed cost. Retained evidence and keys need an explicit lifecycle. The demonstrated contribution is a reproducible way to reconcile independent observations and preserve uncertainty when evidence is insufficient.
