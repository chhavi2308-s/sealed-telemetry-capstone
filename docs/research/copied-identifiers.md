# Copied-identifier false negatives

The original two unflagged attack trials were bound-replay: the external client copied invocation/action IDs belonging to an authorized provider request. IBER returned INCONCLUSIVE when two observations competed for one trusted expectation.

`tests/test_identifiability.py` runs the actual local provider for bound-replay and legitimate-retry. Replacing independent random UUIDs while preserving equality relationships leaves identical semantic detector input. Both cases remain INCONCLUSIVE; only external ground truth differs. This is an observational identifiability limitation under propagated identifiers, not a threshold defect. Flagging all duplicates also flags legitimate retries. No threshold was weakened and no attack was relabelled benign.

Stronger deployments could require provider-enforced single-use authorization tickets or distinguish retries through trusted provider semantics. That changes the protocol and prevention mechanism; it is not silently assumed here. Platform metadata and healthy collectors cannot recover an unavailable initiating-party distinction.

The 210-run parameter-holdout stress distribution retains 15 copied-ID false negatives among 45 attacks. This post-development synthetic evaluation is not blind independent validation. Detector inputs and labels are stored separately; virtual timing, uncertainty and Wilson intervals are reported. All cloud latency, containment latency, invocation overhead and billed-cost values remain null.
