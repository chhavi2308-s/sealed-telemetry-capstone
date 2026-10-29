from sealed_telemetry.lab import run_scenario
from sealed_telemetry.schema import canonical


def test_copied_binding_and_benign_retry_are_observational_twins(tmp_path):
    attack = run_scenario(tmp_path / "attack", "bound-replay", "2026-10-27T00:00:00+00:00")
    retry = run_scenario(tmp_path / "retry", "legitimate-retry", "2026-10-27T00:00:00+00:00")

    # Preserve identifier equality and semantic fields; random UUID order has no meaning.
    def view(report):
        rows = sorted(
            [r["event"] for r in report["timeline"]],
            key=lambda r: (r["source_id"], r["event_type"]),
        )
        names = {
            "event_id",
            "run_id",
            "credential_fingerprint",
            "invocation_id",
            "action_id",
            "provider_request_id",
        }
        mapping = {name: {} for name in names}
        output = []
        for row in rows:
            normalized = dict(row)
            for name in names:
                value = row.get(name)
                if value is not None:
                    mapping[name].setdefault(value, str(len(mapping[name])))
                    normalized[name] = mapping[name][value]
            output.append(normalized)
        return sorted(canonical(r) for r in output)

    assert view(attack) == view(retry)
    assert {d["state"] for d in attack["decisions"]} == {"INCONCLUSIVE"}
    assert {d["state"] for d in retry["decisions"]} == {"INCONCLUSIVE"}
