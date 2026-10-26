"""Calibrate deadlines from independently collected benign delivery delays in seconds."""

import argparse
import json
from pathlib import Path

from sealed_telemetry.measurements import calibrate


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--quantile", type=float, default=0.95)
    p.add_argument("--margin", type=float, default=1.0)
    args = p.parse_args()
    data = json.loads(args.input.read_text())
    result = {
        "calibration_source": str(args.input),
        "deadlines": calibrate(data, probability=args.quantile, margin=args.margin),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
