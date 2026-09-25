"""Generate harmless, repeatable telemetry for local laboratory validation."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_PATH = Path("/workspace/data/events.jsonl")
HEARTBEAT_PATH = Path("/workspace/data/heartbeat")
INTERVAL_SECONDS = float(os.getenv("EVENT_INTERVAL_SECONDS", "5"))


def create_event(sequence: int) -> dict[str, object]:
    return {
        "event_id": f"synthetic-{sequence:06d}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "synthetic-lab-generator",
        "event_type": "authentication",
        "outcome": "failure" if sequence % 3 == 0 else "success",
        "src_ip": "192.0.2.10",
        "user": "lab-user",
        "synthetic": True,
    }


def main() -> None:
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    sequence = 1

    while True:
        event = create_event(sequence)
        with OUTPUT_PATH.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event, sort_keys=True) + "\n")
        HEARTBEAT_PATH.write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
        sequence += 1
        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
