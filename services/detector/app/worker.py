"""JSON-lines detector entry point.

This executable provides a deterministic local development path before the broker
consumer is connected: one normalized JSON event per stdin line, one assessment per
stdout line. It is also convenient for test-lab replay.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from .domain import Event
from .engine import DetectionEngine
from .profiles import ProfileStore
from .rules import RuleEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    rules = RuleEngine.from_directory(repository_root / "policy" / "detection")
    engine = DetectionEngine(rules, ProfileStore())
    logging.info("detector ready; consuming JSON-lines events from stdin")

    for raw_event in sys.stdin:
        if not raw_event.strip():
            continue
        try:
            assessment = engine.assess(Event.from_dict(json.loads(raw_event)))
            print(json.dumps(assessment.to_dict()), flush=True)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            logging.warning("rejected invalid event: %s", error)


if __name__ == "__main__":
    main()
