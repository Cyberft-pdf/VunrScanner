import json
from dataclasses import asdict
from models import ScanResult


def save(result: ScanResult, path: str) -> None:
    data = asdict(result)
    data["timestamp"] = result.timestamp.isoformat()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
