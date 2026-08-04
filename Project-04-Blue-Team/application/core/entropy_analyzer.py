from __future__ import annotations

import math
from collections import Counter
from pathlib import Path


def shannon_entropy(path: Path, limit: int = 2_000_000) -> float:
    data = path.read_bytes()[:limit]
    if not data:
        return 0.0
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in Counter(data).values())
