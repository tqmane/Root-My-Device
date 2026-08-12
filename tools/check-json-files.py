#!/usr/bin/env python3
"""Parse every main-repository JSON file, excluding Git/submodule internals."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for path in ROOT.rglob("*.json"):
    relative = path.relative_to(ROOT)
    if ".git" in relative.parts or relative.parts[:2] == ("src", "kernelsu"):
        continue
    json.loads(path.read_text(encoding="utf-8"))
    print(relative)
