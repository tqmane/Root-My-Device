#!/usr/bin/env python3
"""Check the optimized Pad 3 reclaim call ordering in an unstripped payload."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


def run(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stderr.strip()}"
        )
    return result.stdout


def normalized_target(target: str) -> str:
    return target.split("+", 1)[0].removesuffix("@plt")


def verify(disassembly: str, binary: bytes) -> list[str]:
    errors: list[str] = []
    calls: list[tuple[int, str]] = []
    for index, line in enumerate(disassembly.splitlines()):
        match = re.search(r"\bbl\s+[^<]*<([^>]+)>", line)
        if match:
            calls.append((index, normalized_target(match.group(1))))

    def call_index(name: str, start: int = 0) -> int:
        for index in range(start, len(calls)):
            if calls[index][1] == name:
                return index
        return -1

    capacity = call_index("pad3_reclaim_capacity_exact")
    target_close = call_index("close", capacity + 1)
    first_send = call_index("sendmsg", target_close + 1)
    if min(capacity, target_close, first_send) < 0:
        errors.append("capacity/target-close/first-send call sequence is missing")
    else:
        between_close_and_send = calls[target_close + 1 : first_send]
        if between_close_and_send:
            errors.append(
                "optimized target close is not immediately followed by sendmsg: "
                + ",".join(target for _, target in between_close_and_send)
            )
        if any(
            target == "sched_yield"
            for _, target in calls[capacity + 1 : first_send]
        ):
            errors.append("optimized reclaim path yields after capacity gate")

    loop_send = call_index("sendmsg", first_send + 1)
    holder_check = call_index("pad3_head_guards_intact", loop_send + 1)
    holder_close = call_index("pad3_close_head_guards", holder_check + 1)
    if holder_close < 0:
        # With one target-only guard group, clang inlines the aggregate loop
        # into its single socketpair close while preserving the same ordering.
        holder_close = call_index("pad3_close_socketpair", holder_check + 1)
    if min(loop_send, holder_check, holder_close) < 0 or not (
        loop_send < holder_check < holder_close
    ):
        errors.append("optimized head holders do not survive the reclaim loop")

    if not re.search(r"\bcmp\s+x[0-9]+,\s*#0x3\b", disassembly):
        errors.append("optimized reclaim loop does not carry the exact 4th-send bound")

    for marker in (
        b"Pad3 head guard ready groups=1 sends=8 frees=4 holders=4",
        b"per-group=8/4/4 head=0xe80",
        b"Pad3 KernelSnitch waiter barrier ready=",
        b"Pad3 reclaim geometry sends=4 truesize=0x9100",
        b"min-sndbuf=0x24401 effective-sndbuf=",
        b"Pad3 mm leak validated pointer=",
    ):
        if marker not in binary:
            errors.append(f"binary omits reclaim marker {marker!r}")
    return errors


def run_negative_fixtures() -> int:
    markers = b"\0".join(
        (
            b"Pad3 head guard ready groups=1 sends=8 frees=4 holders=4",
            b"per-group=8/4/4 head=0xe80",
            b"Pad3 KernelSnitch waiter barrier ready=",
            b"Pad3 reclaim geometry sends=4 truesize=0x9100",
            b"min-sndbuf=0x24401 effective-sndbuf=",
            b"Pad3 mm leak validated pointer=",
        )
    )
    positive = "\n".join(
        (
            "100: bl 0x200 <pad3_reclaim_capacity_exact>",
            "104: bl 0x204 <close@plt>",
            "108: bl 0x208 <sendmsg@plt>",
            "10c: bl 0x208 <sendmsg@plt>",
            "110: cmp x24, #0x3",
            "114: bl 0x20c <pad3_head_guards_intact>",
            "118: bl 0x210 <pad3_close_head_guards>",
        )
    )
    if verify(positive, markers):
        raise RuntimeError("positive reclaim binary checker fixture was rejected")
    fixtures = (
        positive.replace(
            "104: bl 0x204 <close@plt>\n108:",
            "104: bl 0x204 <close@plt>\n106: bl 0x300 <printf@plt>\n108:",
        ),
        positive.replace("cmp x24, #0x3", "cmp x24, #0x2"),
        positive.replace(
            "114: bl 0x20c <pad3_head_guards_intact>\n"
            "118: bl 0x210 <pad3_close_head_guards>",
            "114: bl 0x210 <pad3_close_head_guards>\n"
            "118: bl 0x20c <pad3_head_guards_intact>",
        ),
    )
    for index, fixture in enumerate(fixtures):
        if not verify(fixture, markers):
            raise RuntimeError(f"negative reclaim binary fixture escaped: {index}")
    if not verify(positive, markers.replace(b"min-sndbuf=0x24401", b"min-sndbuf=0")):
        raise RuntimeError("negative reclaim binary marker fixture escaped")
    return len(fixtures) + 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--objdump", required=True)
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"missing payload: {args.binary}")
    disassembly = run(
        [
            args.objdump,
            "-d",
            "--disassemble-symbols=prepare_kernel_page",
            str(args.binary),
        ]
    )
    errors = verify(disassembly, args.binary.read_bytes())
    if errors:
        for error in errors:
            print(f"RECLAIM BINARY FAIL  {error}", file=sys.stderr)
        return 1
    fixtures = run_negative_fixtures()
    print(
        "RECLAIM BINARY close->send direct; sends=4; holders survive loop; "
        f"markers exact; negative fixtures={fixtures}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
