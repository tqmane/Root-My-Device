#!/usr/bin/env python3
"""Fail closed if the exact Pad 3 A3 lifetime/cleanup ordering drifts."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_C = ROOT / "src/payloads/CVE-2026-43499/core66/root.c"
FOPS_C = ROOT / "src/payloads/CVE-2026-43499/core66/fops.c"
PIPE_C = ROOT / "src/payloads/CVE-2026-43499/core66/pipe.c"
COMMON_H = ROOT / "src/payloads/CVE-2026-43499/core66/common.h"
SU_C = ROOT / "src/payloads/su_daemon/su_daemon.c"
LATE_C = ROOT / "src/payloads/su_daemon/late_load.c"


def function(text: str, name: str) -> str:
    match = re.search(
        rf"(?m)^\s*(?:static\s+)?(?:int|void|pid_t|ssize_t)\s+"
        rf"\b{name}\s*\([^;]*?\)\s*\{{",
        text,
        re.S,
    )
    if not match:
        raise ValueError(f"missing function {name}")
    start = match.start()
    brace = text.find("{", match.start())
    depth = 0
    for at in range(brace, len(text)):
        if text[at] == "{":
            depth += 1
        elif text[at] == "}":
            depth -= 1
            if depth == 0:
                return text[start : at + 1]
    raise ValueError(f"unterminated function {name}")


def ordered(body: str, markers: list[str], label: str, failures: list[str]) -> None:
    positions = [body.find(marker) for marker in markers]
    if any(pos < 0 for pos in positions):
        missing = [marker for marker, pos in zip(markers, positions) if pos < 0]
        failures.append(f"{label}: missing {missing}")
    elif positions != sorted(positions):
        failures.append(f"{label}: unsafe order {markers}")


def verify(texts: dict[str, str]) -> list[str]:
    failures: list[str] = []
    root = texts["root"]
    fops = texts["fops"]
    pipe = texts["pipe"]
    common = texts["common"]
    su = texts["su"]
    late = texts["late"]

    required_root = [
        "ATOMIC_INT_LOCK_FREE == 2",
        "MAP_SHARED | MAP_ANONYMOUS",
        "MSG_CMSG_CLOEXEC",
        "SCM_RIGHTS",
        "SYS_pidfd_open",
        '"anon_inode:[pidfd]"',
        "_Fork()",
        "SYS_tgkill, self, self, SIGSTOP",
        "WNOHANG | WUNTRACED",
        "pipe_emergency_restore(&mailbox->pipe_guard)",
        "root_a3_guard_restore_selinux(mailbox)",
        "usage != 1",
        "ROOT_A3_DECISION_ABORT_PREPARE",
        "ROOT_A3_DECISION_ABORT_FINAL",
        "ROOT_A3_WATCHDOG_SECONDS 300",
        "SYS_execveat",
        "SO_PEERCRED",
        "memcmp(child->sid, parent_sid, sizeof(parent_sid)) != 0",
        "child->securebits != parent_securebits",
        "root_a2_write_readback(fd, before->cred + CRED_SECUREBITS_OFF",
        "staged.securebits != 0",
    ]
    for marker in required_root:
        if marker not in root:
            failures.append(f"root.c: missing {marker}")
    if "P0_ENABLE_UNSAFE_RAW_WQ_ROUTE" not in root or \
            "#if defined(P0_ENABLE_UNSAFE_RAW_WQ_ROUTE)" not in root:
        failures.append("root.c: raw WQ source is not compile-time isolated")
    if "root_a3_rollback_stopped_child" in root:
        failures.append("root.c: private cred raw rollback was reintroduced")
    if "child->sid[0] != child->sid[1]" in root:
        failures.append("root.c: fork-private SELinux gate assumes osid equals sid")
    private_gate = function(root, "root_a3_initial_child_is_private")
    if "child->securebits != 0" in private_gate:
        failures.append("root.c: fork-private gate assumes inherited securebits are zero")
    scalar_patch = function(root, "root_a3_patch_stopped_child")
    ordered(
        scalar_patch,
        [
            "wanted_securebits = 0",
            "before->cred + CRED_SECUREBITS_OFF",
            "before->cred + CRED_CAPS_OFF",
            "before->security + SELINUX_CRED_BLOB_OFF",
        ],
        "A3 stopped-child scalar patch",
        failures,
    )

    install = function(root, "install_stopped_child_root")
    ordered(
        install,
        [
            "ROOT_A3_CMD_PIPE_GUARD",
            "ROOT_A3_CMD_STOP",
            "root_a3_wait_stopped(child)",
            "root_a3_patch_stopped_child",
            "staged.sid[1] != SELINUX_KERNEL_SID",
            "staged_valid = 1",
            "selinux_touched, 1",
            "root_a2_write_readback(fd, data_addr(SELINUX_ENFORCING)",
            "kill(child, SIGCONT)",
            "ROOT_A3_CMD_WATCHDOG",
            "watchdog_release, 1",
            "ROOT_A3_WATCHDOG_ROOT",
            "ROOT_A3_CMD_GROUPS",
            "root_a3_verify_pin_exclusive",
            "ROOT_A3_CMD_GID",
            "ROOT_A3_CMD_UID",
            "ROOT_A3_CMD_EXEC",
            "root_a2_socket_ready",
        ],
        "A3 install",
        failures,
    )
    child = function(root, "root_a3_child_main")
    ordered(
        child,
        [
            "SYS_rt_sigprocmask",
            "root_a3_send_fd",
            "ROOT_A3_CMD_PIPE_GUARD",
            "ROOT_A3_CMD_STOP",
            "SYS_tgkill",
            "ROOT_A3_CMD_WATCHDOG",
            "SYS_setgroups",
            "SYS_setresgid",
            "SYS_setresuid",
            "PR_SET_PDEATHSIG, 0",
            "ROOT_A3_CMD_EXEC",
            "unblocked_signals",
            "root_a3_exec_sealed_helper_now",
        ],
        "A3 child",
        failures,
    )
    commit = function(root, "root_a3_commit_helper")
    ordered(
        commit,
        [
            "ROOT_A3_DECISION_PENDING",
            "ROOT_A3_DECISION_PREPARE",
            "root_a3_wait_actor_acks(mailbox, ROOT_A3_DECISION_PREPARE",
            "ROOT_A3_DECISION_COMMIT",
            "root_a3_wait_actor_acks(mailbox, ROOT_A3_DECISION_COMMIT",
        ],
        "A3 two-phase commit",
        failures,
    )
    if re.search(r"PENDING[\s\S]{0,180}DECISION_COMMIT", commit):
        failures.append("A3 commit: direct PENDING->COMMIT transition")

    guard = function(root, "root_a3_pipe_guard_main")
    for marker in ["poll(&outer", "pipe_active_start", "permissive_start",
                   "ROOT_A3_DECISION_ABORT_PREPARE",
                   "ROOT_A3_DECISION_ABORT_FINAL"]:
        if marker not in guard:
            failures.append(f"pipe guardian: missing {marker}")
    abort_block = guard[guard.find("ROOT_A3_DECISION_ABORT_PREPARE") :]
    pipe_at = abort_block.find("pipe_emergency_restore")
    selinux_at = abort_block.find("root_a3_guard_restore_selinux")
    if pipe_at < 0 or selinux_at < 0 or "&&" in abort_block[pipe_at:selinux_at]:
        failures.append("pipe guardian: pipe/SELinux cleanup is short-circuited")

    p_read = function(pipe, "pipe_phys_read")
    p_write = function(pipe, "pipe_phys_write")
    for label, body in [("pipe read", p_read), ("pipe write", p_write)]:
        ordered(body, ["pipe_guard_begin", "kernel_write_data", "pipe_guard_end"],
                label, failures)
    for marker in ["struct pipe_emergency_guard", "pipe_set_emergency_guard",
                   "pipe_emergency_restore"]:
        if marker not in common + pipe:
            failures.append(f"pipe receipt: missing {marker}")

    stage = function(fops, "try_cfi_stage")
    ordered(stage, ["restore_cfi_redirect_exact", "commit_result = root_a3_commit_helper()",
                    "commit_result != 1", "close(fd)"],
            "fops final handoff", failures)
    if "!root_a3_commit_helper()" in fops:
        failures.append("fops: tri-state commit used as boolean")
    if "abort_ok == 1" not in fops or "root_a3_abort_helper() != 1" not in fops:
        failures.append("fops: abort result is not exact at every failure join")

    umh = function(su, "umh_post_exec_contract")
    for marker in ["getresuid", "getresgid", "SYS_setfsuid", "SYS_setfsgid",
                   "SYS_capget", "PR_CAPBSET_READ", "PR_GET_SECCOMP",
                   "PR_GET_NO_NEW_PRIVS", "PR_GET_PDEATHSIG",
                   '"u:r:kernel:s0"']:
        if marker not in umh:
            failures.append(f"post-exec gate: missing {marker}")
    watchdog = re.search(r"#define\s+ROOT_A3_WATCHDOG_SECONDS\s+(\d+)", root)
    late_timeout = re.search(
        r"#define\s+LATE_LOAD_WORKER_TIMEOUT_SECONDS\s+(\d+)", late
    )
    if not watchdog or int(watchdog.group(1)) < 300:
        failures.append("watchdog: post-commit deadline below 300 seconds")
    if not late_timeout:
        failures.append("watchdog: late-load worker timeout marker missing")
    elif watchdog and int(watchdog.group(1)) <= int(late_timeout.group(1)):
        failures.append("watchdog: no margin over late-load watchdog")
    return failures


def main() -> int:
    texts = {
        "root": ROOT_C.read_text(), "fops": FOPS_C.read_text(),
        "pipe": PIPE_C.read_text(), "common": COMMON_H.read_text(),
        "su": SU_C.read_text(), "late": LATE_C.read_text(),
    }
    failures = verify(texts)
    if failures:
        for failure in failures:
            print(f"A3 FAIL  {failure}", file=sys.stderr)
        return 1

    # Negative fixtures prove the checker itself fails closed for representative
    # missing markers in every contract layer.
    fixtures = [
        ("root", "SYS_pidfd_open"),
        ("root", "ROOT_A3_CMD_STOP"),
        ("root", "ROOT_A3_DECISION_PREPARE"),
        ("root", "memcmp(child->sid, parent_sid, sizeof(parent_sid)) != 0"),
        ("root", "child->securebits != parent_securebits"),
        ("root", "root_a2_write_readback(fd, before->cred + CRED_SECUREBITS_OFF"),
        ("root", "staged.securebits != 0"),
        ("fops", "commit_result != 1"),
        ("pipe", "pipe_guard_begin"),
        ("su", "PR_GET_NO_NEW_PRIVS"),
        ("late", "LATE_LOAD_WORKER_TIMEOUT_SECONDS"),
    ]
    for key, marker in fixtures:
        mutated = dict(texts)
        mutated[key] = mutated[key].replace(marker, "REMOVED_CRITICAL_MARKER")
        if not verify(mutated):
            print(f"A3 FAIL  negative fixture escaped: {key}:{marker}", file=sys.stderr)
            return 1
    print(f"A3 SOURCE exact ordering verified; negative fixtures={len(fixtures)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
