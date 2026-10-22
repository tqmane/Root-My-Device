#!/usr/bin/env python3
import unittest
from analyze import KERNEL, analyze, parse_probe

BASE = dict(
    MODEL="A059", DEVICE="Asteroids", BUILD="Asteroids-B4.1-260618-1048-JPN",
    SDK="36", PATCH="2026-06-01", KERNEL=KERNEL, ABI="arm64-v8a",
    PAGE_SIZE="4096", ROOT_UID="0", CAP_EFF="0000003fffffffff",
    BUSYBOX="/data/adb/ksu/bin/busybox",
    BB_UNSHARE="yes", BB_NSENTER="yes", BB_PIVOT_ROOT="yes",
    BB_LOSETUP="yes", BB_MOUNT="yes",
    MOUNT_NAMESPACE="yes", FREE_LOOP="yes", EXT4_KERNEL="yes",
    SELINUX="Enforcing", BINDER="present",
    INIT_ZYGOTE="running", INIT_SURFACEFLINGER="running", INIT_NETD="running",
    FREE_DATA_KB="8500000",
)

class AnalysisTests(unittest.TestCase):
    def test_known_android16_is_only_capability_ready(self):
        checks, blocked = analyze(BASE)
        self.assertFalse(blocked)
        self.assertTrue(any("NOT ported" in message for _, message in checks))

    def test_android17_is_blocked(self):
        p = dict(BASE, BUILD="Asteroids-C5.0-260915-2123", SDK="37", PATCH="2026-09-01")
        _, blocked = analyze(p)
        self.assertTrue(blocked)

    def test_unprivileged_shell_is_blocked(self):
        p = dict(BASE, ROOT_UID="2000", CAP_EFF="0")
        _, blocked = analyze(p)
        self.assertTrue(blocked)

    def test_unknown_build_is_blocked(self):
        p = dict(BASE, BUILD="Asteroids-B4.1-260928-1204")
        _, blocked = analyze(p)
        self.assertTrue(blocked)

    def test_no_namespace_is_blocked(self):
        p = dict(BASE, MOUNT_NAMESPACE="no")
        _, blocked = analyze(p)
        self.assertTrue(blocked)

    def test_parse_ignores_noise(self):
        self.assertEqual(parse_probe("MODEL=A059\nnoise\nROOT_UID=0\n"), {"MODEL": "A059", "ROOT_UID": "0"})

if __name__ == "__main__":
    unittest.main()
