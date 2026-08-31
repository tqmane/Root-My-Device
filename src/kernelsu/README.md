# Shared KernelSU sources

This monorepo uses one shared pair of Git submodules for both device projects:

- `KernelSU` at `932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e` (v3.3.0 / 32601)
- `Root-My-Device-KSU` at the commit pinned by this repository gitlink

The Nothing Phone (3a) build applies the six KernelSU 32601 common patches and
three `asteroids` patches. The OnePlus Pad 3 build applies the same six common
patches and thirteen `oneplus-pad3` patches. Both series are read directly from
the exact patch submodule; no duplicate patch copy is kept in the main tree.

Initialize both worktrees from the repository root:

```bash
git submodule update --init --recursive
```

Both device build scripts verify the shared submodule HEADs before building.
