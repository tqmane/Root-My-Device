# Shared KernelSU sources

This monorepo uses one shared pair of Git submodules for both device projects:

- `KernelSU` at `b0bc817b4e966aa6aa830834eaf6ef765d821d40`
- `Root-My-Device-KSU` at `bf5bfa9ba0e7430611cca4b55ab12885df2d4eaa`

The Nothing Phone (3a) build applies the six KernelSU 32525 common patches and
three `asteroids` patches. The OnePlus Pad 3 build applies the same six common
patches and thirteen `oneplus-pad3` patches. Both series are read directly from
the exact patch submodule; no duplicate patch copy is kept in the main tree.

Initialize both worktrees from the repository root:

```bash
git submodule update --init --recursive
```

Both device build scripts verify the shared submodule HEADs before building.
