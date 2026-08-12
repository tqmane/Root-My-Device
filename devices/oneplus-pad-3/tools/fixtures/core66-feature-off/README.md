# core66 feature-off compile fixture

`target-core66.h` in this directory is not a supported device profile. The
release build uses it only to compile-check that Pad 3-only feature gates remain
target-scoped and that the legacy core66 feature-off path still builds.

Keeping the fixture here prevents an unrelated device directory from being
mistaken for public support.
