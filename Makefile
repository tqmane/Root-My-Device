SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

NOTHING := devices/nothing-phone-3a
ONEPLUS := devices/oneplus-pad-3

.PHONY: help audit syntax artifacts contracts apps check release build-all nothing-debug nothing-release oneplus-release clean

help:
	@printf '%s\n' \
	  'Root My Device monorepo targets:' \
	  '  make audit            publication/layout audit' \
	  '  make syntax           Python/JSON/shell syntax checks' \
	  '  make artifacts        embedded artifact identity checks' \
	  '  make contracts        OnePlus source-contract self-tests' \
	  '  make apps             both app unit tests + debug APKs' \
	  '  make check            audit + syntax + artifacts + contracts + apps' \
	  '  make release          build both signer-aware release sets' \
	  '  make nothing-debug    full Nothing native/debug build' \
	  '  make nothing-release  full Nothing native/release build' \
	  '  make oneplus-release  full OnePlus signer-matched release build'

audit:
	python3 tools/audit-public-tree.py

syntax:
	python3 -m compileall -q tools devices/nothing-phone-3a/tools devices/oneplus-pad-3/tools
	find devices tools -type f -name '*.sh' -print0 | xargs -0 -r -n1 bash -n
	python3 tools/check-json-files.py

artifacts:
	python3 tools/verify-app-artifacts.py

contracts:
	cd $(ONEPLUS) && python3 tools/verify-a3-source-contract.py
	cd $(ONEPLUS) && python3 tools/verify-profile.py --mode4-contract-self-test
	cd $(ONEPLUS) && python3 tools/verify-profile.py --reclaim-contract-self-test

apps:
	cd $(NOTHING) && ./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug
	cd $(ONEPLUS) && ./gradlew --no-daemon :app:testDebugUnitTest :app:assembleDebug

check: audit syntax artifacts contracts apps

release build-all:
	./tools/build-all.sh --release

nothing-debug:
	cd $(NOTHING) && ./tools/build-asteroids-fixed.sh

nothing-release:
	cd $(NOTHING) && ./tools/build-asteroids-fixed.sh --release

oneplus-release:
	cd $(ONEPLUS) && ./tools/build-oneplus-pad3.sh --release

clean:
	cd $(NOTHING) && ./gradlew --no-daemon clean || true
	cd $(ONEPLUS) && ./gradlew --no-daemon clean || true
	rm -rf $(NOTHING)/build $(ONEPLUS)/build
