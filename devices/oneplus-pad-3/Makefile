# Exact-build native build for OnePlus Pad 3 OPD2415 / EX01.
SUPPORTED_TARGET := oneplus-pad3/ex/6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k
SUPPORTED_CORE := core66

# Generic CI hosts often export TARGET/CORE/API for unrelated jobs. Ignore only
# environment-origin values; an explicit `make TARGET=...` remains validated.
ifneq ($(findstring environment,$(origin API)),)
override API := 35
endif
API ?= 35
ifneq ($(findstring environment,$(origin TARGET)),)
override TARGET := $(SUPPORTED_TARGET)
endif
TARGET ?= $(SUPPORTED_TARGET)
ifneq ($(findstring environment,$(origin CORE)),)
override CORE := $(SUPPORTED_CORE)
endif
CORE ?= $(SUPPORTED_CORE)
ifneq ($(findstring environment,$(origin PAYLOAD)),)
override PAYLOAD := CVE-2026-43499
endif
PAYLOAD ?= CVE-2026-43499

ifneq ($(TARGET),$(SUPPORTED_TARGET))
$(error this repository supports only TARGET=$(SUPPORTED_TARGET))
endif
ifneq ($(CORE),$(SUPPORTED_CORE))
$(error this repository supports only CORE=$(SUPPORTED_CORE))
endif
ifneq ($(PAYLOAD),CVE-2026-43499)
$(error this repository supports only PAYLOAD=CVE-2026-43499)
endif

TARGET_DIR := src/targets/$(TARGET)
TARGET_HEADER_NAME := target-$(CORE).h
TARGET_HEADER := $(TARGET_DIR)/$(TARGET_HEADER_NAME)
TARGET_INCLUDE := targets/$(TARGET)/$(TARGET_HEADER_NAME)
PAYLOAD_DIR := src/payloads/$(PAYLOAD)
CORE_DIR := $(PAYLOAD_DIR)/$(CORE)
HELPER_DIR := src/payloads/su_daemon
ROOT_GLUE := $(CORE_DIR)/root.c
OUTDIR ?= build/$(subst /,_,$(TARGET))

TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang
ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif
ifeq ($(wildcard $(TARGET_HEADER)),)
$(error missing exact target header: $(TARGET_HEADER))
endif

PAYLOAD_SLUG := $(shell echo '$(PAYLOAD)' | tr 'A-Z' 'a-z')
PRELOAD := $(OUTDIR)/$(PAYLOAD_SLUG)
PRELOAD_EXE := $(OUTDIR)/$(PAYLOAD_SLUG)-standalone
APP_PRELOAD := $(OUTDIR)/$(PAYLOAD_SLUG)-app.so
APP_RELEASE := $(OUTDIR)/$(PAYLOAD_SLUG)-app.release.so
APP_RELEASE_SIZE ?= 196608
ROOT_HELPER := $(OUTDIR)/$(PAYLOAD_SLUG)-root

CORE_SRCS := \
  $(CORE_DIR)/main.c \
  $(CORE_DIR)/util.c \
  $(CORE_DIR)/slide.c \
  $(CORE_DIR)/fops.c \
  $(CORE_DIR)/pipe.c

PRELOAD_SRCS := \
  $(CORE_SRCS) \
  $(ROOT_GLUE) \
  $(PAYLOAD_DIR)/root_helper.c \
  $(PAYLOAD_DIR)/mte.c \
  $(PAYLOAD_DIR)/preload.c

HELPER_SRCS := \
  $(HELPER_DIR)/su_daemon.c \
  $(HELPER_DIR)/late_load.c \
  $(HELPER_DIR)/hold_refs.c

PAYLOAD_DEPS := \
  $(TARGET_HEADER) \
  $(wildcard $(TARGET_DIR)/*.h) \
  $(PAYLOAD_DIR)/payload.h \
  $(wildcard $(CORE_DIR)/*.h $(CORE_DIR)/kernelsnitch/*.h)

TARGET_HEADER_DEFINES := \
  -DTARGET_HEADER='"$(TARGET_INCLUDE)"' \
  -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"' \
  -DTARGET_KERNEL_RELEASE='"$(notdir $(TARGET))"'

PAYLOAD_EXTRA_CFLAGS ?=
HELPER_EXTRA_CFLAGS ?=
COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  -DGHOSTLOCK_PRELOAD=1 \
  -I$(CORE_DIR) -I$(PAYLOAD_DIR) -I$(TARGET_DIR) -Isrc \
  $(TARGET_HEADER_DEFINES) $(PAYLOAD_EXTRA_CFLAGS)

.DEFAULT_GOAL := all
.PHONY: all release clean info

all: $(PRELOAD) $(PRELOAD_EXE) $(APP_PRELOAD) $(ROOT_HELPER)
release: $(APP_RELEASE)

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -fPIC $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(PRELOAD_EXE): $(PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DSTANDALONE_MAIN=1 -fPIE $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -pie -pthread -o $@

$(ROOT_HELPER): $(HELPER_SRCS) $(HELPER_DIR)/su_daemon.h Makefile | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie -O2 -g0 -Wall -Wextra -I$(HELPER_DIR) \
	  $(HELPER_EXTRA_CFLAGS) $(HELPER_SRCS) -ldl -o $@

$(APP_PRELOAD): $(PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(APP_RELEASE): $(PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC -Oz -g0 \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables \
	  -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	  -DGHOSTLOCK_PRELOAD=1 \
	  -I$(CORE_DIR) -I$(PAYLOAD_DIR) -I$(TARGET_DIR) -Isrc \
	  $(TARGET_HEADER_DEFINES) $(PAYLOAD_EXTRA_CFLAGS) \
	  $(PRELOAD_SRCS) -shared -pthread \
	  -Wl,--gc-sections -Wl,--icf=all -s -o $@
	@test $$(stat -c %s $@) -le $(APP_RELEASE_SIZE)
	truncate -s $(APP_RELEASE_SIZE) $@

info:
	@echo "TARGET=$(TARGET)"
	@echo "CORE=$(CORE)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "OUTDIR=$(OUTDIR)"

clean:
	rm -rf $(OUTDIR)
