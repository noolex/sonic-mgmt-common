#######################################################################
#
# Copyright 2019 Broadcom. All rights reserved.
# The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries.
#
#######################################################################

TOPDIR    ?= ..
BUILD_DIR ?= $(TOPDIR)/build

GO     ?= go
export GO

TRANSLIB_BLD = $(BUILD_DIR)/translib
TRANSLIB_PKG = $(BUILD_DIR)/pkg/linux_amd64/translib.a
STATIC_CHECK = $(TRANSLIB_BLD)/.staticcheck

TRANSLIB_MAIN_SRCS = $(shell find . -name '*.go' | grep -v '_test.go' | grep -v '/test\|transformer/')
TRANSLIB_TEST_SRCS = $(shell find . -maxdepth 1 -name '*_test.go')
TRANSL_DB_ALL_SRCS = $(shell find db/ -name '*.go' | grep -v '/test/')

TRANSLIB_TEST_DIR  = $(BUILD_DIR)/tests/translib
YANG_DIR           = $(TOPDIR)/models/yang
YANG_PATCH_DIR     = $(YANG_DIR)/patches
PATCH_YANG         = $(BUILD_DIR)/yang/.patchdone
TRANSLIB_TEST_BIN  = $(TRANSLIB_TEST_DIR)/translib.test
TRANSL_DB_TEST_BIN = $(TRANSLIB_TEST_DIR)/db.test

TRANSFORMER_TEST_BIN = $(TRANSLIB_TEST_DIR)/transformer.test
TRANSFORMER_TEST_FILES=$(wildcard transformer/*_test.go)
TRANSFORMER_SRCS = $(shell find transformer/ -name '*.go' | grep -v '/test/')

YANG_FILES = $(shell find $(YANG_DIR) -name '*.yang')
YANG_PATCH_FILES = $(shell find $(YANG_PATCH_DIR) -name '*.patch')
YGOT_BINDS = ocbinds/ocbinds.go

DEFAULT_TARGETS = $(YGOT_BINDS) $(STATIC_CHECK)
ifeq ($(NO_TEST_BINS),)
DEFAULT_TARGETS += $(TRANSLIB_TEST_BIN) $(TRANSL_DB_TEST_BIN) $(TRANSFORMER_TEST_BIN)
endif

default: $(DEFAULT_TARGETS)

all: $(DEFAULT_TARGETS) $(TRANSLIB_PKG)

$(PATCH_YANG): $(YANG_PATCH_FILES)
	$(MAKE) -C $(TOPDIR)/models/yang ../../build/yang/.patchdone

$(TRANSLIB_PKG): $(TRANSLIB_MAIN_SRCS) $(YGOT_BINDS)
	$(GO) build -mod=vendor -gcflags="all=-N -l" -v -o $(TRANSLIB_PKG) ../translib

$(TRANSLIB_TEST_BIN): $(TRANSLIB_MAIN_SRCS) $(TRANSLIB_TEST_SRCS) $(YGOT_BINDS)
	$(GO) test -mod=vendor -cover -coverpkg=../translib,../translib/tlerr -c ../translib -o $@

$(TRANSL_DB_TEST_BIN) : $(TRANSL_DB_ALL_SRCS)
	$(GO) test -mod=vendor -cover -c ../translib/db -o $@

$(TRANSFORMER_TEST_BIN): $(TRANSFORMER_TEST_FILES) $(TRANSFORMER_SRCS) $(TRANSLIB_MAIN_SRCS) $(YGOT_BINDS)
	mkdir -p $(@D)/testdata && cp -r transformer/testdata/*.json $(@D)/testdata
	$(GO) test -mod=vendor -c -vet=off -cover -coverpkg=../translib/transformer ../translib/transformer -o $@

$(YGOT_BINDS): $(YANG_FILES) $(YANG_PATCH_FILES) | $(PATCH_YANG)
	$(RM) $@
	cd ocbinds && $(GO) generate

$(STATIC_CHECK): $(TRANSLIB_MAIN_SRCS) $(TRANSFORMER_SRCS) | $(YGOT_BINDS)
	$(TOPDIR)/tools/test/static-check.sh \
		--log=$(TRANSLIB_BLD)/staticcheck.log \
		--exclude=ocbinds
	touch $@

clean:
	$(RM) $(YGOT_BINDS)
	$(RM) $(TRANSLIB_PKG)
	$(RM) -r $(TRANSLIB_BLD)
	$(RM) -r $(TRANSLIB_TEST_DIR)

