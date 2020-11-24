################################################################################
#                                                                              #
#  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or   #
#  its subsidiaries.                                                           #
#                                                                              #
#  Licensed under the Apache License, Version 2.0 (the "License");             #
#  you may not use this file except in compliance with the License.            #
#  You may obtain a copy of the License at                                     #
#                                                                              #
#     http://www.apache.org/licenses/LICENSE-2.0                               #
#                                                                              #
#  Unless required by applicable law or agreed to in writing, software         #
#  distributed under the License is distributed on an "AS IS" BASIS,           #
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    #
#  See the License for the specific language governing permissions and         #
#  limitations under the License.                                              #
#                                                                              #
################################################################################

GO?=go
SRC_FILES=$(shell find . -name '*.go' | grep -v '_test.go' | grep -v '/tests/')
TEST_FILES=$(wildcard *_test.go)
TOP_DIR := ..
GOFLAGS:=
BUILD_DIR:=$(TOP_DIR)/build/cvl
CVL_PKG=$(TOP_DIR)/build/pkg/linux_amd64/cvl.a

STATIC_CHECK = $(BUILD_DIR)/.staticcheck
CVL_TEST_DIR = $(TOP_DIR)/build/tests/cvl
CVL_TEST_BIN = $(CVL_TEST_DIR)/cvl.test
CVL_TEST_SCHEMA_DIR = $(CVL_TEST_DIR)/testdata/schema
CVL_TEST_CONFIG = $(CVL_TEST_DIR)/cvl_cfg.json
CVL_SCHEMA_DIR = $(BUILD_DIR)/schema
CVL_SCHEMA_FILES := 

CVL_SCHEMA_FILES += sonic-extension.yin sonic-common.yin 

ifdef DEBUG
	GOFLAGS += -gcflags="all=-N -l"
endif

DEFAULT_TARGETS = deps schema $(STATIC_CHECK)
ifeq ($(NO_TEST_BINS),)
DEFAULT_TARGETS += $(CVL_TEST_BIN) test-schema
endif

default: $(DEFAULT_TARGETS)

all: $(DEFAULT_TARGETS) $(CVL_PKG)

deps: 
	$(shell mkdir -p $(BUILD_DIR))
	$(shell mkdir -p $(CVL_SCHEMA_DIR))
	$(shell mkdir -p $(CVL_TEST_SCHEMA_DIR))
	$(shell mkdir -p $(CVL_TEST_SCHEMA_DIR)/platform/quanta_ix8)

$(CVL_PKG): $(SRC_FILES)
	@echo "Building $@"
	$(GO) build -mod=vendor $(GOFLAGS) -o $(CVL_PKG) ../cvl

$(CVL_TEST_BIN): $(TEST_FILES) $(SRC_FILES)
	cp -r testdata/*.json $(@D)/testdata
	$(GO) test -mod=vendor -cover -coverpkg=../cvl,../cvl/internal/util,../cvl/internal/yparser -c ../cvl -o $@

.PHONY: schema
schema:deps
	make -C schema

test-schema:schema
	make -C testdata/schema
	#Copy all required schema to test-schema location
	@for f in $(CVL_SCHEMA_FILES) ; do \
		cp -f $(CVL_SCHEMA_DIR)/$$f $(CVL_TEST_SCHEMA_DIR)/`dirname $$f` ; \
	done

tests:
	make -C tests

$(CVL_TEST_CONFIG): conf/cvl_cfg.json
	sed -E 's/((TRACE|LOG).*)\"false\"/\1\"true\"/' conf/cvl_cfg.json > $@

gotest:schema test-schema $(CVL_TEST_CONFIG)
	CVL_CFG_FILE=$(abspath $(CVL_TEST_CONFIG)) CVL_SCHEMA_PATH=$(CVL_TEST_SCHEMA_DIR) tests/run_test.sh

$(STATIC_CHECK): $(SRC_FILES)
	$(TOPDIR)/tools/test/static-check.sh \
		--log=$(BUILD_DIR)/staticcheck.log
	touch $@

clean:
	make -C tests clean
	make -C schema clean
	make -C testdata/schema clean
	$(RM) $(CVL_PKG)
	$(RM) -r $(BUILD_DIR)
	$(RM) -r $(CVL_TEST_DIR)

cleanall:clean

