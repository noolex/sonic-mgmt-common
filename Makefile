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

TOPDIR := $(abspath .)
BUILD_DIR := build

export GOPATH ?= /tmp/go
export GO     ?= /usr/local/go/bin/go

# GOPATH is overriten by Version Cache framework
export GOPATH := $(shell GOPATH=$(GOPATH) ${GO} env GOPATH)

INSTALL := /usr/bin/install

GO_MOD     = go.mod
GO_DEPS    = vendor/.done
GO_PATCHES = $(shell find patches -type f)
GOYANG_BIN = $(abspath $(BUILD_DIR)/bin/goyang)

export TOPDIR GO GOPATH 

all: models cvl translib

$(GO_MOD):
	$(GO) mod init github.com/Azure/sonic-mgmt-common

$(GO_DEPS): $(GO_MOD) $(GO_PATCHES)
	$(GO) mod vendor
	patches/apply.sh vendor
	touch  $@

go-deps: $(GO_DEPS)

go-deps-clean:
	$(RM) -r vendor

.PHONY: cvl
cvl: $(GO_DEPS)
	$(MAKE) -C ./cvl

cvl-all: $(GO_DEPS)
	$(MAKE) -C ./cvl all

cvl-clean:
	$(MAKE) -C ./cvl clean

cvl-test:
	$(MAKE) -C ./cvl gotest

.PHONY: translib
translib: $(GO_DEPS) | models
	$(MAKE) -C ./translib

translib-all: $(GO_DEPS) | models
	$(MAKE) -C ./translib all

translib-clean:
	$(MAKE) -C ./translib clean

.PHONY: models
models:
	$(MAKE) -C models

models-clean:
	$(MAKE) -C models clean

annotgen: $(GOYANG_BIN)

$(GOYANG_BIN): $(GO_DEPS)
	cd vendor/github.com/openconfig/goyang && \
		$(GO) build -o $@ *.go

clean: models-clean translib-clean cvl-clean go-deps-clean
	git check-ignore debian/* | xargs -r $(RM) -r
	$(RM) -r debian/.debhelper
	$(RM) -r $(BUILD_DIR)

cleanall: clean
	chmod -R u+w /tmp/go/pkg && $(RM) -r /tmp/go/pkg

