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

GOPATH ?= /tmp/go
GO     ?= /usr/local/go/bin/go
RMDIR  ?= rm -rf

INSTALL := /usr/bin/install

GO_MOD     = go.mod
GO_DEPS    = vendor/.done
GO_PATCHES = $(shell find patches -type f)
GOYANG_BIN = $(abspath $(BUILD_DIR)/bin/goyang)

export TOPDIR GO GOPATH RMDIR

all: models cvl translib

$(GO_MOD):
	$(GO) mod init github.com/Azure/sonic-mgmt-common

$(GO_DEPS): $(GO_MOD) $(GO_PATCHES)
	$(GO) mod vendor
	patches/apply.sh vendor
	touch  $@

go-deps: $(GO_DEPS)

go-deps-clean:
	$(RMDIR) vendor

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
translib: $(GO_DEPS)
	$(MAKE) -C ./translib

translib-all: $(GO_DEPS)
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

install:
	# Scripts for host service
	# TODO move to debian install file
	$(INSTALL) -d $(DESTDIR)/usr/lib/sonic_host_service/host_modules
	$(INSTALL) -D $(TOPDIR)/scripts/sonic_host_server.py $(DESTDIR)/usr/lib/sonic_host_service
	$(INSTALL) -D $(TOPDIR)/scripts/host_modules/*.py $(DESTDIR)/usr/lib/sonic_host_service/host_modules
ifneq ($(ENABLE_ZTP),y)
	$(RM) -f $(DESTDIR)/usr/lib/sonic_host_service/host_modules/ztp_handler.py
endif
	$(INSTALL) -d $(DESTDIR)/etc/dbus-1/system.d
	$(INSTALL) -D $(TOPDIR)/scripts/org.sonic.hostservice.conf $(DESTDIR)/etc/dbus-1/system.d
	$(INSTALL) -d $(DESTDIR)/lib/systemd/system
	$(INSTALL) -D $(TOPDIR)/scripts/sonic-hostservice.service $(DESTDIR)/lib/systemd/system
	$(INSTALL) -d $(DESTDIR)/etc/sonic/
	$(INSTALL) -D $(TOPDIR)/config/cfg_mgmt.json $(DESTDIR)/etc/sonic/

clean: models-clean translib-clean cvl-clean
	git check-ignore debian/* | xargs -r $(RMDIR)
	$(RMDIR) $(BUILD_DIR)

cleanall: clean go-deps-clean
	$(MAKE) -C cvl cleanall

