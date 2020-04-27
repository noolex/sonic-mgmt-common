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

MAIN_TARGET = sonic-mgmt-common_1.0.0_amd64.deb

GO_MOD     = go.mod
GO_DEPS    = vendor/.done
GO_PATCHES = $(shell find patches -type f)
GOYANG_BIN = $(abspath $(BUILD_DIR)/bin/goyang)

export TOPDIR GO GOPATH RMDIR

all: models translib

$(GO_MOD):
	$(GO) mod init github.com/Azure/sonic-mgmt-common

$(GO_DEPS): $(GO_MOD) $(GO_PATCHES)
	$(GO) mod vendor
	patches/apply.sh vendor
	touch  $@

.PHONY: cvl
cvl: $(GO_DEPS)
	$(MAKE) -C ./cvl

cvl-test:
	$(MAKE) -C ./cvl gotest

.PHONY: translib
translib: cvl
	$(MAKE) -C ./translib

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
	$(INSTALL) -d $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/sonic/*.yang $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/sonic/common/*.yang $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/*.yang $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/config/transformer/models_list $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/config/transformer/sonic_table_info.json $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/common/*.yang $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/annotations/*.yang $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/extensions/*.yang $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/models/yang/version.xml $(DESTDIR)/usr/models/yang/
	$(INSTALL) -D $(TOPDIR)/build/yang/api_ignore $(DESTDIR)/usr/models/yang/
	
	# Copy all CVL schema files
	$(INSTALL) -d $(DESTDIR)/usr/sbin/schema/
	cp -aT build/cvl/schema $(DESTDIR)/usr/sbin/schema
	cp -rf $(TOPDIR)/cvl/conf/cvl_cfg.json $(DESTDIR)/usr/sbin/cvl_cfg.json
	
	# Scripts for host service
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

$(addprefix $(DEST)/, $(MAIN_TARGET)): $(DEST)/% :
	mv $* $(DEST)/

clean: models-clean
	$(MAKE) -C translib clean
	$(MAKE) -C cvl clean
	$(RMDIR) debian/.debhelper
	$(RMDIR) $(BUILD_DIR)

cleanall: clean
	$(MAKE) -C cvl cleanall
	$(RMDIR) vendor

