################################################################################
#                                                                              #
#  Copyright 2020 Broadcom. The term Broadcom refers to Broadcom Inc. and/or   #
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

TOPDIR := ../../..

SONIC_YANGDIR           := .
SONIC_YANGDIR_DEVIATION := $(SONIC_YANGDIR)/deviation
SONIC_YANGDIR_COMMON    := $(SONIC_YANGDIR)/common
SONIC_YANGDIR_COMMON_IETF := $(SONIC_YANGDIR_COMMON)/ietf
SONIC_YANG_MOD_FILES  := $(shell find $(SONIC_YANGDIR) -maxdepth 1 -name '*.yang' | sort)
SONIC_YANG_COMMON_FILES  := $(shell find $(SONIC_YANGDIR_COMMON) -name '*.yang' | sort)
SONIC_YANG_COMMON_FILES  += $(shell find $(SONIC_YANGDIR_COMMON_IETF) -name '*.yang' | sort)

SONIC_TOOLS_DIR        := $(TOPDIR)/tools
SONIC_PYANG_PLUGIN_DIR := $(SONIC_TOOLS_DIR)/pyang/pyang_plugins
PYANG                  ?= pyang

all: allyangs.tree allyangs_tree.html yang_tree.md


allyangs.tree:  $(SONIC_YANG_MOD_FILES) $(SONIC_YANG_COMMON_FILES)
	$(PYANG) \
		-f tree \
		-o $@ \
		-p $(SONIC_YANGDIR_COMMON):$(SONIC_YANGDIR) \
		$(SONIC_YANG_MOD_FILES)
	@echo "+++++ Generation of  YANG tree for Sonic Yang modules completed +++++"

yang_tree.md:  $(SONIC_YANG_MOD_FILES) $(SONIC_YANG_COMMON_FILES)
	$(PYANG) \
		-f doctree \
		-o $@ \
		--plugindir $(SONIC_PYANG_PLUGIN_DIR) \
		-p $(SONIC_YANGDIR_COMMON):$(SONIC_YANGDIR) \
		$(SONIC_YANG_MOD_FILES)
	@echo "+++++ Generation of  YANG tree in Md Format for Sonic Yang modules completed +++++"

allyangs_tree.html:  $(SONIC_YANG_MOD_FILES) $(SONIC_YANG_COMMON_FILES)
	$(PYANG) \
		-f jstree \
		-o $@ \
		-p $(SONIC_YANGDIR_COMMON):$(SONIC_YANGDIR) \
		$(SONIC_YANG_MOD_FILES)
	@echo "+++++ Generation of  HTML tree for Sonic Yang modules completed +++++"

clean:
	rm -f allyangs.tree allyangs_tree.html yang_tree.md
