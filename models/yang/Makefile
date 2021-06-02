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

TOPDIR := ../..
BUILD_DIR := $(TOPDIR)/build

YANGDIR                     := .
YANGDIR_COMMON              := $(YANGDIR)/common
YANGDIR_ANNOTATIONS         := $(YANGDIR)/annotations
YANGDIR_EXTENSIONS_DIR	    := $(YANGDIR)/extensions
YANGDIR_SONIC               := $(YANGDIR)/sonic
YANGDIR_PATCH               := $(YANGDIR)/patches
YANG_ANNOTATIONS_FILES      := $(shell find $(YANGDIR_ANNOTATIONS) -name '*.yang' | sort)
OC_COMMUNITY_LINTER         := $(TOPDIR)/build/oc-community-linter
OC_COMMUNITY_LINTER_PATCH   := $(OC_COMMUNITY_LINTER)/.done
YANG_MOD_FILES              := $(shell find $(YANGDIR) -maxdepth 1 -name '*.yang' | sort)
YANG_MOD_EXTENSION_FILES    := $(shell find $(YANGDIR_EXTENSIONS_DIR) -maxdepth 1 -name '*.yang' | sort)
YANG_COMMON_FILES           := $(shell find $(YANGDIR_COMMON) -name '*.yang' | sort)
YANG_PATCH_FILES            := $(shell find $(YANGDIR_PATCH) -name '*.patch' | sort)

YANG_BUILD_DIR                  := $(TOPDIR)/build/yang
YANG_BUILD_DIR_COMMON           := $(YANG_BUILD_DIR)/common
YANG_BUILD_DIR_EXTENSIONS_DIR	:= $(YANG_BUILD_DIR)/extensions
YANG_ANNOTS_CHK                 := $(YANG_BUILD_DIR)/annots_checked
YANG_VALIDATE_CHK               := $(YANG_BUILD_DIR)/validate_checked
PATCH_STD_YANGS                 := $(YANG_BUILD_DIR)/.patchdone
SYNC_STD_YANGS_TO_BUILD         := $(YANG_BUILD_DIR)/.syncdone

TOOLS_DIR        := $(TOPDIR)/tools
PYANG_PLUGIN_DIR := $(TOOLS_DIR)/pyang/pyang_plugins
PYANG            ?= pyang
LINTER           := $(TOOLS_DIR)/test/yang_validate.sh

.PHONY: all
all: allyangs.tree allyangs_tree.html yang_tree.md $(YANG_ANNOTS_CHK) $(YANG_VALIDATE_CHK) | $(PATCH_STD_YANGS)

.PHONY: annot
annot: $(YANG_ANNOTS_CHK)

$(YANG_ANNOTS_CHK): $(YANG_ANNOTATIONS_FILES) $(YANG_MOD_FILES) $(YANG_MOD_EXTENSION_FILES) $(YANG_COMMON_FILES)
	$(RM) $@
	$(PYANG) --strict -f tree \
		-p $(YANGDIR_COMMON):$(YANGDIR_SONIC):$(YANGDIR_ANNOTATIONS):$(YANGDIR):$(YANGDIR_EXTENSIONS_DIR) \
		$(YANG_ANNOTATIONS_FILES) > /dev/null
	touch $@

%.tree %.html %.md: BUILD_YANG_MOD_EXTENSION_FILES  = $(shell find $(YANG_BUILD_DIR_EXTENSIONS_DIR) -maxdepth 1 -name '*.yang' | sort)
%.tree %.html %.md: BUILD_YANG_MOD_FILES            = $(shell find $(YANG_BUILD_DIR) -maxdepth 1 -name '*.yang' | sort)

allyangs.tree: $(PATCH_STD_YANGS)
	$(PYANG) \
		-f tree \
		-o $@ \
		-p $(YANG_BUILD_DIR_COMMON):$(YANG_BUILD_DIR):$(YANG_BUILD_DIR_EXTENSIONS_DIR) \
		$(BUILD_YANG_MOD_FILES) $(BUILD_YANG_MOD_EXTENSION_FILES)
	@echo "+++++ Generation of  YANG tree for Yang modules completed +++++"

allyangs_tree.html: $(PATCH_STD_YANGS)
	$(PYANG) \
		-f jstree \
		-o $@ \
		-p $(YANG_BUILD_DIR_COMMON):$(YANG_BUILD_DIR):$(YANG_BUILD_DIR_EXTENSIONS_DIR) \
		$(BUILD_YANG_MOD_FILES) $(BUILD_YANG_MOD_EXTENSION_FILES)
	@echo "+++++ Generation of  HTML tree for Yang modules completed +++++"

yang_tree.md: $(PATCH_STD_YANGS)
	$(PYANG) \
		-f doctree \
		--basepaths $(YANGDIR):$(YANGDIR_COMMON):$(YANGDIR_EXTENSIONS_DIR) \
		-o $@ \
		--extdir $(YANG_BUILD_DIR_EXTENSIONS_DIR) \
		--plugindir $(PYANG_PLUGIN_DIR) \
		-p $(YANG_BUILD_DIR_COMMON):$(YANG_BUILD_DIR):$(YANG_BUILD_DIR_EXTENSIONS_DIR) \
		$(BUILD_YANG_MOD_FILES) $(BUILD_YANG_MOD_EXTENSION_FILES)
	@echo "+++++ Generation of  DOC tree for Yang modules completed +++++"

#======================================================================
# Cleanups
#======================================================================

clean:
	$(RM) -f $(YANG_ANNOTS_CHK) $(YANG_VALIDATE_CHK)
	$(RM) -r $(YANG_BUILD_DIR_COMMON) $(YANG_BUILD_DIR_EXTENSIONS_DIR) $(YANG_BUILD_DIR)
	$(RM) -f allyangs.tree allyangs_tree.html yang_tree.md *.log $(PATCH_STD_YANGS) $(SYNC_STD_YANGS_TO_BUILD)

validate: $(YANG_VALIDATE_CHK)

$(OC_COMMUNITY_LINTER):
	git clone https://github.com/openconfig/oc-pyang.git $(OC_COMMUNITY_LINTER)

$(OC_COMMUNITY_LINTER_PATCH): $(OC_COMMUNITY_LINTER)
	cd $(OC_COMMUNITY_LINTER); \
	git reset --hard c4f450d93905cdd95deba000a3551293bcf79710 && \
	git apply $(TOOLS_DIR)/pyang/patches/openconfig_validator.patch
	touch $@

$(YANG_VALIDATE_CHK): $(YANG_MOD_FILES) $(YANG_COMMON_FILES) $(YANG_MOD_EXTENSION_FILES) $(OC_COMMUNITY_LINTER_PATCH) $(YANG_PATCH_FILES) $(PATCH_STD_YANGS)
	$(RM) $@
	$(LINTER) 
	touch $@

$(SYNC_STD_YANGS_TO_BUILD): $(YANG_MOD_FILES) $(YANG_COMMON_FILES) $(YANG_MOD_EXTENSION_FILES) $(YANG_PATCH_FILES)
	$(RM) $@
	mkdir -p $(@D)
	rsync -avh --exclude-from=$(YANGDIR)/copy_to_build_dir.exclude $(YANGDIR) $(YANG_BUILD_DIR)
	touch $@

$(PATCH_STD_YANGS): $(SYNC_STD_YANGS_TO_BUILD)
	$(RM) $@

	cd $(YANG_BUILD_DIR); \
	git init ;\
	git add -f "."; \
	git commit -m "Original files" ; \
	git tag ORIG; \
	stg init; \
	stg import -s ../../models/yang/patches/series

	touch $@
