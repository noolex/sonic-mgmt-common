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
YANG_MOD_FILES              := $(shell find $(YANGDIR) -maxdepth 1 -name '*.yang' | sort)
YANG_MOD_EXTENSION_FILES    := $(shell find $(YANGDIR_EXTENSIONS_DIR) -maxdepth 1 -name '*.yang' | sort)
YANG_IETF_MOD_EXT_FILES     := $(shell find $(YANGDIR_EXTENSIONS_DIR) -maxdepth 1 -name 'ietf-*.yang' | sort)
YANG_ANNOTATIONS_FILES      := $(shell find $(YANGDIR_ANNOTATIONS) -name '*.yang' | sort)
YANG_COMMON_FILES           := $(shell find $(YANGDIR_COMMON) -name '*.yang' | sort)

YANG_BUILD_DIR    := $(TOPDIR)/build/yang
YANG_API_IGNORES  := $(YANG_BUILD_DIR)/api_ignore
YANG_ANNOTS_CHK   := $(YANG_BUILD_DIR)/annots_checked
YANG_VALIDATE_CHK := $(YANG_BUILD_DIR)/validate_checked

TOOLS_DIR        := $(TOPDIR)/tools
PYANG_PLUGIN_DIR := $(TOOLS_DIR)/pyang/pyang_plugins
PYANG            ?= pyang
LINTER           := $(TOOLS_DIR)/test/yang_validate.sh

.PHONY: all
all: allyangs.tree allyangs_tree.html yang_tree.md $(YANG_API_IGNORES) $(YANG_ANNOTS_CHK) $(YANG_VALIDATE_CHK)

.PHONY: annot
annot: $(YANG_ANNOTS_CHK)
	
$(YANG_ANNOTS_CHK): $(YANG_ANNOTATIONS_FILES) $(YANG_MOD_FILES) $(YANG_MOD_EXTENSION_FILES) $(YANG_COMMON_FILES)
	$(PYANG) --strict -f tree \
		-p $(YANGDIR_COMMON):$(YANGDIR_SONIC):$(YANGDIR_ANNOTATIONS):$(YANGDIR):$(YANGDIR_EXTENSIONS_DIR) \
		$(YANG_ANNOTATIONS_FILES) > /dev/null
	touch $@

allyangs.tree:  $(YANG_MOD_FILES) $(YANG_COMMON_FILES) $(YANG_MOD_EXTENSION_FILES)
	$(PYANG) \
		-f tree \
		-o $@ \
		-p $(YANGDIR_COMMON):$(YANGDIR):$(YANGDIR_EXTENSIONS_DIR) \
		$(YANG_MOD_FILES) $(YANG_MOD_EXTENSION_FILES)
	@echo "+++++ Generation of  YANG tree for Yang modules completed +++++"

allyangs_tree.html:  $(YANG_MOD_FILES) $(YANG_COMMON_FILES) $(YANG_MOD_EXTENSION_FILES)
	$(PYANG) \
		-f jstree \
		-o $@ \
		-p $(YANGDIR_COMMON):$(YANGDIR):$(YANGDIR_EXTENSIONS_DIR) \
		$(YANG_MOD_FILES) $(YANG_MOD_EXTENSION_FILES)
	@echo "+++++ Generation of  HTML tree for Yang modules completed +++++"

yang_tree.md:  $(YANG_MOD_FILES) $(YANG_COMMON_FILES) $(YANG_MOD_EXTENSION_FILES)
	$(PYANG) \
		-f doctree \
		-o $@ \
		--extdir $(YANGDIR_EXTENSIONS_DIR) \
		--plugindir $(PYANG_PLUGIN_DIR) \
		-p $(YANGDIR_COMMON):$(YANGDIR):$(YANGDIR_EXTENSIONS_DIR) \
		$(YANG_MOD_FILES) $(YANG_MOD_EXTENSION_FILES)
	@echo "+++++ Generation of  DOC tree for Yang modules completed +++++"

#======================================================================
# Generate api_ignore file
#======================================================================
$(YANG_API_IGNORES): $(YANG_ANNOTATIONS_FILES)
	mkdir -p $(@D)
	echo "# Yangs ignored" > $@
	(cd $(YANGDIR_ANNOTATIONS) && ls -f *.yang) >> $@

#======================================================================
# Cleanups
#======================================================================

clean:
	rm -f $(YANG_API_IGNORES) $(YANG_ANNOTS_CHK) $(YANG_VALIDATE_CHK)
	rm -f allyangs.tree allyangs_tree.html yang_tree.md

validate: $(YANG_VALIDATE_CHK)

$(YANG_VALIDATE_CHK): $(YANG_MOD_FILES) $(YANG_COMMON_FILES) $(YANG_MOD_EXTENSION_FILES)
	$(LINTER) 
	touch $@


