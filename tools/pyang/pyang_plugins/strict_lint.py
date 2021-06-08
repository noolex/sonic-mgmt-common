################################################################################
#                                                                              #
#  Copyright 2019 Broadcom. The term Broadcom refers to Broadcom Inc. and/or   #
#  its subsidiaries.                                                            #
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

import optparse
import sys
import os
import io
import pdb
import subprocess
import re

import pyang
from pyang import plugin
from pyang import statements
from pyang import error
from pyang import util
from pyang import types
from pyang.error import err_add

try:
    from StringIO import StringIO ## for Python 2
except ImportError:
    from io import StringIO ## for Python 3

issues = []
extensionModulesList = []

def prepare_ignore_list(ctx,ignore_file_dict):
    ignore_file = ctx.opts.ignore_file
    with open(ignore_file, "r") as ignore_fh:
        for entry in ignore_fh:
            entry = entry.strip()
            if entry.startswith('#'):
                continue
            entry_list = list(filter(None,entry.split(' ')))
            if len(entry_list) == 0:
                continue
            mod_name = entry_list[0]
            if mod_name not in ignore_file_dict:
                ignore_file_dict[mod_name] = set()
            for line_num in entry_list[1:]:
                ignore_file_dict[mod_name].add(int(line_num.strip()))

def prepare_patched_mods_list(ctx,patched_mods):
    patch_dir = ctx.opts.patch_dir
    for patch_file in os.listdir(patch_dir):
        if patch_file.endswith('.patch'):
            mod_name = patch_file.replace('.patch','').replace('.yang','')
            patched_mods.add(mod_name)

def get_error_flags(elevel,error_seen):
    kind = "warning"
    if not error.is_warning(elevel):
        kind = "error"
        error_seen = True
    return kind,error_seen

def pyang_plugin_init():
    plugin.register_plugin(CheckStrictLintPlugin())

class CheckStrictLintPlugin(plugin.PyangPlugin):
    
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['strictlint'] = self

    def add_opts(self, optparser):
        optlist = [
            optparse.make_option("--patchdir",
                                 type="string",
                                 dest="patch_dir",
                                 help="YANG Patch files directory"),
            optparse.make_option("--ignorefile",
                                 type="string",
                                 dest="ignore_file",
                                 help="File path containing ignore list of modules"), 
        ]
        g = optparser.add_option_group("CheckStrictLintPlugin options")
        g.add_options(optlist)

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):
        error_seen = False
        ignore_file_dict = dict()
        patched_mods = set()
        prepare_ignore_list(ctx,ignore_file_dict)
        prepare_patched_mods_list(ctx,patched_mods)
        if ctx.opts.outfile is not None:
            fd = open(ctx.opts.outfile, "w")        
        for (epos, etag, eargs) in ctx.errors:
            elevel = error.err_level(etag)
            
            if "/extensions/" not in str(epos):
                mod_name = epos.ref.split('/')[-1].split('.')[0]
                if mod_name in patched_mods:
                    if mod_name in ignore_file_dict:
                        if len(ignore_file_dict[mod_name]) == 0:
                            kind = "ignored"
                        else:
                            line_num = epos.line
                            if line_num in ignore_file_dict[mod_name]:
                                kind = "ignored"
                            else:
                                kind,error_seen = get_error_flags(elevel,error_seen)
                    else:
                        kind,error_seen = get_error_flags(elevel,error_seen)
                else:
                    kind = "ignored"
            else:
                kind,error_seen = get_error_flags(elevel,error_seen)
                
            fd.write(str(epos) + ': %s: ' % kind + \
                                    error.err_to_str(etag, eargs) + '\n')
        
        if ctx.opts.outfile is not None:
            fd.close()
        if error_seen:
            sys.exit(1)
        else:
            sys.exit(0)

