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

def pyang_plugin_init():
    plugin.register_plugin(CheckStrictLintPlugin())

class CheckStrictLintPlugin(plugin.PyangPlugin):
    
    def add_output_format(self, fmts):
        self.multiple_modules = True
        fmts['strictlint'] = self

    def add_opts(self, optparser):
        optlist = []
        g = optparser.add_option_group("CheckStrictLintPlugin options")
        g.add_options(optlist)

    def setup_fmt(self, ctx):
        ctx.implicit_errors = False

    def emit(self, ctx, modules, fd):

        for (epos, etag, eargs) in ctx.errors:
            elevel = error.err_level(etag)
            if error.is_warning(elevel):
                kind = "warning"
            else:
                kind = "error"
            if "/extensions/" not in str(epos):
                continue
            fd.write(str(epos) + ': %s: ' % kind + \
                                    error.err_to_str(etag, eargs) + '\n')        

        ctx.errors = []

