#!/usr/bin/env python3
'''
Copyright 2019 Broadcom. The term "Broadcom" refers to Broadcom Inc.
and/or its subsidiaries.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import sys
import os
import subprocess
import errno
import time
import datetime
import signal
import host_service
import json
import syslog
import shlex
import re

"""KDUMP command handler"""

MOD_NAME = 'KDUMP'

class KDUMP(host_service.HostModule):
    """DBus endpoint that executes ZTP related commands
    """
    @staticmethod
    def _run_command(cmd):
        '''!
        Execute a given command

        @param cmd (str) Command to execute. Since we execute the command directly, and not within the
                         context of the shell, the full path needs to be provided ($PATH is not used).
                         Command parameters are simply separated by a space.
                         Should be either string or a list

        '''
        try:
            shcmd = shlex.split(cmd)
            proc = subprocess.Popen(shcmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, close_fds=True)
            output_stdout, output_stderr = proc.communicate()
            list_stdout = []
            for l in output_stdout.splitlines():
                list_stdout.append(str(l.decode()))
            list_stderr = []
            for l in output_stderr.splitlines():
                list_stderr.append(str(l.decode()))
            return (proc.returncode, list_stdout, list_stderr)
        except (OSError, ValueError) as e:
            print("!Exception [%s] encountered while processing the command : %s" % (str(e), str(cmd)))
            return (1, None, None)

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='as', out_signature='is')
    def configure(self, options):
        param = options[0]
        value = options[1]

        cmd = '/usr/bin/config kdump %s %s' % (param, value)
        (rc, output, output_err) = self._run_command(cmd);

        result=''
        for s in output:
            if s != '':
                s = '\n' + s
            result = result + s

        return rc, result

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='as', out_signature='is')
    def reset(self, options):
        param = options[0]
        value = None
        if param == "memory":
            value = "0M-2G:256M,2G-4G:320M,4G-8G:384M,8G-:448M"
        elif param == "num_dumps":
            value = "3"
        else:
            return 1, "Invalid parameter"

        cmd = '/usr/bin/config kdump %s %s' % (param, value)
        (rc, output, output_err) = self._run_command(cmd);

        result=''
        for s in output:
            if s != '':
                s = '\n' + s
            result = result + s
        return rc, result

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='', out_signature='s')
    def status(self):
        print("KDUMP Host module: Calling kdump status")       
        cmd = '/usr/bin/sonic-kdump-config --status-json'
        (rc, output, output_err) = self._run_command(cmd)
        if rc == 0:
            return "".join(output)
        else:
            print("KDUMP Host module: kdump status command returned error")       
            return "{}"

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='', out_signature='s')
    def getconfig(self):
        print("KDUMP Host module: Calling kdump config")
        cmd = '/usr/bin/sonic-kdump-config --config-json'
        (rc, output, output_err) = self._run_command(cmd)
        if rc == 0:
            return "".join(output)
        else:
            print("KDUMP Host module: kdump config command returned error")       
            return "{}"

def register():
    """Return the class name"""
    return KDUMP, MOD_NAME
