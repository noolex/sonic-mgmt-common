#!/usr/bin/env python3
'''
Copyright 2020 Broadcom. The term "Broadcom" refers to Broadcom Inc.
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
from swsssdk import ConfigDBConnector

"""coredumpctl command handler"""

MOD_NAME = 'coredumpctl'

class coredumpctl(host_service.HostModule):
    """DBus endpoint that executes coredumpctl commands
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

    @staticmethod
    def _get_coredump_operstate():
        coredump_mode = False
        try:
            with open("/proc/sys/kernel/core_pattern", "r") as fp:
                pstring = fp.read().strip()
                if pstring != "":
                   coredump_mode = True
        except:
            print("Error! Failed to read core_pattern from proc filesystem")
        return coredump_mode

    def _get_coredump_admin_mode(self):
        coredump_mode = True
        try:
            configDB = ConfigDBConnector()
            configDB.connect()
            mode = configDB.get_entry("COREDUMP", "config")
            if mode.get("enabled") == "false":
                coredump_mode = False
        except:
            pass
        return coredump_mode

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='as', out_signature='is')
    def configure(self, options):
        param = options[0]
        value = options[1]
        if param == 'enable' and self._get_coredump_admin_mode():
            return 0, ''
        elif param == 'disable' and self._get_coredump_admin_mode() is False:
            return 0, ''
        cmd = '/usr/bin/config core %s %s' % (param, value)
        (rc, output, output_err) = self._run_command(cmd);
        result=''
        for s in output:
            if s != '':
                s = '\n' + s
            result = result + s

        return rc, result

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='', out_signature='s')
    def records(self):
        cmd = 'journalctl -r -n all -t systemd-coredump -o json --no-pager > /tmp/core_files_list'
        rc = os.system(cmd)
        if rc == 0:
            coredump_mode = self._get_coredump_operstate()
            corefile_records = dict()
            data = {}
            machine_id = None
            try:
                with open("/etc/machine-id", "r") as fp:
                    mid = fp.read().strip()
                    if mid != "":
                       machine_id = mid
            except:
                print("Error! Failed to read machine-id")

            try:
                records_list = []
                with open("/tmp/core_files_list") as fp:
                    line_count = 0
                    # Limit total number of core files reported to the latest 1000 records
                    while line_count < 1000:
                        line = fp.readline()
                        if not line:
                            break
                        record = json.loads(line)
                        records_list.append(record)
                        line_count = line_count + 1
                for r in records_list:
                    if machine_id is None or machine_id == r.get("_MACHINE_ID"):
                        record_data = dict()
                        record_data["timestamp"] = r.get("_SOURCE_REALTIME_TIMESTAMP")
                        record_data["executable"] = r.get("COREDUMP_EXE")
                        record_data["core-file"] = r.get("COREDUMP_FILENAME")
                        record_data["pid"] = r.get("COREDUMP_PID")
                        record_data["uid"] = r.get("COREDUMP_UID")
                        record_data["gid"] = r.get("COREDUMP_GID")
                        record_data["signal"] = r.get("COREDUMP_SIGNAL")
                        record_data["command-line"] = r.get("COREDUMP_CMDLINE")
                        record_data["boot-identifier"] = r.get("_BOOT_ID")
                        record_data["machine-identifier"] = r.get("_MACHINE_ID")
                        record_data["crash-message"] = r.get("MESSAGE")
                        if r.get("COREDUMP_FILENAME"):
                            record_data["core-file-present"] = os.path.exists(r.get("COREDUMP_FILENAME"))
                        else:
                            record_data["core-file-present"] = False
                        corefile_records[record_data["timestamp"]] = record_data
            except Exception as e:
                print("Error [%s]! Failed to retrieve corefile records" %(e))

            data["core-file-record"] = corefile_records
            if os.path.exists("/tmp/core_files_list"):
                os.remove("/tmp/core_files_list")
            return json.dumps(data, indent=4)
        else:
            print("coredumpctl Host module: Failed to retrieve corefile records")
            return "{}"

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='', out_signature='s')
    def status(self):
        coredump_mode = self._get_coredump_operstate()
        data = { "enable" : coredump_mode }
        return json.dumps(data, indent=4)

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='', out_signature='s')
    def getconfig(self):
        if self._get_coredump_admin_mode():
            return '{"enable" : true}'
        else:
            return '{"enable" : false}'

def register():
    """Return the class name"""
    return coredumpctl, MOD_NAME
