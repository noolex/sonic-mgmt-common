"""infra ops provided command handler"""

import host_service
import shlex
import subprocess
import re


MOD_NAME = 'infra_host'

class InfraHost(host_service.HostModule):
    """DBus endpoint that executes the boot provided command
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

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='s', out_signature='is')
    def exec_cmd(self, param):

        # All results, formatted as a  string
        if param != None:
            cmd = 'sudo %s' % param
        else:
            print("!Encountered while processing empty param")
            return (1, None)

        (rc, output, output_err) = self._run_command(cmd);
        result=''
        for s in output:
            if s != '':
                s = '\n' + s
            result = result + s

        return 0, result

def register():
    """Return the class name"""
    return InfraHost, MOD_NAME
