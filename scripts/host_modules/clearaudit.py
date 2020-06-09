"""Clear Audit Log command handler"""

import host_service
import subprocess
import re

MOD_NAME = 'clearaudit'

class ClearAudit(host_service.HostModule):
    """DBus endpoint that executes the "rm /var/log/audit.log and service rsyslog restart" commands
    """
    @host_service.method(host_service.bus_name(MOD_NAME))
    def action():

        print("Host side: Clearing audit log")
        rmcmd = ['/bin/rm -rf /var/log/audit.log']
        restartcmd = ['service rsyslog restart']

        try:
            rc = 0
            p = subprocess.Popen(rmcmd, shell=True, stdout=subprocess.PIPE)
            output = p.stdout.read()
            p = subprocess.Popen(restartcmd, shell=True, stdout=subprocess.PIPE)
            output = p.stdout.read()
        except subprocess.CalledProcessError as err:
            rc = err.returncode
            output = 'Error: Failure code {:-5}'.format(rc)
            print("%Error: Host side: Failed: " + str(rc))
            return rc

        return rc

def register():
    """Return the class name"""
    return ClearAudit, MOD_NAME
