""" Renew DHCP lease handler"""
import host_service
import subprocess
import shlex
import os

MOD_NAME= 'renew_dhcp_lease'

def run_command(cmd):
    try:
        cmd_opt = shlex.split(cmd)
        subprocess.check_call(cmd_opt)
    except subprocess.CalledProcessError as err:
        return False
    return True

def dhclient_cleanup(path):
    try:
        if os.path.exists(path):
            cmd = shlex.split("cat {}".format(path))
            cmd_obj = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = cmd_obj.communicate()
            out_list = out.splitlines()
            if len(out_list) > 0:
                pid = out_list[0].decode()
                cmd = "kill {}".format(pid)
                run_command(cmd)
            cmd = "rm -f {}".format(path)
            run_command(cmd)
    except:
        pass

class RENEW_DHCP_LEASE(host_service.HostModule):
    """DBus endpoint that executes RENEW_DHCP_LEASE related commands """

    @staticmethod
    def _run_command(options):
        """ Run renew dhcp lease command """
        if len(options) < 2:
            print("RENEW_DHCP_LEASE Invalid options, {}".format(options))
            return 1, "Invalid options"
            
        ifName = options[0]
        version = ""
        file_ext = ""
        cmd_opt = ""
        output = ""
        rc = 0
            
        for x in options[1:]:
            if x == "ipv6":
                version = "-6"
                file_ext = "6"
                cmd_opt = "-D LL"
            else:
                cmd_opt = "-e IF_METRIC=202"
                    
            cmd = "/sbin/dhclient {} -r {}".format(version, ifName)
            run_command(cmd)
            path = "/var/run/dhclient{}.{}.pid".format(file_ext, ifName)
            dhclient_cleanup(path)
            cmd = "/sbin/dhclient {} -pf /run/dhclient{}.{}.pid -lf /var/lib/dhcp/dhclient{}.{}.leases {} -nw {} ".format(version, file_ext, ifName, file_ext, ifName, ifName, cmd_opt)
            if run_command(cmd):
                output = "SUCCESS"
            else:
                rc = 1
                output = "DHCLIENT lease renewal FAILED"

        return rc,output

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='as', out_signature='is')
    def action(self, options):
        return RENEW_DHCP_LEASE._run_command(options)

def register():
    """Return class name"""
    return RENEW_DHCP_LEASE, MOD_NAME
