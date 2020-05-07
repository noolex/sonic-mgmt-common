""" docker version"""
import host_service
import subprocess
import syslog as log

MOD_NAME= 'docker_version'

class DOCKER_VERSION(host_service.HostModule):
    """DBus endpoint that executes MGMT related commands """

    @staticmethod
    def _run_command(options):
        """ Run docker images command """
        cmd = 'sudo docker images --format "table {{.Repository}}\\t{{.Tag}}\\t{{.ID}}\\t{{.Size}}" | grep -v REPOSITORY'

        output = ""
        try:
            rc = 0
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            output = p.stdout.read()

        except subprocess.CalledProcessError as err:
            print ("Exception when calling get_sonic_error -> %s\n" %(err))
            rc = err.returncode
            output = err.output
        return rc, output

    @host_service.method(host_service.bus_name(MOD_NAME), in_signature='as', out_signature='is')
    def action(self, options):
        return DOCKER_VERSION._run_command(options)

def register ():
    """Return class name"""
    return DOCKER_VERSION, MOD_NAME


