import subprocess

def ping_host(host, count):
    # Reachability check against the given host.
    cmd = "ping -c %d %s" % (count, host)
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
