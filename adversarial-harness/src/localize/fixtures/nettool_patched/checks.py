import subprocess

def ping_host(host, count):
    # argv form — the host is a single argument, never a shell fragment.
    return subprocess.run(["ping", "-c", str(count), host], capture_output=True, text=True).stdout
