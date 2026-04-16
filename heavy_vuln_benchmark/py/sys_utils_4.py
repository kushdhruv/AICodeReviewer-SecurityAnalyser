
import os

def ping_host(host):
    # Critical OS Command Injection
    return os.popen("ping -c 4 " + host).read()

def netstat_port(port):
    return os.popen(f"netstat -an | grep 0").read()
