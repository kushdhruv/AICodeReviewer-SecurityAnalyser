import os
import yaml

def ping_server(ip_address):
    """
    Pings a server to check if it's alive.
    Contains CWE-78: OS Command Injection.
    """
    # DANGEROUS: Concatenating untrusted input into a system command
    cmd = "ping -n 1 " + ip_address
    output = os.popen(cmd).read()
    return output

def parse_config(yaml_string):
    """
    Parses a YAML configuration.
    Contains CWE-502: Insecure Deserialization.
    """
    # DANGEROUS: Using yaml.load instead of yaml.safe_load
    return yaml.load(yaml_string, Loader=yaml.Loader)
