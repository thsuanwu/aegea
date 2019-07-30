"""
Connect to an EC2 instance via SSH, by name or instance ID.

Security groups, network ACLs, interfaces, VPC routing tables, VPC
Internet Gateways, and internal firewalls for the instance must be
configured to allow SSH connections.

To facilitate SSH connections, ``aegea ssh`` resolves instance names
to public DNS names assigned by AWS, and securely retrieves SSH host
public keys from instance metadata before connecting. This avoids both
the prompt to save the instance public key and the resulting transient
MITM vulnerability.
"""

import os, sys, argparse, subprocess, string, functools

from . import register_parser, logger
from .util.aws import resolve_instance_id, resources, clients, ARN
from .util.crypto import add_ssh_host_key_to_known_hosts
from .util.printing import BOLD
from .util.exceptions import AegeaException
from .util.compat import lru_cache

@lru_cache(8)
def resolve_instance_public_dns(name):
    instance = resources.ec2.Instance(resolve_instance_id(name))
    if not getattr(instance, "public_dns_name", None):
        msg = "Unable to resolve public DNS name for {} (state: {})"
        raise AegeaException(msg.format(instance, getattr(instance, "state", {}).get("Name")))

    tags = {tag["Key"]: tag["Value"] for tag in instance.tags or []}
    ssh_host_key = tags.get("SSHHostPublicKeyPart1", "") + tags.get("SSHHostPublicKeyPart2", "")
    if ssh_host_key:
        # FIXME: this results in duplicates.
        # Use paramiko to detect if the key is already listed and not insert it then (or only insert if different)
        add_ssh_host_key_to_known_hosts(instance.public_dns_name + " " + ssh_host_key + "\n")
    return instance.public_dns_name

def get_linux_username():
    username = ARN.get_iam_username()
    assert username != "unknown"
    username, at, domain = username.partition("@")
    return username

def ssh(args):
    prefix, at, name = args.name.rpartition("@")
    ssh_args = ["ssh", prefix + at + resolve_instance_public_dns(name)]
    if not (prefix or at):
        try:
            ssh_args += ["-l", get_linux_username()]
        except Exception:
            logger.info("Unable to determine IAM username, using local username")
    os.execvp("ssh", ssh_args + args.ssh_args)

ssh_parser = register_parser(ssh, help="Connect to an EC2 instance", description=__doc__)
ssh_parser.add_argument("name")
ssh_parser.add_argument("ssh_args", nargs=argparse.REMAINDER,
                        help="Arguments to pass to ssh; please see " + BOLD("man ssh") + " for details")

def scp(args):
    """
    Transfer files to or from EC2 instance.

    Use "--" to separate scp args from aegea args:

        aegea scp -- -r local_dir instance_name:~/remote_dir
    """
    if args.scp_args[0] == "--":
        del args.scp_args[0]
    user_or_hostname_chars = string.ascii_letters + string.digits
    for i, arg in enumerate(args.scp_args):
        if arg[0] in user_or_hostname_chars and ":" in arg:
            hostname, colon, path = arg.partition(":")
            username, at, hostname = hostname.rpartition("@")
            hostname = resolve_instance_public_dns(hostname)
            if not (username or at):
                try:
                    username, at = get_linux_username(), "@"
                except Exception:
                    logger.info("Unable to determine IAM username, using local username")
            args.scp_args[i] = username + at + hostname + colon + path
    os.execvp("scp", ["scp"] + args.scp_args)

scp_parser = register_parser(scp, help="Transfer files to or from EC2 instance", description=scp.__doc__)
scp_parser.add_argument("scp_args", nargs=argparse.REMAINDER,
                        help="Arguments to pass to scp; please see " + BOLD("man scp") + " for details")
