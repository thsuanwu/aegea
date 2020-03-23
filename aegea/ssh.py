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

``aegea ssh`` also supports Bless, via the --bless-config CONFIG_FILE
option or the BLESS_CONFIG environment variable. This should point to a
YAML file with the format described in
https://github.com/chanzuckerberg/blessclient/blob/master/examples/config.yml.
"""

import os, sys, argparse, string, datetime, json, base64, time, fnmatch

import boto3, yaml

from . import register_parser, logger
from .util.aws import resolve_instance_id, resources, clients, ARN
from .util.crypto import (add_ssh_host_key_to_known_hosts, ensure_local_ssh_key, get_public_key_from_pair,
                          add_ssh_key_to_agent, get_ssh_key_path)
from .util.printing import BOLD
from .util.exceptions import AegeaException
from .util.compat import lru_cache
from .util.aws.ssm import ensure_session_manager_plugin

opts_by_nargs = {
    "ssh": {0: "46AaCfGgKkMNnqsTtVvXxYy", 1: "BbcDEeFIiJLlmOopQRSW"},
    "scp": {0: "346BCpqrv", 1: "cFiloPS"}
}

def add_bless_and_passthrough_opts(parser, program):
    parser.add_argument("--bless-config", default=os.environ.get("BLESS_CONFIG"),
                        help="Path to a Bless configuration file (or pass via the BLESS_CONFIG environment variable)")
    parser.add_argument("--use-kms-auth", help=argparse.SUPPRESS)
    for opt in opts_by_nargs[program][0]:
        parser.add_argument("-" + opt, action="store_true", help=argparse.SUPPRESS)
    for opt in opts_by_nargs[program][1]:
        parser.add_argument("-" + opt, action="append", help=argparse.SUPPRESS)

def extract_passthrough_opts(args, program):
    opts = []
    for opt in opts_by_nargs[program][0]:
        if getattr(args, opt):
            opts.append("-" + opt)
    for opt in opts_by_nargs[program][1]:
        for value in getattr(args, opt) or []:
            opts.extend(["-" + opt, value])
    return opts

@lru_cache(8)
def get_instance(name):
    return resources.ec2.Instance(resolve_instance_id(name))

def save_instance_public_key(name):
    instance = get_instance(name)
    tags = {tag["Key"]: tag["Value"] for tag in instance.tags or []}
    ssh_host_key = tags.get("SSHHostPublicKeyPart1", "") + tags.get("SSHHostPublicKeyPart2", "")
    if ssh_host_key:
        # FIXME: this results in duplicates.
        # Use paramiko to detect if the key is already listed and not insert it then (or only insert if different)
        add_ssh_host_key_to_known_hosts(instance.public_dns_name + " " + ssh_host_key + "\n")

def resolve_instance_public_dns(name):
    instance = get_instance(name)
    if not getattr(instance, "public_dns_name", None):
        msg = "Unable to resolve public DNS name for {} (state: {})"
        raise AegeaException(msg.format(instance, getattr(instance, "state", {}).get("Name")))
    return instance.public_dns_name

def get_linux_username():
    username = ARN.get_iam_username()
    assert username != "unknown"
    username, at, domain = username.partition("@")
    return username

def get_kms_auth_token(session, bless_config, lambda_regional_config):
    logger.info("Requesting new KMS auth token in %s", lambda_regional_config["aws_region"])
    token_not_before = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    token_not_after = token_not_before + datetime.timedelta(hours=1)
    token = dict(not_before=token_not_before.strftime("%Y%m%dT%H%M%SZ"),
                 not_after=token_not_after.strftime("%Y%m%dT%H%M%SZ"))
    encryption_context = {
        "from": session.resource("iam").CurrentUser().user_name,
        "to": bless_config["lambda_config"]["function_name"],
        "user_type": "user"
    }
    kms = session.client('kms', region_name=lambda_regional_config["aws_region"])
    res = kms.encrypt(KeyId=lambda_regional_config["kms_auth_key_id"],
                      Plaintext=json.dumps(token),
                      EncryptionContext=encryption_context)
    return base64.b64encode(res["CiphertextBlob"]).decode()

def ensure_bless_ssh_cert(ssh_key_name, bless_config, use_kms_auth, max_cert_age=1800):
    ssh_key = ensure_local_ssh_key(ssh_key_name)
    ssh_key_filename = get_ssh_key_path(ssh_key_name)
    ssh_cert_filename = ssh_key_filename + "-cert.pub"
    if os.path.exists(ssh_cert_filename) and time.time() - os.stat(ssh_cert_filename).st_mtime < max_cert_age:
        logger.info("Using cached Bless SSH certificate %s", ssh_cert_filename)
        return ssh_cert_filename
    logger.info("Requesting new Bless SSH certificate")

    for lambda_regional_config in bless_config["lambda_config"]["regions"]:
        if lambda_regional_config["aws_region"] == clients.ec2.meta.region_name:
            break
    session = boto3.Session(profile_name=bless_config["client_config"]["aws_user_profile"])
    iam = session.resource("iam")
    sts = session.client("sts")
    assume_role_res = sts.assume_role(RoleArn=bless_config["lambda_config"]["role_arn"], RoleSessionName=__name__)
    awslambda = boto3.client('lambda',
                             region_name=lambda_regional_config["aws_region"],
                             aws_access_key_id=assume_role_res['Credentials']['AccessKeyId'],
                             aws_secret_access_key=assume_role_res['Credentials']['SecretAccessKey'],
                             aws_session_token=assume_role_res['Credentials']['SessionToken'])
    bless_input = dict(bastion_user=iam.CurrentUser().user_name,
                       bastion_user_ip="0.0.0.0/0",
                       bastion_ips=",".join(bless_config["client_config"]["bastion_ips"]),
                       remote_usernames=",".join(bless_config["client_config"]["remote_users"]),
                       public_key_to_sign=get_public_key_from_pair(ssh_key),
                       command="*")
    if use_kms_auth:
        bless_input["kmsauth_token"] = get_kms_auth_token(session=session,
                                                          bless_config=bless_config,
                                                          lambda_regional_config=lambda_regional_config)
    res = awslambda.invoke(FunctionName=bless_config["lambda_config"]["function_name"], Payload=json.dumps(bless_input))
    bless_output = json.loads(res["Payload"].read().decode())
    if "certificate" not in bless_output:
        raise AegeaException("Error while requesting Bless SSH certificate: {}".format(bless_output))
    with open(ssh_cert_filename, "w") as fh:
        fh.write(bless_output["certificate"])
    return ssh_cert_filename

def match_instance_to_bastion(instance, bastions):
    for bastion_config in bastions:
        for ipv4_pattern in bastion_config["hosts"]:
            if fnmatch.fnmatch(instance.private_ip_address, ipv4_pattern["pattern"]):
                logger.info("Using %s to connect to %s", bastion_config["pattern"], instance)
                return bastion_config

def prepare_ssh_host_opts(username, hostname, bless_config_filename=None, ssh_key_name=__name__, use_kms_auth=True,
                          use_ssm=True):
    if bless_config_filename:
        with open(bless_config_filename) as fh:
            bless_config = yaml.safe_load(fh)
        ensure_bless_ssh_cert(ssh_key_name=ssh_key_name,
                              bless_config=bless_config,
                              use_kms_auth=use_kms_auth)
        add_ssh_key_to_agent(ssh_key_name)
        instance = get_instance(hostname)
        if not username:
            username = bless_config["client_config"]["remote_users"][0]
        bastion_config = match_instance_to_bastion(instance=instance, bastions=bless_config["ssh_config"]["bastions"])
        if bastion_config:
            jump_host = bastion_config["user"] + "@" + bastion_config["pattern"]
            return ["-o", "ProxyJump=" + jump_host], username + "@" + instance.private_ip_address
        elif instance.public_dns_name:
            logger.warn("No bastion host found for %s, trying direct connection", instance.private_ip_address)
            return [], username + "@" + instance.public_dns_name
        else:
            raise AegeaException("No bastion host or public route found for {}".format(instance))
    else:
        if get_instance(hostname).key_name is not None:
            add_ssh_key_to_agent(get_instance(hostname).key_name)
        if not username:
            username = get_linux_username()
        save_instance_public_key(hostname)
        return [], username + "@" + (get_instance(hostname).id if use_ssm else resolve_instance_public_dns(hostname))

def init_ssm(instance_id):
    ssm_plugin_path = ensure_session_manager_plugin()
    os.environ["PATH"] = os.environ["PATH"] + ":" + os.path.dirname(ssm_plugin_path)
    return ["-o", "ProxyCommand=aws ssm start-session --document-name AWS-StartSSHSession --target " + instance_id]

def ssh(args):
    ssh_opts = ["-o", "ServerAliveInterval={}".format(args.server_alive_interval)]
    ssh_opts += ["-o", "ServerAliveCountMax={}".format(args.server_alive_count_max)]
    ssh_opts += extract_passthrough_opts(args, "ssh")
    prefix, at, name = args.name.rpartition("@")

    if args.use_ssm:
        ssh_opts += init_ssm(get_instance(name).id)

    host_opts, hostname = prepare_ssh_host_opts(username=prefix, hostname=name,
                                                bless_config_filename=args.bless_config,
                                                use_kms_auth=args.use_kms_auth, use_ssm=args.use_ssm)
    os.execvp("ssh", ["ssh"] + ssh_opts + host_opts + [hostname] + args.ssh_args)

ssh_parser = register_parser(ssh, help="Connect to an EC2 instance", description=__doc__)
ssh_parser.add_argument("name")
ssh_parser.add_argument("ssh_args", nargs=argparse.REMAINDER,
                        help="Arguments to pass to ssh; please see " + BOLD("man ssh") + " for details")
ssh_parser.add_argument("--server-alive-interval", help=argparse.SUPPRESS)
ssh_parser.add_argument("--server-alive-count-max", help=argparse.SUPPRESS)
ssh_parser.add_argument("--no-ssm", action="store_false", dest="use_ssm")
add_bless_and_passthrough_opts(ssh_parser, "ssh")

def scp(args):
    """
    Transfer files to or from EC2 instance.
    """
    scp_opts, host_opts = extract_passthrough_opts(args, "scp"), []
    user_or_hostname_chars = string.ascii_letters + string.digits
    ssm_init_complete = False
    for i, arg in enumerate(args.scp_args):
        if arg[0] in user_or_hostname_chars and ":" in arg:
            hostname, colon, path = arg.partition(":")
            username, at, hostname = hostname.rpartition("@")
            if args.use_ssm and not ssm_init_complete:
                scp_opts += init_ssm(get_instance(hostname).id)
                ssm_init_complete = True
            host_opts, hostname = prepare_ssh_host_opts(username=username, hostname=hostname,
                                                        bless_config_filename=args.bless_config,
                                                        use_kms_auth=args.use_kms_auth, use_ssm=args.use_ssm)
            args.scp_args[i] = hostname + colon + path
    os.execvp("scp", ["scp"] + scp_opts + host_opts + args.scp_args)

scp_parser = register_parser(scp, help="Transfer files to or from EC2 instance", description=scp.__doc__)
scp_parser.add_argument("scp_args", nargs=argparse.REMAINDER,
                        help="Arguments to pass to scp; please see " + BOLD("man scp") + " for details")
scp_parser.add_argument("--no-ssm", action="store_false", dest="use_ssm")
add_bless_and_passthrough_opts(scp_parser, "scp")
