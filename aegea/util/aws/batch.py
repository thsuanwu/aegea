import io, json, base64, hashlib

import yaml
from botocore.exceptions import ClientError

from . import ARN, resources, clients, expect_error_codes, ensure_s3_bucket
from ..exceptions import AegeaException
from ... import __version__

bash_cmd_preamble = ["/bin/bash", "-c", 'for i in "$@"; do eval "$i"; done', __name__]

env_mgr_shellcode = """
set -a
if [ -f /etc/environment ]; then source /etc/environment; fi
if [ -f /etc/default/locale ]; then source /etc/default/locale; else export LC_ALL=C.UTF-8 LANG=C.UTF-8; fi
export AWS_DEFAULT_REGION={region}
set +a
if [ -f /etc/profile ]; then source /etc/profile; fi
set -euo pipefail
"""

apt_mgr_shellcode = """
sed -i -e "s|/archive.ubuntu.com|/{region}.ec2.archive.ubuntu.com|g" /etc/apt/sources.list
apt-get update -qq"""

ebs_vol_mgr_shellcode = apt_mgr_shellcode + """
apt-get install -qqy --no-install-suggests --no-install-recommends httpie awscli jq python3-{{pip,setuptools,wheel}}
pip3 install aegea=={aegea_version}
aegea_ebs_cleanup() {{ echo Detaching EBS volume $aegea_ebs_vol_id; aegea ebs detach --unmount --delete $aegea_ebs_vol_id; }}
trap aegea_ebs_cleanup EXIT
aegea_ebs_vol_id=$(aegea ebs create --size-gb {size_gb} --volume-type {volume_type} --tags managedBy=aegea batchJobId=$AWS_BATCH_JOB_ID --attach --format mkfs.ext4 --mount {mountpoint} | jq -r .VolumeId)
"""  # noqa

efs_vol_shellcode = """mkdir -p {efs_mountpoint}
MAC=$(curl http://169.254.169.254/latest/meta-data/mac)
export SUBNET_ID=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/subnet-id)
NFS_ENDPOINT=$(echo "$AEGEA_EFS_DESC" | jq -r ".[] | select(.SubnetId == env.SUBNET_ID) | .IpAddress")
mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2 $NFS_ENDPOINT:/ {efs_mountpoint}"""

instance_storage_mgr_shellcode = apt_mgr_shellcode + """
apt-get install -qqy --no-install-suggests --no-install-recommends mdadm
aegea_bd=(/dev/disk/by-id/nvme-Amazon_EC2_NVMe_Instance_Storage_*)
if [ ! -e /dev/md0 ]; then mdadm --create /dev/md0 --force --auto=yes --level=0 --chunk=256 --raid-devices=${{#aegea_bd[@]}} ${{aegea_bd[@]}}; mkfs.ext4 -L aegea-ephemeral -E lazy_itable_init,lazy_journal_init /dev/md0; fi
mount -L aegea-ephemeral {mountpoint}
"""  # noqa

def ensure_dynamodb_table(name, hash_key_name, read_capacity_units=5, write_capacity_units=5):
    try:
        table = resources.dynamodb.create_table(TableName=name,
                                                KeySchema=[dict(AttributeName=hash_key_name, KeyType="HASH")],
                                                AttributeDefinitions=[dict(AttributeName=hash_key_name,
                                                                           AttributeType="S")],
                                                ProvisionedThroughput=dict(ReadCapacityUnits=read_capacity_units,
                                                                           WriteCapacityUnits=write_capacity_units))
    except ClientError as e:
        expect_error_codes(e, "ResourceInUseException")
        table = resources.dynamodb.Table(name)
    table.wait_until_exists()
    return table


def get_command_and_env(args):
    # shellcode = ['for var in ${{!AWS_BATCH_@}}; do echo "{}.env.$var=${{!var}}"; done'.format(__name__)]
    shellcode = env_mgr_shellcode.strip().format(region=ARN.get_region()).splitlines()
    if args.mount_instance_storage or args.storage:
        args.privileged = True
        args.volumes.append(["/dev", "/dev"])
    if args.mount_instance_storage:
        shellcode += instance_storage_mgr_shellcode.strip().format(region=ARN.get_region(),
                                                                   mountpoint=args.mount_instance_storage).splitlines()
    if args.storage:
        for mountpoint, size_gb in args.storage:
            volume_type = "st1"
            if args.volume_type:
                volume_type = args.volume_type
            shellcode += ebs_vol_mgr_shellcode.strip().format(region=ARN.get_region(),
                                                              aegea_version=__version__,
                                                              size_gb=size_gb,
                                                              volume_type=volume_type,
                                                              mountpoint=mountpoint).splitlines()
    elif args.efs_storage:
        args.privileged = True
        if "=" in args.efs_storage:
            mountpoint, efs_id = args.efs_storage.split("=")
        else:
            mountpoint, efs_id = args.efs_storage, __name__
        if not efs_id.startswith("fs-"):
            for filesystem in clients.efs.describe_file_systems()["FileSystems"]:
                if filesystem["Name"] == efs_id:
                    efs_id = filesystem["FileSystemId"]
                    break
            else:
                raise AegeaException('Could not resolve "{}" to a valid EFS filesystem ID'.format(efs_id))
        mount_targets = clients.efs.describe_mount_targets(FileSystemId=efs_id)["MountTargets"]
        args.environment.append(dict(name="AEGEA_EFS_DESC", value=json.dumps(mount_targets)))
        commands = efs_vol_shellcode.format(efs_mountpoint=args.efs_storage, efs_id=efs_id).splitlines()
        shellcode += commands

    if args.execute:
        bucket = ensure_s3_bucket("aegea-batch-jobs-{}".format(ARN.get_account_id()))

        key_name = hashlib.sha256(args.execute.read()).hexdigest()
        args.execute.seek(0)
        bucket.upload_fileobj(args.execute, key_name)
        payload_url = clients.s3.generate_presigned_url(
            ClientMethod='get_object',
            Params=dict(Bucket=bucket.name, Key=key_name),
            ExpiresIn=3600 * 24 * 7
        )
        tmpdir_fmt = "${AWS_BATCH_CE_NAME:-$AWS_EXECUTION_ENV}.${AWS_BATCH_JQ_NAME:-}.${AWS_BATCH_JOB_ID:-}.XXXXX"
        shellcode += ['BATCH_SCRIPT=$(mktemp --tmpdir "{tmpdir_fmt}")'.format(tmpdir_fmt=tmpdir_fmt),
                      "apt-get update -qq",
                      "apt-get install -qqy --no-install-suggests --no-install-recommends curl ca-certificates gnupg",
                      "curl '{payload_url}' > $BATCH_SCRIPT".format(payload_url=payload_url),
                      "chmod +x $BATCH_SCRIPT",
                      "$BATCH_SCRIPT"]
    elif args.cwl:
        ensure_dynamodb_table("aegea-batch-jobs", hash_key_name="job_id")
        bucket = ensure_s3_bucket("aegea-batch-jobs-{}".format(ARN.get_account_id()))
        args.environment.append(dict(name="AEGEA_BATCH_S3_BASE_URL", value="s3://" + bucket.name))

        from cwltool.main import main as cwltool_main
        with io.BytesIO() as preprocessed_cwl:
            if cwltool_main(["--print-pre", args.cwl], stdout=preprocessed_cwl) != 0:
                raise AegeaException("Error while running cwltool")
            cwl_spec = yaml.load(preprocessed_cwl.getvalue())
            payload = base64.b64encode(preprocessed_cwl.getvalue()).decode()
            args.environment.append(dict(name="AEGEA_BATCH_CWL_DEF_B64", value=payload))
            payload = base64.b64encode(args.cwl_input.read()).decode()
            args.environment.append(dict(name="AEGEA_BATCH_CWL_JOB_B64", value=payload))

        for requirement in cwl_spec.get("requirements", []):
            if requirement["class"] == "DockerRequirement":
                # FIXME: dockerFile support: ensure_ecr_image(...)
                # container_props["image"] = requirement["dockerPull"]
                pass

        shellcode += [
            # 'sed -i -e "s|http://archive.ubuntu.com|http://us-east-1.ec2.archive.ubuntu.com|g" /etc/apt/sources.list',
            # "apt-get update -qq",
            # "apt-get install -qqy --no-install-suggests --no-install-recommends --force-yes python-pip python-requests python-yaml python-lockfile python-pyparsing awscli", # noqa
            # "pip install ruamel.yaml==0.13.4 cwltool==1.0.20161227200419 dynamoq tractorbeam",
            "cwltool --no-container --preserve-entire-environment <(echo $AEGEA_BATCH_CWL_DEF_B64 | base64 -d) <(echo $AEGEA_BATCH_CWL_JOB_B64 | base64 -d | tractor pull) | tractor push $AEGEA_BATCH_S3_BASE_URL/$AWS_BATCH_JOB_ID | dynamoq update aegea-batch-jobs $AWS_BATCH_JOB_ID" # noqa
        ]
    args.command = bash_cmd_preamble + shellcode + (args.command or [])
    return args.command, args.environment
