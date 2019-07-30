import io, json, base64, hashlib

import yaml
from botocore.exceptions import ClientError

from . import ARN, resources, clients, expect_error_codes, ensure_s3_bucket
from ..exceptions import AegeaException

bash_cmd_preamble = ["/bin/bash", "-c", 'for i in "$@"; do eval "$i"; done', __name__]

ebs_vol_mgr_shellcode = """apt-get update -qq
apt-get install -qqy --no-install-suggests --no-install-recommends httpie awscli jq psmisc lsof

iid=$(http http://169.254.169.254/latest/dynamic/instance-identity/document)
aws configure set default.region $(echo "$iid" | jq -r .region)
az=$(echo "$iid" | jq -r .availabilityZone)

echo Creating volume >&2
vid=$(aws ec2 create-volume --availability-zone $az --size %s --volume-type %s | jq -r .VolumeId)
aws ec2 create-tags --resource $vid --tags Key=aegea_batch_job,Value=$AWS_BATCH_JOB_ID

echo Setting up SIGEXIT handler >&2
trap "cd / ; \
      fuser %s >&2 || echo Fuser exit code \$? >&2; \
      lsof %s | grep -iv lsof | awk '{print \$2}' | grep -v PID | xargs kill -9 || echo LSOF exit code \$? >&2; \
      sleep 3; \
      umount %s || umount -l %s; \
      aws ec2 detach-volume --volume-id $vid; \
      let try=1; \
      sleep 10; \
      while ! aws ec2 describe-volumes --volume-ids $vid | jq -re .Volumes[0].Attachments==[]; do \
          if [[ \$try -gt 2 ]]; then \
              echo Forcefully detaching volume $vid >&2; \
              aws ec2 detach-volume --force --volume-id $vid; \
              sleep 10; \
              echo Deleting volume $vid >&2; \
              aws ec2 delete-volume --volume-id $vid; \
              exit; \
          fi; \
          sleep 10; \
          let try=\$try+1; \
      done; \
      echo Deleting volume $vid >&2; \
      aws ec2 delete-volume --volume-id $vid" EXIT

echo Waiting for volume $vid to be created >&2
while [[ $(aws ec2 describe-volumes --volume-ids $vid | jq -r .Volumes[0].State) != available ]]; do \
    sleep 1; \
done

# let each process start trying from a different /dev/xvd{letter}
let pid=$$
echo Finding unused devnode for volume $vid >&2
# when N processes compete, for every success there can be N-1 failures; so the appropriate number of retries is O(N^2)
# let us size this for 10 competitors
# NOTE: the constants 9 and 10 in the $ind and $devnode calculation below are based on strlen("/dev/xvda")
let delay=2+$pid%%5
for try in {1..100}; do \
    if [[ $try == 100 ]]; then \
        echo "Unable to mount $vid on $devnode"; \
        exit 1; \
    fi; \
    if [[ $try -gt 1 ]]; then \
        sleep $delay; \
    fi; \
    devices=$(echo /dev/xvd* /dev/xvd{a..z} /dev/xvd{a..z} | sed 's= =\\n=g' | sort | uniq -c | sort -n | grep ' 2 ' | awk '{print $2}'); \
    let devcnt=${#devices}/10+1; \
    let ind=$pid%%devcnt; \
    devnode=${devices:10*$ind:9}; \
    aws ec2 attach-volume --instance-id $(echo "$iid" | jq -r .instanceId) --volume-id $vid --device $devnode || continue; \
    break; \
done

# attach-volume is not instantaneous, and describe-volume requests are rate-limited
echo Waiting for volume $vid to attach on $devnode >&2
let delay=5+$pid%%11
sleep $delay
let try=1
let max_tries=32
while [[ $(aws ec2 describe-volumes --volume-ids $vid | jq -r .Volumes[0].State) != in-use ]]; do \
    if [[ $try == $max_tries ]]; then \
        break; \
    fi; \
    let foo=1+$try%%5; \
    let delay=2**$foo+$pid%%11; \
    sleep $delay; \
done
while [[ ! -e $devnode ]]; do \
    sleep 1; \
done

echo Making filesystem on $devnode >&2
mkfs.ext4 $devnode

echo Mounting $devnode >& 2
mount $devnode %s

echo Devnode $devnode mounted >& 2
""" # noqa

ebs_vol_mgr_shellcode = "\n".join(
    [l.strip() for l in ebs_vol_mgr_shellcode.replace("\\\n", "").splitlines() if l.strip() and not l.startswith("#")]
)

efs_vol_shellcode = """mkdir -p {efs_mountpoint}
MAC=$(curl http://169.254.169.254/latest/meta-data/mac)
export SUBNET_ID=$(curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/$MAC/subnet-id)
NFS_ENDPOINT=$(echo "$AEGEA_EFS_DESC" | jq -r ".[] | select(.SubnetId == env.SUBNET_ID) | .IpAddress")
mount -t nfs -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2 $NFS_ENDPOINT:/ {efs_mountpoint}"""

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
    shellcode = ["set -a",
                 "if [ -f /etc/environment ]; then source /etc/environment; fi",
                 "if [ -f /etc/default/locale ]; then source /etc/default/locale; fi",
                 "set +a",
                 "if [ -f /etc/profile ]; then source /etc/profile; fi",
                 "set -euo pipefail"]
    if args.storage:
        args.privileged = True
        args.volumes.append(["/dev", "/dev"])
        for mountpoint, size_gb in args.storage:
            volume_type = "st1"
            if args.volume_type:
                volume_type = args.volume_type
            shellcode += (ebs_vol_mgr_shellcode % tuple([size_gb] + [volume_type] + [mountpoint] * 5)).splitlines()
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
        shellcode += ['BATCH_SCRIPT=$(mktemp --tmpdir "$AWS_BATCH_CE_NAME.$AWS_BATCH_JQ_NAME.$AWS_BATCH_JOB_ID.XXXXX")',
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
