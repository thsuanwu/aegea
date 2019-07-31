"""
Manage AWS Batch jobs, queues, and compute environments.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, base64, collections, io, subprocess, json, time, re, hashlib
from datetime import datetime

from botocore.exceptions import ClientError

from . import logger
from .ls import register_parser, register_listing_parser
from .ecr import ecr_image_name_completer
from .util import Timestamp, paginate
from .util.crypto import ensure_ssh_key
from .util.printing import page_output, tabulate, YELLOW, RED, GREEN, BOLD, ENDC
from .util.aws import (ARN, resources, clients, ensure_iam_role, ensure_instance_profile, make_waiter, ensure_vpc,
                       ensure_security_group, ensure_log_group, IAMPolicyBuilder, resolve_ami)
from .util.aws.spot import SpotFleetBuilder
from .util.aws.logs import CloudwatchLogReader
from .util.aws.batch import bash_cmd_preamble, ebs_vol_mgr_shellcode, get_command_and_env

def batch(args):
    batch_parser.print_help()

batch_parser = register_parser(batch, help="Manage AWS Batch resources", description=__doc__)

def queues(args):
    table = clients.batch.describe_job_queues()["jobQueues"]
    page_output(tabulate(table, args))

parser = register_listing_parser(queues, parent=batch_parser, help="List Batch queues")

def create_queue(args):
    ces = [dict(computeEnvironment=e, order=i) for i, e in enumerate(args.compute_environments)]
    logger.info("Creating queue %s in %s", args.name, ces)
    queue = clients.batch.create_job_queue(jobQueueName=args.name, priority=args.priority, computeEnvironmentOrder=ces)
    make_waiter(clients.batch.describe_job_queues, "jobQueues[].status", "VALID", "pathAny").wait(jobQueues=[args.name])
    return queue

parser = register_parser(create_queue, parent=batch_parser, help="Create a Batch queue")
parser.add_argument("name")
parser.add_argument("--priority", type=int, default=5)
parser.add_argument("--compute-environments", nargs="+", required=True)

def delete_queue(args):
    clients.batch.update_job_queue(jobQueue=args.name, state="DISABLED")
    make_waiter(clients.batch.describe_job_queues, "jobQueues[].status", "VALID", "pathAny").wait(jobQueues=[args.name])
    clients.batch.delete_job_queue(jobQueue=args.name)

parser = register_parser(delete_queue, parent=batch_parser, help="Delete a Batch queue")
parser.add_argument("name")
def compute_environments(args):
    table = clients.batch.describe_compute_environments()["computeEnvironments"]
    page_output(tabulate(table, args))

parser = register_listing_parser(compute_environments, parent=batch_parser, help="List Batch compute environments")
def create_compute_environment(args):
    batch_iam_role = ensure_iam_role(args.service_role, trust=["batch"], policies=["service-role/AWSBatchServiceRole"])
    vpc = ensure_vpc()
    ssh_key_name = ensure_ssh_key(args.ssh_key_name, base_name=__name__)
    instance_profile = ensure_instance_profile(args.instance_role,
                                               policies={"service-role/AmazonAPIGatewayPushToCloudWatchLogs",
                                                         "service-role/AmazonEC2ContainerServiceforEC2Role",
                                                         IAMPolicyBuilder(action="sts:AssumeRole", resource="*")})
    compute_resources = dict(type=args.compute_type,
                             minvCpus=args.min_vcpus, desiredvCpus=args.desired_vcpus, maxvCpus=args.max_vcpus,
                             instanceTypes=args.instance_types,
                             subnets=[subnet.id for subnet in vpc.subnets.all()],
                             securityGroupIds=[ensure_security_group("aegea.launch", vpc).id],
                             instanceRole=instance_profile.name,
                             bidPercentage=100,
                             spotIamFleetRole=SpotFleetBuilder.get_iam_fleet_role().name,
                             ec2KeyPair=ssh_key_name)
    if args.ecs_container_instance_ami:
        compute_resources["imageId"] = args.ecs_container_instance_ami
    elif args.ecs_container_instance_ami_tags:
        # TODO: build ECS CI AMI on demand
        compute_resources["imageId"] = resolve_ami(**args.ecs_container_instance_ami_tags)
    logger.info("Creating compute environment %s in %s", args.name, vpc)
    compute_environment = clients.batch.create_compute_environment(computeEnvironmentName=args.name,
                                                                   type=args.type,
                                                                   computeResources=compute_resources,
                                                                   serviceRole=batch_iam_role.name)
    wtr = make_waiter(clients.batch.describe_compute_environments, "computeEnvironments[].status", "VALID", "pathAny",
                      delay=2, max_attempts=300)
    wtr.wait(computeEnvironments=[args.name])
    return compute_environment

cce_parser = register_parser(create_compute_environment, parent=batch_parser, help="Create a Batch compute environment")
cce_parser.add_argument("name")
cce_parser.add_argument("--type", choices={"MANAGED", "UNMANAGED"})
cce_parser.add_argument("--compute-type", choices={"EC2", "SPOT"})
cce_parser.add_argument("--min-vcpus", type=int)
cce_parser.add_argument("--desired-vcpus", type=int)
cce_parser.add_argument("--max-vcpus", type=int)
cce_parser.add_argument("--instance-types", nargs="+")
cce_parser.add_argument("--ssh-key-name")
cce_parser.add_argument("--instance-role", default=__name__ + ".ecs_container_instance")
cce_parser.add_argument("--service-role", default=__name__ + ".service")
cce_parser.add_argument("--ecs-container-instance-ami")
cce_parser.add_argument("--ecs-container-instance-ami-tags")

def delete_compute_environment(args):
    clients.batch.update_compute_environment(computeEnvironment=args.name, state="DISABLED")
    wtr = make_waiter(clients.batch.describe_compute_environments, "computeEnvironments[].status", "VALID", "pathAny")
    wtr.wait(computeEnvironments=[args.name])
    clients.batch.delete_compute_environment(computeEnvironment=args.name)

parser = register_parser(delete_compute_environment, parent=batch_parser, help="Delete a Batch compute environment")
parser.add_argument("name")

def get_ecr_image_uri(tag):
    return "{}.dkr.ecr.{}.amazonaws.com/{}".format(ARN.get_account_id(), ARN.get_region(), tag)

def ensure_ecr_image(tag):
    pass

def set_ulimits(args, container_props):
    if args.ulimits:
        container_props.setdefault("ulimits", [])
        for ulimit in args.ulimits:
            name, value = ulimit.split(":", 1)
            container_props["ulimits"].append(dict(name=name, hardLimit=int(value), softLimit=int(value)))

def set_volumes(args, container_props):
    if args.volumes:
        for i, (host_path, guest_path) in enumerate(args.volumes):
            container_props["volumes"].append({"host": {"sourcePath": host_path}, "name": "vol%d" % i})
            container_props["mountPoints"].append({"sourceVolume": "vol%d" % i, "containerPath": guest_path})

def ensure_job_definition(args):
    if args.ecs_image:
        args.image = get_ecr_image_uri(args.ecs_image)
    container_props = {k: getattr(args, k) for k in ("image", "vcpus", "memory", "privileged")}
    container_props.update(volumes=[], mountPoints=[], resourceRequirements=[], environment=[], command=[])
    set_volumes(args, container_props)
    set_ulimits(args, container_props)
    if args.gpus:
        container_props["resourceRequirements"].append({"type": "GPU", "value": str(args.gpus)})
    iam_role = ensure_iam_role(args.job_role, trust=["ecs-tasks"],
                               policies=["AmazonEC2FullAccess", "AmazonDynamoDBFullAccess", "AmazonS3FullAccess"])
    container_props.update(jobRoleArn=iam_role.arn)
    expect_job_defn = dict(status="ACTIVE", type="container", parameters={},
                           retryStrategy={'attempts': args.retry_attempts}, containerProperties=container_props)
    job_hash = hashlib.sha256(json.dumps(container_props, sort_keys=True).encode()).hexdigest()[:8]
    job_defn_name = __name__.replace(".", "_") + "_job_" + job_hash
    for job_defn in paginate(clients.batch.get_paginator('describe_job_definitions'), jobDefinitionName=job_defn_name):
        job_defn_desc = {k: job_defn.pop(k) for k in ("jobDefinitionName", "jobDefinitionArn", "revision")}
        if job_defn == expect_job_defn:
            return job_defn_desc
    return clients.batch.register_job_definition(jobDefinitionName=job_defn_name,
                                                 type="container",
                                                 containerProperties=container_props,
                                                 retryStrategy=dict(attempts=args.retry_attempts))

def ensure_queue(name):
    cq_args = argparse.Namespace(name=name, priority=5, compute_environments=[name])
    try:
        return create_queue(cq_args)
    except ClientError:
        create_compute_environment(cce_parser.parse_args(args=[name]))
        return create_queue(cq_args)

def submit(args):
    ensure_log_group("docker")
    ensure_log_group("syslog")
    command, environment = get_command_and_env(args)
    if args.job_definition_arn is None:
        jd_res = ensure_job_definition(args)
        args.job_definition_arn = jd_res["jobDefinitionArn"]
        args.name = args.name or "{}_{}".format(jd_res["jobDefinitionName"], jd_res["revision"])
    submit_args = dict(jobName=args.name,
                       jobQueue=args.queue,
                       dependsOn=[dict(jobId=dep) for dep in args.depends_on],
                       jobDefinition=args.job_definition_arn,
                       parameters={k: v for k, v in args.parameters},
                       containerOverrides=dict(command=command, environment=environment))
    if args.dry_run:
        return {"Dry run succeeded": True}
    try:
        job = clients.batch.submit_job(**submit_args)
    except ClientError as e:
        if not re.search("JobQueue .+ not found", str(e)):
            raise
        ensure_queue(args.queue)
        job = clients.batch.submit_job(**submit_args)
    if args.watch:
        watch(watch_parser.parse_args([job["jobId"]]))
        if args.cwl:
            job.update(resources.dynamodb.Table("aegea-batch-jobs").get_item(Key={"job_id": job["jobId"]})["Item"])
    elif args.wait:
        raise NotImplementedError()
    return job

submit_parser = register_parser(submit, parent=batch_parser, help="Submit a job to a Batch queue")
submit_parser.add_argument("--name")
submit_parser.add_argument("--queue", default=__name__.replace(".", "_"))
submit_parser.add_argument("--depends-on", nargs="+", metavar="JOB_ID", default=[])
submit_parser.add_argument("--job-definition-arn")

def add_command_args(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--watch", action="store_true", help="Monitor submitted job, stream log until job completes")
    group.add_argument("--wait", action="store_true",
                       help="Block on job. Exit with code 0 if job succeeded, 1 if failed")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--command", nargs="+", help="Run these commands as the job (using " + BOLD("bash -c") + ")")
    group.add_argument("--execute", type=argparse.FileType("rb"), metavar="EXECUTABLE",
                       help="Read this executable file and run it as the job")
    group.add_argument("--cwl", metavar="CWL_DEFINITION",
                       help="Read this Common Workflow Language definition file and run it as the job")
    parser.add_argument("--cwl-input", type=argparse.FileType("rb"), metavar="CWLINPUT", default=sys.stdin,
                        help="With --cwl, use this file as the CWL job input (default: stdin)")
    parser.add_argument("--environment", nargs="+", metavar="NAME=VALUE",
                        type=lambda x: dict(zip(["name", "value"], x.split("=", 1))), default=[])

def add_job_defn_args(parser):
    parser.add_argument("--ulimits", nargs="*",
                        help="Separate ulimit name and value with colon, for example: --ulimits nofile:20000",
                        default=["nofile:100000"])
    img_group = parser.add_mutually_exclusive_group()
    img_group.add_argument("--image", default="ubuntu", help="Docker image URL to use for running job/task")
    ecs_img_help = "Name of Docker image residing in this account's Elastic Container Registry"
    ecs_img_arg = img_group.add_argument("--ecs-image", "--ecr-image", "-i", metavar="REPO[:TAG]", help=ecs_img_help)
    ecs_img_arg.completer = ecr_image_name_completer
    parser.add_argument("--volumes", nargs="+", metavar="HOST_PATH=GUEST_PATH", type=lambda x: x.split("=", 1), default=[])
    parser.add_argument("--memory-mb", dest="memory", type=int, default=1024)

add_command_args(submit_parser)

group = submit_parser.add_argument_group(title="job definition parameters", description="""
See http://docs.aws.amazon.com/batch/latest/userguide/job_definitions.html""")
add_job_defn_args(group)
group.add_argument("--vcpus", type=int, default=1)
group.add_argument("--gpus", type=int, default=0)
group.add_argument("--privileged", action="store_true", default=False)
group.add_argument("--volume-type", choices={"standard", "io1", "gp2", "sc1", "st1"},
                   help="io1, PIOPS SSD; gp2, general purpose SSD; sc1, cold HDD; st1, throughput optimized HDD")
group.add_argument("--parameters", nargs="+", metavar="NAME=VALUE", type=lambda x: x.split("=", 1), default=[])
group.add_argument("--job-role", metavar="IAM_ROLE", default=__name__ + ".worker",
                   help="Name of IAM role to grant to the job")
group.add_argument("--storage", nargs="+", metavar="MOUNTPOINT=SIZE_GB",
                   type=lambda x: x.rstrip("GBgb").split("=", 1), default=[])
group.add_argument("--efs-storage", action="store", dest="efs_storage", default=False,
                   help="mount nfs drive to the mount point specified. i.e. --efs-storage /mnt")
submit_parser.add_argument("--timeout",
                           help="Terminate (and possibly restart) the job after this time (use suffix s, m, h, d, w)")
submit_parser.add_argument("--retry-attempts", type=int, default=1,
                           help="Number of times to restart the job upon failure")
submit_parser.add_argument("--dry-run", action="store_true", help="Gather arguments and stop short of submitting job")

def terminate(args):
    return clients.batch.terminate_job(jobId=args.job_id, reason="Terminated by {}".format(__name__))

parser = register_parser(terminate, parent=batch_parser, help="Terminate a Batch job")
parser.add_argument("job_id")

def ls(args, page_size=100):
    table, job_ids = [], []
    for q in args.queues or [q["jobQueueName"] for q in clients.batch.describe_job_queues()["jobQueues"]]:
        for s in args.status:
            job_ids.extend(j["jobId"] for j in clients.batch.list_jobs(jobQueue=q, jobStatus=s)["jobSummaryList"])
    for i in range(0, len(job_ids), page_size):
        table.extend(clients.batch.describe_jobs(jobs=job_ids[i:i + page_size])["jobs"])
    page_output(tabulate(table, args, cell_transforms={"createdAt": Timestamp}))

job_status_colors = dict(SUBMITTED=YELLOW(), PENDING=YELLOW(), RUNNABLE=BOLD() + YELLOW(),
                         STARTING=GREEN(), RUNNING=GREEN(),
                         SUCCEEDED=BOLD() + GREEN(), FAILED=BOLD() + RED())
job_states = job_status_colors.keys()
parser = register_listing_parser(ls, parent=batch_parser, help="List Batch jobs")
parser.add_argument("--queues", nargs="+")
parser.add_argument("--status", nargs="+", default=job_states, choices=job_states)

def describe(args):
    return clients.batch.describe_jobs(jobs=[args.job_id])["jobs"][0]

parser = register_parser(describe, parent=batch_parser, help="Describe a Batch job")
parser.add_argument("job_id")

def format_job_status(status):
    return job_status_colors[status] + status + ENDC()

def get_logs(args):
    for event in CloudwatchLogReader(args.log_stream_name, head=args.head, tail=args.tail):
        print(str(Timestamp(event["timestamp"])), event["message"])

def save_job_desc(job_desc):
    try:
        cprops = dict(image="busybox", vcpus=1, memory=4,
                      environment=[dict(name="job_desc", value=json.dumps(job_desc))])
        jd_name = "{}_job_desc_{}".format(__name__.replace(".", "_"), job_desc["jobId"])
        clients.batch.register_job_definition(jobDefinitionName=jd_name, type="container", containerProperties=cprops)
    except Exception as e:
        logger.debug("Error while saving job description: %s", e)

def get_job_desc(job_id):
    try:
        return clients.batch.describe_jobs(jobs=[job_id])["jobs"][0]
    except IndexError:
        jd_name = "{}_job_desc_{}".format(__name__.replace(".", "_"), job_id)
        jd = clients.batch.describe_job_definitions(jobDefinitionName=jd_name)["jobDefinitions"][0]
        return json.loads(jd["containerProperties"]["environment"][0]["value"])

def watch(args):
    job_desc = get_job_desc(args.job_id)
    args.job_name = job_desc["jobName"]
    logger.info("Watching job %s (%s)", args.job_id, args.job_name)
    last_status = None
    while last_status not in {"SUCCEEDED", "FAILED"}:
        job_desc = get_job_desc(args.job_id)
        if job_desc["status"] != last_status:
            logger.info("Job %s %s", args.job_id, format_job_status(job_desc["status"]))
            last_status = job_desc["status"]
            if job_desc["status"] in {"RUNNING", "SUCCEEDED", "FAILED"}:
                logger.info("Job %s log stream: %s", args.job_id, job_desc.get("container", {}).get("logStreamName"))
                save_job_desc(job_desc)
        if job_desc["status"] in {"RUNNING", "SUCCEEDED", "FAILED"} and "logStreamName" in job_desc["container"]:
            args.log_stream_name = job_desc["container"]["logStreamName"]
            get_logs(args)
        if "statusReason" in job_desc:
            logger.info("Job %s: %s", args.job_id, job_desc["statusReason"])
        time.sleep(1)

get_logs_parser = register_parser(get_logs, parent=batch_parser, help="Retrieve logs for a Batch job")
get_logs_parser.add_argument("log_stream_name")
watch_parser = register_parser(watch, parent=batch_parser, help="Monitor a running Batch job and stream its logs")
watch_parser.add_argument("job_id")
for parser in get_logs_parser, watch_parser:
    lines_group = parser.add_mutually_exclusive_group()
    lines_group.add_argument("--head", type=int, nargs="?", const=10,
                             help="Retrieve this number of lines from the beginning of the log (default 10)")
    lines_group.add_argument("--tail", type=int, nargs="?", const=10,
                             help="Retrieve this number of lines from the end of the log (default 10)")

def ssh(args):
    job_desc = clients.batch.describe_jobs(jobs=[args.job_id])["jobs"][0]
    job_queue_desc = clients.batch.describe_job_queues(jobQueues=[job_desc["jobQueue"]])["jobQueues"][0]
    ce = job_queue_desc["computeEnvironmentOrder"][0]["computeEnvironment"]
    ce_desc = clients.batch.describe_compute_environments(computeEnvironments=[ce])["computeEnvironments"][0]
    ecs_ci_arn = job_desc["container"]["containerInstanceArn"]
    ecs_ci_desc = clients.ecs.describe_container_instances(cluster=ce_desc["ecsClusterArn"],
                                                           containerInstances=[ecs_ci_arn])["containerInstances"][0]
    ecs_ci_ec2_id = ecs_ci_desc["ec2InstanceId"]
    for reservation in paginate(clients.ec2.get_paginator("describe_instances"), InstanceIds=[ecs_ci_ec2_id]):
        ecs_ci_address = reservation["Instances"][0]["PublicDnsName"]
    logger.info("Job {} is on ECS container instance {} ({})".format(args.job_id, ecs_ci_ec2_id, ecs_ci_address))
    ssh_args = ["ssh", "-l", "ec2-user", ecs_ci_address,
                "docker", "ps", "--filter", "name=" + args.job_id, "--format", "{{.ID}}"]
    logger.info("Running: {}".format(" ".join(ssh_args)))
    container_id = subprocess.check_output(ssh_args).decode().strip()
    subprocess.call(["ssh", "-t", "-l", "ec2-user", ecs_ci_address,
                     "docker", "exec", "--interactive", "--tty", container_id] + (args.ssh_args or ["/bin/bash", "-l"]))

ssh_parser = register_parser(ssh, parent=batch_parser, help="Log in to a running Batch job via SSH")
ssh_parser.add_argument("job_id")
ssh_parser.add_argument("ssh_args", nargs=argparse.REMAINDER)
