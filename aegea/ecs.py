"""
Manage AWS Elastic Container Service (ECS) resources, including Fargate tasks.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse, time

from botocore.exceptions import ClientError

from . import logger
from .batch import add_command_args, add_job_defn_args, set_ulimits, set_volumes, get_ecr_image_uri
from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate
from .util.compat import USING_PYTHON2
from .util.printing import page_output, tabulate, YELLOW, RED, GREEN, BOLD, ENDC
from .util.aws import (ARN, clients, ensure_security_group, ensure_vpc, ensure_iam_role, ensure_log_group,
                       expect_error_codes)
from .util.aws.logs import CloudwatchLogReader
from .util.aws.batch import get_command_and_env

def ecs(args):
    ecs_parser.print_help()

ecs_parser = register_parser(ecs, help="Manage Elastic Container Service resources", description=__doc__)

def clusters(args):
    if not args.clusters:
        args.clusters = list(paginate(clients.ecs.get_paginator("list_clusters")))
    cluster_desc = clients.ecs.describe_clusters(clusters=args.clusters)["clusters"]
    page_output(tabulate(cluster_desc, args))

parser = register_listing_parser(clusters, parent=ecs_parser, help="List ECS clusters")
parser.add_argument("clusters", nargs="*")

def tasks(args):
    list_tasks_args = {}
    if args.cluster:
        list_tasks_args["cluster"] = args.cluster
    if args.launch_type:
        list_tasks_args["launchType"] = args.launch_type
    if args.desired_status:
        list_tasks_args["desiredStatus"] = args.desired_status
    if not args.tasks:
        list_tasks = clients.ecs.get_paginator("list_tasks")
        args.tasks = list(paginate(list_tasks, **list_tasks_args))
        if not args.desired_status:
            args.tasks += list(paginate(list_tasks, desiredStatus="STOPPED", **list_tasks_args))
    task_desc = clients.ecs.describe_tasks(cluster=args.cluster, tasks=args.tasks)["tasks"] if args.tasks else []
    page_output(tabulate(task_desc, args))

parser = register_listing_parser(tasks, parent=ecs_parser, help="List ECS tasks")
parser.add_argument("tasks", nargs="*")
parser.add_argument("--cluster")
parser.add_argument("--desired-status", choices={"RUNNING", "STOPPED"})
parser.add_argument("--launch-type", choices={"EC2", "FARGATE"})

def run(args):
    args.storage = args.efs_storage = None
    command, environment = get_command_and_env(args)
    vpc = ensure_vpc()
    clients.ecs.create_cluster(clusterName=args.cluster)
    log_config = {
        "logDriver": "awslogs",
        "options": {
            "awslogs-region": clients.ecs.meta.region_name,
            "awslogs-group": args.task_name,
            "awslogs-stream-prefix": args.task_name
        }
    }
    ensure_log_group(log_config["options"]["awslogs-group"])

    if args.ecs_image:
        args.image = get_ecr_image_uri(args.ecs_image)

    container_defn = dict(name=args.task_name,
                          image=args.image,
                          memory=args.memory,
                          command=command,
                          environment=environment,
                          logConfiguration=log_config)
    set_volumes(args, container_defn)
    set_ulimits(args, container_defn)
    exec_role = ensure_iam_role(args.execution_role, trust=["ecs-tasks"], policies=["service-role/AWSBatchServiceRole"])
    task_role = ensure_iam_role(args.task_role)
    clients.ecs.register_task_definition(family=args.task_name,
                                         containerDefinitions=[container_defn],
                                         requiresCompatibilities=["FARGATE"],
                                         executionRoleArn=exec_role.arn,
                                         taskRoleArn=task_role.arn,
                                         networkMode="awsvpc",
                                         cpu=args.fargate_cpu,
                                         memory=args.fargate_memory)
    network_config = {
        'awsvpcConfiguration': {
            'subnets': [
                subnet.id for subnet in vpc.subnets.all()
            ],
            'securityGroups': [ensure_security_group(args.security_group, vpc).id],
            'assignPublicIp': 'ENABLED'
        }
    }
    res = clients.ecs.run_task(cluster=args.cluster,
                               taskDefinition=args.task_name,
                               launchType="FARGATE",
                               networkConfiguration=network_config)
    task_arn = res["tasks"][0]["taskArn"]
    if args.watch:
        watch(watch_parser.parse_args([args.task_name, task_arn, "--cluster", args.cluster]))
    elif args.wait:
        raise NotImplementedError()
    return res["tasks"][0]

register_parser_args = dict(parent=ecs_parser, help="Run a Fargate task")
if not USING_PYTHON2:
    register_parser_args["aliases"] = ["launch"]

parser = register_parser(run, **register_parser_args)
add_command_args(parser)
add_job_defn_args(parser)
parser.add_argument("--execution-role", metavar="IAM_ROLE", default=__name__)
parser.add_argument("--task-role", metavar="IAM_ROLE", default=__name__)
parser.add_argument("--security-group", default=__name__)
parser.add_argument("--cluster", default=__name__.replace(".", "_"))
parser.add_argument("--task-name", default=__name__.replace(".", "_"))
parser.add_argument("--fargate-cpu", help="Execution vCPU count")
parser.add_argument("--fargate-memory")

task_status_colors = dict(PROVISIONING=YELLOW(), PENDING=BOLD() + YELLOW(), ACTIVATING=BOLD() + YELLOW(),
                          RUNNING=GREEN(),
                          DEACTIVATING=BOLD() + GREEN(), STOPPING=BOLD() + GREEN(), DEPROVISIONING=BOLD() + GREEN(),
                          STOPPED=BOLD() + GREEN())

def format_task_status(status):
    return task_status_colors[status] + status + ENDC()

def watch(args):
    task_uuid = ARN(args.task_arn).resource.split("/")[1]
    logger.info("Watching task %s (%s)", task_uuid, args.cluster)
    last_status = None
    while last_status != "STOPPED":
        task_desc = clients.ecs.describe_tasks(cluster=args.cluster, tasks=[args.task_arn])["tasks"][0]
        if task_desc["lastStatus"] != last_status:
            logger.info("Task %s %s", args.task_arn, format_task_status(task_desc["lastStatus"]))
            last_status = task_desc["lastStatus"]
        try:
            for event in CloudwatchLogReader("/".join([args.task_name, args.task_name, task_uuid]),
                                             log_group_name=args.task_name):
                print(str(Timestamp(event["timestamp"])), event["message"])
        except ClientError as e:
            expect_error_codes(e, "ResourceNotFoundException")
        time.sleep(1)

watch_parser = register_parser(watch, parent=ecs_parser, help="Monitor a running ECS Fargate task and stream its logs")
watch_parser.add_argument("task_name")
watch_parser.add_argument("task_arn")
watch_parser.add_argument("--cluster", default=__name__.replace(".", "_"))
lines_group = watch_parser.add_mutually_exclusive_group()
lines_group.add_argument("--head", type=int, nargs="?", const=10,
                         help="Retrieve this number of lines from the beginning of the log (default 10)")
lines_group.add_argument("--tail", type=int, nargs="?", const=10,
                         help="Retrieve this number of lines from the end of the log (default 10)")
