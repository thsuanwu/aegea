"""
Manage AWS Elastic Container Service (ECS) resources, including Fargate tasks.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse, time, json, hashlib, concurrent.futures
from itertools import product
from functools import partial

from botocore.exceptions import ClientError

from . import logger
from .batch import add_command_args, add_job_defn_args
from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate
from .util.compat import USING_PYTHON2
from .util.printing import page_output, tabulate, YELLOW, RED, GREEN, BOLD, ENDC
from .util.aws import (ARN, clients, ensure_security_group, ensure_vpc, ensure_iam_role, ensure_log_group,
                       ensure_ecs_cluster, expect_error_codes)
from .util.aws.logs import CloudwatchLogReader
from .util.aws.batch import get_command_and_env, set_ulimits, set_volumes, get_ecr_image_uri

def complete_cluster_name(**kwargs):
    return [ARN(c).resource.partition("/")[2] for c in paginate(clients.ecs.get_paginator("list_clusters"))]

def ecs(args):
    ecs_parser.print_help()

ecs_parser = register_parser(ecs, help="Manage Elastic Container Service resources", description=__doc__)

def clusters(args):
    if not args.clusters:
        args.clusters = list(paginate(clients.ecs.get_paginator("list_clusters")))
    cluster_desc = clients.ecs.describe_clusters(clusters=args.clusters)["clusters"]
    page_output(tabulate(cluster_desc, args))

parser = register_listing_parser(clusters, parent=ecs_parser, help="List ECS clusters")
parser.add_argument("clusters", nargs="*").completer = complete_cluster_name

def tasks(args):
    list_clusters = clients.ecs.get_paginator("list_clusters")
    list_tasks = clients.ecs.get_paginator("list_tasks")

    def list_tasks_worker(worker_args):
        cluster, status = worker_args
        return cluster, status, list(paginate(list_tasks, cluster=cluster, desiredStatus=status))

    def describe_tasks_worker(t, cluster=None):
        return clients.ecs.describe_tasks(cluster=cluster, tasks=t)["tasks"] if t else []

    task_descs = []
    if args.clusters is None:
        args.clusters = [__name__.replace(".", "_")] if args.tasks else list(paginate(list_clusters))
    if args.tasks:
        task_descs = describe_tasks_worker(args.tasks, cluster=args.clusters[0])
    else:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            for cluster, status, tasks in executor.map(list_tasks_worker, product(args.clusters, args.desired_status)):
                worker = partial(describe_tasks_worker, cluster=cluster)
                descs = executor.map(worker, (tasks[pos:pos + 100] for pos in range(0, len(tasks), 100)))
                task_descs += sum(descs, [])
    page_output(tabulate(task_descs, args))

parser = register_listing_parser(tasks, parent=ecs_parser, help="List ECS tasks")
parser.add_argument("tasks", nargs="*")
parser.add_argument("--clusters", nargs="*").completer = complete_cluster_name
parser.add_argument("--desired-status", nargs=1, choices={"RUNNING", "STOPPED"}, default=["RUNNING", "STOPPED"])
parser.add_argument("--launch-type", nargs=1, choices={"EC2", "FARGATE"}, default=["EC2", "FARGATE"])

def run(args):
    args.storage = args.efs_storage = args.mount_instance_storage = None
    command, environment = get_command_and_env(args)
    vpc = ensure_vpc()
    ensure_ecs_cluster(args.cluster)
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
                          cpu=0,
                          memory=args.memory,
                          command=[],
                          environment=[],
                          portMappings=[],
                          essential=True,
                          logConfiguration=log_config,
                          mountPoints=[dict(sourceVolume="scratch", containerPath="/mnt")],
                          volumesFrom=[])
    set_volumes(args, container_defn)
    set_ulimits(args, container_defn)
    exec_role = ensure_iam_role(args.execution_role, trust=["ecs-tasks"],
                                policies=["service-role/AmazonEC2ContainerServiceforEC2Role",
                                          "service-role/AWSBatchServiceRole"])
    task_role = ensure_iam_role(args.task_role, trust=["ecs-tasks"])

    expect_task_defn = dict(containerDefinitions=[container_defn],
                            requiresCompatibilities=["FARGATE"],
                            taskRoleArn=task_role.arn,
                            executionRoleArn=exec_role.arn,
                            networkMode="awsvpc",
                            cpu=args.fargate_cpu,
                            memory=args.fargate_memory,
                            volumes=[dict(name="scratch", host={})])

    task_hash = hashlib.sha256(json.dumps(expect_task_defn, sort_keys=True).encode()).hexdigest()[:8]
    task_defn_name = __name__.replace(".", "_") + "_" + task_hash

    try:
        task_defn = clients.ecs.describe_task_definition(taskDefinition=task_defn_name)["taskDefinition"]
        assert task_defn["status"] == "ACTIVE"
        assert "FARGATE" in task_defn["compatibilities"]
        desc_keys = ["family", "revision", "taskDefinitionArn", "status", "compatibilities", "placementConstraints",
                     "requiresAttributes"]
        task_desc = {key: task_defn.pop(key) for key in desc_keys}
        if expect_task_defn["cpu"].endswith(" vCPU"):
            expect_task_defn["cpu"] = str(int(expect_task_defn["cpu"][:-len(" vCPU")]) * 1024)
        if expect_task_defn["memory"].endswith(" GB"):
            expect_task_defn["memory"] = str(int(expect_task_defn["memory"][:-len(" GB")]) * 1024)
        assert task_defn == expect_task_defn
        logger.debug("Reusing task definition %s", task_desc["taskDefinitionArn"])
    except (ClientError, AssertionError):
        logger.debug("Registering new ECS task definition %s", task_defn_name)
        task_desc = clients.ecs.register_task_definition(family=task_defn_name, **expect_task_defn)["taskDefinition"]

    network_config = {
        'awsvpcConfiguration': {
            'subnets': [
                subnet.id for subnet in vpc.subnets.all()
            ],
            'securityGroups': [ensure_security_group(args.security_group, vpc).id],
            'assignPublicIp': 'ENABLED'
        }
    }
    container_overrides = [dict(name=args.task_name, command=command, environment=environment)]
    res = clients.ecs.run_task(cluster=args.cluster,
                               taskDefinition=task_desc["taskDefinitionArn"],
                               launchType="FARGATE",
                               networkConfiguration=network_config,
                               overrides=dict(containerOverrides=container_overrides))
    task_arn = res["tasks"][0]["taskArn"]
    if args.watch:
        watch(watch_parser.parse_args([task_arn, "--task-name", args.task_name]))
    elif args.wait:
        raise NotImplementedError()
    if args.watch or args.wait:
        res = clients.ecs.describe_tasks(cluster=args.cluster, tasks=[task_arn])
        print(json.dumps(res["tasks"][0], indent=2, default=lambda x: str(x)))
        return SystemExit(res["tasks"][0]["containers"][0]["exitCode"])
    else:
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
    _, cluster, task_id = ARN(args.task_arn).resource.split("/")
    logger.info("Watching task %s (%s)", task_id, cluster)
    last_status, events_received = None, 0
    while last_status != "STOPPED":
        res = clients.ecs.describe_tasks(cluster=cluster, tasks=[args.task_arn])
        if len(res["tasks"]) == 1:
            task_desc = res["tasks"][0]
            if task_desc["lastStatus"] != last_status:
                logger.info("Task %s %s", args.task_arn, format_task_status(task_desc["lastStatus"]))
                last_status = task_desc["lastStatus"]
        try:
            for event in CloudwatchLogReader("/".join([args.task_name, args.task_name, task_id]),
                                             log_group_name=args.task_name):
                print(str(Timestamp(event["timestamp"])), event["message"])
                events_received += 1
        except ClientError as e:
            expect_error_codes(e, "ResourceNotFoundException")
        if last_status is None and events_received > 0:
            break  # Logs retrieved successfully but task record is no longer in ECS
        time.sleep(1)

watch_parser = register_parser(watch, parent=ecs_parser, help="Monitor a running ECS Fargate task and stream its logs")
watch_parser.add_argument("task_arn")
watch_parser.add_argument("--task-name", default=__name__.replace(".", "_"))
lines_group = watch_parser.add_mutually_exclusive_group()
lines_group.add_argument("--head", type=int, nargs="?", const=10,
                         help="Retrieve this number of lines from the beginning of the log (default 10)")
lines_group.add_argument("--tail", type=int, nargs="?", const=10,
                         help="Retrieve this number of lines from the end of the log (default 10)")
