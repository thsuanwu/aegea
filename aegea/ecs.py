"""
Manage AWS Elastic Container Service (ECS) resources, including Fargate tasks.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import argparse, time

from botocore.exceptions import ClientError

from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate
from .util.printing import page_output, tabulate
from .util.aws import ARN, clients, ensure_security_group, ensure_vpc, ensure_iam_role, ensure_log_group
from .batch import LogReader

def ecs(args):
    ecs_parser.print_help()

ecs_parser = register_parser(ecs, help="Manage Elastic Container Service resources", description=__doc__,
                             formatter_class=argparse.RawTextHelpFormatter)

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

def launch(args):
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
    container_defn = dict(name=args.task_name,
                          image=args.image,
                          memory=args.memory,
                          command=args.command,
                          logConfiguration=log_config)
    iam_role = ensure_iam_role("aegea.fargate", trust=["ecs-tasks"], policies=["service-role/AWSBatchServiceRole"])
    clients.ecs.register_task_definition(family=args.task_name,
                                         containerDefinitions=[container_defn],
                                         requiresCompatibilities=["FARGATE"],
                                         executionRoleArn=iam_role.arn,
                                         taskRoleArn=iam_role.arn,
                                         networkMode="awsvpc",
                                         cpu=args.fargate_cpu,
                                         memory=args.fargate_memory)
    network_config = {
        'awsvpcConfiguration': {
            'subnets': [
                subnet.id for subnet in vpc.subnets.all()
            ],
            'securityGroups': [ensure_security_group("aegea.fargate", vpc).id],
            'assignPublicIp': 'ENABLED'
        }
    }
    res = clients.ecs.run_task(cluster=args.cluster,
                               taskDefinition=args.task_name,
                               launchType="FARGATE",
                               networkConfiguration=network_config)
    task_arn = res["tasks"][0]["taskArn"]
    task_uuid = ARN(task_arn).resource.split("/")[1]

    class FargateLogReader(LogReader):
        log_group_name = args.task_name

    while res["tasks"][0]["lastStatus"] != "STOPPED":
        print(task_arn, res["tasks"][0]["lastStatus"])
        time.sleep(1)
        res = clients.ecs.describe_tasks(cluster=args.cluster, tasks=[task_arn])

    for event in FargateLogReader("/".join([args.task_name, args.task_name, task_uuid])):
        print(event["message"])

parser = register_parser(launch, parent=ecs_parser, help="Run a Fargate task")
parser.add_argument("command", nargs="*")
parser.add_argument("--cluster", default=__name__.replace(".", "_"))
parser.add_argument("--task-name", default=__name__.replace(".", "_"))
parser.add_argument("--memory", type=int)
parser.add_argument("--fargate-cpu")
parser.add_argument("--fargate-memory")
parser.add_argument("--image")
