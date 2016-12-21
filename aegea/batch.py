"""
Manage AWS Batch jobs, queues, and compute environments.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse

from botocore.exceptions import ClientError

from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate, hashabledict
from .util.printing import format_table, page_output, get_field, get_cell, tabulate
from .util.exceptions import AegeaException
from .util.crypto import ensure_ssh_key
from .util.compat import lru_cache
from .util.aws import (ARN, resources, clients, expect_error_codes, ensure_iam_role, make_waiter, ensure_subnet,
                       ensure_vpc, ensure_security_group, SpotFleetBuilder)

def batch(args):
    batch_parser.print_help()

batch_parser = register_parser(batch, help="Manage AWS Batch resources", description=__doc__,
                               formatter_class=argparse.RawTextHelpFormatter)

def queues(args):
    table = clients.batch.describe_job_queues()["jobQueues"]
    page_output(tabulate(table, args))

parser = register_listing_parser(queues, parent=batch_parser, help="List Batch queues")

def create_queue(args):
    ces = [dict(computeEnvironment=e, order=i) for i, e in enumerate(args.compute_environments)]
    return clients.batch.create_job_queue(jobQueueName=args.name,
                                          priority=args.priority,
                                          computeEnvironmentOrder=ces)

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

# FIXME: ensure instance role has AmazonAPIGatewayPushToCloudWatchLogs, AmazonEC2ContainerServiceforEC2Role, ...
# FIXME: ensure ssh key pair is real
def create_compute_environment(args):
    batch_iam_role = ARN(service="iam", region="", resource="role/service-role/AWSBatchServiceRole")
    vpc = ensure_vpc()
    ensure_ssh_key(args.ssh_key_name)
    compute_resources = dict(type=args.compute_type,
                             minvCpus=args.min_vcpus, desiredvCpus=args.desired_vcpus, maxvCpus=args.max_vcpus,
                             instanceTypes=["optimal"],
                             subnets=[subnet.id for subnet in vpc.subnets.all()],
                             securityGroupIds=[ensure_security_group("aegea.launch", vpc).id],
                             instanceRole="aegea.launch",
                             bidPercentage=100,
                             spotIamFleetRole=SpotFleetBuilder.get_iam_fleet_role().name,
                             ec2KeyPair=args.ssh_key_name)
    return clients.batch.create_compute_environment(computeEnvironmentName=args.name,
                                                    type=args.type,
                                                    computeResources=compute_resources,
                                                    serviceRole=str(batch_iam_role))

parser = register_parser(create_compute_environment, parent=batch_parser, help="Create a Batch compute environment")
parser.add_argument("name")
parser.add_argument("--type", required=True, choices={"MANAGED", "UNMANAGED"})
parser.add_argument("--compute-type", required=True, choices={"EC2", "SPOT"})
parser.add_argument("--min-vcpus", type=int, default=0)
parser.add_argument("--desired-vcpus", type=int, default=2)
parser.add_argument("--max-vcpus", type=int, default=8)
parser.add_argument("--ssh-key-name", default=__name__)

def delete_compute_environment(args):
    clients.batch.update_compute_environment(computeEnvironment=args.name, state="DISABLED")
    wtr = make_waiter(clients.batch.describe_compute_environments, "computeEnvironments[].status", "VALID", "pathAny")
    wtr.wait(computeEnvironments=[args.name])
    clients.batch.delete_compute_environment(computeEnvironment=args.name)

parser = register_parser(delete_compute_environment, parent=batch_parser, help="Delete a Batch compute environment")
parser.add_argument("name")

def ensure_job_definition(args):
    container_props = {k: vars(args)[k] for k in ("image", "vcpus", "memory", "command")}
    return clients.batch.register_job_definition(jobDefinitionName=__name__.replace(".", "_"),
                                                 type="container",
                                                 containerProperties=container_props)

def submit(args):
    if args.job_definition_arn is None:
        args.job_definition_arn = ensure_job_definition(args)["jobDefinitionArn"]
    return clients.batch.submit_job(jobName=args.name,
                                    jobQueue=args.queue,
                                    dependsOn=args.depends_on,
                                    jobDefinition=args.job_definition_arn,
                                    parameters=args.parameters,
                                    containerOverrides={})

parser = register_parser(submit, parent=batch_parser, help="Submit a job to a Batch queue")
parser.add_argument("name")
parser.add_argument("--queue", required=True)
parser.add_argument("--depends-on", nargs="+", default=[])
parser.add_argument("--image", default="ubuntu")
parser.add_argument("--vcpus", type=int, default=1)
parser.add_argument("--memory", type=int, default=1024)
parser.add_argument("--command", required=True, nargs="+")
parser.add_argument("--job-definition-arn")
parser.add_argument("--parameters", nargs="+", metavar="NAME=VALUE", type=lambda x: x.split("=", 1), default={})

def terminate(args):
    raise NotImplementedError()

def ls(args):
    table = []
    if args.queues is None:
        args.queues = [q["jobQueueName"] for q in clients.batch.describe_job_queues()["jobQueues"]]
    if args.status is None:
        args.status = {'SUBMITTED', 'PENDING', 'RUNNABLE', 'STARTING', 'RUNNING', 'SUCCEEDED', 'FAILED'}
    for queue in args.queues:
        for status in args.status:
            for job in clients.batch.list_jobs(jobQueue=queue, jobStatus=status)["jobSummaryList"]:
                table.extend(clients.batch.describe_jobs(jobs=[job["jobId"]])["jobs"])
    page_output(tabulate(table, args, cell_transforms={"createdAt": lambda cell, row: Timestamp(cell)}))

parser = register_listing_parser(ls, parent=batch_parser, help="List Batch jobs")
parser.add_argument("--queues", nargs="+")
parser.add_argument("--status", nargs="+")

parser = register_parser(terminate, parent=batch_parser, help="Terminate a Batch job")
