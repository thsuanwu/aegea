"""
Manage AWS Step Functions state machines and executions.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, json, concurrent.futures

from botocore.exceptions import ClientError

from . import logger
from .ls import register_parser, register_listing_parser
from .ecr import ecr_image_name_completer
from .util import Timestamp, paginate, get_mkfs_command
from .util.aws import clients, ARN
from .util.printing import page_output, tabulate, YELLOW, RED, GREEN, BOLD, ENDC

def complete_state_machine_name(**kwargs):
    return [c["name"] for c in paginate(clients.stepfunctions.get_paginator("list_state_machines"))]

def sfn(args):
    sfn_parser.print_help()

sfn_parser = register_parser(sfn, help="Manage AWS Step Functions", description=__doc__)

def state_machines(args):
    page_output(tabulate(paginate(clients.stepfunctions.get_paginator("list_state_machines")), args))

parser = register_listing_parser(state_machines, parent=sfn_parser, help="List state machines")

def ls(args):
    if args.state_machine:
        sm_arn = ARN(service="states", resource="stateMachine:" + args.state_machine)
        state_machines = [dict(stateMachineArn=str(sm_arn))]
    else:
        state_machines = paginate(clients.stepfunctions.get_paginator("list_state_machines"))

    def list_executions(state_machine):
        list_executions_paginator = clients.stepfunctions.get_paginator("list_executions")
        return list(paginate(list_executions_paginator, stateMachineArn=state_machine["stateMachineArn"]))

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executions = sum(executor.map(list_executions, state_machines), [])

    page_output(tabulate(executions, args))

parser = register_listing_parser(ls, parent=sfn_parser, help="List executions for state machines in this account")
parser.add_argument("--state-machine").completer = complete_state_machine_name

def describe(args):
    exec_desc = clients.stepfunctions.describe_execution(executionArn=args.execution_arn)
    exec_desc["input"] = json.loads(exec_desc.get("input", "null"))
    exec_desc["output"] = json.loads(exec_desc.get("output", "null"))
    return exec_desc

parser = register_parser(describe, parent=sfn_parser, help="Describe an execution of a state machine")
parser.add_argument("execution_arn")
