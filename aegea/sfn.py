"""
Manage AWS Step Functions state machines and executions.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, base64, collections, io, subprocess, json, time, re, hashlib, concurrent.futures, itertools

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

def executions(args):
    sm_arn = ARN(service="states", resource="stateMachine:" + args.state_machine)
    list_executions_paginator = clients.stepfunctions.get_paginator("list_executions")
    page_output(tabulate(paginate(list_executions_paginator, stateMachineArn=str(sm_arn)), args))

parser = register_listing_parser(executions, parent=sfn_parser, help="List the executions of a state machine")
parser.add_argument("state_machine").completer = complete_state_machine_name
