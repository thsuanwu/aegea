"""
Manage AWS Step Functions state machines and executions.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, json, time, concurrent.futures

from botocore.exceptions import ClientError

from . import batch, logger
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

state_machines_parser = register_listing_parser(state_machines, parent=sfn_parser, help="List state machines")

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

ls_parser = register_listing_parser(ls, parent=sfn_parser, help="List executions for state machines in this account")
ls_parser.add_argument("--state-machine").completer = complete_state_machine_name

def describe(args):
    if ARN(args.resource_arn).resource.startswith("execution"):
        desc = clients.stepfunctions.describe_execution(executionArn=args.resource_arn)
        desc["input"] = json.loads(desc.get("input", "null"))
        desc["output"] = json.loads(desc.get("output", "null"))
    else:
        desc = clients.stepfunctions.describe_state_machine(stateMachineArn=args.resource_arn)
        desc["definition"] = json.loads(desc.get("definition", "null"))
    return desc

describe_parser = register_parser(describe, parent=sfn_parser, help="Describe a state machine or execution")
describe_parser.add_argument("resource_arn")

sfn_status_colors = dict(RUNNING=GREEN(), SUCCEEDED=BOLD() + GREEN(),
                         FAILED=BOLD() + RED(), TIMED_OUT=BOLD() + RED(), ABORTED=BOLD() + RED())

def watch(args):
    seen_events = set()
    previous_status = None
    while True:
        exec_desc = clients.stepfunctions.describe_execution(executionArn=str(args.execution_arn))
        if exec_desc["status"] == previous_status:
            sys.stderr.write(".")
            sys.stderr.flush()
        else:
            logger.info("%s %s", exec_desc["executionArn"],
                        sfn_status_colors[exec_desc["status"]] + exec_desc["status"] + ENDC())
            previous_status = exec_desc["status"]
        history = clients.stepfunctions.get_execution_history(executionArn=str(args.execution_arn))
        for event in sorted(history["events"], key=lambda x: x["id"]):
            if event["id"] not in seen_events:
                details = {}
                for key in event.keys():
                    if key.endswith("EventDetails") and event[key]:
                        details = event[key]
                logger.info("%s %s %s %s %s %s", event["timestamp"], event["type"],
                            details.get("resourceType", ""), details.get("resource", ""), details.get("name", ""),
                            json.loads(details.get("parameters", "{}")).get("FunctionName", ""))
                if "taskSubmittedEventDetails" in event:
                    if event.get("taskSubmittedEventDetails", {}).get("resourceType") == "batch":
                        job_id = json.loads(event["taskSubmittedEventDetails"]["output"])["JobId"]
                        logger.info("Batch job ID %s", job_id)
                        batch.watch(batch.watch_parser.parse_args([job_id]))
                seen_events.add(event["id"])
        if exec_desc["status"] in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}:
            break
        time.sleep(1)

    if exec_desc["status"] == "SUCCEEDED":
        return exec_desc["output"]
    else:
        history = clients.stepfunctions.get_execution_history(executionArn=str(args.execution_arn))
        last_event = sorted(history["events"], key=lambda x: x["id"])[-1]
        logger.error("%s %s", args.execution_arn, sfn_status_colors[exec_desc["status"]] + exec_desc["status"] + ENDC())
        return SystemExit(json.dumps(last_event, indent=4, default=str))


watch_parser = register_parser(watch, parent=sfn_parser,
                               help="Monitor a state machine execution and stream its execution history")
watch_parser.add_argument("execution_arn")
