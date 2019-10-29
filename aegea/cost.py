from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, collections
from datetime import datetime, timedelta

import boto3, requests

from . import register_parser
from .util import paginate, Timestamp
from .util.printing import format_table, page_output, tabulate, format_datetime
from .util.aws import region_name, offers_api, clients, instance_type_completer, get_products

def format_float(f):
    return "{:.2f}".format(f) if isinstance(f, float) else f

def cost(args):
    get_cost_and_usage_args = dict(TimePeriod=dict(Start=args.time_period_start.date().isoformat(),
                                                   End=args.time_period_end.date().isoformat()),
                                   Granularity=args.granularity, Metrics=args.metrics,
                                   GroupBy=[dict(Type="DIMENSION", Key=k) for k in args.group_by])
    rows = collections.defaultdict(dict)
    args.columns, cell_transforms = [args.group_by[0]], {"TOTAL": format_float}
    for page in clients.ce.get_cost_and_usage(**get_cost_and_usage_args)["ResultsByTime"]:
        args.columns.append(page["TimePeriod"]["Start"])
        cell_transforms[page["TimePeriod"]["Start"]] = format_float
        for i, group in enumerate(page["Groups"]):
            value = group["Metrics"][args.metrics[0]]
            if isinstance(value, dict) and "Amount" in value:
                value = float(value["Amount"])
            rows[group["Keys"][0]].setdefault(args.group_by[0], group["Keys"][0])
            rows[group["Keys"][0]].setdefault("TOTAL", 0)
            rows[group["Keys"][0]]["TOTAL"] += value
            rows[group["Keys"][0]][page["TimePeriod"]["Start"]] = value
    args.columns.append("TOTAL")
    rows = [row for row in rows.values() if row["TOTAL"] > args.min_total]
    rows = sorted(rows, key=lambda row: -row["TOTAL"])
    page_output(tabulate(rows, args, cell_transforms=cell_transforms))

parser = register_parser(cost, help="List AWS costs")
parser.add_argument("--metrics", nargs="+", default=["AmortizedCost"],
                    choices={"AmortizedCost", "BlendedCost", "NetAmortizedCost", "NetUnblendedCost",
                             "NormalizedUsageAmount", "UnblendedCost", "UsageQuantity"})
parser.add_argument("--time-period-start", type=Timestamp, default=Timestamp("-7d"),
                    help="Time to start cost history." + Timestamp.__doc__)
parser.add_argument("--time-period-end", type=Timestamp, default=Timestamp("-1d"),
                    help="Time to end cost history." + Timestamp.__doc__)
parser.add_argument("--granularity", default="DAILY", choices={"HOURLY", "DAILY", "MONTHLY"})
parser.add_argument("--group-by", nargs="+", default=["SERVICE"],
                    choices={"AZ", "INSTANCE_TYPE", "LEGAL_ENTITY_NAME", "LINKED_ACCOUNT", "OPERATION", "PLATFORM",
                             "PURCHASE_TYPE", "SERVICE", "TAGS", "TENANCY", "USAGE_TYPE"})
parser.add_argument("--min-total", type=int, default=1, help="Omit rows that total below this number")
