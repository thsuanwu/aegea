"""
Manage AWS Lambda functions and their event sources
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, collections, random, string

from . import config, logger
from .ls import register_parser, register_listing_parser
from .util import Timestamp, paginate
from .util.printing import page_output, tabulate
from .util.aws import resources, clients

def _lambda(args):
    lambda_parser.print_help()

lambda_parser = register_parser(_lambda, name="lambda", help=__doc__.strip())

def ls(args):
    paginator = getattr(clients, "lambda").get_paginator("list_functions")
    page_output(tabulate(paginate(paginator), args, cell_transforms={"LastModified": Timestamp}))

parser_ls = register_listing_parser(ls, parent=lambda_parser)

def event_source_mappings(args):
    paginator = getattr(clients, "lambda").get_paginator("list_event_source_mappings")
    page_output(tabulate(paginate(paginator), args))

parser_event_source_mappings = register_listing_parser(event_source_mappings, parent=lambda_parser)
