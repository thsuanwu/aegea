"""
List, read, and write Aegea configuration parameters.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, argparse, json

from .ls import register_parser, register_listing_parser
from .util import paginate
from .util.aws import resources, clients
from .util.printing import page_output, format_table

def config(args):
    config_parser.print_help()

config_parser = register_parser(config,
                                help=__doc__.strip(),
                                description=__doc__,
                                formatter_class=argparse.RawTextHelpFormatter)

def ls(args):
    from . import config, tweak

    def collect_kv(d, path, collector):
        for k, v in d.items():
            if isinstance(v, (dict, tweak.Config)):
                collect_kv(d[k], path + "." + k, collector)
            else:
                collector.append([path.lstrip(".") + "." + k, repr(v)])
    collector = []
    collect_kv(config, "", collector)
    page_output(format_table(collector))

ls_parser = register_listing_parser(ls, parent=config_parser)

def get(args):
    """Get an Aegea configuration parameter by name"""
    from . import config
    for key in args.key.split("."):
        config = getattr(config, key)
    print(json.dumps(config))

get_parser = register_parser(get, parent=config_parser)
get_parser.add_argument("key")

def set(args):
    """Get an Aegea configuration parameter to a given value"""
    raise NotImplementedError()

set_parser = register_parser(set, parent=config_parser)
set_parser.add_argument("key")
set_parser.add_argument("value")

def sync(args):
    """Save Aegea configuration to your AWS IAM account, or retrieve a previously saved configuration"""
    raise NotImplementedError()

sync_parser = register_listing_parser(sync, parent=config_parser)
