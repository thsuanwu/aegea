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
    print("config here")

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
                collector.append([path + "." + k, repr(v)])
    collector = []
    collect_kv(config, "", collector)
    page_output(format_table(collector))

ls_parser = register_listing_parser(ls, parent=config_parser)

def get(args):
    pass

get_parser = register_listing_parser(get, parent=config_parser)

def set(args):
    pass

set_parser = register_listing_parser(set, parent=config_parser)

def sync(args):
    pass

sync_parser = register_listing_parser(sync, parent=config_parser)
