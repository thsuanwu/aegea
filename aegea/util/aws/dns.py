import os, time

from ... import logger
from .. import VerboseRepr, paginate
from ..exceptions import AegeaException
from . import ARN, clients, ensure_vpc

def get_client_token(iam_username, service):
    from getpass import getuser
    from socket import gethostname
    tok = "{}.{}.{}:{}@{}".format(iam_username, service, int(time.time()), getuser(), gethostname().split(".")[0])
    return tok[:64]

class DNSZone(VerboseRepr):
    def __init__(self, zone_name=None, use_unique_private_zone=True, create_default_private_zone=True):
        if zone_name:
            self.zone = clients.route53.list_hosted_zones_by_name(DNSName=zone_name)["HostedZones"][0]
            assert self.zone["Name"].rstrip(".") == zone_name.rstrip(".")
        elif use_unique_private_zone:
            private_zones = []
            for zone in paginate(clients.route53.get_paginator("list_hosted_zones")):
                if zone.get("Config", {}).get("PrivateZone") is True:
                    private_zones.append(zone)
            if len(private_zones) == 1:
                self.zone = private_zones[0]
            elif len(private_zones) == 0 and create_default_private_zone:
                vpc = ensure_vpc()
                vpc.modify_attribute(EnableDnsSupport=dict(Value=True))
                vpc.modify_attribute(EnableDnsHostnames=dict(Value=True))
                res = clients.route53.create_hosted_zone(Name="aegea.",
                                                         CallerReference=get_client_token(None, "route53"),
                                                         HostedZoneConfig=dict(PrivateZone=True),
                                                         VPC=dict(VPCRegion=ARN.get_region(), VPCId=vpc.vpc_id))
                self.zone = res["HostedZone"]
            else:
                msg = "Found {} private DNS zones; unable to determine zone to use. Set the dns.private_zone key in Aegea config" # noqa
                raise AegeaException(msg.format(len(private_zones)))
        else:
            raise AegeaException("Unable to determine DNS zone to use")
        self.zone_id = os.path.basename(self.zone["Id"])

    def update(self, names, values, action="UPSERT", record_type="CNAME", ttl=60):
        def format_rrs(name, value):
            return dict(Name=name + "." + self.zone["Name"],
                        Type=record_type,
                        TTL=ttl,
                        ResourceRecords=value if isinstance(value, (list, tuple)) else [{"Value": value}])
        if not isinstance(names, (list, tuple)):
            names, values = [names], [values]
        updates = [dict(Action=action, ResourceRecordSet=format_rrs(k, v)) for k, v in zip(names, values)]
        return clients.route53.change_resource_record_sets(HostedZoneId=self.zone_id,
                                                           ChangeBatch=dict(Changes=updates))

    def delete(self, name, value=None, record_type="CNAME", missing_ok=True):
        if value is None:
            res = clients.route53.list_resource_record_sets(HostedZoneId=self.zone_id,
                                                            StartRecordName=name + "." + self.zone["Name"],
                                                            StartRecordType=record_type)
            for rrs in res["ResourceRecordSets"]:
                if rrs["Name"] == name + "." + self.zone["Name"] and rrs["Type"] == record_type:
                    value = rrs["ResourceRecords"]
                    break
            else:
                msg = "Could not find {t} record {n} in Route53 zone {z}"
                msg = msg.format(t=record_type, n=name, z=self.zone["Name"])
                if missing_ok:
                    logger.warn(msg)
                    return
                else:
                    raise AegeaException(msg)
        return self.update(name, value, action="DELETE", record_type=record_type)
