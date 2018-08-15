# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2017 Datadog, Inc.

from __future__ import print_function

import os
import gzip
import json
import re
import time
import urllib
import urllib2
from base64 import b64decode
from StringIO import StringIO
from collections import defaultdict, Counter
import sys
from edn_timer import timer 

import boto3

print('Loading function')

# retrieve datadog options from KMS
KMS_ENCRYPTED_KEYS = 'AQICAHi7wMMzxQdsGmB1aYgGTdEAMynmCM+uVLtgnQzMjYntCwHJDU3zpKyhAu2A0YyLyh6GAAABATCB/gYJKoZIhvcNAQcGoIHwMIHtAgEAMIHnBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDGYOHzRFKWpV46ZDBwIBEICBuYJg4zMcXO8N59YBTnTXfI4SUBggVxl3oQdyaXJsPHrG18lV7ExN+VE6rsLEfO239Y8Zvf4PFVYdIVtC4osRcNbTUx5cjpjMSr5nOnAD8cbFcV75V2127IlWyE/lBG2Yne5cz23qZGfcCcyIiHzCFcDToNpsIMaX6dUV+fgMP2K/mUfXmBIvjaYvaW7AAqFgCxA+KuheATEs078si+44nqObivyaeyqUqqk/LqOITm0UpLF52c7QUM4W'
kms = boto3.client('kms')
datadog_keys = json.loads(kms.decrypt(CiphertextBlob=b64decode(KMS_ENCRYPTED_KEYS))['Plaintext'])

# Alternatively set datadog keys directly
# datadog_keys = {
#     "api_key": "abcd",
#     "app_key": "efgh",
# }

def process_message(message, tags, timestamp, node_ip):
    timer(35, time.clock(), 'is')
    version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, _bytes, start, end, action, log_status = message.split(" ")

    detailed_tags = [
        "interface_id:%s" % interface_id,
        "protocol:%s" % protocol_id_to_name(protocol),
        "ip:%s" % node_ip,
    ] + tags
    if srcaddr == node_ip:
        timer(35, time.clock(), 'iex')
        timer(43, time.clock(), 's')
        detailed_tags.append("direction:outbound")
        timer(43, time.clock(), 'e')
    timer(35, time.clock(), 'ie')
    timer(44, time.clock(), 'is')
    if dstaddr == node_ip:
        timer(44, time.clock(), 'iex')
        timer(45, time.clock(), 's')
        detailed_tags.append("direction:inbound")
        timer(45, time.clock(), 'e')
    timer(44, time.clock(), 'ie')
    timer(47, 'process_log_status', 'c')
    process_log_status(log_status, detailed_tags, timestamp)
    timer(48, time.clock(), 'is')
    if log_status == 'NODATA':
        timer(48, time.clock(), 'iex')
        return
    timer(48, time.clock(), 'ie')

    timer(51, 'process_action', 'c')
    process_action(action, detailed_tags, timestamp)
    timer(52, 'process_duration', 'c')
    process_duration(start, end, detailed_tags, timestamp)
    timer(53, 'process_packets', 'c')
    process_packets(packets, detailed_tags, timestamp)
    timer(54, 'process_bytes', 'c')
    process_bytes(_bytes, detailed_tags, timestamp)


def compute_node_ip(events):
    timer(58, time.clock(), 's')
    ip_count = Counter()
    timer(58, time.clock(), 'e')
    timer(59, time.clock(), 'fs')
    for event in events:
        timer(59, time.clock(), 'fex')
        timer(61, time.clock(), 'is')
        src_ip, dest_ip = event['message'].split(" ", 5)[3:5]
        if len(src_ip) > 1 and len(dest_ip) > 1:  # account for '-'
            timer(61, time.clock(), 'iex')
            timer(62, time.clock(), 's')
            ip_count[src_ip] += 1
            ip_count[dest_ip] += 1
            timer(62, time.clock(), 'e')
        timer(61, time.clock(), 'ie')
    timer(59, time.clock(), 'fe')
    timer(65, time.clock(), 'is')
    most_comm = ip_count.most_common()
    if most_comm:
        timer(65, time.clock(), 'iex')
        timer(66, time.clock(), 'is')
        if most_comm[0][1] > 1:  # we have several events
            timer(66, time.clock(), 'iex')
            try:
                return ip_count.most_common()[0][0]
            finally:
                timer(65, time.clock(), 'ie')
                timer(66, time.clock(), 'ie')
        timer(66, time.clock(), 'ie')
    timer(65, time.clock(), 'ie')
    timer(68, time.clock(), 's')
    try:
        return 'unknown'
    finally:
        timer(68, time.clock(), 'e')


def protocol_id_to_name(protocol):
    timer(72, time.clock(), 'is')
    if protocol == '-':
        timer(72, time.clock(), 'iex')
        return protocol
    timer(72, time.clock(), 'ie')
    timer(74, time.clock(), 's')
    protocol_map = {
        0: "HOPOPT",
        1: "ICMP",
        2: "IGMP",
        3: "GGP",
        4: "IPv4",
        5: "ST",
        6: "TCP",
        7: "CBT",
        8: "EGP",
        9: "IGP",
        10: "BBN-RCC-MON",
        11: "NVP-II",
        12: "PUP",
        13: "ARGUS",
        14: "EMCON",
        15: "XNET",
        16: "CHAOS",
        17: "UDP",
        18: "MUX",
        19: "DCN-MEAS",
        20: "HMP",
        21: "PRM",
        22: "XNS-IDP",
        23: "TRUNK-1",
        24: "TRUNK-2",
        25: "LEAF-1",
        26: "LEAF-2",
        27: "RDP",
        28: "IRTP",
        29: "ISO-TP4",
        30: "NETBLT",
        31: "MFE-NSP",
        32: "MERIT-INP",
        33: "DCCP",
        34: "3PC",
        35: "IDPR",
        36: "XTP",
        37: "DDP",
        38: "IDPR-CMTP",
        39: "TP++",
        40: "IL",
        41: "IPv6",
        42: "SDRP",
        43: "IPv6-Route",
        44: "IPv6-Frag",
        45: "IDRP",
        46: "RSVP",
        47: "GRE",
        48: "DSR",
        49: "BNA",
        50: "ESP",
        51: "AH",
        52: "I-NLSP",
        53: "SWIPE",
        54: "NARP",
        55: "MOBILE",
        56: "TLSP",
        57: "SKIP",
        58: "IPv6-ICMP",
        59: "IPv6-NoNxt",
        60: "IPv6-Opts",
        62: "CFTP",
        64: "SAT-EXPAK",
        65: "KRYPTOLAN",
        66: "RVD",
        67: "IPPC",
        69: "SAT-MON",
        70: "VISA",
        71: "IPCV",
        72: "CPNX",
        73: "CPHB",
        74: "WSN",
        75: "PVP",
        76: "BR-SAT-MON",
        77: "SUN-ND",
        78: "WB-MON",
        79: "WB-EXPAK",
        80: "ISO-IP",
        81: "VMTP",
        82: "SECURE-VMTP",
        83: "VINES",
        84: "TTP",
        84: "IPTM",
        85: "NSFNET-IGP",
        86: "DGP",
        87: "TCF",
        88: "EIGRP",
        89: "OSPFIGP",
        90: "Sprite-RPC",
        91: "LARP",
        92: "MTP",
        93: "AX.25",
        94: "IPIP",
        95: "MICP",
        96: "SCC-SP",
        97: "ETHERIP",
        98: "ENCAP",
        100: "GMTP",
        101: "IFMP",
        102: "PNNI",
        103: "PIM",
        104: "ARIS",
        105: "SCPS",
        106: "QNX",
        107: "A/N",
        108: "IPComp",
        109: "SNP",
        110: "Compaq-Peer",
        111: "IPX-in-IP",
        112: "VRRP",
        113: "PGM",
        115: "L2TP",
        116: "DDX",
        117: "IATP",
        118: "STP",
        119: "SRP",
        120: "UTI",
        121: "SMP",
        122: "SM",
        123: "PTP",
        124: "ISIS",
        125: "FIRE",
        126: "CRTP",
        127: "CRUDP",
        128: "SSCOPMCE",
        129: "IPLT",
        130: "SPS",
        131: "PIPE",
        132: "SCTP",
        133: "FC",
        134: "RSVP-E2E-IGNORE",
        135: "Mobility",
        136: "UDPLite",
        137: "MPLS-in-IP",
        138: "manet",
        139: "HIP",
        140: "Shim6",
        141: "WESP",
        142: "ROHC",
    }
    try:
        return protocol_map.get(int(protocol), protocol)
    finally:
        timer(74, time.clock(), 'e')

def process_log_status(log_status, tags, timestamp):
    timer(219, 'stats.increment', 'c')
    stats.increment("log_status", tags=["status:%s" % log_status] + tags, timestamp=timestamp)


def process_action(action, tags, timestamp):
    timer(223, 'stats.increment', 'c')
    stats.increment("action", tags=["action:%s" % action] + tags, timestamp=timestamp)


def process_duration(start, end, tags, timestamp):
    timer(227, 'stats.histogram', 'c')
    stats.histogram("duration.per_request", int(int(end) - int(start)), tags=tags, timestamp=timestamp)


def process_packets(packets, tags, timestamp):
    timer(231, 'stats.histogram', 'c')
    stats.histogram("packets.per_request", int(packets), tags=tags, timestamp=timestamp)
    timer(232, 'stats.increment', 'c')
    stats.increment("packets.total", int(packets), tags=tags, timestamp=timestamp)


def process_bytes(_bytes, tags, timestamp):
    timer(236, 'stats.histogram', 'c')
    stats.histogram("bytes.per_request", int(_bytes), tags=tags, timestamp=timestamp)
    timer(237, 'stats.increment', 'c')
    stats.increment("bytes.total", int(_bytes), tags=tags, timestamp=timestamp)


class Stats(object):

    def _initialize(self):
        timer(243, time.clock(), 's')
        self.counts = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        self.histograms = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        timer(243, time.clock(), 'e')

    def __init__(self):
        timer(247, time.clock(), 's')
        self._initialize()
        self.metric_prefix = "aws.vpc.flowlogs"
        timer(247, time.clock(), 'e')

    def increment(self, metric, value=1, timestamp=None, tags=None):
        timer(251, time.clock(), 's')
        metric_name = '%s.%s' % (self.metric_prefix, metric)
        timestamp = timestamp or int(time.time())
        _tags = ','.join(sorted(tags))
        self.counts[metric_name][_tags][timestamp] += value
        timer(251, time.clock(), 'e')

    def histogram(self, metric, value=1, timestamp=None, tags=None):
        timer(257, time.clock(), 's')
        metric_name = '%s.%s' % (self.metric_prefix, metric)
        timestamp = timestamp or int(time.time())
        _tags = ','.join(sorted(tags))
        self.histograms[metric_name][_tags][timestamp].append(value)
        timer(257, time.clock(), 'e')

    def flush(self):
        timer(263, time.clock(), 's')
        percentiles_to_submit = [0, 50, 90, 95, 99, 100]
        series = []
        timer(263, time.clock(), 'e')
        timer(265, time.clock(), 'fs')
        for metric_name, count_payload in self.counts.iteritems():
            timer(265, time.clock(), 'fex')
            timer(266, time.clock(), 'fs')
            for tag_set, datapoints in count_payload.iteritems():
                timer(266, time.clock(), 'fex')
                timer(267, time.clock(), 's')
                points = [(ts, val) for ts, val in datapoints.iteritems()]
                series.append(
                    {
                        'metric': metric_name,
                        'points': points,
                        'type': 'count',
                        'tags': tag_set.split(','),
                    }
                )
                timer(267, time.clock(), 'e')
            timer(266, time.clock(), 'fe')
        timer(265, time.clock(), 'fe')
        timer(277, time.clock(), 'fs')
        for metric_name, histogram_payload in self.histograms.iteritems():
            timer(277, time.clock(), 'fex')
            timer(278, time.clock(), 'fs')
            for tag_set, datapoints in histogram_payload.iteritems():
                timer(278, time.clock(), 'fex')
                timer(279, time.clock(), 's')
                percentiles = defaultdict(list)
                timer(279, time.clock(), 'e')
                timer(280, time.clock(), 'fs')
                for ts, values in datapoints.iteritems():
                    timer(280, time.clock(), 'fex')
                    timer(281, time.clock(), 's')
                    values.sort()
                    total_points = len(values)
                    timer(281, time.clock(), 'e')
                    timer(283, time.clock(), 'fs')
                    for pct in percentiles_to_submit:
                        timer(283, time.clock(), 'fex')
                        timer(284, time.clock(), 's')
                        percentiles[pct].append((ts, values[max(0, int((pct - 1) * total_points / 100))]))
                        timer(284, time.clock(), 'e')
                    timer(283, time.clock(), 'fe')
                timer(280, time.clock(), 'fe')
                timer(286, time.clock(), 'fs')
                for pct, points in percentiles.iteritems():
                    timer(286, time.clock(), 'fex')
                    timer(288, time.clock(), 'is')
                    metric_suffix = 'p%s' % pct
                    if pct == 0:
                        timer(288, time.clock(), 'iex')
                        timer(289, time.clock(), 's')
                        metric_suffix = 'min'
                        timer(289, time.clock(), 'e')
                    timer(288, time.clock(), 'ie')
                    timer(290, time.clock(), 'is')
                    if pct == 50:
                        timer(290, time.clock(), 'iex')
                        timer(291, time.clock(), 's')
                        metric_suffix = 'median'
                        timer(291, time.clock(), 'e')
                    timer(290, time.clock(), 'ie')
                    timer(292, time.clock(), 'is')
                    if pct == 100:
                        timer(292, time.clock(), 'iex')
                        timer(293, time.clock(), 's')
                        metric_suffix = 'max'
                        timer(293, time.clock(), 'e')
                    timer(292, time.clock(), 'ie')    
                    
                    timer(294, time.clock(), 's')
                    series.append(
                        {
                            'metric': '%s.%s' % (metric_name, metric_suffix),
                            'points': points,
                            'type': 'gauge',
                            'tags': tag_set.split(','),
                        }
                    )
                    
                timer(286, time.clock(), 'fe')
            timer(278, time.clock(), 'fe')
        timer(277, time.clock(), 'fe')
        timer(303, 'stats._initialize', 'c')
        self._initialize()

        timer(305, time.clock(), 's')
        metrics_dict = {
            'series': series,
        }

        creds = urllib.urlencode(datadog_keys)
        data = json.dumps(metrics_dict)
        url = '%s?%s' % (datadog_keys.get('api_host', 'https://app.datadoghq.com/api/v1/series'), creds)
        #req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
        #response = urllib2.urlopen(req)
        print('INFO Submitted data with status {}')
       #print('INFO Submitted data with status {}'.format(response.getcode()))
        timer(305, time.clock(), 'e')

stats = Stats()


def lambda_handler(event, context):
    timer(321, time.clock(), 's')
    # event is a dict containing a base64 string gzipped
    event = event['awslogs']['data'].decode('base64')
    event = json.loads(event)
    #event = json.loads(gzip.GzipFile(fileobj=StringIO(event['awslogs']['data'].decode('base64'))).read())
    #function_arn = context.invoked_function_arn
    function_arn = 'arn:aws:lambda:us-east-1:1234123412:function:VPCFlowLogs'
    # 'arn:aws:lambda:us-east-1:1234123412:function:VPCFlowLogs'
    region, account = function_arn.split(':', 5)[3:5]

    tags = ["region:%s" % region, "aws_account:%s" % account]
    unsupported_messages = 0
    timer(321, time.clock(), 'e')
    timer(334, 'compute_node_ip', 'c')
    node_ip = compute_node_ip(event['logEvents'])
    
    timer(336, time.clock(), 'fs')
    for event in event['logEvents']:
        timer(336, time.clock(), 'fex')
        timer(337, time.clock(), 'is')
        message = "2 123456789010 eni-abc123de 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK"
        #message = event['message']
        
        if message[0] != "2":
            timer(337, time.clock(), 'iex')
            timer(340, time.clock(), 's')
            unsupported_messages += 1
            timer(340, time.clock(), 'e')
            try:
                continue
            finally:
                timer(337, time.clock(), 'ie')
        timer(337, time.clock(), 'ie')
        timer(342, time.clock(), 's')
        timestamp = event['timestamp'] / 1000
        timer(342, time.clock(), 'e')
        timer(343, 'process_message', 'c')
        process_message(message, tags, timestamp, node_ip)

    timer(336, time.clock(), 'fe')
    timer(345, time.clock(), 'is')
    if unsupported_messages:
        timer(345, time.clock(), 'iex')
        timer(346, time.clock(), 's')
        print("Unsupported vpc flowlog message type, please contact Datadog")
        timer(346, time.clock(), 'e')
        timer(347, 'stats.increment', 'c')
        stats.increment("unsupported_message", value=unsupported_messages, tags=tags)
    timer(345, time.clock(), 'ie')
    timer(351, 'stats.flush', 'c')
    stats.flush()
    



if __name__ == '__main__':
    sys.stdout = open('C:\\Users\\eyl\\workspace\\TestingGrounds\\outputs\\vpc_output.data', 'w')
    for _ in range(10): 
       # sys.stdout = open('outputs\\rds_output'+repr(i)+'.data', 'w')
        with open("C:\\Users\\eyl\\workspace\\Trace\\inputs\\rds_input0.json", "r") as f:
            data = json.load(f)
            lambda_handler(data, 'arn:aws:lambda:us-east-1:1234123412:function:VPCFlowLogs')
    for _ in range(90): 
        #sys.stdout = open('outputs\\rds_output'+repr(i)+'.data', 'w')
        with open("C:\\Users\\eyl\\workspace\\Trace\\inputs\\rds_input1.json", "r") as f:
            data = json.load(f)
            lambda_handler(data, 'arn:aws:lambda:us-east-1:1234123412:function:VPCFlowLogs')