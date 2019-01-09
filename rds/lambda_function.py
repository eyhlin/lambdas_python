# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2017 Datadog, Inc.

import gzip
import json
import os
import re
import time
import urllib
import urllib2
from base64 import b64decode
from StringIO import StringIO

import boto3
import sys

# retrieve datadog options from KMS
KMS_ENCRYPTED_KEYS = 'AQICAHi7wMMzxQdsGmB1aYgGTdEAMynmCM+uVLtgnQzMjYntCwHJDU3zpKyhAu2A0YyLyh6GAAABATCB/gYJKoZIhvcNAQcGoIHwMIHtAgEAMIHnBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDGYOHzRFKWpV46ZDBwIBEICBuYJg4zMcXO8N59YBTnTXfI4SUBggVxl3oQdyaXJsPHrG18lV7ExN+VE6rsLEfO239Y8Zvf4PFVYdIVtC4osRcNbTUx5cjpjMSr5nOnAD8cbFcV75V2127IlWyE/lBG2Yne5cz23qZGfcCcyIiHzCFcDToNpsIMaX6dUV+fgMP2K/mUfXmBIvjaYvaW7AAqFgCxA+KuheATEs078si+44nqObivyaeyqUqqk/LqOITm0UpLF52c7QUM4W'
kms = boto3.client('kms', region_name='us-east-2')
datadog_keys = json.loads(kms.decrypt(CiphertextBlob=b64decode(KMS_ENCRYPTED_KEYS))['Plaintext'])

print 'INFO Lambda function initialized, ready to send metrics'

times = {}
frequency = {}
def timer(uid, t, cxt):
    if cxt=='s':
        if uid not in times:
            times[uid] = t
    elif cxt =='e':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
    elif cxt == 'fs':
        if uid not in times:
            times[uid] = t
            frequency[uid] = 0
    elif cxt == 'fex':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        frequency[uid]+=1
    elif cxt == 'fe':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        print (repr(uid)+'f: '+ repr(frequency[uid]))
    elif cxt == 'is':
        if uid not in times:
            times[uid] = t
            frequency[uid] = -1
    elif cxt == 'iex':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        frequency[uid]=1
    elif cxt == 'ie':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        print (repr(uid)+'f: '+ repr(frequency[uid]))

def _process_rds_enhanced_monitoring_message(ts, message, account, region):
    instance_id = message["instanceID"]
    host_id = message["instanceResourceID"]
    tags = [
        'dbinstanceidentifier:%s' % instance_id,
        'aws_account:%s' % account,
        'engine:%s' % message["engine"],
    ]

    # metrics generation

    # uptime: "54 days, 1:53:04" to be converted into seconds
    uptime = 0
    uptime_msg = re.split(' days?, ', message["uptime"])  # edge case "1 day 1:53:04"
    if len(uptime_msg) == 2:
        uptime += 24 * 3600 * int(uptime_msg[0])
    uptime_day = uptime_msg[-1].split(':')
    uptime += 3600 * int(uptime_day[0])
    uptime += 60 * int(uptime_day[1])
    uptime += int(uptime_day[2])
    stats.gauge(
        'aws.rds.uptime', uptime, timestamp=ts, tags=tags, host=host_id
    )
    stats.gauge(
        'aws.rds.virtual_cpus', message["numVCPUs"], timestamp=ts, tags=tags, host=host_id
    )
    stats.gauge(
        'aws.rds.load.1', message["loadAverageMinute"]["one"],
        timestamp=ts, tags=tags, host=host_id
    )
    stats.gauge(
        'aws.rds.load.5', message["loadAverageMinute"]["five"],
        timestamp=ts, tags=tags, host=host_id
    )
    stats.gauge(
        'aws.rds.load.15', message["loadAverageMinute"]["fifteen"],
        timestamp=ts, tags=tags, host=host_id
    )
    for namespace in ["cpuUtilization", "memory", "tasks", "swap"]:
        for key, value in message[namespace].iteritems():
            stats.gauge(
                'aws.rds.%s.%s' % (namespace.lower(), key), value,
                timestamp=ts, tags=tags, host=host_id
            )

    for network_stats in message["network"]:
        network_tag = ["interface:%s" % network_stats.pop("interface")]
        for key, value in network_stats.iteritems():
            stats.gauge(
                'aws.rds.network.%s' % key, value,
                timestamp=ts, tags=tags + network_tag, host=host_id
            )
    disk_stats = message["diskIO"][0]  # we never expect to have more than one disk
    for key, value in disk_stats.iteritems():
        stats.gauge(
            'aws.rds.diskio.%s' % key, value,
            timestamp=ts, tags=tags, host=host_id
        )
    for fs_stats in message["fileSys"]:
        fs_tag = [
            "name:%s" % fs_stats.pop("name"),
            "mountPoint:%s" % fs_stats.pop("mountPoint")
        ]
        for key, value in fs_stats.iteritems():
            stats.gauge(
                'aws.rds.filesystem.%s' % key, value,
                timestamp=ts, tags=tags + fs_tag, host=host_id
            )
    for process_stats in message["processList"]:
        process_tag = [
            "name:%s" % process_stats.pop("name"),
            "id:%s" % process_stats.pop("id")
        ]
        for key, value in process_stats.iteritems():
            stats.gauge(
                'aws.rds.process.%s' % key, value,
                timestamp=ts, tags=tags + process_tag, host=host_id
            )

def lambda_handler(event, context):
    start = time.clock()
    ''' Process a RDS enhenced monitoring DATA_MESSAGE,
        coming from CLOUDWATCH LOGS
    '''
    # event is a dict containing a base64 string gzipped
    event = event['awslogs']['data']
    event = json.loads(
        event.decode('base64')
        #gzip.GzipFile(fileobj=StringIO(event.decode('base64'))).read()
    )

    account = event['owner']
    region = 'us-east-2'
    #region = context.invoked_function_arn.split(':', 4)[3]

    log_events = event['logEvents']

    
    for log_event in log_events:
        mm="{\"engine\": \"Aurora\",\"instanceID\": \"instanceid\",\"instanceResourceID\": \"db-QPCTQVLJ4WIQPCTQVLJ4WIJ4WI\",\"timestamp\": \"2016-01-01T01:01:01Z\",\"version\": 1.00,\"uptime\": \"10 days, 1:53:04\",\"numVCPUs\": 2,\"cpuUtilization\": {\"guest\": 0.00,\"irq\": 0.00,\"system\": 0.88,\"wait\": 0.54,\"idle\": 97.57,\"user\": 0.68,\"total\": 1.56,\"steal\": 0.07,\"nice\": 0.25},\"loadAverageMinute\": {\"fifteen\": 0.14,\"five\": 0.17,\"one\": 0.18},\"memory\": {\"writeback\": 0,\"hugePagesFree\": 0,\"hugePagesRsvd\": 0,\"hugePagesSurp\": 0,\"cached\": 11742648,\"hugePagesSize\": 2048,\"free\": 259016,\"hugePagesTotal\": 0,\"inactive\": 1817176,\"pageTables\": 25808,\"dirty\": 660,\"mapped\": 8087612,\"active\": 13016084,\"total\": 15670012,\"slab\": 437916,\"buffers\": 272136},\"tasks\": {\"sleeping\": 223,\"zombie\": 0,\"running\": 1,\"stopped\": 0,\"total\": 224,\"blocked\": 0},\"swap\": {\"cached\": 0,\"total\": 0,\"free\": 0},\"network\": [{\"interface\": \"eth0\",\"rx\": 217.57,\"tx\": 2319.67}],\"diskIO\": [{\"readLatency\": 0.00,\"writeLatency\": 1.53,\"writeThroughput\": 2048.20,\"readThroughput\": 0.00,\"readIOsPS\": 0.00,\"diskQueueDepth\": 0,\"writeIOsPS\": 5.83}],\"fileSys\": [{\"used\": 7006720,\"name\": \"rdsfilesys\",\"usedFiles\": 2650,\"usedFilePercent\": 0.13,\"maxFiles\": 1966080,\"mountPoint\": \"/rdsdbdata\",\"total\": 30828540,\"usedPercent\": 22.73}],\"processList\": [{\"vss\": 11170084,\"name\": \"aurora\",\"tgid\": 8455,\"parentID\": 1,\"memoryUsedPc\": 66.93,\"cpuUsedPc\": 0.00,\"id\": 8455,\"rss\": 10487696}, {\"vss\": 11170084,\"name\": \"aurora\",\"tgid\": 8455,\"parentID\": 1,\"memoryUsedPc\": 66.93,\"cpuUsedPc\": 0.82,\"id\": 8782,\"rss\": 10487696}, {\"vss\": 11170084,\"name\": \"aurora\",\"tgid\": 8455,\"parentID\": 1,\"memoryUsedPc\": 66.93,\"cpuUsedPc\": 0.05,\"id\": 8784,\"rss\": 10487696}, {\"vss\": 647304,\"name\": \"OS processes\",\"tgid\": 0,\"parentID\": 0,\"memoryUsedPc\": 0.18,\"cpuUsedPc\": 0.02,\"id\": 0,\"rss\": 22600}, {\"vss\": 3244792,\"name\": \"RDS processes\",\"tgid\": 0,\"parentID\": 0,\"memoryUsedPc\": 2.80,\"cpuUsedPc\": 0.78,\"id\": 0,\"rss\": 441652}]}"
        #message = json.loads(mm)
        message = json.loads((log_event)['message'])
        ts = log_event['timestamp'] / 1000
        _process_rds_enhanced_monitoring_message(ts, message, account, region)

    stats.flush()
    try:
        return {'Status': 'OK'}
    finally:
        end = time.clock()
        print(end-start)


# Helpers to send data to Datadog, inspired from https://github.com/DataDog/datadogpy

class Stats(object):

    def __init__(self):
        self.series = []

    def gauge(self, metric, value, timestamp=None, tags=None, host=None):
        base_dict = {
            'metric': metric,
            'points': [(int(timestamp or time.time()), value)],
            'type': 'gauge',
            'tags': tags,
        }
        if host:
            base_dict.update({'host': host})
        self.series.append(base_dict)

    def flush(self):
        metrics_dict = {
            'series': self.series,
        }
        self.series = []

        creds = urllib.urlencode(datadog_keys)
        data = json.dumps(metrics_dict)
        url = '%s?%s' % (datadog_keys.get('api_host', 'https://app.datadoghq.com/api/v1/series'), creds)
        #req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
        #response = urllib2.urlopen(req)
        #print 'INFO Submitted data with status'#, response.getcode()

stats = Stats()


if __name__ == '__main__':
    i=0
    for _ in range(15): 
       # sys.stdout = open('outputs\\rds_output'+repr(i)+'.data', 'w')
        with open("inputs\\rds_input0.json", "r") as f:
            data = json.load(f)
            lambda_handler(data, '')
        i+=1
    for _ in range(15): 
        #sys.stdout = open('outputs\\rds_output'+repr(i)+'.data', 'w')
        with open("inputs\\rds_input1.json", "r") as f:
            data = json.load(f)
            lambda_handler(data, '')
        i+=1