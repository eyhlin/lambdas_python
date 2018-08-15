import gzip
import json
import logging
import os
import sys

from shipper_edn import LogzioShipper
from StringIO import StringIO

# set logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

import time
time.clock()
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
    elif cxt == 'iez':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        frequency[uid]=0
    elif cxt == 'ie':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        print (repr(uid)+'f: '+ repr(frequency[uid]))
    elif cxt == 'c':
        print (repr(uid)+'c: '+t)

def _extract_aws_logs_data(event):
    # type: (dict) -> dict
    try:
        timer(17, time.clock(), 's')
        logs_data_decoded = event['awslogs']['data'].decode('base64')
        #logs_data_unzipped = gzip.GzipFile(fileobj=StringIO(logs_data_decoded)).read()
        logs_data_unzipped = logs_data_decoded
        logs_data_dict = json.loads(logs_data_unzipped)
        timer(17, time.clock(), 'e')
        return logs_data_dict
    except ValueError as e:
        logger.error("Got exception while loading json, message: {}".format(e))
        raise ValueError("Exception: json loads")


def _parse_cloudwatch_log(log, aws_logs_data, log_type):
    timer(29, time.clock(), 's')
    # type: (dict, dict) -> None
    if '@timestamp' not in log:
        log['@timestamp'] = str(log['timestamp'])
        del log['timestamp']

    log['message'] = log['message'].replace('\n', '')
    log['logStream'] = aws_logs_data['logStream']
    log['messageType'] = aws_logs_data['messageType']
    log['owner'] = aws_logs_data['owner']
    log['logGroup'] = aws_logs_data['logGroup']
    log['function_version'] = aws_logs_data['function_version']
    log['invoked_function_arn'] = aws_logs_data['invoked_function_arn']
    log['type'] = log_type

    
    # If FORMAT is json treat message as a json
    try:
        if os.environ['FORMAT'].lower() == 'json':
            json_object = json.loads(log['message'])
            for key, value in json_object.items():
                log[key] = value
    except (KeyError, ValueError):
        pass
    timer(29, time.clock(), 'e')

def _enrich_logs_data(aws_logs_data, context):
    # type: (dict, 'LambdaContext') -> None
    timer(54, time.clock(), 's')
    try:
        aws_logs_data['function_version'] = context.function_version
        aws_logs_data['invoked_function_arn'] = context.invoked_function_arn
    except KeyError:
        pass
    timer(54, time.clock(), 'e')

def lambda_handler(event, context):
    timer(65, time.clock(), 's')
    # type: (dict, 'LambdaContext') -> None
    try:
        #logzio_url = "{0}/?token={1}".format(os.environ['URL'], os.environ['TOKEN'])
        logzio_url = ''
        #log_type = (os.environ['TYPE'])
        log_type = 'TYPE'
    except KeyError as e:
        logger.error("Missing one of the environment variable: {}".format(e))
        raise

    timer(65, time.clock(), 'e')
    timer(72, '_extract_aws_logs_data', 'c')
    aws_logs_data = _extract_aws_logs_data(event)
    timer(73, '_enrich_logs_data', 'c')
    _enrich_logs_data(aws_logs_data, context)
    
    timer(74, 'Shipper.__init__', 'c')
    shipper = LogzioShipper(logzio_url)

    #logger.info("About to send {} logs".format(len(aws_logs_data['logEvents'])))
    timer(77, time.clock(),'fs')
    for log in aws_logs_data['logEvents']:
        timer(77, time.clock(),'fex')
        if not isinstance(log, dict):
            raise TypeError("Expected log inside logEvents to be a dict but found another type")

        timer(81, '_parse_cloudwatch_log', 'c')
        _parse_cloudwatch_log(log, aws_logs_data, log_type)
        timer(82, 'Shipper.add', 'c')
        shipper.add(log)
    timer(77, time.clock(),'fe')
#shipper.flush()
class Context(object):
    function_version = 1
    invoked_function_arn = 1
    memory_limit_in_mb = 128
    
if __name__ == '__main__':
    sys.stdout = open('C:\\Users\\eyl\\workspace\\TestingGrounds\\outputs\\logzio_output.data', 'w')
    for _ in range(10): 
        with open("C:\\Users\\eyl\\workspace\\Trace\\inputs\\rds_input0.json", "r") as f:
                data = json.load(f)
                lambda_handler(data, Context)
    for _ in range(20): 
        with open("C:\\Users\\eyl\\workspace\\Trace\\inputs\\rds_input1.json", "r") as f:
                data = json.load(f)
                lambda_handler(data, Context)


