import sys
import json
import lambda_function_edn



class Context(object):
    function_version = 1
    invoked_function_arn = 1
    memory_limit_in_mb = '128'
    function_name = 'test_function'

if __name__ == '__main__':
    sys.stdout = open('C:\\Users\\eyl\\workspace\\TestingGrounds\\outputs\\log_output.data', 'w')
    for _ in range(10): 
        with open("C:\\Users\\eyl\\workspace\\Trace\\inputs\\rds_input0.json", "r") as f:
                data = json.load(f)
                lambda_function_edn.lambda_handler(data, Context)
    for _ in range(20): 
        with open("C:\\Users\\eyl\\workspace\\Trace\\inputs\\rds_input1.json", "r") as f:
                data = json.load(f)
                lambda_function_edn.lambda_handler(data, Context)