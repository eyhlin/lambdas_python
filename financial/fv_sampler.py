import lambda_handlers_edn as lambda_handlers
import logging


if __name__ == '__main__':
    
    input=\
    {
      "rate": 0.004166666666667,
      "nper": 120,
      "pmt": -100,
      "pv": -100
    }
    logging.basicConfig()
    logger = logging.getLogger('logger')
    
    result = lambda_handlers.fv_handler(input, '')
    print(result['result'])