#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations.errors
"""
TUNE Mv-Integration Exit Codes
"""

from pyhttpstatus_utils.status_dicts import description as http_status_desc
from pyhttpstatus_utils.status_dicts import name as http_status_codes

name = {
    -1: 'Unassigned',
    0: 'Success',
    600: 'Module Error',
    601: 'Configuration Error',
    602: 'Argument Error',
    603: 'Access Error',
    604: 'I/O Error',
    605: 'No Input',
    606: 'No Permissions',
    607: 'Request Error',
    608: 'Software Error',
    609: 'Invalid Usage',
    610: 'Unexpected Value',
    611: 'Unexpected Exit',
    612: 'Request Ambiguous Error',
    613: 'Request HTTP',
    614: 'Request Connect',
    615: 'Request Redirect',
    616: 'Response Incomplete Read',
    617: 'Response Chuncked Encoding',
    618: 'Response Data Invalid',
    620: 'Retry Exhausted',
    621: 'Service Unavailable',
    622: 'Job Stopped',
    630: 'Payload Read',
    631: 'Payload Not Found',
    632: 'AWS S3 URL Expired',
    640: 'Collect Data Error',
    641: 'Upload Data Error',
    642: 'Integration Error',
    650: 'Run Timeout Error',
    651: 'Runtime Error',
    652: 'Run Stopped Error',
    660: 'Auth Error',
    661: 'Auth JSON Error',
    662: 'Auth Response Error',
    663: 'Auth Missing Parameters',
    664: 'Auth Invalid Parameters',
    699: 'Unexpected Error'
}

description = {
    -1: 'Unassiged exit condition',
    0: 'Successfully completed',
    600: 'Error occurred somewhere within module',
    601: 'Configuration Error',
    602: 'Invalid or missing argument provided',
    603: 'User has access issues',
    604: 'Error occurred while doing I/O on some file',
    605: 'Input file did not exist or was not readable',
    606: 'Insufficient permissions to perform the operation',
    607: 'Unexpected request failure',
    608: 'Unexpected software error was detected',
    609: 'Command was used incorrectly, such as when the wrong number of arguments are given',
    610: 'Unexpected value returned',
    611: 'Integration ended unexpectedly and thereby no exit code was properly determined',
    612: 'There was an ambiguous exception that occurred while handling your request',
    613: 'Request HTTP error occurred',
    614: 'Request Connection error occurred',
    615: 'Request Redirect',
    616: 'Response Incomplete Read',
    617: 'Response Chuncked Encoding',
    618: 'Response Data Invalid',
    620: 'Retry Exhausted',
    621: 'Service Unavailable',
    622: 'Job Stopped',
    623: 'Unexpected content-type returned',
    630: 'Payload Read',
    631: 'Payload Not Found',
    632: 'AWS S3 URL Expired',
    640: 'Collect Data Error',
    641: 'Upload Data Error',
    642: 'Integration Error',
    650: 'Timeout error during data collection',
    651: 'Runtime error during data collection',
    652: 'Stopped error during data collection',
    660: 'Auth Error',
    661: 'Auth JSON Error',
    662: 'Auth Response Error',
    663: 'Auth Missing Parameters',
    664: 'Auth Invalid Parameters',
    699: 'Unexpected Error'
}

type = {600: 'Module Error', 630: 'Configuration Error', 640: 'Process Error', 650: 'Run Error', 660: 'Auth Error'}


def exit_name(exit_code):
    """Provide definition of Exit Code

    Args:
        exit_code:

    Returns:

    """
    if exit_code is None or not isinstance(exit_code, int):
        return "Exit Code: Invalid Type: {}: {}".format(exit_code, type(exit_code))

    exit_code_name_ = http_status_codes.get(exit_code, None)
    if exit_code_name_ is not None:
        return exit_code_name_

    exit_code_name_ = name.get(exit_code, None)
    if exit_code_name_ is not None:
        return exit_code_name_

    return "Exit Code: Undefined: {}".format(exit_code)


def exit_desc(exit_code):
    """Provide definition of Exit Code

    Args:
        exit_code:

    Returns:

    """
    if exit_code is None or not isinstance(exit_code, int):
        return "Exit Code: Invalid Type: {}: {}".format(exit_code, type(exit_code))

    exit_code_description_ = http_status_desc.get(exit_code, None)
    if exit_code_description_ is not None:
        return exit_code_description_

    exit_code_description_ = description.get(exit_code, None)
    if exit_code_description_ is not None:
        return exit_code_description_

    return "Exit Code: Undefined: {}".format(exit_code)
