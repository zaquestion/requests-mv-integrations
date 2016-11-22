#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations.errors
"""
TUNE Mv-Integration Exit Codes
"""

from pyhttpstatus_utils.status_code import HttpStatusCode


class TuneIntegrationExitCode(HttpStatusCode):
    """TUNE Mv-Integration Exit Codes
    """
    MOD_ERR_UNASSIGNED = -1

    MOD_OK = 0  # Success process

    #
    # 6xx Integration Module Errors
    #

    MOD_ERR_MODULE = 600  # Module Error

    MOD_ERR_CONFIG = 601
    # Exit code that means that some kind of configuration
    # error occurred.

    MOD_ERR_ARGUMENT = 602
    # Invalid or missing argument provided.

    MOD_ERR_ACCESS = 603
    # Exit code that means a user
    # specified access issues.

    MOD_ERR_IO = 604
    # Exit code that means that an error
    # occurred while doing I/O on some file.

    MOD_ERR_NOINPUT = 605
    # Exit code that means an input
    # file did not exist or was not readable.

    MOD_ERR_NOPERM = 606
    # Exit code that means that there were insufficient
    # permissions to perform the operation (but not
    # intended for file system problems).

    MOD_ERR_REQUEST = 607
    # Exit code that request failed.

    MOD_ERR_SOFTWARE = 608
    # Exit code that means an internal
    # software error was detected.

    MOD_ERR_INVALID_USAGE = 609
    # Exit code that means the command
    # was used incorrectly, such as when the
    # wrong number of arguments are given.

    MOD_ERR_UNEXPECTED_VALUE = 610
    # Unexpected value either
    # returned or null.

    MOD_ERR_UNEXPECTED_EXIT = 611
    # Integration ended unexpectedly
    # and thereby no exit code was properly determined.

    MOD_ERR_REQUEST = 612
    # There was an ambiguous
    # exception that occurred while handling your request.

    MOD_ERR_REQUEST_HTTP = 613
    # An HTTP error occurred.

    MOD_ERR_REQUEST_CONNECT = 614
    # A Connection error occurred.

    MOD_ERR_REQUEST_REDIRECTS = 615
    MOD_ERR_INCOMPLETE_READ = 616
    MOD_ERR_CHUNKED_ENCODING = 617
    MOD_ERR_DATA_INVALID = 618  # Data not valid

    MOD_ERR_SERVICE_UNAVAILABLE = 620  # Service Unavailable
    MOD_ERR_JOB_STOPPED = 621  # Job Stopped
    MOD_ERR_RETRY_EXHAUSTED = 622  # Retry Exhausted
    MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED = 623  # Unexpected content-type returned

    MOD_ERR_PAYLOAD_READ = 630
    MOD_ERR_PAYLOAD_NOT_FOUND = 631
    MOD_ERR_CONFIG_S3_URL_EXPIRED = 632

    MOD_ERR_COLLECT_DATA = 640  # Error during data collection
    MOD_ERR_UPLOAD_DATA = 641  # Error during data upload
    MOD_ERR_INTEGRATION = 642  # Error during integration

    MOD_ERR_RUN_TIMEOUT = 650  # Timeout error during data collection
    MOD_ERR_RUNTIME_ERROR = 651  # Runtime error during data collection
    MOD_ERR_RUN_STOPPED = 652  # Stopped error during data collection

    MOD_ERR_AUTH_ERROR = 660  # Auth Error
    MOD_ERR_AUTH_JSON_ERROR = 661  # Auth JSON Error
    MOD_ERR_AUTH_RESP_ERROR = 662  # Auth Response Error
    MOD_ERR_AUTH_MISSING_PARAMS = 663  # Auth Missing Parameters
    MOD_ERR_AUTH_INVALID_PARAMS = 664  # Auth Invalid Parameters

    MOD_ERR_UNEXPECTED = 699  # Unexpected Error
