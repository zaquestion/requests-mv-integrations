#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations
"""
TUNE Multiverse Request
=======================
"""

from logging import getLogger

import base64
import copy
import csv
import datetime as dt
import gzip
import http.client as http_client
import io
import json
import logging
import os
import re
import time
import urllib.parse
from functools import partial

import bs4
import requests
import requests_toolbelt
import xmltodict

from pprintpp import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from requests_mv_integrations.errors.exceptions import (
    TuneRequestError,
    TuneRequestClientError,
    TuneRequestServiceError,
    TuneRequestModuleError
)
from requests_mv_integrations.errors.errors_traceback import (
    get_exception_message,
    print_traceback
)
from requests_mv_integrations.errors.exit_code import (
    IntegrationExitCode
)
from pyhttpstatus_utils import (
    HttpStatusCode,
    HttpStatusType,
    http_status_code_to_desc,
    http_status_code_to_type,
    is_http_status_type,
    is_http_status_successful
)
from requests_mv_integrations.support import (
    command_line_request_curl,
    convert_size,
    detect_bom,
    base_class_name,
    python_check_version,
    remove_bom,
    requests_response_text_html,
    safe_dict,
    safe_int,
    safe_str,

    __USER_AGENT__
)
from requests_mv_integrations import (
    __python_required_version__
)

from .tune_request import (
    TuneRequest
)

from .tune_request_mv_integration import (
    TuneRequestMvIntegration
)

log = getLogger(__name__)

python_check_version(__python_required_version__)


class TuneRequestMvUpload(TuneRequestMvIntegration):

    def request_upload_json_file(
            self,
            upload_request_url,
            upload_data_file_path,
            upload_data_file_size,
            is_upload_gzip,
            request_label,
            upload_timeout=None
    ):
        """Upload File to requested URL.

        Args:
            upload_request_url:
            upload_data_file_path:
            upload_data_file_size:
            upload_timeout:

        Returns:

        """
        request_retry_excps = \
            self._REQUEST_RETRY_EXCPS

        upload_request_retry = {
            "timeout": 60,
            "tries": -1,
            "delay": 60
        }

        upload_request_headers = {
            'Content-Length': '{}'.format(upload_data_file_size)
        }

        if is_upload_gzip:
            upload_request_headers.update({
                'Content-Type': 'application/gzip'
            })
        else:
            upload_request_headers.update({
                'Content-Type': 'application/json; charset=utf8'
            })

        if upload_timeout:
            upload_request_retry["timeout"] = int(upload_timeout)

        upload_extra = {
            'upload_request_url': upload_request_url,
            'upload_data_file_path': upload_data_file_path,
            'upload_data_file_size': upload_data_file_size,
            'upload_request_retry': upload_request_retry,
            'upload_request_headers': upload_request_headers
        }

        log.debug(
            "Upload: Details",
            extra=upload_extra
        )

        try:
            with open(upload_data_file_path, 'rb') as upload_fp:
                response = self.request(
                    request_method="PUT",
                    request_url=upload_request_url,
                    request_params=None,
                    request_data=upload_fp,
                    request_retry=upload_request_retry,
                    request_headers=upload_request_headers,
                    request_retry_excps=request_retry_excps,
                    request_retry_excps_func=self._upload_request_retry_excps_func,
                    allow_redirects=False,
                    build_request_curl=False,
                    request_label="{}: Request Upload".format(request_label),
                    verbose=False
                )
        except TuneRequestError as tmv_ex:

            tmv_ex_extra = tmv_ex.to_dict()
            tmv_ex_extra.update({
                'error_exception': base_class_name(tmv_ex)
            })

            log.error(
                "Request Upload: Failed",
                extra=tmv_ex_extra
            )

            raise

        except Exception as ex:
            log.error(
                "Request Upload: Failed: Unexpected",
                extra={
                    'error_exception': base_class_name(ex),
                    'error_details': get_exception_message(ex)
                }
            )

            print_traceback(ex)

            raise TuneRequestModuleError(
                error_message=(
                    "Request Upload: Failed: Unexpected: {}: {}"
                ).format(
                    base_class_name(ex),
                    get_exception_message(ex)
                ),
                errors=ex,
                exit_code=IntegrationExitCode.MOD_ERR_UPLOAD_DATA
            )

        return response


    def request_upload_data(
            self,
            upload_request_url,
            upload_data,
            upload_data_size,
            upload_timeout=None,
            verbose=False
    ):
        """Upload Data to requested URL.

        Args:
            upload_request_url:
            upload_data:

        Returns:
            requests.Response
        """
        log.info(
            "Uploading Data",
            extra={
                'upload_data_size': upload_data_size,
                'upload_request_url': upload_request_url
            }
        )

        request_retry_excps = self._REQUEST_RETRY_EXCPS

        upload_request_retry = {
            "timeout": 60,
            "tries": -1,
            "delay": 60
        }

        request_headers = {
            'Content-type': 'application/json; charset=utf8',
            'Accept': 'text/plain',
            'Content-Length': "{}".format(upload_data_size)
        }

        if upload_timeout:
            upload_request_retry["timeout"] = int(upload_timeout)

        try:
            response = self.request(
                request_method="PUT",
                request_url=upload_request_url,
                request_params=None,
                request_data=upload_data,
                request_retry=upload_request_retry,
                request_retry_excps=request_retry_excps,
                request_retry_excps_func=self._upload_request_retry_excps_func,
                request_headers=request_headers,
                allow_redirects=False,
                build_request_curl=False,
                request_label="Upload Data to URL",
                verbose=verbose
            )
        except TuneRequestError as tmv_ex:
            tmv_ex_extra = tmv_ex.to_dict()
            tmv_ex_extra.update({
                'error_exception': base_class_name(tmv_ex)
            })

            log.error(
                "Upload: Failed",
                extra=tmv_ex_extra
            )
            raise

        except Exception as ex:
            print_traceback(ex)

            log.error(
                "Upload: Failed: Unexpected",
                extra={
                    'error_exception': base_class_name(ex),
                    'error_details': get_exception_message(ex)
                }
            )
            raise TuneRequestModuleError(
                error_message=(
                    "TuneRequestMvIntegration: Failed: {}"
                ).format(
                    get_exception_message(ex)
                ),
                errors=ex,
                exit_code=IntegrationExitCode.MOD_ERR_UPLOAD_DATA
            )

        return response

    def _upload_request_retry_excps_func(
            self,
            excp,
            request_label
    ):
        """Upload Request Retry Exception Function

        Args:
            excp:

        Returns:

        """
        error_exception = base_class_name(excp)
        error_details = get_exception_message(excp)

        if isinstance(excp, TuneRequestError):
            log.debug(
                "Request Retry: Upload Exception Func",
                extra={
                    'request_label': request_label,
                    'error_exception': error_exception,
                    'error_details': error_details
                }
            )
        else:
            log.debug(
                "Request Retry: Upload Exception Func: Unexpected",
                extra={
                    'request_label': request_label,
                    'error_exception': error_exception,
                    'error_details': error_details
                }
            )

        if isinstance(excp, TuneRequestError) and \
                        excp.exit_code == IntegrationExitCode.MOD_ERR_REQUEST_CONNECT:
            if error_details.find('RemoteDisconnected') >= 0 or \
                            error_details.find('ConnectionResetError') >= 0:
                log.debug(
                    "Request Retry: Upload Exception Func: Retry",
                    extra={
                        'request_label': request_label,
                        'error_exception': error_exception,
                        'error_details': error_details
                    }
                )
                return True

        if isinstance(excp, requests.exceptions.ConnectionError):
            if error_details.find('RemoteDisconnected') >= 0 or \
                            error_details.find('ConnectionResetError') >= 0:
                log.debug(
                    "Request Retry: Upload Exception Func: Retry",
                    extra={
                        'request_label': request_label,
                        'error_exception': error_exception,
                        'error_details': error_details
                    }
                )
                return True

        log.debug(
            "Request Retry: Upload Exception Func: Not Retry",
            extra={
                'request_label': request_label,
                'error_exception': error_exception,
                'error_details': error_details
            }
        )

        return False