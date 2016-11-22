#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations
"""
TUNE Multiverse Request
=======================
"""

import copy
import datetime as dt
import json
import logging
import os
import time
import urllib.parse
from functools import partial
import http.client as http_client
import bs4
import re
import csv
import gzip
import io
import requests
import requests_toolbelt
import xmltodict
from logging_mv_integrations import (TuneLoggingFormat, TuneLoggingHandler, get_logger)
from pprintpp import pprint
from pyhttpstatus_utils import (
    HttpStatusCode, HttpStatusType, http_status_code_to_desc, http_status_code_to_type, is_http_status_type,
    is_http_status_successful
)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from requests_mv_integrations import (__python_required_version__, __version__)
from requests_mv_integrations.errors import (
    TuneRequestError, TuneRequestClientError, TuneRequestServiceError, TuneRequestModuleError, get_exception_message,
    print_traceback, TuneIntegrationExitCode, ModuleArgumentError
)
from requests_mv_integrations.support import (
    command_line_request_curl, convert_size, base_class_name, python_check_version, requests_response_text_html,
    safe_dict, safe_int, safe_str, detect_bom, remove_bom, REQUEST_RETRY_EXCPS, REQUEST_RETRY_HTTP_STATUS_CODES,
    __USER_AGENT__
)
from requests_mv_integrations.support.tune_request import (TuneRequest)

python_check_version(__python_required_version__)


# @brief Request with retry class for TUNE Multiverse classes
#
# @namespace requests_mv_integrations.RequestMvIntegration
class RequestMvIntegration(object):
    """Request with retry class for TUNE Multiverse classes
    """

    _REQUEST_CONFIG = {
        "timeout": 60,  # timeout: the number of seconds to connect to
        # and then read from a remote machine.
        "tries": 3,  # tries: the maximum number of attempts.
        # (-1 is infinite). default: 10 tries.
        "delay": 10  # delay: initial delay between attempts.
        # default: 10 seconds.
    }

    # Current directory
    # @var string
    CURRENT_DIR = \
        os.path.dirname(os.path.realpath(__file__))

    __tune_request = None
    __built_request_curl = None
    __logger = None

    @property
    def built_request_curl(self):
        return self.__built_request_curl

    @built_request_curl.setter
    def built_request_curl(self, value):
        self.__built_request_curl = value

    @property
    def logger(self):
        """Get Property: Logger
        """
        if self.__logger is None:
            self.__logger = get_logger(
                logger_name=__name__.split('.')[0],
                logger_version=__version__,
                logger_format=self.logger_format,
                logger_level=self.logger_level
            )

        return self.__logger

    @property
    def tune_request(self):
        return self.__tune_request

    @tune_request.setter
    def tune_request(self, value):
        self.__tune_request = value

    def __init__(
        self,
        logger_level=logging.INFO,
        logger_format=TuneLoggingFormat.JSON,
    ):
        self.logger_level = logger_level
        self.logger_format = logger_format

        self._requests_logger()

    def _requests_logger(self):
        """Set logging format to package 'requests'"""
        if self.logger:
            request_logger_level = self.logger_level

            if request_logger_level == logging.INFO:
                request_logger_level = logging.WARNING

            tune_loggin_handler = TuneLoggingHandler(logger_format=self.logger_format)

            tune_loggin_handler.add_logger_version('requests', requests.__version__)

            requests_logger = logging.getLogger('requests')
            requests_logger.addHandler(tune_loggin_handler.log_handler)
            requests_logger.propagate = True
            requests_logger.setLevel(level=request_logger_level)

    def request(
        self,
        request_method,
        request_url,
        request_params=None,
        request_data=None,
        request_json=None,
        request_retry=None,
        request_retry_excps=None,
        request_retry_http_status_codes=None,
        request_retry_func=None,
        request_retry_excps_func=None,
        request_headers=None,
        request_auth=None,
        cookie_payload=None,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        stream=False,
        request_label=None
    ):
        """Request data from remote source with retries.

        Args:
            request_method: request_method for the new :class:`Request` object.
            request_url: URL for the new :class:`Request` object.
            request_params: (optional) Dictionary or bytes to be sent in the
                query string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_json: (optional) json data to send in the body of
                the :class:`Request`.
            request_retry: (optional) Retry configuration.
            request_retry_func: (optional) Retry function, alternative
                to request_retry_excps.
            request_retry_excps: An exception or a tuple of exceptions
                to catch.
            request_headers: (optional) Dictionary of HTTP Headers to
                send with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
            allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE
                redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            stream: (optional) if ``False``, the response content will be
                immediately downloaded.
            request_label:

        Returns:
            requests.Response: Data result if success or None if error.

        Raises:
            ServiceGatewayTimeoutError: Upon any timeout condition.
            Exception: Upon error within this request_method.

        Notes:
            * tries: the maximum number of attempts. default: 1.
            * delay: initial delay between attempts. default: 1.
            * max_delay: the maximum value of delay. default: None (no limit).
            * backoff: multiplier applied to delay between attempts.
                default: 1 (no backoff).
            * jitter: extra seconds added to delay between attempts.
                default: 0.
        """
        self.logger.debug("Request: Start: {}".format(request_label if request_label else ""))

        timeout = None

        retry_tries = None
        retry_delay = None
        retry_backoff = 0
        retry_jitter = 0
        retry_max_delay = None

        if not verify:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        if request_method:
            request_method = request_method.upper()

        if not request_retry:
            request_retry = {}

        if 'timeout' not in request_retry:
            request_retry['timeout'] = self._REQUEST_CONFIG['timeout']
        if 'tries' not in request_retry:
            request_retry['tries'] = self._REQUEST_CONFIG['tries']
        if 'delay' not in request_retry:
            request_retry['delay'] = self._REQUEST_CONFIG['delay']

        if 'timeout' in request_retry:
            timeout = request_retry['timeout']
        if 'tries' in request_retry:
            retry_tries = request_retry['tries']
        if 'delay' in request_retry:
            retry_delay = request_retry['delay']
        if 'max_delay' in request_retry:
            retry_max_delay = request_retry['max_delay']
        if 'backoff' in request_retry:
            retry_backoff = request_retry['backoff']
        if 'jitter' in request_retry:
            retry_jitter = request_retry['jitter']

        logger_extra = {
            'request_method': request_method,
            'request_url': request_url,
        }

        if request_params:
            logger_extra.update({'request_params': request_params})

        if request_retry:
            logger_extra.update({'request_retry': request_retry})

        if request_headers:
            logger_extra.update({'request_headers': request_headers})

        if request_auth:
            logger_extra.update({'request_auth': request_auth})

        if request_json:
            logger_extra.update({'request_json': request_json})

        self.logger.debug("Request: Setup: {}".format(request_label if request_label else ""), extra=logger_extra)

        key_user_agent = 'User-Agent'
        header_user_agent = {key_user_agent: __USER_AGENT__}

        if request_headers:
            if key_user_agent not in request_headers:
                request_headers.update(header_user_agent)
        else:
            request_headers = header_user_agent

        kwargs = {
            'request_method': request_method,
            'request_url': request_url,
            'request_params': request_params,
            'request_data': request_data,
            'request_json': request_json,
            'request_headers': request_headers,
            'request_auth': request_auth,
            'cookie_payload': cookie_payload,
            'request_label': request_label,
            'timeout': timeout,
            'build_request_curl': build_request_curl,
            'allow_redirects': allow_redirects,
            'verify': verify,
            'stream': stream
        }

        time_start_req = dt.datetime.now()

        if not request_retry_http_status_codes:
            request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES
        self.request_retry_http_status_codes = request_retry_http_status_codes

        if not request_retry_excps:
            request_retry_excps = REQUEST_RETRY_EXCPS
        self.request_retry_excps = request_retry_excps

        self.logger.debug(
            "Request: Details: {}".format(request_label if request_label else ""),
            extra={
                'request_method': request_method,
                'request_retry': request_retry,
                'request_url': request_url,
                'request_params': request_params,
                'request_data': request_data,
                'request_json': request_json,
                'request_headers': request_headers,
                'request_auth': request_auth,
                'timeout': timeout,
                'allow_redirects': allow_redirects,
                'verify': verify,
                'stream': stream
            }
        )

        try:
            response = self._request_retry(
                call_func=self._request,
                fargs=None,
                fkwargs=kwargs,
                timeout=timeout,
                request_retry_func=request_retry_func,
                request_retry_excps_func=request_retry_excps_func,
                retry_tries=retry_tries,
                retry_delay=retry_delay,
                retry_max_delay=retry_max_delay,
                retry_backoff=retry_backoff,
                retry_jitter=retry_jitter,
                request_label=request_label
            )

        except (
            requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout
        ) as ex_req_timeout:
            raise TuneRequestError(
                error_message="Request: Exception: Timeout",
                errors=ex_req_timeout,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.GATEWAY_TIMEOUT
            )

        except requests.exceptions.HTTPError as ex_req_http:
            raise TuneRequestError(
                error_message="Request: Exception: HTTP Error",
                errors=ex_req_http,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST_HTTP,
                error_request_curl=self.built_request_curl
            )

        except requests.exceptions.ConnectionError as ex_req_connect:
            raise TuneRequestError(
                error_message="Request: Exception: Connection Error",
                errors=ex_req_connect,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except BrokenPipeError as ex_broken_pipe:
            raise TuneRequestError(
                error_message="Request: Exception: Broken Pipe Error",
                errors=ex_broken_pipe,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except ConnectionError as ex_connect:
            raise TuneRequestError(
                error_message="Request: Exception: Connection Error",
                errors=ex_connect,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ProtocolError as ex_req_urllib3_protocol:
            raise TuneRequestError(
                error_message="Request: Exception: Protocol Error",
                errors=ex_req_urllib3_protocol,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ReadTimeoutError as ex_req_urllib3_read_timeout:
            raise TuneRequestError(
                error_message="Request: Exception: Urllib3: Read Timeout Error",
                errors=ex_req_urllib3_read_timeout,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.GATEWAY_TIMEOUT
            )

        except requests.exceptions.TooManyRedirects as ex_req_redirects:
            raise TuneRequestError(
                error_message="Request: Exception: Too Many Redirects",
                errors=ex_req_redirects,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST_REDIRECTS
            )

        except requests.exceptions.RequestException as ex_req_request:
            raise TuneRequestError(
                error_message="Request: Exception: Request Error",
                errors=ex_req_request,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST
            )

        except TuneRequestError:
            raise

        except Exception as ex:
            print_traceback(ex)

            raise TuneRequestError(
                error_message="Request: Exception: Unexpected",
                errors=ex,
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_SOFTWARE
            )

        time_end_req = dt.datetime.now()
        diff_req = time_end_req - time_start_req

        request_time_msecs = int(diff_req.total_seconds() * 1000)

        self.logger.debug(
            "Request: Completed", extra={'request_label': request_label,
                                         'request_time_msecs': request_time_msecs}
        )

        return response

    def _request_retry(
        self,
        call_func,
        fargs=None,
        fkwargs=None,
        timeout=60,
        request_retry_func=None,
        request_retry_excps_func=None,
        retry_tries=-1,  # default: -1 (indefinite)
        retry_delay=0,
        retry_max_delay=None,
        retry_backoff=0,
        retry_jitter=0,
        request_label=None
    ):
        """Request Retry

        Args:
            call_func: the function to execute.
            request_retry_excps: A tuple of exceptions to catch.
            fargs: the positional arguments of the function to execute.
            fkwargs: the named arguments of the function to execute.
            timeout: (optional) How long to wait for the server to send
                data before giving up.
            request_retry_func: (optional) Retry alternative to request_retry_excps.

            retry_tries: the maximum number of attempts.
                default: -1 (infinite).
            retry_delay: initial delay between attempts.
                default: 0.
            retry_max_delay:the maximum value of delay.
                default: None (no limit).
            retry_backoff: multiplier applied to delay between attempts.
                default: 1 (no backoff).
            retry_jitter: extra seconds added to delay between attempts.
                default: 0.
            request_label: Label

        Returns:

        """
        request_retry_extra = {'timeout': timeout}

        request_retry_extra.update({'request_retry_http_status_codes': self.request_retry_http_status_codes})

        if self.request_retry_excps is not None:
            request_retry_excp_names = [excp.__name__ for excp in list(self.request_retry_excps)]
            request_retry_extra.update({'request_retry_excps': request_retry_excp_names})

        if request_retry_func is not None:
            request_retry_func_name = request_retry_func.__name__
            request_retry_extra.update({'request_retry_func': request_retry_func_name})

        if request_retry_excps_func is not None:
            request_retry_excps_func_name = request_retry_excps_func.__name__
            request_retry_extra.update({'request_retry_excps_func': request_retry_excps_func_name})

        self.logger.debug(
            "Request Retry: Start: {}".format(request_label if request_label else ""), extra=request_retry_extra
        )

        args = fargs if fargs else list()
        kwargs = fkwargs if fkwargs else dict()

        request_url = kwargs['request_url'] if kwargs and 'request_url' in kwargs else ""

        _attempts = 0

        self.retry_tries = retry_tries
        self.retry_backoff = retry_backoff

        _tries, _delay, _timeout = retry_tries, retry_delay, timeout
        while _tries:
            _attempts += 1

            fkwargs['timeout'] = _timeout
            request_func = partial(call_func, *args, **kwargs)

            self.logger.debug(
                "Request Retry: Attempt: {}: {}".format(request_label if request_label else "", _attempts),
                extra={
                    'attempts': _attempts,
                    'timeout': _timeout,
                    'tries': _tries,
                    'delay': _delay,
                    'request_url': request_url
                }
            )

            error_exception = None
            _tries -= 1

            try:
                response = request_func()

                if not response:
                    raise TuneRequestModuleError(
                        error_message="Request Retry: No response",
                        exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_VALUE
                    )

                self.logger.debug(
                    "Request Retry: Checking Response",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

                if request_retry_func:
                    if not request_retry_func(response):
                        self.logger.debug(
                            "Request Retry: Response: Valid: Not Retry Candidate",
                            extra={'request_url': request_url,
                                   'request_label': request_label}
                        )
                        return response
                else:
                    self.logger.debug(
                        "Request Retry: Response: Valid",
                        extra={'request_url': request_url,
                               'request_label': request_label}
                    )
                    return response

                self.logger.debug(
                    "Request Retry: Response: Valid: Retry Candidate",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

            except self.request_retry_excps as retry_ex:
                error_exception = retry_ex

                self.logger.warning(
                    "Request Retry: Expected: {}: Retry Candidate".format(base_class_name(error_exception)),
                    extra={
                        'error_details': get_exception_message(error_exception),
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                if not _tries:
                    self.logger.error(
                        "Request Retry: Expected: {}: Exhausted Retries".format(base_class_name(error_exception))
                    )
                    raise

            except TuneRequestError as tmv_ex:
                error_exception = tmv_ex
                tmv_ex_extra = tmv_ex.to_dict()
                tmv_ex_extra.update({
                    'error_exception': base_class_name(error_exception),
                    'error_details': get_exception_message(error_exception),
                    'request_label': request_label
                })

                if not request_retry_excps_func or \
                        not request_retry_excps_func(tmv_ex, request_label):
                    self.logger.error(
                        "Request Retry: Integration: {}: Not Retry Candidate".format(base_class_name(error_exception)),
                        extra=tmv_ex_extra
                    )
                    raise

                self.logger.warning(
                    "Request Retry: Integration: {}: Retry Candidate".format(base_class_name(error_exception)),
                    extra=tmv_ex_extra
                )

                if not _tries:
                    self.logger.error(
                        "Request Retry: Integration: {}: Exhausted Retries".format(base_class_name(error_exception))
                    )
                    raise

            except Exception as ex:
                error_exception = ex
                ex_extra = {
                    'error_exception': base_class_name(error_exception),
                    'error_details': get_exception_message(error_exception),
                    'request_url': request_url,
                    'request_label': request_label
                }

                if not request_retry_excps_func or \
                        not request_retry_excps_func(error_exception, request_label):
                    self.logger.error(
                        "Request Retry: Unexpected: {}: Not Retry Candidate".format(base_class_name(error_exception)),
                        extra=ex_extra
                    )
                    raise

                self.logger.warning(
                    "Request Retry: Unexpected: {}: Retry Candidate".format(base_class_name(error_exception)),
                    extra=ex_extra
                )

                if not _tries:
                    raise TuneRequestError(
                        error_message="Unexpected: {}".format(base_class_name(error_exception)),
                        errors=error_exception,
                        error_request_curl=self.built_request_curl,
                        exit_code=TuneIntegrationExitCode.MOD_ERR_RETRY_EXHAUSTED
                    )

            if not _tries:
                self.logger.error(
                    "Request Retry: Exhausted Retries",
                    extra={
                        'attempts': _attempts,
                        'tries': _tries,
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                raise TuneRequestError(
                    error_message=("Request Retry: Exhausted Retries: {}: {}").format(request_label, request_url),
                    error_request_curl=self.built_request_curl,
                    exit_code=TuneIntegrationExitCode.MOD_ERR_RETRY_EXHAUSTED
                )

            self.logger.info(
                "Request Retry: Performing Retry",
                extra={
                    'tries': _tries,
                    'delay': _delay,
                    'timeout': _timeout,
                    'request_url': request_url,
                    'request_label': request_label
                }
            )

            time.sleep(_delay)

            if retry_backoff and retry_backoff > 0:
                _delay *= retry_backoff

            if retry_jitter and retry_jitter > 0:
                _delay += retry_jitter

            if retry_max_delay is not None:
                _delay = min(_delay, retry_max_delay)

    # Request Data
    #
    def _request(
        self,
        request_method,
        request_url,
        request_params=None,
        request_data=None,
        request_json=None,
        request_headers=None,
        request_auth=None,
        cookie_payload=None,
        request_label=None,
        timeout=60,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        stream=False
    ):
        """Constructs and sends a :class:`Request <Request>`.

        Args:
            request_method: request_method for the new :class:`Request` object.
            logger: logging instance
            request_url: URL for the new :class:`Request` object.
            request_params: (optional) Dictionary or bytes to be sent in the
                query string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_json: (optional) json data to send in the body of
                the :class:`Request`.
            request_headers: (optional) Dictionary of HTTP Headers to send
                with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable Basic/Digest/Custom HTTP Auth.
            timeout: (optional) How long to wait for the server to send data
                before giving up.
            allow_redirects: (optional) Boolean. Set to True if POST/PUT/DELETE
                redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            stream: (optional) if ``False``, the response content will be
                immediately downloaded.

        Returns:
            requests.Response

        """
        if not self.tune_request:
            self.tune_request = TuneRequest(
                retry_tries=self.retry_tries,
                retry_backoff=self.retry_backoff,
                retry_codes=self.request_retry_http_status_codes
            )

        if not request_method:
            raise ModuleArgumentError(error_message="Parameter 'request_method' not defined")
        if not request_url:
            raise TuneRequestError(error_message="Parameter 'request_url' not defined")

        self.built_request_curl = None

        self.logger.debug(
            "Session: Details",
            extra={'cookie_payload': self.tune_request.session.cookies.get_dict(),
                   'request_label': request_label}
        )

        response = None
        headers = None

        if request_headers:
            headers = request_headers

        request_method = request_method.upper()

        if request_data and isinstance(request_data, str):
            if len(request_data) <= 20:
                request_data_extra = request_data
            else:
                request_data_extra = request_data[:20] + ' ...'
        else:
            request_data_extra = safe_str(request_data)

        request_extra = {
            'request_method': request_method,
            'request_url': request_url,
            'timeout': timeout,
            'request_params': safe_dict(request_params),
            'request_data': request_data_extra,
            'request_headers': safe_dict(headers),
            'request_label': request_label
        }

        self.logger.debug("Send Request: Details: {}".format(request_label), extra=request_extra)

        self.built_request_curl = None

        kwargs = {}
        if headers:
            kwargs.update({'headers': headers})

        if request_auth:
            kwargs.update({'auth': request_auth})

        if timeout:
            kwargs.update({'timeout': (timeout, timeout)})

        if allow_redirects:
            kwargs.update({'allow_redirects': allow_redirects})

        if stream:
            kwargs.update({'stream': stream})

        if cookie_payload:
            kwargs.update({'cookies': cookie_payload})

        kwargs.update({'verify': verify})

        try:
            if request_method == 'GET':
                request_params_encoded = None
                if request_params:
                    request_params_encoded = \
                        urllib.parse.urlencode(request_params)

                if build_request_curl:
                    self.built_request_curl = command_line_request_curl(
                        request_method=request_method,
                        request_url=request_url,
                        request_headers=headers,
                        request_data=request_params_encoded,
                        request_timeout=timeout,
                        request_allow_redirects=allow_redirects
                    )

                    self.logger.debug(
                        "Send Request: Request Base: GET",
                        extra={
                            'request_label': request_label,
                            'request_method': request_method,
                            'request_curl': self.built_request_curl
                        }
                    )

                if request_params_encoded:
                    kwargs.update({'params': request_params_encoded})

                kwargs.update({'request_method': 'GET', 'request_url': request_url})

                response = self.tune_request.request(**kwargs)

            elif request_method == 'POST':
                if request_params:
                    request_url += "?" + urllib.parse.urlencode(request_params)

                if build_request_curl:
                    self.built_request_curl = command_line_request_curl(
                        request_method=request_method,
                        request_url=request_url,
                        request_headers=headers,
                        request_data=request_data,
                        request_json=request_json,
                        request_timeout=timeout,
                        request_allow_redirects=allow_redirects
                    )

                    self.logger.debug(
                        "Send Request: Request Base: POST",
                        extra={
                            'request_label': request_label,
                            'request_method': request_method,
                            'request_curl': self.built_request_curl
                        }
                    )

                if request_data:
                    kwargs.update({'data': request_data})
                if request_json:
                    kwargs.update({'json': request_json})

                kwargs.update({'request_method': 'POST', 'request_url': request_url})

                response = self.tune_request.request(**kwargs)

            elif request_method == 'PUT':
                if request_params:
                    request_url += "?" + urllib.parse.urlencode(request_params)

                if build_request_curl:
                    self.built_request_curl = command_line_request_curl(
                        request_method=request_method,
                        request_url=request_url,
                        request_headers=headers,
                        request_data=request_data,
                        request_timeout=timeout,
                        request_allow_redirects=allow_redirects
                    )

                    self.logger.debug(
                        "Send Request: Request Base: PUT",
                        extra={'request_label': request_label,
                               'request_curl': self.built_request_curl}
                    )

                if request_data:
                    kwargs.update({'data': request_data})

                kwargs.update({'request_method': 'PUT', 'request_url': request_url})

                response = self.tune_request.request(**kwargs)

            elif request_method == 'HEAD':
                if request_params:
                    request_url += \
                        "?" + urllib.parse.urlencode(request_params)

                if headers:
                    kwargs.update({'headers': headers})

                kwargs.update({'request_method': 'HEAD', 'request_url': request_url})

                response = self.tune_request.request(**kwargs)

            else:
                raise ValueError("Request: Unexpected 'request_method':'{}'".format(request_method))

        except Exception as ex:
            self.logger.error(
                "Send Request: Request Base: Error",
                extra={
                    'request_label': request_label,
                    'error_exception': base_class_name(ex),
                    'error_details': get_exception_message(ex)
                }
            )
            raise

        if not response:
            self.logger.error("Failed to get response", extra={'request_curl': self.built_request_curl})
            raise TuneRequestError(
                error_message="Failed to get response",
                exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_VALUE,
                error_request_curl=self.built_request_curl
            )

        http_status_code = response.status_code
        response_headers = json.loads(json.dumps(dict(response.headers)))

        http_status_type = \
            http_status_code_to_type(http_status_code)
        http_status_desc = \
            http_status_code_to_desc(http_status_code)

        response_extra = {
            'request_label': request_label,
            'http_status_code': http_status_code,
            'http_status_type': http_status_type,
            'http_status_desc': http_status_desc,
            'response_headers': safe_dict(response_headers),
            'request_label': request_label
        }

        self.logger.debug("Send Request: Response: Details", extra=response_extra)

        http_status_successful = is_http_status_type(
            http_status_code=http_status_code, http_status_type=HttpStatusType.SUCCESSFUL
        )

        http_status_redirection = is_http_status_type(
            http_status_code=http_status_code, http_status_type=HttpStatusType.REDIRECTION
        )

        if http_status_successful or http_status_redirection:
            if hasattr(response, 'url') and \
                    response.url and \
                    len(response.url) > 0:
                response_extra.update({'response_url': response.url})

            self.logger.debug(
                "Send Request: Cookie Payload",
                extra={'cookie_payload': self.tune_request.session.cookies.get_dict(),
                       'request_label': request_label}
            )

            assert response
            return response
        else:
            response_extra.update({'error_request_curl': self.built_request_curl})

            self.logger.error("Send Request: Response: Failed", extra=response_extra)

            json_response_error = \
                self.build_response_error_details(
                    response=response,
                    request_label=request_label,
                    request_url=request_url
                )

            extra_error = copy.deepcopy(json_response_error)

            if self.logger_level == logging.INFO:
                error_response_details = \
                    extra_error.get('response_details', None)

                if error_response_details and \
                        isinstance(error_response_details, str) and \
                        len(error_response_details) > 100:
                    extra_error['response_details'] = \
                        error_response_details[:100] + ' ...'

            if self.built_request_curl and \
                    'error_request_curl' not in extra_error:
                extra_error.update({'error_request_curl': self.built_request_curl})

            self.logger.error("Send Request: Error: Response: Details", extra=extra_error)

            kwargs = {
                'error_status': json_response_error.get("response_status", None),
                'error_reason': json_response_error.get("response_reason", None),
                'error_details': json_response_error.get("response_details", None),
                'error_request_curl': self.built_request_curl
            }

            if http_status_code in [
                HttpStatusCode.BAD_REQUEST, HttpStatusCode.UNAUTHORIZED, HttpStatusCode.FORBIDDEN,
                HttpStatusCode.NOT_FOUND, HttpStatusCode.METHOD_NOT_ALLOWED, HttpStatusCode.NOT_ACCEPTABLE,
                HttpStatusCode.REQUEST_TIMEOUT, HttpStatusCode.CONFLICT, HttpStatusCode.GONE,
                HttpStatusCode.UNPROCESSABLE_ENTITY, HttpStatusCode.TOO_MANY_REQUESTS
            ]:
                kwargs.update({'exit_code': http_status_code})
                raise TuneRequestClientError(**kwargs)

            if http_status_code in [
                HttpStatusCode.INTERNAL_SERVER_ERROR, HttpStatusCode.NOT_IMPLEMENTED, HttpStatusCode.BAD_GATEWAY,
                HttpStatusCode.SERVICE_UNAVAILABLE, HttpStatusCode.NETWORK_AUTHENTICATION_REQUIRED
            ]:
                kwargs.update({'exit_code': http_status_code})
                raise TuneRequestServiceError(**kwargs)

            kwargs.update({'exit_code': json_response_error["response_status_code"]})

            extra_unhandled = copy.deepcopy(kwargs)
            extra_unhandled.update({'http_status_code': http_status_code})
            self.logger.error("Send Request: Error: Unhandled", extra=extra_unhandled)

            raise TuneRequestModuleError(**kwargs)

    def validate_response(self, response, request_label=None):
        """Validate response

        Args:
            response:
            request_label:
            request_url:

        Returns:

        """
        response_extra = {}
        if request_label:
            response_extra.update({'request_label': request_label})

        if not response:
            self.logger.error("Validate Response: Failed: None", extra=response_extra)

            raise TuneRequestModuleError(
                error_message="Validate Response: Failed: None",
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_SOFTWARE
            )
        else:
            self.logger.debug("Validate Response: Defined", extra=response_extra)

        response_extra.update({'http_status_code': response.status_code})

        if hasattr(response, 'text'):
            response_text_length = len(response.text)
            response_extra.update({'response_text_length': response_text_length})

        if response.headers:
            if 'Content-Type' in response.headers:
                response_headers_content_type = \
                    safe_str(response.headers['Content-Type'])
                response_extra.update({'Content-Type': response_headers_content_type})

            if 'Content-Length' in response.headers:
                response_headers_content_length = \
                    safe_int(response.headers['Content-Length'])
                response_extra.update({'Content-Length': convert_size(response_headers_content_length)})

            if 'Content-Encoding' in response.headers:
                response_content_encoding = \
                    safe_str(response.headers['Content-Encoding'])
                response_extra.update({'Content-Encoding': response_content_encoding})

            if 'Transfer-Encoding' in response.headers:
                response_transfer_encoding = \
                    safe_str(response.headers['Transfer-Encoding'])
                response_extra.update({'Transfer-Encoding': response_transfer_encoding})

        if not is_http_status_successful(http_status_code=response.status_code):
            self.logger.error("Validate Response: Failed", extra=response_extra)

            raise TuneRequestModuleError(
                error_message="Validate Request: Failed",
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_SOFTWARE
            )
        else:
            self.logger.debug("Validate Response: Success", extra=response_extra)

    def validate_json_response(
        self,
        response,
        request_label=None,
        response_content_type_expected='application/json',
        raise_ex_if_not_json_response=True
    ):
        """Validate JSON response.

        Args:
            response:
            request_label:
            response_content_type_expected:
            raise_ex_if_not_json_response:

        Returns:

        """
        self.validate_response(response, request_label)

        json_response = None
        response_extra = {}
        if request_label:
            response_extra.update({'request_label': request_label})

        response_extra.update({'Content-Type (Expected)': response_content_type_expected})

        if hasattr(response, 'headers'):
            response_content_type = response.headers.get('Content-Type', None)

        if response_content_type is not None:
            is_valid_response_content_type = \
                response_content_type == response_content_type_expected or \
                response_content_type.startswith(response_content_type_expected)

            if is_valid_response_content_type:
                json_response = self.requests_response_json(response=response, request_label=request_label)
            elif response_content_type.startswith('text/html'):
                try:
                    response_content_html_lines = \
                        requests_response_text_html(
                            response=response
                        )
                except Exception as ex:
                    raise TuneRequestModuleError(
                        error_message=request_label,
                        errors=ex,
                        error_request_curl=self.built_request_curl,
                        exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
                    )

                raise TuneRequestModuleError(
                    error_message="Unexpected 'Content-Type': '{}', Expected: '{}'".format(
                        response_content_type, response_content_type_expected
                    ),
                    errors=response_content_html_lines,
                    error_request_curl=self.built_request_curl,
                    exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
                )
            else:
                raise TuneRequestModuleError(
                    error_message="Unexpected 'Content-Type': '{}', Expected: '{}'".format(
                        response_content_type, response_content_type_expected
                    ),
                    error_request_curl=self.built_request_curl,
                    exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
                )
        else:
            raise TuneRequestModuleError(
                error_message="Undefined 'Content-Type'",
                error_request_curl=self.built_request_curl,
                exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
            )

        response_extra.update({
            'http_status_code': response.status_code,
            'raise_ex_if_not_json_response': raise_ex_if_not_json_response
        })

        self.logger.debug("Validate JSON Response: Details", extra=response_extra)

        return json_response

    def requests_response_json(self, response, request_label=None, raise_ex_if_not_json_response=True):
        """Get JSON from response from requests

        Args:
            response:
            request_label:

        Returns:

        """
        json_response = None
        response_extra = {}
        if request_label:
            response_extra.update({'request_label': request_label})

        try:
            json_response = response.json()
            response_details_source = 'json'
            response_content_length = len(json_response)

            response_extra.update({
                'response_details_source': response_details_source,
                'response_content_length': response_content_length
            })
        except json.decoder.JSONDecodeError as json_decode_ex:
            self.logger.error("Validate JSON Response: Failed: JSONDecodeError", extra=response_extra)

            data = requests_toolbelt.utils.dump.dump_all(response)
            pprint(data.decode('utf-8'))

            pprint(response.text)

            self.handle_json_decode_error(
                response_decode_ex=json_decode_ex,
                response=response,
                response_extra=response_extra,
                request_label=request_label,
                request_curl=self.built_request_curl
            )

        except Exception as ex:
            self.logger.error("Validate JSON Response: Failed: Exception", extra=response_extra)

            pprint(response.text)

            self.handle_json_decode_error(
                response_decode_ex=ex,
                response=response,
                response_extra=response_extra,
                request_label=request_label,
                request_curl=self.built_request_curl
            )

        if json_response is None:
            if raise_ex_if_not_json_response:
                self.logger.error("Validate JSON Response: Failed: None", extra=response_extra)

                raise TuneRequestModuleError(
                    error_message="Validate JSON Response: Failed: None",
                    error_request_curl=self.built_request_curl,
                    exit_code=TuneIntegrationExitCode.MOD_ERR_SOFTWARE
                )
            else:
                self.logger.warning("Validate JSON Response: None", extra=response_extra)
        else:
            self.logger.debug("Validate JSON Response: Valid", extra=response_extra)

        return json_response

    @staticmethod
    def build_response_error_details(request_label, request_url, response):
        """Build gather status of Requests' response.

        Args:
            request_url:
            response:
            response_verbose:

        Returns:

        """
        http_status_code = \
            response.status_code
        http_status_type = \
            http_status_code_to_type(http_status_code)
        http_status_desc = \
            http_status_code_to_desc(http_status_code)

        response_status = "{}: {}: {}".format(http_status_code, http_status_type, http_status_desc)

        response_error_details = {
            'request_url': request_url,
            'request_label': request_label,
            'response_status': response_status,
            'response_status_code': http_status_code,
            'response_status_type': http_status_type,
            'response_status_desc': http_status_desc
        }

        if response.headers:
            if 'Content-Type' in response.headers:
                response_headers_content_type = \
                    safe_str(response.headers['Content-Type'])
                response_error_details.update({'Content-Type': response_headers_content_type})

            if 'Content-Length' in response.headers and \
                    response.headers['Content-Length']:
                response_headers_content_length = \
                    safe_int(response.headers['Content-Length'])
                response_error_details.update({'Content-Length': response_headers_content_length})

            if 'Transfer-Encoding' in response.headers and \
                    response.headers['Transfer-Encoding']:
                response_headers_transfer_encoding = \
                    safe_str(response.headers['Transfer-Encoding'])
                response_error_details.update({'Transfer-Encoding': response_headers_transfer_encoding})

            if 'Content-Encoding' in response.headers and \
                    response.headers['Content-Encoding']:
                response_headers_content_encoding = \
                    safe_str(response.headers['Content-Encoding'])
                response_error_details.update({'Content-Encoding': response_headers_content_encoding})

        if hasattr(response, "reason") and response.reason:
            response_error_details.update({'response_reason': response.reason})

        response_details = None
        response_details_source = None

        try:
            response_details = response.json()
            response_details_source = 'json'
        except Exception:
            if hasattr(response, 'text') and \
                    response.text and \
                    len(response.text) > 0:
                response_details = response.text
                response_details_source = 'text'

                if response_details.startswith('<html'):
                    response_details_source = 'html'
                    soup_html = bs4.BeautifulSoup(response_details, "html.parser")
                    # kill all script and style elements
                    for script in soup_html(["script", "style"]):
                        script.extract()  # rip it out
                    text_html = soup_html.get_text()
                    lines_html = [line for line in text_html.split('\n') if line.strip() != '']
                    lines_html = [line.strip(' ') for line in lines_html]
                    response_details = lines_html

                elif response_details.startswith('<?xml'):
                    response_details_source = 'xml'
                    response_details = json.dumps(xmltodict.parse(response_details))

        response_error_details.update({
            'response_details': response_details,
            'response_details_source': response_details_source
        })

        # pprint(response_error_details)

        return response_error_details

    @staticmethod
    def handle_json_decode_error(
        self, response_decode_ex, response, response_extra=None, request_label=None, request_curl=None
    ):
        """Handle JSON Decode Error

        Args:
            response_json_decode_error:
            response:
            response_extra:
            request_label:

        Returns:

        """
        if response_extra is None:
            response_extra = {}

        if request_label:
            response_extra.update({'request_label': request_label})

        if hasattr(response, 'text') and \
                response.text and \
                len(response.text) > 0:
            response_details = response.text
            response_details_source = 'text'
            response_content_length = len(response_details)

            if response_details.startswith('<html'):
                response_details_source = 'html'
                soup_html = bs4.BeautifulSoup(response_details, "html.parser")
                # kill all script and style elements
                for script in soup_html(["script", "style"]):
                    script.extract()  # rip it out
                text_html = soup_html.get_text()
                lines_html = [line for line in text_html.split('\n') if line.strip() != '']
                lines_html = [line.strip(' ') for line in lines_html]
                response_details = lines_html

            elif response_details.startswith('<?xml'):
                response_details_source = 'xml'
                response_details = json.dumps(xmltodict.parse(response_details))
            else:
                pprint(response_details)

            response_extra.update({
                'response_details': response_details,
                'response_details_source': response_details_source,
                'response_content_length': response_content_length,
                'error_exception': base_class_name(response_decode_ex),
                'error_details': get_exception_message(response_decode_ex)
            })

        self.logger.error("Validate JSON Response: Failed: Invalid", extra=response_extra)

        raise TuneRequestModuleError(
            error_message="Validate JSON Response: Failed: Invalid",
            errors=response_decode_ex,
            error_request_curl=request_curl,
            exit_code=TuneIntegrationExitCode.MOD_ERR_SOFTWARE
        )

    def request_csv_download(
        self,
        request_method,
        request_url,
        tmp_csv_file_name,
        tmp_directory='./tmp',
        request_params=None,
        request_data=None,
        request_retry=None,
        request_retry_func=None,
        request_retry_excps=None,
        request_retry_http_status_codes=None,
        request_retry_excps_func=None,
        request_headers=None,
        request_auth=None,
        request_label=None,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        skip_first_row=False,
        skip_last_row=False,
        read_first_row=False,
        csv_delimiter=',',
        csv_header=None,
        encoding_write=None,
        encoding_read=None,
        decode_unicode=False
    ):
        """Download and Read CSV file.

        Args:
            request_method: request_method for the new :class:`Request` object.
            request_url: URL for the new :class:`Request` object.
            tmp_csv_file_name: Provide temporary name for downloaded CSV
            tmp_directory: Provide temporary directory to hold downloaded CSV
            request_params: (optional) Dictionary or bytes to be sent in the query
                string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_retry: (optional) Retry configuration.
            request_headers: (optional) Dictionary of HTTP Headers to
                send with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable
                Basic/Digest/Custom HTTP Auth.
            allow_redirects: (optional) Boolean. Set to True if
                POST/PUT/DELETE redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            skip_first_row: (optional) Skip first row if it does not contain
                column headers.
            skip_last_row: (optional) Skip first row if it does not contain
                column values.
            read_first_row: (optional) Read first row separate from data returned.
            csv_delimiter: (optional) Delimiter character, default comma ','.
            csv_header:
            encoding_write:
            encoding_read:
            decode_unicode:

        Returns:
            Generator containing CSV data by rows in JSON dictionary format.

        """
        self.logger.info(
            "Request CSV Download: Start",
            extra={
                'request_url': request_url,
                'encoding_write': encoding_write,
                'encoding_read': encoding_read,
                'request_label': request_label
            }
        )

        timer_start = dt.datetime.now()

        _attempts = 0
        _tries = 60
        _delay = 10

        while _tries:
            _attempts += 1

            self.logger.info(
                "Request CSV Download: Attempt: {}".format(_attempts),
                extra={'request_url': request_url,
                       'request_label': request_label}
            )

            response = self.request(
                request_method=request_method,
                request_url=request_url,
                request_params=request_params,
                request_data=request_data,
                request_retry=request_retry,
                request_retry_func=request_retry_func,
                request_retry_excps=request_retry_excps,
                request_retry_http_status_codes=request_retry_http_status_codes,
                request_retry_excps_func=request_retry_excps_func,
                request_headers=request_headers,
                request_auth=request_auth,
                build_request_curl=build_request_curl,
                allow_redirects=allow_redirects,
                verify=verify,
                stream=True,
                request_label=request_label
            )

            if response is None:
                self.logger.error(
                    "Request CSV Download: No response",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

                raise TuneRequestModuleError(
                    error_message="Request CSV Download: No response",
                    exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST
                )

            http_status_code = response.status_code

            timer_end = dt.datetime.now()
            timer_delta = timer_end - timer_start
            response_time_secs = timer_delta.seconds
            response_headers = None

            if hasattr(response, 'headers'):
                response_headers = \
                    json.loads(
                        json.dumps(
                            dict(response.headers)
                        )
                    )

            self.logger.debug(
                "Request CSV Download: Response Status",
                extra={
                    'http_status_code': http_status_code,
                    'response_time_secs': response_time_secs,
                    'response_url': response.url,
                    'response_headers': safe_dict(response_headers),
                    'request_label': request_label
                }
            )

            (tmp_csv_file_path, tmp_csv_file_size) = self.download_csv(
                response,
                tmp_directory,
                tmp_csv_file_name,
                request_label=request_label,
                encoding_write=encoding_write,
                decode_unicode=decode_unicode
            )

            if tmp_csv_file_path is not None:
                break

            _tries -= 1
            if not _tries:
                self.logger.error(
                    "Request CSV Download: Exhausted Retries",
                    extra={'tries': _tries,
                           'request_url': request_url,
                           'request_label': request_label}
                )

                raise TuneRequestModuleError(
                    error_message="Request CSV Download: Exhausted Retries",
                    exit_code=TuneIntegrationExitCode.MOD_ERR_RETRY_EXHAUSTED
                )

            self.logger.info(
                "Request CSV Download: Performing Retry",
                extra={'tries': _tries,
                       'delay': _delay,
                       'request_url': request_url,
                       'request_label': request_label}
            )

            time.sleep(_delay)

        self.logger.info(
            "Request CSV Download: Downloaded",
            extra={
                'request_label': request_label,
                'file_path': tmp_csv_file_path,
                'file_size': convert_size(tmp_csv_file_size),
                'encoding_read': encoding_read
            }
        )

        with open(file=tmp_csv_file_path, mode='r', encoding=encoding_read) as csv_file_r:
            if read_first_row:
                csv_report_name = csv_file_r.readline()
                csv_report_name = re.sub('\"', '', csv_report_name)
                csv_report_name = re.sub('\n', '', csv_report_name)
                self.logger.info("Request CSV Download: Report '{}'".format(csv_report_name))
            elif skip_first_row:
                next(csv_file_r)

            csv_file_header = next(csv_file_r)
            csv_header_actual = \
                [h.strip() for h in csv_file_header.split(csv_delimiter)]

            csv_header_hr = []
            index = 0
            for column_name in csv_header_actual:
                csv_header_hr.append({'index': index, 'name': column_name})
                index += 1

            self.logger.info("Request CSV Download: Content Header", extra={'csv_header': csv_header_hr})

            csv_fieldnames = csv_header if csv_header else csv_header_actual

            csv_dict_reader = csv.DictReader(csv_file_r, fieldnames=csv_fieldnames, delimiter=csv_delimiter)

            if skip_last_row:
                for row in self._skip_last_row(csv_dict_reader):
                    yield row
            else:
                for row in csv_dict_reader:
                    yield row

    def request_json_download(
        self,
        request_method,
        request_url,
        tmp_json_file_name,
        tmp_directory='./tmp',
        request_params=None,
        request_data=None,
        request_retry=None,
        request_retry_func=None,
        request_retry_excps=None,
        request_retry_excps_func=None,
        request_headers=None,
        request_auth=None,
        request_label=None,
        build_request_curl=False,
        allow_redirects=True,
        verify=True,
        encoding_write=None,
        encoding_read=None
    ):
        """Download and Read JSON file.

        Args:
            request_method: request_method for the new :class:`Request` object.
            request_url: URL for the new :class:`Request` object.
            tmp_json_file_name: Provide temporary name for downloaded CSV
            tmp_directory: Provide temporary directory to hold downloaded CSV
            request_params: (optional) Dictionary or bytes to be sent in the query
                string for the :class:`Request`.
            request_data: (optional) Dictionary, bytes, or file-like object to
                send in the body of the :class:`Request`.
            request_retry: (optional) Retry configuration.
            request_headers: (optional) Dictionary of HTTP Headers to
                send with the :class:`Request`.
            request_auth: (optional) Auth tuple to enable
                Basic/Digest/Custom HTTP Auth.
            build_request_curl: (optional) Build a copy-n-paste curl for command line
                that provides same request as this call.
            allow_redirects: (optional) Boolean. Set to True if
                POST/PUT/DELETE redirect following is allowed.
            verify: (optional) whether the SSL cert will be verified. A
                CA_BUNDLE path can also be provided. Defaults to ``True``.
            encoding_write:
            encoding_read:
            decode_unicode:

        Returns:
            Generator containing JSON data by rows in JSON dictionary format.

        """
        self.logger.debug(
            "Request JSON Download",
            extra={
                'request_url': request_url,
                'encoding_write': encoding_write,
                'encoding_read': encoding_read,
                'request_label': request_label
            }
        )

        timer_start = dt.datetime.now()

        _attempts = 0
        _tries = 60
        _delay = 10

        while _tries:
            _attempts += 1

            self.logger.info(
                "Request JSON Download",
                extra={'attempts': _attempts,
                       'request_url': request_url,
                       'request_label': request_label}
            )

            response = self.request(
                request_method=request_method,
                request_url=request_url,
                request_params=request_params,
                request_data=request_data,
                request_retry=request_retry,
                request_retry_func=request_retry_func,
                request_retry_excps=request_retry_excps,
                request_retry_excps_func=request_retry_excps_func,
                request_headers=request_headers,
                request_auth=request_auth,
                build_request_curl=build_request_curl,
                allow_redirects=allow_redirects,
                verify=verify,
                stream=True,
                request_label=request_label
            )

            if response is None:
                self.logger.error(
                    "Request JSON Download: No response",
                    extra={'request_url': request_url,
                           'request_label': request_label}
                )

                raise TuneRequestModuleError(
                    error_message="Request JSON Download: No response",
                    exit_code=TuneIntegrationExitCode.MOD_ERR_REQUEST
                )

            http_status_code = response.status_code

            timer_end = dt.datetime.now()
            timer_delta = timer_end - timer_start
            response_time_secs = timer_delta.seconds
            response_headers = None

            if hasattr(response, 'headers'):
                response_headers = \
                    json.loads(
                        json.dumps(
                            dict(response.headers)
                        )
                    )

            self.logger.debug(
                "Request JSON Download: Response Status",
                extra={
                    'http_status_code': http_status_code,
                    'response_time_secs': response_time_secs,
                    'response_url': response.url,
                    'response_headers': safe_dict(response_headers),
                    'request_label': request_label
                }
            )

            if not os.path.exists(tmp_directory):
                os.mkdir(tmp_directory)

            tmp_json_file_path = \
                "{tmp_directory}/{tmp_json_file_name}".format(
                    tmp_directory=tmp_directory,
                    tmp_json_file_name=tmp_json_file_name
                )

            if os.path.exists(tmp_json_file_path):
                self.logger.debug("Request JSON Download: Removing", extra={'file_path': tmp_json_file_path})
                os.remove(tmp_json_file_path)

            mode_write = 'wb' if encoding_write is None else 'w'

            self.logger.debug(
                "Request JSON Download: Download Raw",
                extra={
                    'file_path': tmp_json_file_path,
                    'mode_write': mode_write,
                    'encoding_write': encoding_write,
                    'request_label': request_label
                }
            )

            chunk_total_sum = 0

            with open(file=tmp_json_file_path, mode=mode_write, encoding=encoding_write) as json_raw_file_w:
                self.logger.debug(
                    "Request JSON Download: Response Raw: Started",
                    extra={'file_path': tmp_json_file_path,
                           'request_label': request_label}
                )

                _tries -= 1
                error_exception = None
                error_details = None
                chunk_size = 8192
                try:
                    raw_response = response.raw
                    while True:
                        chunk = raw_response.read(chunk_size, decode_content=True)
                        if not chunk:
                            break

                        chunk_total_sum += chunk_size

                        json_raw_file_w.write(chunk)
                        json_raw_file_w.flush()
                        os.fsync(json_raw_file_w.fileno())

                    self.logger.debug(
                        "Request JSON Download: By Chunk: Completed",
                        extra={'file_path': tmp_json_file_path,
                               'request_label': request_label}
                    )

                    break

                except requests.exceptions.ChunkedEncodingError as chunked_encoding_ex:
                    error_exception = base_class_name(chunked_encoding_ex)
                    error_details = get_exception_message(chunked_encoding_ex)

                    self.logger.warning(
                        "Request JSON Download: {}".format(error_exception),
                        extra={
                            'error_details': error_details,
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )

                    if not _tries:
                        self.logger.error("Request JSON Download: {}: Exhausted Retries".format(error_exception))
                        raise

                except http_client.IncompleteRead as incomplete_read_ex:
                    error_exception = base_class_name(incomplete_read_ex)
                    error_details = get_exception_message(incomplete_read_ex)

                    self.logger.warning(
                        "Request JSON Download: IncompleteRead",
                        extra={
                            'error_exception': error_exception,
                            'error_details': error_details,
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )

                    if not _tries:
                        self.logger.error("Request JSON Download: {}: Exhausted Retries".format(error_exception))
                        raise

                except requests.exceptions.RequestException as request_ex:
                    self.logger.error(
                        "Request JSON Download: Request Exception",
                        extra={
                            'error_exception': base_class_name(request_ex),
                            'error_details': get_exception_message(request_ex),
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )
                    raise

                except Exception as ex:
                    self.logger.error(
                        "Request JSON Download: Unexpected Exception",
                        extra={
                            'error_exception': base_class_name(ex),
                            'error_details': get_exception_message(ex),
                            'chunk_total_sum': chunk_total_sum,
                            'request_label': request_label
                        }
                    )
                    raise

                if not _tries:
                    self.logger.error(
                        "Request JSON Download: Exhausted Retries",
                        extra={'tries': _tries,
                               'request_url': request_url,
                               'request_label': request_label}
                    )

                    raise TuneRequestModuleError(
                        error_message=("Request JSON Download: Exhausted Retries: {}: {}").format(
                            request_label, request_url
                        ),
                        error_request_curl=self.built_request_curl,
                        exit_code=TuneIntegrationExitCode.MOD_ERR_RETRY_EXHAUSTED
                    )

                self.logger.info(
                    "Request JSON Download: Performing Retry",
                    extra={
                        'tries': _tries,
                        'delay': _delay,
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                time.sleep(_delay)

        tmp_json_file_size = os.path.getsize(tmp_json_file_path)
        bom_enc, bom_len, bom_header = detect_bom(tmp_json_file_path)

        self.logger.info(
            "Request JSON Download: By Chunk: Completed: Details",
            extra={
                'file_path': tmp_json_file_path,
                'file_size': convert_size(tmp_json_file_size),
                'chunk_total_sum': chunk_total_sum,
                'bom_encoding': bom_enc
            }
        )

        if bom_enc == 'gzip':
            tmp_json_gz_file_path = "{}.gz".format(tmp_json_file_path)

            os.rename(src=tmp_json_file_path, dst=tmp_json_gz_file_path)

            with open(file=tmp_json_file_path, mode=mode_write, encoding=encoding_write) as json_file_w:
                self.logger.debug(
                    "Request JSON Download: GZip: Started",
                    extra={'file_path': tmp_json_file_path,
                           'request_label': request_label}
                )

                with gzip.open(tmp_json_gz_file_path, 'r') as gzip_file_r:
                    json_file_w.write(gzip_file_r.read())

        response_extra = {
            'file_path': tmp_json_file_path,
            'file_size': convert_size(tmp_json_file_size),
            'request_label': request_label
        }

        self.logger.info("Request JSON Download: Read Downloaded", extra=response_extra)

        json_download = None
        with open(tmp_json_file_path, mode='r') as json_file_r:
            json_file_content = json_file_r.read()
            try:
                json_download = json.loads(json_file_content)
            except json.decoder.JSONDecodeError as json_decode_ex:
                pprint(json_file_content)

                response_extra.update({
                    'json_file_content': json_file_content,
                    'json_file_content_len': len(json_file_content)
                })

                self.handle_json_decode_error(
                    response_decode_ex=json_decode_ex,
                    response=response,
                    response_extra=response_extra,
                    request_label=request_label,
                    request_curl=self.built_request_curl
                )

            except Exception as ex:
                pprint(json_file_content)

                response_extra.update({
                    'json_file_content': json_file_content,
                    'json_file_content_len': len(json_file_content)
                })

                self.logger.error("Request JSON Download: Failed: Exception", extra=response_extra)

                self.handle_json_decode_error(
                    response_decode_ex=ex,
                    response=response,
                    response_extra=response_extra,
                    request_label=request_label,
                    request_curl=self.built_request_curl
                )

        response_extra.update({'json_file_content_len': len(json_download)})

        self.logger.info("Request JSON Download: Finished", extra=response_extra)

        return json_download

    def download_csv(
        self, response, tmp_directory, tmp_csv_file_name, request_label=None, encoding_write=None, decode_unicode=False
    ):
        self.logger.debug("Download CSV: Start")

        if not os.path.exists(tmp_directory):
            os.mkdir(tmp_directory)

        tmp_csv_file_path = \
            "{tmp_directory}/{tmp_csv_file_name}".format(
                tmp_directory=tmp_directory,
                tmp_csv_file_name=tmp_csv_file_name
            )

        if os.path.exists(tmp_csv_file_path):
            self.logger.debug("Removing previous CSV", extra={'file_path': tmp_csv_file_path})
            os.remove(tmp_csv_file_path)

        mode_write = 'wb' if encoding_write is None else 'w'

        self.logger.debug(
            "Download CSV: Details",
            extra={
                'file_path': tmp_csv_file_path,
                'mode_write': mode_write,
                'encoding_write': encoding_write,
                'request_label': request_label
            }
        )

        chunk_total_sum = 0

        with open(file=tmp_csv_file_path, mode=mode_write, encoding=encoding_write) as csv_file_wb:
            self.logger.debug(
                "Download CSV: By Chunk: Started",
                extra={'file_path': tmp_csv_file_path,
                       'request_label': request_label}
            )

            error_exception = None
            error_details = None

            try:
                for chunk in response.iter_content(chunk_size=8192, decode_unicode=decode_unicode):
                    if not chunk:
                        break

                    chunk_total_sum += 8192

                    csv_file_wb.write(chunk)
                    csv_file_wb.flush()
                    os.fsync(csv_file_wb.fileno())

                self.logger.debug(
                    "Download CSV: By Chunk: Completed",
                    extra={'file_path': tmp_csv_file_path,
                           'request_label': request_label}
                )

            except requests.exceptions.ChunkedEncodingError as chunked_encoding_ex:
                error_exception = base_class_name(chunked_encoding_ex)
                error_details = get_exception_message(chunked_encoding_ex)

                self.logger.warning(
                    "Download CSV: ChunkedEncodingError",
                    extra={
                        'error_exception': error_exception,
                        'error_details': error_details,
                        'chunk_total_sum': convert_size(chunk_total_sum),
                        'request_label': request_label
                    }
                )

                return (None, 0)

            except http_client.IncompleteRead as incomplete_read_ex:
                error_exception = base_class_name(incomplete_read_ex)
                error_details = get_exception_message(incomplete_read_ex)

                self.logger.warning(
                    "Download CSV: IncompleteRead",
                    extra={
                        'error_exception': error_exception,
                        'error_details': error_details,
                        'chunk_total_sum': convert_size(chunk_total_sum),
                        'request_label': request_label
                    }
                )

                return (None, 0)

            except requests.exceptions.RequestException as request_ex:
                self.logger.error(
                    "Download CSV: Request Exception",
                    extra={
                        'error_exception': base_class_name(request_ex),
                        'error_details': get_exception_message(request_ex),
                        'chunk_total_sum': convert_size(chunk_total_sum),
                        'request_label': request_label
                    }
                )
                raise

            except Exception as ex:
                self.logger.error(
                    "Download CSV: Unexpected Exception",
                    extra={
                        'error_exception': base_class_name(ex),
                        'error_details': get_exception_message(ex),
                        'chunk_total_sum': convert_size(chunk_total_sum),
                        'request_label': request_label
                    }
                )
                raise

        tmp_csv_file_size = os.path.getsize(tmp_csv_file_path)
        bom_enc, bom_len, bom_header = detect_bom(tmp_csv_file_path)

        self.logger.debug(
            "Download CSV: By Chunk: Completed: Details",
            extra={
                'file_path': tmp_csv_file_path,
                'file_size': convert_size(tmp_csv_file_size),
                'chunk_total_sum': convert_size(chunk_total_sum),
                'bom_encoding': bom_enc
            }
        )

        tmp_csv_file_name_wo_ext = \
            os.path.splitext(
                os.path.basename(tmp_csv_file_name)
            )[0]

        tmp_csv_file_path_wo_bom = \
            "{tmp_directory}/{tmp_csv_file_name}_wo_bom.csv".format(
                tmp_directory=tmp_directory,
                tmp_csv_file_name=tmp_csv_file_name_wo_ext
            )

        if os.path.exists(tmp_csv_file_path_wo_bom):
            os.remove(tmp_csv_file_path_wo_bom)

        bom_enc, bom_len = remove_bom(tmp_csv_file_path, tmp_csv_file_path_wo_bom)

        self.logger.debug("Download CSV: Encoding", extra={'bom_enc': bom_enc, 'bom_len': bom_len})

        if bom_len > 0:
            tmp_csv_file_path = tmp_csv_file_path_wo_bom

        return (tmp_csv_file_path, tmp_csv_file_size)

    def stream_csv(
        self,
        request_url,
        request_params,
        csv_delimiter=',',
        request_retry=None,
        request_headers=None,
        chunk_size=1024,
        decode_unicode=False,
        remove_bom_length=0
    ):
        """Stream CSV and Yield JSON

        Args:
            request_url:
            request_params:
            csv_delimiter:
            request_retry:
            request_headers:
            chunk_size:
            decode_unicode:
            remove_bom_length:

        Returns:

        """
        self.logger.info("Stream CSV: Start", extra={'report_url': request_url})

        response = self.request(
            request_method="GET",
            request_url=request_url,
            request_params=request_params,
            request_retry=request_retry,
            request_headers=request_headers,
            stream=True,
            request_label="Stream CSV"
        )

        self.logger.info(
            "Stream CSV: Response",
            extra={
                'response_status_code': response.status_code,
                'response_headers': response.headers,
                'report_url': request_url
            }
        )

        self.validate_response(response=response, request_label="Stream CSV")

        response_content_type = response.headers.get('Content-Type', None)
        response_transfer_encoding = response.headers.get('Transfer-Encoding', None)
        response_http_status_code = response.status_code

        self.logger.debug(
            "Stream CSV: Status: Details",
            extra={
                'response_content_type': response_content_type,
                'response_transfer_encoding': response_transfer_encoding,
                'response_http_status_code': response_http_status_code
            }
        )

        line_count = 0
        csv_keys_str = None
        csv_keys_list = None
        csv_keys_list_len = None
        pre_str_line = None

        for str_line in response.iter_lines(chunk_size=chunk_size, decode_unicode=decode_unicode):

            if str_line:  # filter out keep-alive new chunks
                line_count += 1

                if line_count == 1:
                    if remove_bom_length > 0:
                        str_line = str_line[remove_bom_length:]
                    csv_keys_str = str_line
                    csv_keys_list = csv_keys_str.split(csv_delimiter)
                    csv_keys_list = [csv_key.strip() for csv_key in csv_keys_list]
                    csv_keys_list_len = len(csv_keys_list)
                    continue

                if pre_str_line is not None:
                    str_line = pre_str_line + str_line
                    pre_str_line = None

                csv_values_str = str_line.replace('\n', ' ').replace('\r', ' ')

                csv_values_str_io = io.StringIO(csv_values_str)
                reader = csv.reader(csv_values_str_io, delimiter=csv_delimiter)
                csv_values_list = None
                for row in reader:
                    csv_values_list = row

                csv_values_list_len = len(csv_values_list)

                if csv_values_list_len < csv_keys_list_len:
                    pre_str_line = str_line
                    continue

                if csv_keys_list_len != csv_values_list_len:
                    self.logger.error(
                        "Mismatch: CSV Key",
                        extra={
                            'line': line_count,
                            'csv_keys_list_len': csv_keys_list_len,
                            'csv_keys_str': csv_keys_str,
                            'csv_keys_list': csv_keys_list,
                            'csv_values_list_len': csv_values_list_len,
                            'csv_values_str': csv_values_str,
                            'csv_values_list': csv_values_list,
                        }
                    )
                    raise TuneRequestModuleError(
                        error_message="Mismatch: CSV Key '{}': Values '{}'".format(csv_keys_str, csv_values_str),
                        exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_VALUE
                    )

                json_data_row = {}
                for idx, csv_key in enumerate(csv_keys_list):
                    csv_value = csv_values_list[idx]
                    json_data_row.update({csv_key: csv_value.strip('"')})

                yield json_data_row

    def download_csv_transform_to_json(self, response, tmp_directory, tmp_json_file_name, config_job):
        """Download CSV and Transform to JSON

        Args:
            response:
            tmp_directory:
            tmp_csv_file_name:
            request_label:

        Returns:

        """
        self.logger.debug("Download CSV Transform JSON: Start")

        if not os.path.exists(tmp_directory):
            os.mkdir(tmp_directory)

        tmp_json_file_path = \
            "{tmp_directory}/{tmp_json_file_name}".format(
                tmp_directory=tmp_directory,
                tmp_json_file_name=tmp_json_file_name
            )

        if os.path.exists(tmp_json_file_path):
            self.logger.debug("Removing previous JSON File", extra={'file_path': tmp_json_file_path})
            os.remove(tmp_json_file_path)

        line_count = 0
        csv_keys_str = None
        csv_keys_list = None
        csv_keys_list_len = None
        pre_str_line = None

        try:
            with open(file=tmp_json_file_path, mode='w') as dw_file_w:
                for bytes_line in response.iter_lines(chunk_size=4096):
                    if bytes_line:  # filter out keep-alive new chunks
                        line_count += 1
                        str_line = bytes_line.decode("utf-8")

                        if line_count == 1:
                            csv_keys_str = str_line
                            csv_keys_list = csv_keys_str.split(',')
                            csv_keys_list_len = len(csv_keys_list)
                            continue
                        elif line_count > 2:
                            dw_file_w.write('\n')

                        if pre_str_line is not None:
                            str_line = pre_str_line + str_line
                            pre_str_line = None

                        csv_values_str = str_line.replace('\n', ' ').replace('\r', ' ')
                        data = io.StringIO(csv_values_str)
                        reader = csv.reader(data, delimiter=',')
                        csv_values_list = None
                        for row in reader:
                            csv_values_list = row

                        csv_values_list_len = len(csv_values_list)

                        if csv_values_list_len < csv_keys_list_len:
                            pre_str_line = str_line
                            continue

                        if csv_keys_list_len != csv_values_list_len:
                            self.logger.error(
                                "Mismatch: CSV Key",
                                extra={
                                    'line': line_count,
                                    'csv_keys_list_len': csv_keys_list_len,
                                    'csv_keys_str': csv_keys_str,
                                    'csv_keys_list': csv_keys_list,
                                    'csv_values_list_len': csv_values_list_len,
                                    'csv_values_str': csv_values_str,
                                    'csv_values_list': csv_values_list,
                                }
                            )
                            raise TuneRequestModuleError(
                                error_message="Mismatch: CSV Key '{}': Values '{}'".format(
                                    csv_keys_str, csv_values_str
                                ),
                                exit_code=TuneIntegrationExitCode.MOD_ERR_UNEXPECTED_VALUE
                            )

                        json_dict = {}
                        for idx, csv_key in enumerate(csv_keys_list):
                            csv_value = csv_values_list[idx]
                            json_dict.update({csv_key: csv_value.strip('"')})

                        csv_row_mapped = self.map_data_row(data_row=json_dict, config_job=config_job)

                        json_str = json.dumps(csv_row_mapped)
                        dw_file_w.write(json_str)
                    dw_file_w.flush()

        except requests.exceptions.StreamConsumedError as request_ex:
            self.logger.error(
                "Download CSV Transform JSON: Stream Previously Consumed Exception",
                extra={
                    'error_exception': base_class_name(request_ex),
                    'error_details': get_exception_message(request_ex)
                }
            )
            raise

        except requests.exceptions.RequestException as request_ex:
            self.logger.error(
                "Download CSV Transform JSON: Request Exception",
                extra={
                    'error_exception': base_class_name(request_ex),
                    'error_details': get_exception_message(request_ex)
                }
            )
            raise

        except Exception as ex:
            self.logger.error(
                "Download CSV Transform JSON: Unexpected Exception",
                extra={'error_exception': base_class_name(ex),
                       'error_details': get_exception_message(ex)}
            )
            raise

        tmp_json_file_size = \
            os.path.getsize(tmp_json_file_path)

        return (tmp_json_file_path, tmp_json_file_size, line_count)

    @staticmethod
    def _skip_last_row(iterator):
        """Skip last CSV row.

        Args:
            iterator:

        Returns:

        """
        prev = next(iterator)
        for item in iterator:
            yield prev
            prev = item
