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
import datetime as dt
import json
import logging
import os
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
    base_class_name,
    python_check_version,
    requests_response_text_html,
    safe_dict,
    safe_int,
    safe_str,

    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES,

    __USER_AGENT__
)
from requests_mv_integrations import (
    __python_required_version__
)

from .tune_request import (
    TuneRequest
)

log = getLogger(__name__)

python_check_version(__python_required_version__)


# @brief Request with retry class for TUNE Multiverse classes
#
# @namespace requests_mv_integrations.TuneRequestMvIntegration
class TuneRequestMvIntegration(object):
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

    __session = None
    __built_request_curl = None

    @property
    def session(self):
        return self.__session

    @session.setter
    def session(self, value):
        self.__session = value

    @property
    def built_request_curl(self):
        return self.__built_request_curl

    @built_request_curl.setter
    def built_request_curl(self, value):
        self.__built_request_curl = value

    def __init__(
        self
    ):
        pass

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
        request_session=False,
        cookie_payload=None,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        stream=False,
        verbose=False,
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
            verbose: (optional) Boolean, provide request and response details.
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
        log.debug(
            "Request: Start: {}".format(
                request_label
            )
        )

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
            logger_extra.update({
                'request_params': request_params
            })

        if request_retry:
            logger_extra.update({
                'request_retry': request_retry
            })

        if request_headers:
            logger_extra.update({
                'request_headers': request_headers
            })

        if request_auth:
            logger_extra.update({
                'request_auth': request_auth
            })

        if request_json:
            logger_extra.update({
                'request_json': request_json
            })

        log.debug(
            "Request: Setup: {}".format(
                request_label
            ),
            extra=logger_extra
        )

        key_user_agent = 'User-Agent'
        header_user_agent = {
            key_user_agent: __USER_AGENT__
        }

        if request_headers:
            if key_user_agent not in request_headers:
                request_headers.update(
                    header_user_agent
                )
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
            'request_session': request_session,
            'cookie_payload': cookie_payload,
            'request_label': request_label,
            'timeout': timeout,
            'build_request_curl': build_request_curl,
            'allow_redirects': allow_redirects,
            'verify': verify,
            'stream': stream,
            'verbose': verbose
        }

        time_start_req = dt.datetime.now()

        if not request_retry_http_status_codes:
            request_retry_http_status_codes = REQUEST_RETRY_HTTP_STATUS_CODES
        if not request_retry_excps:
            request_retry_excps = REQUEST_RETRY_EXCPS

        log.debug(
            "Request: Details: {}".format(
                request_label
            ),
            extra={
                'request_label': request_label,
                'request_method': request_method,
                'request_retry': request_retry,
                'request_url': request_url,
                'request_params': request_params,
                'request_data': request_data,
                'request_json': request_json,
                'request_headers': request_headers,
                'request_auth': request_auth,
                'request_session': request_session,
                'timeout': timeout,
                'allow_redirects': allow_redirects,
                'verify': verify,
                'stream': stream,
                'verbose': verbose
            }
        )

        try:
            request = TuneRequest()

            response = self._request_retry(
                call_func=self._request,
                fargs=None,
                fkwargs=kwargs,
                timeout=timeout,
                request_retry_http_status_codes=request_retry_http_status_codes,
                request_retry_excps=request_retry_excps,
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
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.Timeout
        ) as ex_req_timeout:
            raise TuneRequestError(
                error_message="Request: Exception: Timeout",
                errors=ex_req_timeout,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.GATEWAY_TIMEOUT
            )

        except requests.exceptions.HTTPError as ex_req_http:
            raise TuneRequestError(
                error_message="Request: Exception: HTTP Error",
                errors=ex_req_http,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST_HTTP,
                error_request_curl=self.built_request_curl
            )

        except requests.exceptions.ConnectionError as ex_req_connect:
            raise TuneRequestError(
                error_message="Request: Exception: Connection Error",
                errors=ex_req_connect,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except BrokenPipeError as ex_broken_pipe:
            raise TuneRequestError(
                error_message="Request: Exception: Broken Pipe Error",
                errors=ex_broken_pipe,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except ConnectionError as ex_connect:
            raise TuneRequestError(
                error_message="Request: Exception: Connection Error",
                errors=ex_connect,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ProtocolError as ex_req_urllib3_protocol:
            raise TuneRequestError(
                error_message="Request: Exception: Protocol Error",
                errors=ex_req_urllib3_protocol,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ReadTimeoutError as ex_req_urllib3_read_timeout:
            raise TuneRequestError(
                error_message="Request: Exception: Urllib3: Read Timeout Error",
                errors=ex_req_urllib3_read_timeout,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.GATEWAY_TIMEOUT
            )

        except requests.exceptions.TooManyRedirects as ex_req_redirects:
            raise TuneRequestError(
                error_message="Request: Exception: Too Many Redirects",
                errors=ex_req_redirects,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST_REDIRECTS
            )

        except requests.exceptions.RequestException as ex_req_request:
            raise TuneRequestError(
                error_message="Request: Exception: Request Error",
                errors=ex_req_request,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_REQUEST
            )

        except (
            TuneRequestError
        ) as ex_expected:
            raise

        except Exception as ex:
            print_traceback(ex)

            raise TuneRequestError(
                error_message="Request: Exception: Unexpected",
                errors=ex,
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_SOFTWARE
            )

        time_end_req = dt.datetime.now()
        diff_req = time_end_req - time_start_req

        request_time_msecs = int(diff_req.total_seconds() * 1000)

        log.debug(
            "Request: Completed",
            extra={
                'request_label': request_label,
                'request_time_msecs': request_time_msecs
            }
        )

        return response

    def _request_retry(
        self,
        call_func,
        request_retry_http_status_codes,
        request_retry_excps,
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
        log.debug(
            "Request Retry: Start: {}".format(
                request_label
            )
        )

        logger_label = \
            "Request Retry: Request"

        request_retry_extra = {
            'timeout': timeout
        }

        if request_label is not None:
            logger_label = "{}: {}".format(logger_label, request_label)
            request_retry_extra.update({
                'request_label': request_label
            })

        if request_retry_http_status_codes is not None:
            request_retry_extra.update({
                'request_retry_http_status_codes': request_retry_http_status_codes
            })

        if request_retry_excps is not None:
            request_retry_excp_names = [excp.__name__ for excp in list(request_retry_excps)]
            request_retry_extra.update({
                'request_retry_excps': request_retry_excp_names
            })

        if request_retry_func is not None:
            request_retry_func_name = request_retry_func.__name__
            logger_label = "{}: {}".format(logger_label, request_label)
            request_retry_extra.update({
                'request_retry_func': request_retry_func_name
            })

        if request_retry_excps_func is not None:
            request_retry_excps_func_name = request_retry_excps_func.__name__
            request_retry_extra.update({
                'request_retry_excps_func': request_retry_excps_func_name
            })


        log.debug(
            msg="{}: Begin".format(logger_label),
            extra=request_retry_extra
        )

        args = fargs if fargs else list()
        kwargs = fkwargs if fkwargs else dict()

        request_url = kwargs['request_url'] if kwargs and 'request_url' in kwargs else ""

        _attempts = 0

        _tries, _delay, _timeout = retry_tries, retry_delay, timeout
        while _tries:
            _attempts += 1

            fkwargs['timeout'] = _timeout
            request_func = partial(call_func, *args, **kwargs)

            if request_label:
                log.debug(
                    msg="{}: Attempt: {}".format(logger_label, _attempts),
                    extra={
                        'attempts': _attempts,
                        'timeout': _timeout,
                        'tries': _tries,
                        'delay': _delay,
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )
            else:
                log.debug(
                    msg=logger_label,
                    extra={
                        'attempts': _attempts,
                        'timeout': _timeout,
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

            error_exception = None
            error_details = None
            _tries -= 1

            try:
                response = request_func()

                if not response:
                    raise TuneRequestModuleError(
                        error_message=(
                            "Request Retry: No response"
                        ),
                        exit_code=IntegrationExitCode.MOD_ERR_UNEXPECTED_VALUE
                    )

                log.debug(
                    "Request Retry: Checking Response",
                    extra={
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                if request_retry_func:
                    if not request_retry_func(response):
                        log.debug(
                            "Request Retry: Response: Valid: Not Retry Candidate",
                            extra={
                                'request_url': request_url,
                                'request_label': request_label
                            }
                        )
                        return response
                else:
                    log.debug(
                        "Request Retry: Response: Valid",
                        extra={
                            'request_url': request_url,
                            'request_label': request_label
                        }
                    )
                    return response

                log.debug(
                    "Request Retry: Response: Valid: Retry Candidate",
                    extra={
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

            except request_retry_excps as retry_ex:
                error_exception = retry_ex

                log.warning(
                    "Request Retry: Expected: {}: Retry Candidate".format(
                        base_class_name(error_exception)
                    ),
                    extra={
                        'error_details': get_exception_message(error_exception),
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                if not _tries:
                    log.error(
                        "Request Retry: Expected: {}: Exhausted Retries".format(
                            base_class_name(error_exception)
                        )
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
                    log.error(
                        "Request Retry: Integration: {}: Not Retry Candidate".format(
                            base_class_name(error_exception)
                        ),
                        extra=tmv_ex_extra
                    )
                    raise

                log.warning(
                    "Request Retry: Integration: {}: Retry Candidate".format(
                        base_class_name(error_exception)
                    ),
                    extra=tmv_ex_extra
                )

                if not _tries:
                    log.error(
                        "Request Retry: Integration: {}: Exhausted Retries".format(
                            base_class_name(error_exception)
                        )
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
                    log.error(
                        "Request Retry: Unexpected: {}: Not Retry Candidate".format(
                            base_class_name(error_exception)
                        ),
                        extra=ex_extra
                    )
                    raise

                log.warning(
                    "Request Retry: Unexpected: {}: Retry Candidate".format(
                        base_class_name(error_exception)
                    ),
                    extra=ex_extra
                )

                if not _tries:
                    raise TuneRequestError(
                        error_message="Unexpected: {}".format(
                            base_class_name(error_exception)
                        ),
                        errors=error_exception,
                        error_request_curl=self.built_request_curl,
                        exit_code=IntegrationExitCode.MOD_ERR_RETRY_EXHAUSTED
                    )

            if not _tries:
                log.error(
                    "Request Retry: Exhausted Retries",
                    extra={
                        'attempts': _attempts,
                        'tries': _tries,
                        'request_url': request_url,
                        'request_label': request_label
                    }
                )

                raise TuneRequestError(
                    error_message=(
                        "Request Retry: Exhausted Retries: {}: {}"
                    ).format(
                        request_label,
                        request_url
                    ),
                    error_request_curl=self.built_request_curl,
                    exit_code=IntegrationExitCode.MOD_ERR_RETRY_EXHAUSTED
                )

            log.info(
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
        request_session=False,
        cookie_payload=None,
        request_label=None,
        timeout=60,
        build_request_curl=True,
        allow_redirects=True,
        verify=True,
        stream=False,
        verbose=False
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
            verbose: (optional) Boolean, provide request and response details.

        Returns:
            requests.Response

        """
        log.debug(
            "Request Op: Details: {}".format(
                request_label
            ),
            extra={
                'request_label': request_label,
                'request_method': request_method,
                'request_url': request_url,
                'request_params': request_params,
                'request_data': request_data,
                'request_json': request_json,
                'request_headers': request_headers,
                'request_auth': request_auth,
                'request_session': request_session,
                'cookie_payload': cookie_payload,
                'timeout': timeout,
                'allow_redirects': allow_redirects,
                'verify': verify,
                'stream': stream,
                'verbose': verbose
            }
        )

        if not request_method:
            raise TuneRequestError(
                error_message="Parameter 'request_method' not defined"
            )
        if not request_url:
            raise TuneRequestError(
                error_message="Parameter 'request_url' not defined"
            )

        self.built_request_curl = None

        if request_session:
            log.debug(
                "Request Op: Session: Requested"
            )

            if self.session is None:
                log.debug(
                    "Request Op: Session: New"
                )
                self.session = requests.Session()

            log.debug(
                "Request Op: Session: Existing",
                extra={
                    'cookie_payload': self.session.cookies.get_dict(),
                    'request_label': request_label
                }
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

        if verbose:
            log.info(
                "Request Op: Details: {}".format(
                    request_label
                ),
                extra=request_extra
            )
        else:
            log.debug(
                "Request Op: Details: {}".format(
                    request_label
                ),
                extra=request_extra
            )

        self.built_request_curl = None

        kwargs = {}
        if headers:
            kwargs.update({
                'headers': headers
            })
        if request_auth:
            kwargs.update({
                'auth': request_auth
            })
        if timeout:
            kwargs.update({
                'timeout': (timeout, timeout)
            })
        if allow_redirects:
            kwargs.update({
                'allow_redirects': allow_redirects
            })
        if stream:
            kwargs.update({
                'stream': stream
            })
        kwargs.update({
            'verify': verify
        })

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

                    log.debug(
                        "Request Op: Request Base: GET",
                        extra={
                            'request_label': request_label,
                            'request_method': request_method,
                            'request_curl': self.built_request_curl
                        }
                    )

                kwargs.update({
                    'url': request_url
                })

                if request_params_encoded:
                    kwargs.update({
                        'params': request_params_encoded
                    })

                if request_session and self.session:
                    if cookie_payload:
                        kwargs.update({
                            'cookies': cookie_payload
                        })

                    log.debug(
                        "Request Op: Request Base: Session: GET",
                        extra={
                            'request_label': request_label,
                            'kwargs': kwargs
                        }
                    )

                    response = self.session.get(**kwargs)
                else:
                    log.debug(
                        "Request Op: Request Base: Requests: GET",
                        extra={
                            'request_label': request_label,
                            'kwargs': kwargs
                        }
                    )

                    response = requests.get(**kwargs)

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

                    log.debug(
                        "Request Op: Request Base: POST",
                        extra={
                            'request_label': request_label,
                            'request_method': request_method,
                            'request_curl': self.built_request_curl
                        }
                    )

                kwargs.update({
                    'url': request_url
                })
                if request_data:
                    kwargs.update({
                        'data': request_data
                    })
                if request_json:
                    kwargs.update({
                        'json': request_json
                    })

                if request_session and self.session:
                    if cookie_payload:
                        kwargs.update({
                            'cookies': cookie_payload
                        })

                    log.debug(
                        "Request Op: Request Base: Session: POST",
                        extra={
                            'request_label': request_label,
                            'kwargs': kwargs
                        }
                    )

                    response = self.session.post(**kwargs)
                else:
                    log.debug(
                        "Request Op: Request Base: Requests: POST",
                        extra={
                            'request_label': request_label,
                            'kwargs': kwargs
                        }
                    )

                    response = requests.post(**kwargs)

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

                    log.debug(
                        "Request Op: Request Base: PUT",
                        extra={
                            'request_label': request_label,
                            'request_curl': self.built_request_curl
                        }
                    )

                kwargs.update({
                    'url': request_url
                })
                if request_data:
                    kwargs.update({
                        'data': request_data
                    })

                if request_session and self.session:
                    if cookie_payload:
                        kwargs.update({
                            'cookies': cookie_payload
                        })

                    log.debug(
                        "Request Op: Request Base: Session: PUT",
                        extra={
                            'request_label': request_label,
                            'kwargs': kwargs
                        }
                    )

                    response = self.session.put(**kwargs)
                else:
                    log.debug(
                        "Request Op: Request Base: Requests: PUT",
                        extra={
                            'request_label': request_label,
                            'kwargs': kwargs
                        }
                    )
                    response = requests.put(**kwargs)

            elif request_method == 'HEAD':
                if request_params:
                    request_url += \
                        "?" + urllib.parse.urlencode(request_params)

                kwargs.update({
                    'url': request_url
                })
                if headers:
                    kwargs.update({
                        'headers': headers
                    })

                response = requests.head(**kwargs)
            else:
                raise TuneRequestError(
                    error_message="Request: Unexpected 'request_method':'{}'".format(
                        request_method
                    ),
                    exit_code=IntegrationExitCode.MOD_ERR_ARGUMENT
                )

        except Exception as ex:
            log.error(
                "Request Op: Request Base: Error",
                extra={
                    'request_label': request_label,
                    'error_exception': base_class_name(ex),
                    'error_details': get_exception_message(ex)
                }
            )
            raise

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

        if verbose:
            log.info(
                "Request Op: Response: Details",
                extra=response_extra
            )
        else:
            log.debug(
                "Request Op: Response: Details",
                extra=response_extra
            )

        http_status_successful = is_http_status_type(
            http_status_code=http_status_code,
            http_status_type=HttpStatusType.SUCCESSFUL
        )

        http_status_redirection = is_http_status_type(
            http_status_code=http_status_code,
            http_status_type=HttpStatusType.REDIRECTION
        )

        if http_status_successful or http_status_redirection:
            if hasattr(response, 'url') and \
                    response.url and \
                    len(response.url) > 0:
                response_extra.update({
                    'response_url': response.url
                })

            if verbose:
                log.info(
                    "Request Op: Response: Success",
                    extra=response_extra
                )
            else:
                log.debug(
                    "Request Op: Response: Success",
                    extra=response_extra
                )

            if request_session:
                log.debug(
                    "Request Op: Session: Payload",
                    extra={
                        'cookie_payload': self.session.cookies.get_dict(),
                        'request_label': request_label
                    }
                )

            return response
        else:
            response_extra.update({
                'error_request_curl': self.built_request_curl
            })

            log.error(
                "Request Op: Response: Failed",
                extra=response_extra
            )

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
                extra_error.update({
                    'error_request_curl': self.built_request_curl
                })

            log.error(
                "Request Op: Error: Response: Details",
                extra=extra_error
            )

            kwargs = {
                'error_status': json_response_error.get("response_status", None),
                'error_reason': json_response_error.get("response_reason", None),
                'error_details': json_response_error.get("response_details", None),
                'error_request_curl': self.built_request_curl
            }

            if http_status_code in [
                HttpStatusCode.BAD_REQUEST,
                HttpStatusCode.UNAUTHORIZED,
                HttpStatusCode.FORBIDDEN,
                HttpStatusCode.NOT_FOUND,
                HttpStatusCode.METHOD_NOT_ALLOWED,
                HttpStatusCode.NOT_ACCEPTABLE,
                HttpStatusCode.REQUEST_TIMEOUT,
                HttpStatusCode.CONFLICT,
                HttpStatusCode.GONE,
                HttpStatusCode.UNPROCESSABLE_ENTITY,
                HttpStatusCode.TOO_MANY_REQUESTS
            ]:
                kwargs.update({
                    'exit_code': http_status_code
                })
                raise TuneRequestClientError(**kwargs)

            if http_status_code in [
                HttpStatusCode.INTERNAL_SERVER_ERROR,
                HttpStatusCode.NOT_IMPLEMENTED,
                HttpStatusCode.BAD_GATEWAY,
                HttpStatusCode.SERVICE_UNAVAILABLE,
                HttpStatusCode.NETWORK_AUTHENTICATION_REQUIRED
            ]:
                kwargs.update({
                    'exit_code': http_status_code
                })
                raise TuneRequestServiceError(**kwargs)

            kwargs.update({
                'exit_code': json_response_error["response_status_code"]
            })

            extra_unhandled = copy.deepcopy(kwargs)
            extra_unhandled.update({
                'http_status_code': http_status_code
            })
            log.error(
                "Request Op: Error: Unhandled",
                extra=extra_unhandled
            )

            raise TuneRequestModuleError(**kwargs)


    def validate_response(
        self,
        response,
        request_label=None
    ):
        """Validate response

        Args:
            response:
            request_label:
            request_url:

        Returns:

        """
        response_extra = {}
        if request_label:
            response_extra.update({
                'request_label': request_label
            })

        if not response:
            log.error(
                "Validate Response: Failed: None",
                extra=response_extra
            )

            raise TuneRequestModuleError(
                error_message="Validate Response: Failed: None",
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_SOFTWARE
            )
        else:
            log.debug(
                "Validate Response: Defined",
                extra=response_extra
            )

        response_extra.update({
            'http_status_code': response.status_code
        })

        if hasattr(response, 'text'):
            response_text_length = len(response.text)
            response_extra.update({
                'response_text_length': response_text_length
            })

        if response.headers:
            if 'Content-Type' in response.headers:
                response_headers_content_type = \
                    safe_str(response.headers['Content-Type'])
                response_extra.update({
                    'Content-Type': response_headers_content_type
                })

            if 'Content-Length' in response.headers:
                response_headers_content_length = \
                    safe_int(response.headers['Content-Length'])
                response_extra.update({
                    'Content-Length': convert_size(response_headers_content_length)
                })

            if 'Content-Encoding' in response.headers:
                response_content_encoding = \
                    safe_str(response.headers['Content-Encoding'])
                response_extra.update({
                    'Content-Encoding': response_content_encoding
                })

            if 'Transfer-Encoding' in response.headers:
                response_transfer_encoding = \
                    safe_str(response.headers['Transfer-Encoding'])
                response_extra.update({
                    'Transfer-Encoding': response_transfer_encoding
                })

        if not is_http_status_successful(
            http_status_code=response.status_code
        ):
            log.error(
                "Validate Response: Failed",
                extra=response_extra
            )

            raise TuneRequestModuleError(
                error_message="Validate Request: Failed",
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_SOFTWARE
            )
        else:
            log.debug(
                "Validate Response: Success",
                extra=response_extra
            )

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
        self.validate_response(
            response,
            request_label
        )

        json_response = None
        response_extra = {}
        if request_label:
            response_extra.update({
                'request_label': request_label
            })

        response_extra.update({
            'Content-Type (Expected)': response_content_type_expected
        })

        if hasattr(response, 'headers'):
            response_content_type = response.headers.get('Content-Type', None)

        if response_content_type is not None:
            is_valid_response_content_type = \
                response_content_type == response_content_type_expected or \
                response_content_type.startswith(response_content_type_expected)

            if is_valid_response_content_type:
                json_response = self.requests_response_json(
                    response=response,
                    request_label=request_label
                )
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
                        exit_code=IntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
                    )

                raise TuneRequestModuleError(
                    error_message="Unexpected 'Content-Type': '{}', Expected: '{}'".format(
                        response_content_type,
                        response_content_type_expected
                    ),
                    errors=response_content_html_lines,
                    error_request_curl=self.built_request_curl,
                    exit_code=IntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
                )
            else:
                raise TuneRequestModuleError(
                    error_message="Unexpected 'Content-Type': '{}', Expected: '{}'".format(
                        response_content_type,
                        response_content_type_expected
                    ),
                    error_request_curl=self.built_request_curl,
                    exit_code=IntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
                )
        else:
            raise TuneRequestModuleError(
                error_message="Undefined 'Content-Type'",
                error_request_curl=self.built_request_curl,
                exit_code=IntegrationExitCode.MOD_ERR_UNEXPECTED_CONTENT_TYPE_RETURNED
            )

        response_extra.update({
            'http_status_code': response.status_code,
            'raise_ex_if_not_json_response': raise_ex_if_not_json_response
        })

        log.debug(
            "Validate JSON Response: Details",
            extra=response_extra
        )

        return json_response

    def requests_response_json(
        self,
        response,
        request_label=None,
        raise_ex_if_not_json_response=True
    ):
        """Get JSON from response from requests

        Args:
            response:
            request_label:

        Returns:

        """
        json_response = None
        response_extra = {}
        if request_label:
            response_extra.update({
                'request_label': request_label
            })

        try:
            json_response = response.json()
            response_details_source = 'json'
            response_content_length = len(json_response)

            response_extra.update({
                'response_details_source': response_details_source,
                'response_content_length': response_content_length
            })
        except json.decoder.JSONDecodeError as json_decode_ex:
            log.error(
                "Validate JSON Response: Failed: JSONDecodeError",
                extra=response_extra
            )

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
            log.error(
                "Validate JSON Response: Failed: Exception",
                extra=response_extra
            )

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
                log.error(
                    "Validate JSON Response: Failed: None",
                    extra=response_extra
                )

                raise TuneRequestModuleError(
                    error_message="Validate JSON Response: Failed: None",
                    error_request_curl=self.built_request_curl,
                    exit_code=IntegrationExitCode.MOD_ERR_SOFTWARE
                )
            else:
                log.warning(
                    "Validate JSON Response: None",
                    extra=response_extra
                )
        else:
            log.debug(
                "Validate JSON Response: Valid",
                extra=response_extra
            )

        return json_response

    def create_header_authorization_basic(
        self,
        auth_user,
        auth_secret
    ):
        """Create Authorization Basic header

        Args:
            auth_user:
            auth_secret:

        Returns:

        """
        if not auth_user:
            raise TuneRequestModuleError(
                error_message="Missing 'auth_user'",
                exit_code=IntegrationExitCode.MOD_ERR_ARGUMENT
            )
        if not auth_secret:
            raise TuneRequestModuleError(
                error_message="Missing 'auth_secret'",
                exit_code=IntegrationExitCode.MOD_ERR_ARGUMENT
            )
        str_basic_auth = \
            bytes(
                "%s:%s" % (
                    auth_user,
                    auth_secret
                ),
                'utf-8'
            )
        b64bytes_auth = \
            base64.b64encode(str_basic_auth)
        b64_auth = \
            b64bytes_auth.decode('utf-8')

        header_authorization_basic = {
            'Authorization': 'Basic ' + b64_auth
        }

        return header_authorization_basic

    @staticmethod
    def build_response_error_details(
        request_label,
        request_url,
        response
    ):
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

        response_status = "{}: {}: {}".format(
            http_status_code,
            http_status_type,
            http_status_desc
        )

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
                response_error_details.update({
                    'Content-Type': response_headers_content_type
                })

            if 'Content-Length' in response.headers and \
                    response.headers['Content-Length']:
                response_headers_content_length = \
                    safe_int(response.headers['Content-Length'])
                response_error_details.update({
                    'Content-Length': response_headers_content_length
                })

            if 'Transfer-Encoding' in response.headers and \
                    response.headers['Transfer-Encoding']:
                response_headers_transfer_encoding = \
                    safe_str(response.headers['Transfer-Encoding'])
                response_error_details.update({
                    'Transfer-Encoding': response_headers_transfer_encoding
                })

            if 'Content-Encoding' in response.headers and \
                    response.headers['Content-Encoding']:
                response_headers_content_encoding = \
                    safe_str(response.headers['Content-Encoding'])
                response_error_details.update({
                    'Content-Encoding': response_headers_content_encoding
                })

        if hasattr(response, "reason") and response.reason:
            response_error_details.update({
                'response_reason': response.reason
            })

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
        self,
        response_decode_ex,
        response,
        response_extra=None,
        request_label=None,
        request_curl=None
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
            response_extra.update({
                'request_label': request_label
            })

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

        log.error(
            "Validate JSON Response: Failed: Invalid",
            extra=response_extra
        )

        raise TuneRequestModuleError(
            error_message="Validate JSON Response: Failed: Invalid",
            errors=response_decode_ex,
            error_request_curl=request_curl,
            exit_code=IntegrationExitCode.MOD_ERR_SOFTWARE
        )
