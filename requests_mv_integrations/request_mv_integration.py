#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

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
from logging_mv_integrations import (
    TuneLoggingFormat,
    TuneLoggingHandler,
    get_logger,
)
from pprintpp import pprint
from pyhttpstatus_utils import (
    HttpStatusCode,
    HttpStatusType,
    http_status_code_to_desc,
    http_status_code_to_type,
    is_http_status_type,
    is_http_status_successful,
)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from requests_mv_integrations import (
    __python_required_version__,
    __version__,
)
from requests_mv_integrations.errors import (get_exception_message, print_traceback, TuneRequestErrorCodes)
from requests_mv_integrations.exceptions import (
    TuneRequestBaseError,
    TuneRequestClientError,
    TuneRequestServiceError,
    TuneRequestModuleError,
    TuneRequestValueError,
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
    Singleton,
    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES,
    __USER_AGENT__,
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
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.Timeout,
        ) as ex_req_timeout:
            raise TuneRequestServiceError(
                error_message="Request: Exception: Timeout",
                errors=ex_req_timeout,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.GATEWAY_TIMEOUT
            )

        except requests.exceptions.HTTPError as ex_req_http:
            raise TuneRequestModuleError(
                error_message="Request: Exception: HTTP Error",
                errors=ex_req_http,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_HTTP
            )

        except requests.exceptions.ConnectionError as ex_req_connect:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Connection Error",
                errors=ex_req_connect,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except BrokenPipeError as ex_broken_pipe:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Broken Pipe Error",
                errors=ex_broken_pipe,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except ConnectionError as ex_connect:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Connection Error",
                errors=ex_connect,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ProtocolError as ex_req_urllib3_protocol:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Protocol Error",
                errors=ex_req_urllib3_protocol,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_CONNECT
            )

        except requests.packages.urllib3.exceptions.ReadTimeoutError as ex_req_urllib3_read_timeout:
            raise TuneRequestServiceError(
                error_message="Request: Exception: Urllib3: Read Timeout Error",
                errors=ex_req_urllib3_read_timeout,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.GATEWAY_TIMEOUT
            )

        except requests.exceptions.TooManyRedirects as ex_req_redirects:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Too Many Redirects",
                errors=ex_req_redirects,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST_REDIRECTS
            )

        except requests.exceptions.RequestException as ex_req_request:
            raise TuneRequestModuleError(
                error_message="Request: Exception: Request Error",
                errors=ex_req_request,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_REQUEST
            )

        except TuneRequestBaseError:
            raise

        except Exception as ex:
            print_traceback(ex)

            raise TuneRequestModuleError(
                error_message="Request: Exception: Unexpected",
                errors=ex,
                error_request_curl=self.built_request_curl,
                error_code=TuneRequestErrorCodes.REQ_ERR_SOFTWARE
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
                        error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE
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

            except TuneRequestBaseError as tmv_ex:
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
                    raise TuneRequestModuleError(
                        error_message="Unexpected: {}".format(base_class_name(error_exception)),
                        errors=error_exception,
                        error_request_curl=self.built_request_curl,
                        error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
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

                raise TuneRequestModuleError(
                    error_message=("Request Retry: Exhausted Retries: {}: {}").format(request_label, request_url),
                    error_request_curl=self.built_request_curl,
                    error_code=TuneRequestErrorCodes.REQ_ERR_RETRY_EXHAUSTED
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
            raise TuneRequestValueError(error_message="Parameter 'request_method' not defined")
        if not request_url:
            raise TuneRequestValueError(error_message="Parameter 'request_url' not defined")

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
            raise TuneRequestModuleError(
                error_message="Failed to get response",
                error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE,
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
                HttpStatusCode.TOO_MANY_REQUESTS,
            ]:
                kwargs.update({'error_code': http_status_code})
                raise TuneRequestClientError(**kwargs)

            if http_status_code in [
                HttpStatusCode.INTERNAL_SERVER_ERROR,
                HttpStatusCode.NOT_IMPLEMENTED,
                HttpStatusCode.BAD_GATEWAY,
                HttpStatusCode.SERVICE_UNAVAILABLE,
                HttpStatusCode.NETWORK_AUTHENTICATION_REQUIRED,
            ]:
                kwargs.update({'error_code': http_status_code})
                raise TuneRequestServiceError(**kwargs)

            kwargs.update({'error_code': json_response_error["response_status_code"]})

            extra_unhandled = copy.deepcopy(kwargs)
            extra_unhandled.update({'http_status_code': http_status_code})
            self.logger.error("Send Request: Error: Unhandled", extra=extra_unhandled)

            raise TuneRequestModuleError(**kwargs)
