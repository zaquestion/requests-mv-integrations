#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import copy
import re
import json
import urllib.parse
from .constants import (HEADER_CONTENT_TYPE_APP_JSON, __USER_AGENT__)


def command_line_request_curl(
    request_method,
    request_url,
    request_headers,
    request_data=None,
    request_json=None,
    request_timeout=60,
    request_allow_redirects=True
):
    """Command Line: Build Request cUrl

    Args:
        request_method:
        request_url:
        request_headers:
        request_data:
        request_timeout:
        request_allow_redirects:

    Returns:

    """
    key_user_agent = 'User-Agent'
    header_user_agent = {key_user_agent: __USER_AGENT__}

    if request_headers:
        if key_user_agent not in request_headers:
            request_headers.update(header_user_agent)
    else:
        request_headers = header_user_agent

    request_method = request_method.upper()

    command = ("curl" " --verbose" " -X {request_method}" " -H {headers}" " --connect-timeout {timeout}")

    if request_allow_redirects:
        command += " -L"

    if request_method == 'GET':
        if request_data:
            params = request_data.split("&")

            command += (" -G" " --data {params}" " '{url}'")

            params = ["'{0}'".format(urllib.parse.unquote(param)) for param in params]
            params = " --data ".join(params)

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method, headers=headers, params=params, timeout=request_timeout, url=request_url
            )
        else:
            command += (" '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method, headers=headers, timeout=request_timeout, url=request_url
            )

    elif request_method == 'POST':
        if request_data:
            command += (" --data '{data}'" " '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=request_data,
                timeout=request_timeout,
                url=request_url
            )
        elif request_json:
            command += (" --data '{data}'" " '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=json.dumps(request_json),
                timeout=request_timeout,
                url=request_url
            )
        else:
            command += (" '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)
            return command.format(
                request_method=request_method, headers=headers, timeout=request_timeout, url=request_url
            )

    elif request_method == 'PUT':
        if request_data:
            rows = re.split(r'\n', request_data)
            row = None
            if rows and len(rows) > 0:
                row = rows[0]

            command += (" --data '{data}'" " '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method, headers=headers, data=row, timeout=request_timeout, url=request_url
            )
        else:
            command += (" '{url}'")

            headers = ["'{0}: {1}'".format(k, v) for k, v in request_headers.items()]
            headers = " -H ".join(headers)
            return command.format(
                request_method=request_method, headers=headers, timeout=request_timeout, url=request_url
            )


def command_line_request_curl_get(
    request_url, request_params, request_headers=None, request_timeout=60, request_allow_redirects=True
):
    """Command Line: Build Request cUrl for GET method

    Args:
        request_url:
        request_params:
        request_headers:
        request_timeout:
        request_allow_redirects:

    Returns:

    """
    if request_headers is None:
        request_headers = copy.deepcopy(HEADER_CONTENT_TYPE_APP_JSON)

    request_params_encoded = None
    if request_params:
        request_params_encoded = \
            urllib.parse.urlencode(request_params)

    return command_line_request_curl(
        request_method="GET",
        request_url=request_url,
        request_data=request_params_encoded,
        request_headers=request_headers,
        request_timeout=request_timeout,
        request_allow_redirects=request_allow_redirects
    )


def command_line_request_curl_post(
    request_url,
    request_params,
    request_headers=None,
    request_timeout=60,
    request_data=None,
    request_allow_redirects=True
):
    """Command Line: Build Request cUrl for POST method

    Args:
        request_url:
        request_params:
        request_headers:
        request_timeout:
        request_data:
        request_allow_redirects:

    Returns:

    """
    if request_headers is None:
        request_headers = copy.deepcopy(HEADER_CONTENT_TYPE_APP_JSON)

    if request_params:
        request_url += "?" + urllib.parse.urlencode(request_params)

    return command_line_request_curl(
        request_method="POST",
        request_url=request_url,
        request_headers=request_headers,
        request_data=request_data,
        request_timeout=request_timeout,
        request_allow_redirects=request_allow_redirects
    )
