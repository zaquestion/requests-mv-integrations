#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest

from requests_mv_integrations.support import command_line_request_curl

_test_command_line_request_curl = [
    (
        'GET',
        'https://api.partner.com/find',
        {'Content-Type': 'application/json'},
        'api_key=11111111222222223333333344444444',
        [
            "curl --verbose -X GET -H 'Content-Type: application/json' -H 'User-Agent: (requests-mv-integrations/0.2.1, Python/3.5.2)' --connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' 'https://api.partner.com/find'",
            "curl --verbose -X GET -H 'User-Agent: (requests-mv-integrations/0.2.1, Python/3.5.2)' -H 'Content-Type: application/json' --connect-timeout 60 -L -G --data 'api_key=11111111222222223333333344444444' 'https://api.partner.com/find'",
        ],
    ),
]

@pytest.mark.parametrize(
    "request_method, request_url, request_headers, request_data, expected",
    _test_command_line_request_curl
)
def test_curl(request_method, request_url, request_data, request_headers, expected):
    curl_res = command_line_request_curl(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_data=request_data
    )
    res = False
    for exp_curl_res in expected:
        if curl_res == exp_curl_res:
            res = True
            break
    assert(res)
