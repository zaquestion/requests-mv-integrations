#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest

from requests_mv_integrations.support import command_line_request_curl

_test_command_line_request_curl = [
    ('GET',
     'https://api.mobileapptracking.com/v2/advertiser/find',
     {'Content-Type': 'application/json'},
     'api_key=2a2f00e3c3aa5d0093feff066a0948db',
     "curl --verbose -X GET -H 'Content-Type: application/json' -H 'User-Agent: (requests-mv-integrations/0.1.9, Python/3.5.2)' --connect-timeout 60 -L -G --data 'api_key=2a2f00e3c3aa5d0093feff066a0948db' 'https://api.mobileapptracking.com/v2/advertiser/find'"),
]

@pytest.mark.parametrize(
    "request_method, request_url, request_headers, request_data, expected",
    _test_command_line_request_curl
)
def test_curl(request_method, request_url, request_data, request_headers, expected):
    res = command_line_request_curl(
        request_method=request_method,
        request_url=request_url,
        request_headers=request_headers,
        request_data=request_data
    )
    assert res == expected
