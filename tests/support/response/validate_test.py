#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integration

import pytest

from requests_mv_integrations.support.response import validate_response
from requests_mv_integrations.exceptions import TuneRequestModuleError
from requests.models import Response, codes

response_ok = Response()
response_ok.status_code = codes.ok
response_bad = Response()
response_bad.status_code = codes.bad


_test_validate = [
    (response_ok, True),
    (response_bad, False)
]


@pytest.mark.parametrize("response, expected", _test_validate)
def test_validate_response(response, expected):
    res = True
    try:
        validate_response(
            response=response,
            request_curl="Not important request curl",
            request_label="Not important request label",
        )
    except TuneRequestModuleError:
        res = False
    assert res == expected
