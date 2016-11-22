#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace tune_mv_integration

import logging
import httplib2
import urllib

log = logging.getLogger(__name__)

from requests_mv_integrations.support.safe_cast import (
    safe_int
)


def is_valid_url_exists(url):
    try:
        http_connect = httplib2.Http()
        resp = http_connect.request(url, 'HEAD')
        http_status_code = safe_int(resp[0]['status'])
        log.debug(
            "Validate URL Exists",
            extra={
                'url': url,
                'http_status_code': http_status_code
            }
        )
        return http_status_code < 400
    except:
        return False


def is_valid_url_path(url):
    try:
        resp = urllib.parse.urlparse(url)
        if not resp:
            return False

        log.debug(
            "Validate URL Path",
            extra={
                'url': url,
                'url_scheme': resp.scheme,
                'url_netloc': resp.netloc
            }
        )
        return resp.scheme and resp.netloc
    except:
        return False


def create_request_url(
    request_url,
    request_params
):
    """Create Request URL

    Args:
        request_url:
        request_params:

    Returns:

    """
    return "{request_url}?{query_string}".format(
        request_url=request_url,
        query_string=urllib.parse.urlencode(request_params)
    )
