#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import base64

def create_header_authorization_basic(
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
        raise ValueError(
            "Missing 'auth_user'"
        )
    if not auth_secret:
        raise ValueError(
            "Missing 'auth_secret'"
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