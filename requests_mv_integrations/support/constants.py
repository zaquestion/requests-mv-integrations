#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import sys
from requests_mv_integrations import (
    __version__,
    __title__
)

SECONDS_FOR_5_MINUTES = 300
SECONDS_FOR_30_MINUTES = 1800
SECONDS_FOR_HALF_HOUR = 1800
SECONDS_FOR_55_MINUTES = 3300
SECONDS_FOR_60_MINUTES = 3600
SECONDS_FOR_1_HOUR = 3600
SECONDS_FOR_2_HOURS = 7200
SECONDS_FOR_3_HOURS = 10800
SECONDS_FOR_6_HOURS = 21600
SECONDS_FOR_23_AND_HALF_HOURS = 84600
SECONDS_FOR_1_DAY = 86400
SECONDS_FOR_2_DAYS = 172800
SECONDS_FOR_30_DAYS = 86400 * 30

IRONCACHE_MAX_SIZE = 1000000


__MODULE_VERSION_INFO__ = tuple(__version__.split('.'))
__MODULE_SIG__ = "%s/%s" % (
    __title__,
    __version__
)

__TIMEZONE_NAME_DEFAULT__ = "UTC"
__INTEGRATION_NAME_DEFAULT__ = 'TUNE MV Integration'

__PYTHON_VERSION__ = 'Python/%d.%d.%d' % (
    sys.version_info[0],
    sys.version_info[1],
    sys.version_info[2]
)

__USER_AGENT__ = "({}, {})".format(
    __MODULE_SIG__,
    __PYTHON_VERSION__
)

__LOGGER_NAME__ = __name__.split('.')[0]

HEADER_CONTENT_TYPE_APP_JSON = \
    {'Content-Type': 'application/json'}

HEADER_CONTENT_TYPE_APP_URLENCODED = \
    {'Content-Type': 'application/x-www-form-urlencoded'}

HEADER_USER_AGENT = \
    {'User-Agent': __USER_AGENT__}
