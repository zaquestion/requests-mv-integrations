#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

import csv
import io
import json
import logging
import os
import requests
from requests_mv_integrations import (__python_required_version__)
from requests_mv_integrations.errors import (
    get_exception_message,
    TuneRequestErrorCodes,
)
from requests_mv_integrations.exceptions.custom import (TuneRequestModuleError,)
from requests_mv_integrations.support.utils import (base_class_name, python_check_version)

def csv_skip_last_row(iterator):
    """Skip last CSV row.

    Args:
        iterator:

    Returns:

    """
    prev = next(iterator)
    for item in iterator:
        yield prev
        prev = item
