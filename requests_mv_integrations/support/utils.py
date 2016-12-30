#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations
"""Helpers: Functions for commonly used utilities.
"""

import sys


#  Check Python Version
#
def python_check_version(required_version):
    """Check Python Version
    :param: required_version
    """
    current_version = sys.version_info
    if current_version[0] == required_version[0] and \
       current_version[1] >= required_version[1]:
        pass
    elif current_version[0] > required_version[0]:
        pass
    else:
        sys.stderr.write(
            "[%s] - Error: Python interpreter must be %d.%d or greater"
            " to use this library, current version is %d.%d.\n" %
            (sys.argv[0], required_version[0], required_version[1], current_version[0], current_version[1])
        )
        sys.exit(-1)
    return 0


def convert_size(size, precision=2):
    """Convert Size

    Args:
        size:
        precision:

    Returns:

    """
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB']
    suffixIndex = 0

    while size > 1024 and suffixIndex < 4:
        suffixIndex += 1  # increment the index of the suffix
        size = size / 1024.0  # apply the division

    suffix = suffixes[suffixIndex]
    if suffix == 'B':
        precision = 0

    return "%.*f %s" % (precision, size, suffix)


def base_class_name(obj):
    return obj.__class__.__name__


def full_class_name(obj):
    try:
        return obj.__module__ + "." + obj.__class__.__name__
    except Exception as ex:
        return obj.__class__.__name__
