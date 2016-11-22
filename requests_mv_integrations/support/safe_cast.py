#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace tune_mv_integration


def safe_cast(val, to_type, default=None):
    """Safely cast value to type, and if failed, returned default.

    Args:
        val:
        to_type:
        default:

    Returns:

    """
    if val is None:
        return default

    try:
        return to_type(val)
    except ValueError:
        return default


def safe_str(val):
    """Safely cast value to str

    Args:
        val:

    Returns:

    """
    return safe_cast(val, str, "")


def safe_float(val, ndigits=2):
    """Safely cast value to float

    Args:
        val:

    Returns:

    """
    return round(safe_cast(val, float, 0.0), ndigits)


def safe_int(val):
    """Safely cast value to int

    Args:
        val:

    Returns:

    """
    return safe_cast(safe_float(val, 0), int, 0)


def safe_dict(val):
    """Safely cast value to dict

    Args:
        val:

    Returns:

    """
    return safe_cast(val, dict, {})


def safe_smart_cast(val):
    """Safely cast value, default str

    Args:
        val:

    Returns:

    """
    to_type = type(val)
    if to_type == str:
        return safe_str(val)
    if to_type == dict:
        return safe_dict(val)
    if to_type == int:
        return safe_int(val)
    if to_type == float:
        return safe_float(val)

    return safe_str(str(val))


def safe_cost(val):
    return safe_float(val, ndigits=4)
