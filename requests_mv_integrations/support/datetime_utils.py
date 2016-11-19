#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations
"""
Helpers: Datetime Utils.
"""

import time
import pytz
import datetime as dt
import pytz_convert
from pprintpp import pprint


def get_current_date():
    return dt.datetime.now().date().isoformat()


def get_epoch_datetime(
    unix_time_epoch_secs=None,
    tz_name=None
):
    """Get Epoch Datetime

    Args:
        unix_time_epoch_secs:
        tz_name:

    Returns:
        Datetime

    """
    if unix_time_epoch_secs is None:
        unix_time_epoch_secs = time.time()

    epoch_datetime = dt.datetime.fromtimestamp(
        unix_time_epoch_secs,
        pytz.timezone('UTC')
    )

    if tz_name is None or tz_name == 'UTC':
        return epoch_datetime

    return epoch_datetime.astimezone(pytz.timezone(tz_name))


def get_cumulative_report_hour(
    unix_time_epoch_secs,
    datetime_report,
    latency_mins,
    tz_name
):
    """Get Cumulative Report Hour

    Args:
        unix_time_epoch_secs:
        datetime_report:
        latency_mins:
        tz_name:

    Returns:
        Report Hour (int)

    """
    now_utc_datetime = get_epoch_datetime(
        unix_time_epoch_secs,
        tz_name
    )

    datetime_lag = now_utc_datetime + dt.timedelta(minutes=latency_mins * -1)

    if datetime_lag.strftime('%Y-%m-%d') < datetime_report.strftime('%Y-%m-%d'):
        report_hour = 0
    elif datetime_lag.strftime('%Y-%m-%d') == datetime_report.strftime('%Y-%m-%d'):
        report_hour = int(datetime_lag.strftime('%H'))
        if report_hour < 0:
            report_hour = 0
    else:
        report_hour = 23

    return report_hour


def validate_start_end_datetime(
    start_date,
    end_date
):
    try:
        datetime_start = dt.datetime.strptime(start_date, '%Y-%m-%d')
    except ValueError:
        raise

    try:
        datetime_end = dt.datetime.strptime(end_date, '%Y-%m-%d')
    except ValueError:
        raise

    str_date_start = str(datetime_start.date())
    str_date_end = str(datetime_end.date())

    if datetime_start > datetime_end:
        raise ValueError(
            "Invalid 'start_date' {} and 'end_date' {}".format(
                str_date_start,
                str_date_end
            )
        )

    return (datetime_start, datetime_end)


def get_start_end_datetime(
    start_date,
    end_date,
    tz_name=None,
    hourly_resolution=False,
    rolling_delta_hours=25
):
    now_utc_datetime = dt.datetime.utcnow()
    now_utc_date_iso = now_utc_datetime.date().isoformat()

    now_utc_time = now_utc_datetime.time()

    (start_datetime, end_datetime) = \
        validate_start_end_datetime(start_date, end_date)

    if tz_name is None:
        tz_name = 'UTC'

    start_date_tz_offset = pytz_convert.convert_tz_name_to_date_tz_offset(
        tz_name=tz_name,
        str_date=start_date
    )
    end_date_tz_offset = pytz_convert.convert_tz_name_to_date_tz_offset(
        tz_name=tz_name,
        str_date=end_date
    )

    # pprint({
    #     'now_utc_time': now_utc_time,
    #     'now_utc_time_hour': now_utc_time_hour,
    #     'start_date_tz_offset': start_date_tz_offset,
    #     'end_date_tz_offset': end_date_tz_offset
    # })

    start_date_tz_minutes = pytz_convert.convert_tz_offset_to_tz_minutes(
        tz_offset=start_date_tz_offset
    )
    end_date_tz_minutes = pytz_convert.convert_tz_offset_to_tz_minutes(
        tz_offset=end_date_tz_offset
    )

    datatime_format = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00:00")[hourly_resolution]

    if start_date == end_date and end_date == now_utc_date_iso:
        end_datetime += dt.timedelta(
            hours=now_utc_time.hour,
            minutes=now_utc_time.minute,
            seconds=now_utc_time.second
        )
        end_datetime -= dt.timedelta(minutes=end_date_tz_minutes)

        start_datetime = end_datetime - dt.timedelta(hours=rolling_delta_hours)
        start_datetime_str = start_datetime.strftime(datatime_format)

        end_datetime_str = end_datetime.strftime(datatime_format)

    elif start_date != end_date or end_date != now_utc_date_iso:
        end_datetime += dt.timedelta(hours=24) - dt.timedelta(seconds=1)
        end_datetime -= dt.timedelta(minutes=end_date_tz_minutes)

        start_datetime -= dt.timedelta(minutes=start_date_tz_minutes)
        rolling_delta_hours -= 24

        start_datetime -= dt.timedelta(hours=rolling_delta_hours)
        start_datetime_str = start_datetime.strftime(datatime_format)

        end_datetime_str = end_datetime.strftime(datatime_format)

    return (start_datetime_str, end_datetime_str)
