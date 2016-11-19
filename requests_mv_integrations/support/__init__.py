#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

from .constants import (
    SECONDS_FOR_5_MINUTES,
    SECONDS_FOR_30_MINUTES,
    SECONDS_FOR_HALF_HOUR,
    SECONDS_FOR_55_MINUTES,
    SECONDS_FOR_60_MINUTES,
    SECONDS_FOR_1_HOUR,
    SECONDS_FOR_2_HOURS,
    SECONDS_FOR_3_HOURS,
    SECONDS_FOR_6_HOURS,
    SECONDS_FOR_23_AND_HALF_HOURS,
    SECONDS_FOR_1_DAY,
    SECONDS_FOR_2_DAYS,
    SECONDS_FOR_30_DAYS,

    IRONCACHE_MAX_SIZE,

    HEADER_CONTENT_TYPE_APP_JSON,
    HEADER_CONTENT_TYPE_APP_URLENCODED,
    HEADER_USER_AGENT,

    __MODULE_SIG__,
    __PYTHON_VERSION__,
    __TIMEZONE_NAME_DEFAULT__,
    __INTEGRATION_NAME_DEFAULT__,
    __USER_AGENT__,
    __LOGGER_NAME__
)
from .datetime_utils import (
    get_current_date,
    get_cumulative_report_hour,
    get_epoch_datetime,
    get_start_end_datetime
)
from .utils import (
    base_class_name,
    full_class_name,

    convert_size,
    detect_bom,
    determine_encoding,
    json_encode,
    log_memory_usage,
    print_version,
    python_check_version,
    remove_bom,

    requests_response_text_html,
    requests_response_text_xml,

    safe_cast,
    safe_cost,
    safe_dict,
    safe_float,
    safe_int,
    safe_str,

    from_bytes,
    to_bytes,

    urlsafe_b64decode,
    urlsafe_b64encode,

    command_line_request_curl,
    command_line_request_curl_get,
    command_line_request_curl_post,

    create_request_url,
    create_hash_key,

    merge_dicts
)
