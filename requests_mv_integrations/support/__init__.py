#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

from .bom_encoding import (
    detect_bom,
    get_bom_encoding,
    remove_bom,
)
from .constants import (
    HEADER_CONTENT_TYPE_APP_JSON,
    HEADER_CONTENT_TYPE_APP_URLENCODED,
    HEADER_USER_AGENT,
    __MODULE_SIG__,
    __PYTHON_VERSION__,
    __TIMEZONE_NAME_DEFAULT__,
    __USER_AGENT__,
    __LOGGER_NAME__,
    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES,
)
from .curl import (command_line_request_curl)
from .safe_cast import (
    safe_cast,
    safe_dict,
    safe_float,
    safe_int,
    safe_str,
)
from .response import (
    download_csv_transform_to_json,
    csv_skip_last_row,
    requests_response_text_html,
    requests_response_text_xml,
    validate_response,
    validate_json_response,
    requests_response_json,
    build_response_error_details,
    handle_json_decode_error,
)
from .singleton import (Singleton)
from .utils import (
    base_class_name,
    full_class_name,
    convert_size,
    python_check_version,
)
