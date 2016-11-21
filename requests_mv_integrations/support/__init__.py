#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

from .binary import (
    from_bytes,
    to_bytes,

    urlsafe_b64decode,
    urlsafe_b64encode,
    detect_bom,
    determine_encoding,
    remove_bom
)
from .constants import (
    HEADER_CONTENT_TYPE_APP_JSON,
    HEADER_CONTENT_TYPE_APP_URLENCODED,
    HEADER_USER_AGENT,

    __MODULE_SIG__,
    __PYTHON_VERSION__,
    __TIMEZONE_NAME_DEFAULT__,
    __INTEGRATION_NAME_DEFAULT__,
    __USER_AGENT__,
    __LOGGER_NAME__,

    REQUEST_RETRY_EXCPS,
    REQUEST_RETRY_HTTP_STATUS_CODES
)
from .curl import (
    command_line_request_curl,
    command_line_request_curl_get,
    command_line_request_curl_post
)
from .headers import (
    create_header_authorization_basic
)
from .response import (
    requests_response_text_html,
    requests_response_text_xml
)
from .safe_cast import (
    safe_cast,
    safe_cost,
    safe_dict,
    safe_float,
    safe_int,
    safe_str
)
from .url import (
    create_request_url,
    is_valid_url_exists,
    is_valid_url_path
)
from .utils import (
    base_class_name,
    full_class_name,

    convert_size,

    json_encode,
    print_version,
    python_check_version
)