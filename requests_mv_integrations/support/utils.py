#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

"""Helpers: Functions for commonly used utilities.
"""

import base64
import codecs
import copy
import hashlib
import json
import re
import sys
import urllib.parse
import xmltodict

import six
from bs4 import BeautifulSoup

from .constants import (
    HEADER_CONTENT_TYPE_APP_JSON,
    __USER_AGENT__
)


# Print this Docker Job' version.
#
def print_version(name, version):
    """Print Version
    """
    print("Module: {}, Version: {}".format(name, version))


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
            " to use this library, current version is %d.%d.\n"
            % (
                sys.argv[0],
                required_version[0],
                required_version[1],
                current_version[0],
                current_version[1]
            )
        )
        sys.exit(-1)
    return 0


def json_encode(data):
    """JSON Encoding of Data

    Args:
        data:

    Returns:

    """
    return json.dumps(data, separators=(',', ':'))


def to_bytes(value, encoding='ascii'):
    """Converts a string value to bytes, if necessary.

    Unfortunately, ``six.b`` is insufficient for this task since in
    Python2 it does not modify ``unicode`` objects.

    Args:
        value: The string/bytes value to be converted.
        encoding: The encoding to use to convert unicode to bytes. Defaults
                  to "ascii", which will not allow any characters from ordinals
                  larger than 127. Other useful values are "latin-1", which
                  which will only allows byte ordinals (up to 255) and "utf-8",
                  which will encode any unicode that needs to be.

    Returns:
        The original value converted to bytes (if unicode) or as passed in
        if it started out as bytes.

    Raises:
        ValueError if the value could not be converted to bytes.
    """
    result = (value.encode(encoding)
              if isinstance(value, six.text_type) else value)
    if isinstance(result, six.binary_type):
        return result
    else:
        raise ValueError('%r could not be converted to bytes' % (value,))


def from_bytes(value):
    """Converts bytes to a string value, if necessary.

    Args:
        value: The string/bytes value to be converted.

    Returns:
        The original value converted to unicode (if bytes) or as passed in
        if it started out as unicode.

    Raises:
        ValueError if the value could not be converted to unicode.
    """
    result = (value.decode('utf-8')
              if isinstance(value, six.binary_type) else value)
    if isinstance(result, six.text_type):
        return result
    else:
        raise ValueError('%r could not be converted to unicode' % (value,))


def urlsafe_b64encode(raw_bytes):
    """URL Safe Byte 64

    Args:
        raw_bytes:

    Returns:

    """
    raw_bytes = to_bytes(raw_bytes, encoding='utf-8')
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b'=')


def urlsafe_b64decode(b64string):
    """Guard against unicode strings, which base64 can't handle.
    """

    b64string = to_bytes(b64string)
    padded = b64string + b'=' * (4 - len(b64string) % 4)
    return base64.urlsafe_b64decode(padded)


def determine_encoding(
    file_header
):
    """Check file header if it contains byte order mark (BOM)

    Args:
        file_header:

    Returns:

    """
    bom_info = (
        (b'\xc4\x8f\xc2\xbb\xc5\xbc', 6, 'cp1250'),
        (b'\xd0\xbf\xc2\xbb\xd1\x97', 6, 'cp1251'),
        (b'\xc3\xaf\xc2\xbb\xc2\xbf', 6, 'cp1252'),
        (b'\xce\xbf\xc2\xbb\xce\x8f', 6, 'cp1253'),
        (b'\xc3\xaf\xc2\xbb\xc2\xbf', 6, 'cp1254'),
        (b'\xd7\x9f\xc2\xbb\xc2\xbf', 6, 'cp1255'),
        (b'\xc3\xaf\xc2\xbb\xd8\x9f', 6, 'cp1256'),
        (b'\xc4\xbc\xc2\xbb\xc3\xa6', 6, 'cp1257'),
        (b'\xc3\xaf\xc2\xbb\xc2\xbf', 6, 'cp1258'),

        (codecs.BOM_UTF32_BE, 4, 'UTF-32BE'),  # '\x00\x00\xfe\xff' -- UTF-32 Big Endian
        (codecs.BOM_UTF32_LE, 4, 'UTF-32LE'),  # '\xff\xfe\x00\x00' -- UTF-32 Little Endian
        (b'\x50\x4b\x03\x04', 4, 'pkzip'),

        (codecs.BOM_UTF8, 3, 'UTF-8'),         # '\xef\xbb\xbf'

        (codecs.BOM_UTF16_BE, 2, 'UTF-16BE'),  # '\xfe\xff' -- UTF-16 Big Endian
        (codecs.BOM_UTF16_LE, 2, 'UTF-16LE'),  # '\xff\xfe' -- UTF-16 Little Endian
        (b'\x1f\x8b', 2, 'gzip'),
        (b'\x42\x5a', 2, 'bzip')
    )

    for bom_sig, bom_len, bom_enc in bom_info:
        if file_header.startswith(bom_sig):
            return bom_enc, bom_len

    return 'ANSI', 0  # No BOM


def detect_bom(
    filename
):
    """Get byte order mark (BOM) from File

    Args:
        filename:

    Returns:

    """
    with open(filename, 'rb') as file_rb:
        # read first 4 bytes
        file_header = file_rb.read(6)
        bom_enc, bom_len = determine_encoding(file_header)

    bom_header = str(file_header)
    return bom_enc, bom_len, bom_header


def remove_bom(
    filename,
    newfilename
):
    """Remove byte order mark (BOM) from File

    Args:
        filename:
        newfilename:

    Returns:

    """
    with open(filename, 'rb') as file_rb:
        # read first 4 bytes
        file_header = file_rb.read(6)
        bom_enc, bom_len = determine_encoding(file_header)

        if bom_len > 0:
            file_rb.seek(0)
            file_rb.read(bom_len)

            # copy the rest of file
            contents = file_rb.read()
            with open(
                file=newfilename,
                mode='wb+'
            ) as newfile_wb:
                newfile_wb.write(contents)

        return bom_enc, bom_len


def convert_size(
    size,
    precision=2
):
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


def base_class_name(obj):
    return obj.__class__.__name__


def full_class_name(obj):
    try:
        return obj.__module__ + "." + obj.__class__.__name__
    except Exception as ex:
        return obj.__class__.__name__


def safe_cost(val):
    return safe_float(val, ndigits=4)


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


def command_line_request_curl(
    request_method,
    request_url,
    request_headers,
    request_data=None,
    request_json=None,
    request_timeout=60,
    request_allow_redirects=True
):
    """Command Line: Build Request cUrl

    Args:
        request_method:
        request_url:
        request_headers:
        request_data:
        request_timeout:
        request_allow_redirects:

    Returns:

    """
    key_user_agent = 'User-Agent'
    header_user_agent = {
        key_user_agent: __USER_AGENT__
    }

    if request_headers:
        if key_user_agent not in request_headers:
            request_headers.update(
                header_user_agent
            )
    else:
        request_headers = header_user_agent

    request_method = request_method.upper()

    command = (
        "curl"
        " --verbose"
        " -X {request_method}"
        " -H {headers}"
        " --connect-timeout {timeout}"
    )

    if request_allow_redirects:
        command += " -L"

    if request_method == 'GET':
        if request_data:
            params = request_data.split("&")

            command += (
                " -G"
                " --data {params}"
                " '{url}'"
            )

            params = [
                "'{0}'".format(urllib.parse.unquote(param)) for param in params
            ]
            params = " --data ".join(params)

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                params=params,
                timeout=request_timeout,
                url=request_url
            )
        else:
            command += (
                " '{url}'"
            )

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                timeout=request_timeout,
                url=request_url
            )

    elif request_method == 'POST':
        if request_data:
            command += (
                " --data '{data}'"
                " '{url}'"
            )

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=request_data,
                timeout=request_timeout,
                url=request_url
            )
        elif request_json:
            command += (
                " --data '{data}'"
                " '{url}'"
            )

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=json.dumps(request_json),
                timeout=request_timeout,
                url=request_url
            )
        else:
            command += (
                " '{url}'"
            )

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)
            return command.format(
                request_method=request_method,
                headers=headers,
                timeout=request_timeout,
                url=request_url
            )

    elif request_method == 'PUT':
        if request_data:
            rows = re.split(r'\n', request_data)
            row = None
            if rows and len(rows) > 0:
                row = rows[0]

            command += (
                " --data '{data}'"
                " '{url}'"
            )

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)

            return command.format(
                request_method=request_method,
                headers=headers,
                data=row,
                timeout=request_timeout,
                url=request_url
            )
        else:
            command += (
                " '{url}'"
            )

            headers = [
                "'{0}: {1}'".format(k, v) for k, v in request_headers.items()
            ]
            headers = " -H ".join(headers)
            return command.format(
                request_method=request_method,
                headers=headers,
                timeout=request_timeout,
                url=request_url
            )


def command_line_request_curl_get(
    request_url,
    request_params,
    request_headers=None,
    request_timeout=60,
    request_allow_redirects=True
):
    """Command Line: Build Request cUrl for GET method

    Args:
        request_url:
        request_params:
        request_headers:
        request_timeout:
        request_allow_redirects:

    Returns:

    """
    if request_headers is None:
        request_headers = copy.deepcopy(HEADER_CONTENT_TYPE_APP_JSON)

    request_params_encoded = None
    if request_params:
        request_params_encoded = \
            urllib.parse.urlencode(request_params)

    return command_line_request_curl(
        request_method="GET",
        request_url=request_url,
        request_data=request_params_encoded,
        request_headers=request_headers,
        request_timeout=request_timeout,
        request_allow_redirects=request_allow_redirects
    )


def command_line_request_curl_post(
    request_url,
    request_params,
    request_headers=None,
    request_timeout=60,
    request_data=None,
    request_allow_redirects=True
):
    """Command Line: Build Request cUrl for POST method

    Args:
        request_url:
        request_params:
        request_headers:
        request_timeout:
        request_data:
        request_allow_redirects:

    Returns:

    """
    if request_headers is None:
        request_headers = copy.deepcopy(HEADER_CONTENT_TYPE_APP_JSON)

    if request_params:
        request_url += "?" + urllib.parse.urlencode(request_params)

    return command_line_request_curl(
        request_method="POST",
        request_url=request_url,
        request_headers=request_headers,
        request_data=request_data,
        request_timeout=request_timeout,
        request_allow_redirects=request_allow_redirects
    )


def create_hash_key(
    key
):
    if key is None:
        raise ValueError(
            "Parameter 'key' not defined."
        )

    if isinstance(key, str):
        key_str = key
    if isinstance(key, dict):
        key_str = json.dumps(key, sort_keys=True)

    return hashlib.md5(key_str.encode('utf-8')).hexdigest()


def requests_response_text_html(
    response
):
    """Get HTML Text only

    Args:
        response:

    Returns:

    """
    assert response

    response_content_html_lines = None
    response_content_type = response.headers.get('Content-Type', None)

    if response_content_type.startswith('text/html'):
        try:
            response_content_html = response.text
            soup = BeautifulSoup(response_content_html, 'html.parser')
            for elem in soup.findAll(['script', 'style']):
                elem.extract()
            response_content_html_text = soup.get_text()
            response_content_html_lines = response_content_html_text.splitlines()
            response_content_html_lines = \
                [item.strip() for item in response_content_html_lines]
            response_content_html_lines = \
                [x for x in response_content_html_lines if x != '']
        except Exception as ex:
            raise ValueError(
                "Failed to parse text/html",
                errors=ex
            )
    else:
        raise ValueError(
            "Unexpected 'Content-Type': '{}'".format(
                response_content_type
            )
        )

    return response_content_html_lines


def requests_response_text_xml(
    response
):
    """Get HTML Text only

    Args:
        response:

    Returns:

    """
    assert response

    response_http_status_code = response.status_code
    response_content_type = response.headers.get('Content-Type', None)

    response_content = response.text
    response_content_length = len(response_content)

    xml_json = None
    if response_content_type.startswith('text/xml'):
        if response_http_status_code == 200 and \
                response_content_length > 0 and \
                response_content:
            xml_dictionary = xmltodict.parse(response_content)
            xml_json = json.loads(json.dumps(xml_dictionary))

    else:
        raise ValueError(
            "Unexpected 'Content-Type': '{}'".format(
                response_content_type
            )
        )

    return xml_json

