#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace tune_mv_integration

import base64
import codecs
import six

# from pprintpp import pprint


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
    result = (value.encode(encoding) if isinstance(value, six.text_type) else value)
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
    result = (value.decode('utf-8') if isinstance(value, six.binary_type) else value)
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


def determine_encoding(file_header):
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
        (codecs.BOM_UTF8, 3, 'UTF-8'),  # '\xef\xbb\xbf'
        (codecs.BOM_UTF16_BE, 2, 'UTF-16BE'),  # '\xfe\xff' -- UTF-16 Big Endian
        (codecs.BOM_UTF16_LE, 2, 'UTF-16LE'),  # '\xff\xfe' -- UTF-16 Little Endian
        (b'\x1f\x8b', 2, 'gzip'),
        (b'\x42\x5a', 2, 'bzip')
    )

    for bom_sig, bom_len, bom_enc in bom_info:
        if file_header.startswith(bom_sig):
            return bom_enc, bom_len

    return 'ANSI', 0  # No BOM


def detect_bom(filename):
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


def remove_bom(filename, newfilename):
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
            with open(file=newfilename, mode='wb+') as newfile_wb:
                newfile_wb.write(contents)

        return bom_enc, bom_len
