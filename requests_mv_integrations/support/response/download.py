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

log = logging.getLogger(__name__)

python_check_version(__python_required_version__)


def download_csv_transform_to_json(
    self,
    response,
    tmp_directory,
    tmp_json_file_name,
    config_job,
):
    """Download CSV and Transform to JSON

    Args:
        response:
        tmp_directory:
        tmp_csv_file_name:
        request_label:

    Returns:

    """
    log.debug("Download CSV Transform JSON: Start")

    if not os.path.exists(tmp_directory):
        os.mkdir(tmp_directory)

    tmp_json_file_path = \
        "{tmp_directory}/{tmp_json_file_name}".format(
            tmp_directory=tmp_directory,
            tmp_json_file_name=tmp_json_file_name
        )

    if os.path.exists(tmp_json_file_path):
        log.debug("Removing previous JSON File", extra={'file_path': tmp_json_file_path})
        os.remove(tmp_json_file_path)

    line_count = 0
    csv_keys_str = None
    csv_keys_list = None
    csv_keys_list_len = None
    pre_str_line = None

    try:
        with open(file=tmp_json_file_path, mode='w') as dw_file_w:
            for bytes_line in response.iter_lines(chunk_size=4096):
                if bytes_line:  # filter out keep-alive new chunks
                    line_count += 1
                    str_line = bytes_line.decode("utf-8")

                    if line_count == 1:
                        csv_keys_str = str_line
                        csv_keys_list = csv_keys_str.split(',')
                        csv_keys_list_len = len(csv_keys_list)
                        continue
                    elif line_count > 2:
                        dw_file_w.write('\n')

                    if pre_str_line is not None:
                        str_line = pre_str_line + str_line
                        pre_str_line = None

                    csv_values_str = str_line.replace('\n', ' ').replace('\r', ' ')
                    data = io.StringIO(csv_values_str)
                    reader = csv.reader(data, delimiter=',')
                    csv_values_list = None
                    for row in reader:
                        csv_values_list = row

                    csv_values_list_len = len(csv_values_list)

                    if csv_values_list_len < csv_keys_list_len:
                        pre_str_line = str_line
                        continue

                    if csv_keys_list_len != csv_values_list_len:
                        log.error(
                            "Mismatch: CSV Key",
                            extra={
                                'line': line_count,
                                'csv_keys_list_len': csv_keys_list_len,
                                'csv_keys_str': csv_keys_str,
                                'csv_keys_list': csv_keys_list,
                                'csv_values_list_len': csv_values_list_len,
                                'csv_values_str': csv_values_str,
                                'csv_values_list': csv_values_list,
                            }
                        )
                        raise TuneRequestModuleError(
                            error_message="Mismatch: CSV Key '{}': Values '{}'".format(csv_keys_str, csv_values_str),
                            error_code=TuneRequestErrorCodes.REQ_ERR_UNEXPECTED_VALUE
                        )

                    json_dict = {}
                    for idx, csv_key in enumerate(csv_keys_list):
                        csv_value = csv_values_list[idx]
                        json_dict.update({csv_key: csv_value.strip('"')})

                    csv_row_mapped = self.map_data_row(data_row=json_dict, config_job=config_job)

                    json_str = json.dumps(csv_row_mapped)
                    dw_file_w.write(json_str)
                dw_file_w.flush()

    except requests.exceptions.StreamConsumedError as request_ex:
        log.error(
            "Download CSV Transform JSON: Stream Previously Consumed Exception",
            extra={'error_exception': base_class_name(request_ex),
                   'error_details': get_exception_message(request_ex)}
        )
        raise

    except requests.exceptions.RequestException as request_ex:
        log.error(
            "Download CSV Transform JSON: Request Exception",
            extra={'error_exception': base_class_name(request_ex),
                   'error_details': get_exception_message(request_ex)}
        )
        raise

    except Exception as ex:
        log.error(
            "Download CSV Transform JSON: Unexpected Exception",
            extra={'error_exception': base_class_name(ex),
                   'error_details': get_exception_message(ex)}
        )
        raise

    tmp_json_file_size = \
        os.path.getsize(tmp_json_file_path)

    return (tmp_json_file_path, tmp_json_file_size, line_count)


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
