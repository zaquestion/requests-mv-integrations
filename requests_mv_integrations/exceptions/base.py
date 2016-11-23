#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace tune_mv_integration

import six
from requests_mv_integrations.support import (safe_str)
from requests_mv_integrations.errors import (TuneRequestErrorCodes, error_desc, error_name)

# from pprintpp import pprint


# @brief TUNE Multiverse Error Base Class
#
# @namespace tune_mv_integration.TuneRequestBaseError
class TuneRequestBaseError(Exception):
    """TUNE Mv-Integration Exception.
    """
    __error_message = None
    __errors = None
    __exit_code = TuneRequestErrorCodes.REQ_ERR_UNEXPECTED

    __error_status = None
    __error_reason = None
    __error_details = None
    __error_origin = 'Module'
    __error_request_curl = None

    def __init__(
        self,
        error_message=None,
        errors=None,
        error_code=None,
        error_status=None,
        error_reason=None,
        error_details=None,
        error_origin=None,
        error_request_curl=None
    ):
        if error_code is not None:
            self.__exit_code = error_code

        if error_origin is not None:
            self.__error_origin = error_origin

        self.__error_message = self._error_message(error_message=error_message, error_code=self.error_code)

        # Call the base class constructor with the parameters it needs
        super(TuneRequestBaseError, self).__init__(self.error_message)

        self.__errors = errors or None
        self.__error_status = error_status or None
        self.__error_reason = error_reason or None
        self.__error_details = error_details or None
        self.__error_request_curl = error_request_curl or None

    @property
    def error_message(self):
        """Get property of message object.
        """
        return self.__error_message

    @property
    def errors(self):
        """Get property of error object."""
        return self.__errors

    @property
    def error_code(self):
        """Get property of exit code.
        """
        return self.__exit_code

    @property
    def error_reason(self):
        """Get property of response reason for error.
        """
        return self.__error_reason

    @property
    def error_status(self):
        """Get property of response status code.
        """
        return self.__error_status

    @property
    def error_details(self):
        """Get property of error details.
        """
        return self.__error_details

    @property
    def error_origin(self):
        """Get property of error origin.
        """
        return self.__error_origin

    @property
    def error_request_curl(self):
        """Get property of error request curl.
        """
        return self.__error_request_curl

    @error_request_curl.setter
    def error_request_curl(self, value):
        """Set property of error request curl.
        """
        self.__error_request_curl = value

    @staticmethod
    def _error_message(error_message, error_code):
        error_message_ = None
        exit_code_description_ = error_desc(error_code).rstrip('\.')

        error_message_prefix_ = "{}: {}".format(error_code, exit_code_description_)

        error_message = safe_str(error_message).strip()

        if error_message:
            error_message_ = "%s: '%s'" % (error_message_prefix_, six.text_type(error_message))
        elif exit_code_description_:
            error_message_ = error_message_prefix_

        return error_message_

    @staticmethod
    def _exit_code(error_code, exit_code_default):
        """Prepare exit code.
        """
        exit_code_ = None
        if error_code:
            exit_code_ = int(error_code)
        else:
            exit_code_ = exit_code_default

        return exit_code_

    def __str__(self):
        """Stringify
        """
        error_origin = self.error_origin
        error_message = self.error_message

        if not error_message or len(error_message) == 0:
            error_message = None

        if self.error_reason:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Reason: '{error_reason}'".format(error_reason=self.error_reason)
        if self.error_status:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Status: {error_status}".format(error_status=self.error_status)
        if self.error_code:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Code: {error_code}, Name: {error_name}".format(
                error_code=self.error_code, error_name=error_name(self.error_code)
            )
        if self.error_details:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Details: {error_details}".format(error_details=self.error_details)
        if self.errors:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Errors: {errors}".format(errors=self.errors)

        return "{}: {}".format(error_origin, error_message)

    def to_dict(self):

        dict_ = {
            'error_origin': self.error_origin,
            'error_code': self.error_code,
            'error_desc': error_desc(self.error_code),
            'error_name': error_name(self.error_code)
        }

        if self.error_message:
            dict_.update({'error_message': self.error_message})
        if self.error_status:
            dict_.update({'error_status': self.error_status})
        if self.error_reason:
            dict_.update({'error_reason': self.error_reason})
        if self.error_details:
            dict_.update({'error_details': self.error_details})
        if self.errors:
            dict_.update({'errors': self.errors})

        return dict_
