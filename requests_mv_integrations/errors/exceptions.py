#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations.errors
"""
TUNE Mv-Integration Errors
"""

import six
# from pprintpp import pprint

from requests_mv_integrations.support import (
    safe_str
)
from requests_mv_integrations.errors import (
    exit_desc,
    exit_name
)
from requests_mv_integrations.errors.exit_code import (
    IntegrationExitCode
)


# @brief TUNE Multiverse Error Base Class
#
# @namespace requests_mv_integrations.TuneRequestBaseError
class TuneRequestBaseError(Exception):
    """TUNE Mv-Integration Exception.
    """
    __error_message = None
    __errors = None
    __exit_code = IntegrationExitCode.MOD_ERR_UNEXPECTED

    __error_status = None
    __error_reason = None
    __error_details = None
    __error_origin = 'Module'
    __error_request_curl = None

    def __init__(
        self,
        error_message=None,
        errors=None,
        exit_code=None,
        error_status=None,
        error_reason=None,
        error_details=None,
        error_origin=None,
        error_request_curl=None
    ):
        if exit_code is not None:
            self.__exit_code = exit_code

        if error_origin is not None:
            self.__error_origin = error_origin

        self.__error_message = self._error_message(
            error_message=error_message,
            exit_code=self.exit_code
        )

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
    def exit_code(self):
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
    def _error_message(
        error_message,
        exit_code
    ):
        error_message_ = None
        exit_code_description_ = exit_desc(exit_code).rstrip('\.')

        error_message_prefix_ = "{}: {}".format(
            exit_code,
            exit_code_description_
        )

        error_message = safe_str(error_message).strip()

        if error_message:
            error_message_ = "%s: '%s'" % (
                error_message_prefix_,
                six.text_type(error_message)
            )
        elif exit_code_description_:
            error_message_ = error_message_prefix_

        return error_message_

    @staticmethod
    def _exit_code(
        exit_code,
        exit_code_default
    ):
        """Prepare exit code.
        """
        exit_code_ = None
        if exit_code:
            exit_code_ = int(exit_code)
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
            error_message += "Reason: '{error_reason}'".format(
                error_reason=self.error_reason
            )
        if self.error_status:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Status: {error_status}".format(
                error_status=self.error_status
            )
        if self.exit_code:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Code: {exit_code}, Name: {exit_name}".format(
                exit_code=self.exit_code,
                exit_name=exit_name(self.exit_code)
            )
        if self.error_details:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Details: {error_details}".format(
                error_details=self.error_details
            )
        if self.errors:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Errors: {errors}".format(
                errors=self.errors
            )

        return "{}: {}".format(
            error_origin,
            error_message
        )

    def to_dict(self):

        dict_ = {
            'error_origin': self.error_origin,
            'exit_code': self.exit_code,
            'exit_desc': exit_desc(self.exit_code),
            'exit_name': exit_name(self.exit_code)
        }

        if self.error_message:
            dict_.update({
                'error_message': self.error_message
            })
        if self.error_status:
            dict_.update({
                'error_status': self.error_status
            })
        if self.error_reason:
            dict_.update({
                'error_reason': self.error_reason
            })
        if self.error_details:
            dict_.update({
                'error_details': self.error_details
            })
        if self.errors:
            dict_.update({
                'errors': self.errors
            })

        return dict_


class TuneRequestError(TuneRequestBaseError):
    pass


class TuneRequestClientError(TuneRequestError):
    pass


class TuneRequestServiceError(TuneRequestError):
    pass


class TuneRequestModuleError(TuneRequestError):
    pass


class ModuleConfigError(TuneRequestModuleError):
    def __init__(self, **kwargs):
        exit_code = kwargs.pop('exit_code', None) or IntegrationExitCode.MOD_ERR_CONFIG
        super(ModuleConfigError, self).__init__(exit_code=exit_code, **kwargs)


class ModuleArgumentError(TuneRequestModuleError):
    def __init__(self, **kwargs):
        exit_code = kwargs.pop('exit_code', None) or IntegrationExitCode.MOD_ERR_ARGUMENT
        super(ModuleArgumentError, self).__init__(exit_code=exit_code, **kwargs)


class ModuleAuthenticationError(TuneRequestModuleError):
    def __init__(self, **kwargs):
        exit_code = kwargs.pop('exit_code', None) or IntegrationExitCode.MOD_ERR_AUTH_ERROR
        error_origin = kwargs.pop('error_origin', None) or 'Authentication'
        super(ModuleAuthenticationError, self).__init__(
            exit_code=exit_code,
            error_origin=error_origin,
            **kwargs
        )