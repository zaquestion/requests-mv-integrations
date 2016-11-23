#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations.errors

from .error_codes import RequestErrorCode
from .error_desc import (error_desc, error_name)


class RequestBaseError(Exception):

    __error_message = None
    __errors = None
    __exit_code = RequestErrorCode.MOD_ERR_UNEXPECTED
    __error_request_curl = None

    def __init__(self, error_message=None, errors=None, error_code=None, error_request_curl=None):
        if error_message is not None:
            self.__error_message = error_message
        if error_code is not None:
            self.__exit_code = error_code
        self.__errors = errors or None
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
        return self.__exit_code    \

    @property
    def error_request_curl(self):
        """Get property of error request curl.
        """
        return self.__error_request_curl

    def __str__(self):
        """Stringify
        """
        error_message = self.error_message

        if not error_message or len(error_message) == 0:
            error_message = None

        if self.error_code:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Code: {error_code}, Name: {error_name}".format(
                error_code=self.error_code, error_name=error_name(self.error_code)
            )

        if self.errors:
            if error_message:
                error_message += ", "
            else:
                error_message = ""
            error_message += "Errors: {errors}".format(errors=self.errors)

        return error_message

    def to_dict(self):
        dict_ = {
            'error_origin': self.error_origin,
            'error_code': self.error_code,
            'error_desc': error_desc(self.error_code),
            'error_name': error_name(self.error_code)
        }

        if self.error_message:
            dict_.update({'error_message': self.error_message})
        if self.errors:
            dict_.update({'errors': self.errors})

        return dict_


class RequestClientError(RequestBaseError):
    pass


class RequestServiceError(RequestBaseError):
    pass


class RequestModuleError(RequestBaseError):
    pass


class RequestValueError(RequestModuleError):
    """Request Mv Integration: Value error"""

    def __init__(self, **kwargs):
        error_code = kwargs.pop('error_code', None) or RequestErrorCode.MOD_ERR_ARGUMENT
        super(RequestValueError, self).__init__(error_code=error_code, **kwargs)


class RequestAuthenticationError(RequestModuleError):
    """Request Mv Integration: Authentication error"""

    def __init__(self, **kwargs):
        error_code = kwargs.pop('error_code', None) or RequestErrorCode.MOD_ERR_AUTH_ERROR
        super(RequestAuthenticationError, self).__init__(error_code=error_code, **kwargs)
