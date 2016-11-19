#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

from logging import getLogger

import grequests
import requests
from requests.adapters import (HTTPAdapter, DEFAULT_POOLSIZE)
from requests.packages.urllib3.util.retry import Retry

log = getLogger(__name__)


class TuneRequest(object):
    POOL_SIZE = DEFAULT_POOLSIZE
    session = None
    request_buffer = []

    def __init__(
        self,
        retries=3,
        retry_codes=None
    ):
        self.session = requests.session()

        if retry_codes is None:
            set([500, 502, 503, 504])

        self.session.mount(
            'http',
            HTTPAdapter(
                max_retries=Retry(
                    total=retries,
                    backoff_factor=0.1,
                    status_forcelist=retry_codes,
                ),
            ),
        )

    def send(self, method, url, response_hook=None, exception_handler=None, **kwargs):
        response_hook, exception_handler = self.create_hooks(response_hook, exception_handler)

        try:
            return self.session.request(method, url, hooks={'response': response_hook}, **kwargs)
        except Exception as e:
            exception_handler(e)
            return None

    def send_async(self, method, urls, response_hook=None, exception_handler=None, **kwargs):
        response_hook, exception_handler = self.create_hooks(response_hook, exception_handler)

        unsent = [grequests.request(method, url, session=self.session, hooks={'response': response_hook}, **kwargs) for url in urls]
        return grequests.imap(unsent, size=self.POOL_SIZE, exception_handler=exception_handler)

    def response_hook(self, r, *args, **kwargs):
        log.info("{0} {1} {2}".format(r.request.method, r.url, str(r.status_code)))

    def exception_handler(self, r, e):
        log.error("url: {0}".format(r.url))
        raise e

    def create_hooks(self, response_hook=None, exception_handler=None):
        if response_hook is not None:
            def rhook(r, *args, **kwargs):
                response_hook(r, *args, **kwargs)
                self.response_hook(r, *args, **kwargs)
            response_hook = rhook
        else:
            response_hook = self.response_hook

        if exception_handler is not None:
            def ehook(r, e):
                exception_handler(r, e)
                self.exception_handler(r, e)
            exception_handler = ehook
        else:
            exception_handler = self.exception_handler

        return response_hook, exception_handler


def backoff(factor, max_delay):
    sleep_time = 1

    def inner():
        asleep_time = sleep_time * factor
        asleep_time = asleep_time if asleep_time < max_delay else max_delay
        return asleep_time

    return inner
