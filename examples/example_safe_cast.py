#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @copyright 2016 TUNE, Inc. (http://www.tune.com)
#  @namespace requests_mv_integrations

from pprintpp import pprint

from requests_mv_integrations.support import (
    safe_int,
    safe_float,
    safe_str,
)

pprint(safe_int(4))
pprint(safe_float(4))
pprint(safe_str(4))

pprint(safe_int('4'))
pprint(safe_float('4'))
pprint(safe_str('4'))

pprint(safe_int(4.0))
pprint(safe_float(4.0))
pprint(safe_str(4.0))

pprint(safe_int('4.0'))
pprint(safe_float('4.0'))
pprint(safe_str('4.0'))

pprint(safe_int('1.0'))
pprint(safe_int('1'))
pprint(safe_int(1.0))
pprint(safe_int(1.00))
pprint(safe_int(1))

pprint(safe_float('4.1'))
pprint(safe_float('4.12'))
pprint(safe_float('4.123'))
pprint(safe_float('4.123', 4))
pprint(safe_float('4.1234', 4))
pprint(safe_float('4.12345', 4))
pprint(safe_float(4.1))
pprint(safe_float(4.12))
pprint(safe_float(4.123))
pprint(safe_float(4.123, 4))
pprint(safe_float(4.1234, 4))
pprint(safe_float(4.12345, 4))

pprint(safe_int('4.1'))
pprint(safe_int('4.12'))
pprint(safe_int('4.123'))
pprint(safe_int('4.123'))
pprint(safe_int('4.1234'))
pprint(safe_int('4.12345'))
pprint(safe_int(4.1))
pprint(safe_int(4.12))
pprint(safe_int(4.123))
pprint(safe_int(4.123))
pprint(safe_int(4.1234))
pprint(safe_int(4.12345))
