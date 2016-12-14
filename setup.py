#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  @namespace requests-mv-integrations

from __future__ import with_statement

# To install the tune-mv-integration-python library, open a Terminal shell,
# then run this file by typing:
#
# python setup.py install
#

import sys
import re
from setuptools import setup

REQUIREMENTS = [
    req for req in open('requirements.txt')
    .read().split('\n')
    if req != ''
]

PACKAGES = [
    'requests_mv_integrations',
    'requests_mv_integrations.errors',
    'requests_mv_integrations.exceptions',
    'requests_mv_integrations.support',
    'requests_mv_integrations.support.response'
]

CLASSIFIERS = [
    # How mature is this project? Common values are
    #   3 - Alpha
    #   4 - Beta
    #   5 - Production/Stable
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.0',
    'Programming Language :: Python :: 3.1',
    'Programming Language :: Python :: 3.2',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Topic :: Software Development :: Libraries :: Python Modules'
]

with open('requests_mv_integrations/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

if len(sys.argv) < 2 or sys.argv[1] == 'version':
    print(version)
    sys.exit()

setup(
    name='requests-mv-integrations',
    version=version,
    description='',
    author='TUNE Inc., TuneLab',
    author_email='jefft@tune.com',
    url='https://github.com/TuneLab/requests-mv-integrations',
    download_url='https://github.com/TuneLab/requests-mv-integrations/archive/v{0}.tar.gz'.format(version),
    install_requires=REQUIREMENTS,
    packages=PACKAGES,
    package_dir={'requests-mv-integrations': 'requests-mv-integrations'},
    include_package_data=True,
    license='MIT',
    zip_safe=False,
    classifiers=CLASSIFIERS,
    long_description="""

    -----------------------------------------------------

    """
)
