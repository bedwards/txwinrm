#!/usr/bin/env python

##############################################################################
#
# Copyright (C) Zenoss, Inc. 2013-2018, all rights reserved.
#
# This content is made available according to terms specified in the LICENSE
# file at the top-level directory of this package.
#
##############################################################################

setup_kwargs = dict(
    name='txwinrm',
    version='1.3.32',
    description='Asynchronous Python WinRM client',
    long_description=open('README.rst').read(),
    license='See LICENSE file',
    author='Zenoss',
    author_email='dbouchillon@zenoss.com',
    url='https://github.com/zenoss/txwinrm',
    packages=['txwinrm', 'txwinrm.request'],
    package_data={'txwinrm.request': ['*.xml']},
    scripts=[
        'scripts/winrm',
        'scripts/winrs',
        'scripts/wecutil',
        'scripts/typeperf',
        'scripts/genkrb5conf'])

try:
    from setuptools import setup
    setup_kwargs['install_requires'] = ['twisted', 'kerberos', 'pyOpenSSL']
    try:
        import argparse
        if False:
            argparse
    except ImportError:
        setup_kwargs['install_requires'].append('argparse')
    setup(**setup_kwargs)
except ImportError:
    from distutils.core import setup
    setup(**setup_kwargs)
