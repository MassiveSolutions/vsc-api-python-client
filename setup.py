#!/usr/bin/env python

import setuptools

setuptools.setup(
    name = 'VscApiClient',
    version = '0.4.0',
    description = 'Client for VSC Core HTTP API',
    author = 'Aleksey Morarash',
    author_email = 'aleksey.morarash@massivesolutions.eu',
    packages = ['VscApiClient'],
    provides = ['VscApiClient'],
    requires = ['ipaddr', 'dns'],
    include_package_data = True,
    zip_safe = True,
    license = 'GPL-2+',
    platforms = 'Platform Independent',
    classifiers = ['Development Status :: 2 - Pre-Alpha',
                   'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
                   'Intended Audience :: Developers',
                   'Operating System :: OS Independent',
                   'Natural Language :: English',
                   'Topic :: Software Development'])
