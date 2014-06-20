#!/usr/bin/env python

from distutils.core import setup, Extension

appid = Extension(
    name='appid',
    sources=[ 'pyappid.c', 'appid.c', 'appid_hexdump.c', 'appid_list.c' ]
    )

setup(
    name='appid',
    version='1.0',
    author='Arbor Networks',
    author_email='appid-dev@googlegroups.com',
    url='http://code.google.com/p/appid/',
    description='Passive application protocol identification',
    ext_modules=[ appid ]
    )

