# -*- coding: utf-8 -*-
"""
Created on 2016-09-10

@author: joschi <josua.krause@gmail.com>

QuickServer is a quick to use and easy to set up server implementation. It has
the following goals / features and is primarily meant to speed up back end
implementation / iteration:

* serve local files as is with basic black-listing
* provide functionality for dynamic requests
* provide a basic command interpret loop for server commands

The best way to start QuickServer is the `serve_forever` method.
Dynamic requests can be added via the `TYPE_METHOD` annotations where
TYPE is the result type of the request (ie. text, json) and METHOD is the HTTP
method (eg. GET, POST). POST requests can contain JSON encoded form data.
You can bind static paths with the `bind_path` method.

Commands can be added via the `cmd` annotation where the function name is
the command. 'help', 'restart', and 'quit' are built-in commands ready to use.

Note: The server is thread based so all callback functions should be thread-safe.

Please refer to the example folder for usage examples.
"""

from setuptools import setup

from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

# NOTE! steps to distribute:
#$ python setup.py sdist bdist_wheel
#$ twine upload dist/... <- here be the new version!

setup(
    name='quick_server',
    version='0.4.3',
    description='QuickServer is a quick to use and easy to set up server implementation.',
    long_description=long_description,
    url='https://github.com/JosuaKrause/quick_server',
    author='Josua Krause',
    author_email='josua.krause@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='server REST file quick easy',
    packages=['quick_server'],
    install_requires=[],
    extras_require={
        'dev': [],
        'test': [],
    },
    package_data={
        'quick_server': ['favicon.ico', 'worker.js'],
    },
    data_files=[],
)
