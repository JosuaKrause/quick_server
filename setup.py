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
the command. "help", "restart", and "quit" are built-in commands ready to use.

Note: The server is thread based so all callback functions should be
thread-safe.

Please refer to the example folder for usage examples.
"""

from setuptools import setup  # type: ignore


# NOTE! steps to distribute:
# $ make publish

setup()
