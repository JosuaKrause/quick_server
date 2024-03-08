# -*- coding: utf-8 -*-
#
# Copyright 2024 Josua Krause
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
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

if __name__ == "__main__":
    setup()
