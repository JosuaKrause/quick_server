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
"""Starts a quick server that serves static files from the file system."""
import argparse
import sys

from .quick_server import __version__, create_server, msg, setup_restart


if __name__ == "__main__":
    setup_restart()

    parser = argparse.ArgumentParser(
        prog="quick_server", description="Quick Server")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"quick_server version {__version__}")
    parser.add_argument(
        "-a",
        type=str,
        default="localhost",
        help="specifies the server address")
    parser.add_argument(
        "-p",
        type=int,
        default=8080,
        help="specifies the server port")
    parser.add_argument(
        "--www",
        type=str,
        default="..",
        help="the folder to serve files from (defaults to parent folder)")
    args = parser.parse_args()

    addr = args.a
    port = args.p
    www = args.www

    server = create_server((addr, port))
    server.bind_path("/", www)

    server.directory_listing = True
    server.add_default_white_list()
    server.link_empty_favicon_fallback()

    server.suppress_noise = True
    server.report_slow_requests = True

    msg(f"{' '.join(sys.argv)}")
    msg(f"starting server at {addr if addr else 'localhost'}:{port}")
    server.serve_forever()
    msg("shutting down..")
    server.server_close()
