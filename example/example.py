#!/usr/bin/env python
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
"""An example quick server."""
from time import monotonic
from typing import TypedDict

from quick_server import create_server, msg, QuickServerRequestHandler, ReqArgs


ResUptime = TypedDict('ResUptime', {
    "uptime": str,
})


ResVersion = TypedDict('ResVersion', {
    "version": str | None,
})


ResFoo = TypedDict('ResFoo', {
    "foo": str | None,
})


def run() -> None:
    """Runs the example quick server."""
    addr = ""
    port = 8000
    server = create_server((addr, port))
    server.bind_path("/", "..")
    server.add_default_white_list()
    server.link_empty_favicon_fallback()

    start = monotonic()
    count_uptime = 0

    @server.json_get("/api/uptime/")
    def _uptime(req: QuickServerRequestHandler, _args: ReqArgs) -> ResUptime:
        nonlocal count_uptime

        count_uptime += 1
        return {
            "uptime": req.log_elapsed_time_string(
                (monotonic() - start) * 1000.0).strip(),
        }

    @server.json_get("/api/:version/a/b/c/d")
    def _version(_req: QuickServerRequestHandler, args: ReqArgs) -> ResVersion:
        return {
            "version": args["segments"].get("version"),
        }

    @server.json_get("/api/foo/:foo")
    def _foo(_req: QuickServerRequestHandler, args: ReqArgs) -> ResFoo:
        return {
            "foo": args["segments"].get("foo"),
        }

    def complete_requests(_args: list[str], text: str) -> list[str]:
        return ["uptime"] if "uptime".startswith(text) else []

    @server.cmd(1, complete_requests)
    def requests(args: list[str]) -> None:
        if args[0] != "uptime":
            msg(f"unknown request: {args[0]}")
        else:
            msg(f"requests made to {args[0]}: {count_uptime}")

    msg(f"starting server at {addr if addr else 'localhost'}:{port}")
    server.serve_forever()
    msg("shutting down..")
    server.server_close()


if __name__ == "__main__":
    run()
