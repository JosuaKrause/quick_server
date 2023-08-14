#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=missing-module-docstring
from time import monotonic
from typing import TypedDict

from quick_server import QuickServerRequestHandler, ReqArgs, create_server, msg

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
    # pylint: disable=missing-function-docstring
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
            "version": args.get("segments", {}).get("version"),
        }

    @server.json_get("/api/foo/:foo")
    def _foo(_req: QuickServerRequestHandler, args: ReqArgs) -> ResFoo:
        return {
            "foo": args.get("segments", {}).get("foo"),
        }

    def complete_requests(_args: list[str], text: str) -> list[str]:
        return ["uptime"] if "uptime".startswith(text) else []

    @server.cmd(1, complete_requests)
    def _requests(args: list[str]) -> None:
        if args[0] != "uptime":
            msg("unknown request: {0}", args[0])
        else:
            msg("requests made to {0}: {1}", args[0], count_uptime)

    msg("starting server at {0}:{1}", addr if addr else "localhost", port)
    server.serve_forever()
    msg("shutting down..")
    server.server_close()


if __name__ == "__main__":
    run()
