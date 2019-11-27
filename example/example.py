#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=no-name-in-module
from typing import Any, List
try:
    from time import clock
except ImportError:
    from time import monotonic as clock
import sys
import os

from quick_server import (  # type: ignore
    create_server,
    msg,
    QuickServerRequestHandler,
    ReqArgs,
)

addr = ''
port = 8000
server = create_server((addr, port))
server.bind_path('/', '..')
server.add_default_white_list()
server.link_empty_favicon_fallback()

start = clock()
count_uptime = 0


@server.json_get('/api/uptime/')
def uptime(req: QuickServerRequestHandler, args: ReqArgs) -> Any:
    global count_uptime

    count_uptime += 1
    return {
        "uptime": req.log_elapsed_time_string(
            (clock() - start) * 1000.0).strip(),
    }


def complete_requests(_args: List[str], text: str) -> List[str]:
    return ["uptime"] if "uptime".startswith(text) else []


@server.cmd(1, complete_requests)
def requests(args: List[str]) -> None:
    if args[0] != 'uptime':
        msg("unknown request: {0}", args[0])
    else:
        msg("requests made to {0}: {1}", args[0], count_uptime)


msg("starting server at {0}:{1}", addr if addr else 'localhost', port)
server.serve_forever()
msg("shutting down..")
server.server_close()
