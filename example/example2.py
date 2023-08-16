#!/usr/bin/env python
# -*- coding: utf-8 -*-
from time import monotonic, sleep
from typing import Any, TypedDict

from quick_server import (
    create_server,
    msg,
    PreventDefaultResponse,
    QuickServerRequestHandler,
    ReqArgs,
    ReqNext,
    Response,
    setup_restart,
    WorkerArgs,
)


ResUptime = TypedDict('ResUptime', {
    "uptime": Any,
})


def run() -> None:
    addr = ""
    port = 8000
    server = create_server((addr, port))
    server.bind_path("/", "..")
    server.add_default_white_list()
    server.favicon_fallback = "../src/quick_server/favicon.ico"
    server.suppress_noise = True
    server.report_slow_requests = True

    server.link_worker_js("/js/worker.js")
    server.max_file_size = 78

    mcs = server.max_chunk_size
    start = monotonic()
    count_uptime = 0

    @server.json_get("/api/uptime/", 1)
    def _uptime(
            req: QuickServerRequestHandler, args: ReqArgs) -> dict[str, Any]:
        nonlocal count_uptime

        # request has one mandatory additional path segment
        sleep(int(args["paths"][0]))
        count_uptime += 1
        res: dict[str, Any] = {
            "uptime": req.log_elapsed_time_string(
                (monotonic() - start) * 1000.0).strip(),
        }

        def convert(value: Any) -> Any:
            try:
                return float(value)
            except ValueError:
                return value

        for (key, value) in args.get("query", {}).items():
            res[key] = [
                convert(v) for v in f"{value}".split(",")
            ] if "," in f"{value}" else convert(value)
        return res

    @server.json_post("/api/upload")
    def _upload_file(
            _req: QuickServerRequestHandler, args: ReqArgs) -> dict[int, str]:
        ix = 0
        res = {}
        for (k, v) in sorted(args["post"].items(), key=lambda e: e[0]):
            res[ix] = f"{k} is {v}"
            ix += 1
        for (name, f) in sorted(args["files"].items(), key=lambda e: e[0]):
            bfcontent = f.read()
            size = len(bfcontent)
            try:
                fcontent = bfcontent.decode("utf-8")
            except UnicodeDecodeError:
                fcontent = repr(bfcontent)
            res[ix] = f"{name} is {size} bytes"
            ix += 1
            for line in fcontent.split("\n"):
                res[ix] = line
                ix += 1
        return res

    @server.json_worker("/api/uptime_worker")
    def uptime_worker(args: WorkerArgs) -> ResUptime:
        nonlocal count_uptime

        msg(f"sleep {int(args['time'])}")
        sleep(int(args["time"]))
        count_uptime += 1
        return {
            "uptime": (monotonic() - start) * 1000.0
        }

    @server.json_worker("/api/message")
    def _message(args: WorkerArgs) -> str:
        if args["split"]:
            server.max_chunk_size = 10
        else:
            server.max_chunk_size = mcs
        sleep(2)
        return "1234567890 the quick brown fox jumps over the lazy dog"

    def check_login(
            _req: QuickServerRequestHandler,
            args: ReqArgs,
            okay: ReqNext) -> ReqNext | dict[str, str]:
        token = args["query"].get("token")
        if token == "secret":
            args["meta"]["username"] = "user"
            return okay
        if token == "default":
            return {
                "name": "other",
            }
        if token == "except":
            raise PreventDefaultResponse(403, "Forbidden")
        return Response("Authentication Required", 401)

    @server.json_get("/api/user_details")
    @server.middleware(check_login)
    def _user_details(
            _req: QuickServerRequestHandler, args: ReqArgs) -> dict[str, str]:
        return {
            "name": args["meta"]["username"],
        }

    def complete_requests(_args: list[str], text: str) -> list[str]:
        return ["uptime"] if "uptime".startswith(text) else []

    @server.cmd(1, complete_requests)
    def requests(args: list[str]) -> None:
        if args[0] != 'uptime':
            msg(f"unknown request: {args[0]}")
        else:
            msg(f"requests made to {args[0]}: {count_uptime}")

    msg(f"starting server at {addr if addr else 'localhost'}:{port}")
    server.serve_forever()
    msg("shutting down..")
    server.server_close()


if __name__ == "__main__":
    setup_restart()
    run()
