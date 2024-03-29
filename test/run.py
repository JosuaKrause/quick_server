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
"""Runs various tests for quick server."""
import json
import os
import select
import sys
import time
from fcntl import F_GETFL, F_SETFL, fcntl
from subprocess import PIPE, Popen
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.response import addinfourl


NL = "\n"


def run(*, python: list[str], skip: int) -> None:
    """
    Runs the tests.

    Args:
        python (list[str]): The invocation command of the python interpreter.
        skip (int): Skips the given number of tests.
    """
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    def get_time() -> float:
        return time.monotonic()

    def do_sleep(seconds: float, ensure: bool = False) -> None:
        if not ensure:
            time.sleep(seconds)
            return
        now = get_time()
        while get_time() - now < seconds:
            time.sleep(seconds)

    def convert_b(bdata: bytes) -> str:
        return repr(bdata).lstrip("b").strip("'\"").replace("\\", "\\\\")

    def to_str(msg: str | bytes) -> str:
        if isinstance(msg, memoryview):
            bmsg = msg.tobytes()
        elif isinstance(msg, bytearray):
            bmsg = msg
        elif isinstance(msg, bytes):
            bmsg = msg
        else:
            return msg
        try:
            return bmsg.decode("utf-8")
        except UnicodeDecodeError:
            return "\n".join([repr(m) for m in bmsg.split(b"\n")])

    def print_msg(prefix: str, msg: str) -> None:
        for line in msg.split("\n"):
            print(f"[{prefix}] {line}", file=sys.stderr)

    def status(msg: str) -> None:
        print_msg("TEST", msg)

    def note(msg: str) -> None:
        print_msg("NOTE", msg)

    def fail(msg: str) -> bool:  # pragma: no cover
        status(msg)  # pragma: no cover
        status("test failed!")  # pragma: no cover
        return False  # pragma: no cover

    def check_stream(
            text: str,
            requireds: list[str],
            fails: list[str],
            name: str) -> bool:
        requireds = requireds[:]
        for line in text.split("\n"):
            for failout in fails:
                if failout in line:
                    return fail(  # pragma: no cover
                        "invalid line encountered:"  # pragma: no cover
                        f"\n{line}\ncontains {failout}")  # pragma: no cover
            while len(requireds) and requireds[0] in line:
                requireds.pop(0)
        if len(requireds):
            status(f"complete output:\n{text}\n")  # pragma: no cover
            return fail(  # pragma: no cover
                "not all required lines were "  # pragma: no cover
                f"found in {name}:\n{NL.join(requireds)}")  # pragma: no cover
        return True

    def cmd_server_run(
            *,
            commands: list[bytes],
            required_out: list[str],
            fail_out: list[str],
            required_err: list[str],
            fail_err: list[str],
            exit_code: int = 0) -> bool:
        with Popen(
                python + ["example.py"],
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as p:
            boutput, berror = p.communicate(b"\n".join(commands) + b"\nquit\n")
            output = boutput.decode("utf-8")
            error = berror.decode("utf-8")
            if p.returncode != exit_code:
                report_output(  # pragma: no cover
                    output.split("\n"), error.split("\n"))  # pragma: no cover
                return fail(  # pragma: no cover
                    f"wrong exit code {p.returncode} "  # pragma: no cover
                    f"expected {exit_code}")  # pragma: no cover
            if not check_stream(output, required_out, fail_out, "STD_OUT"):
                return False  # pragma: no cover
            if not check_stream(error, required_err, fail_err, "STD_ERR"):
                return False  # pragma: no cover
            return True

    def access_curl(
            *,
            url: str,
            fields: list[str],
            required_out: list[str],
            fail_out: list[str],
            required_err: list[str],
            fail_err: list[str],
            exit_code: int = 0) -> bool:
        full_url = f"http://localhost:8000/{url}"
        call = ["curl", "--output", "-"]
        for f in fields:
            call.append("-F")
            call.append(f)
        call.append(full_url)
        with Popen(
                call,
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as p:
            boutput, berror = p.communicate()
            output = boutput.decode("utf-8")
            error = berror.decode("utf-8")
            if p.returncode != exit_code:
                report_output(  # pragma: no cover
                    output.split("\n"), error.split("\n"))  # pragma: no cover
                return fail(  # pragma: no cover
                    f"wrong exit code {p.returncode} "  # pragma: no cover
                    f"expected {exit_code}")  # pragma: no cover
            if not check_stream(output, required_out, fail_out, "STD_OUT"):
                return False  # pragma: no cover
            if not check_stream(error, required_err, fail_err, "STD_ERR"):
                return False  # pragma: no cover
            return True

    def curl_server_run(
            probes: list[Any],
            script: str = "example.py") -> bool:
        done = False
        with Popen(
                python + [script],
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as p:
            try:
                do_sleep(1)  # give the server some time to wake up
                for parr in probes:
                    if not access_curl(
                            url=parr[0],
                            fields=parr[1],
                            required_out=parr[2],
                            fail_out=parr[3],
                            required_err=parr[4],
                            fail_err=parr[5],
                            exit_code=parr[6] if len(parr) > 6 else 0):
                        return False  # pragma: no cover
                done = True
            finally:
                boutput, berr = p.communicate(b"quit\n")
                output = boutput.decode("utf-8")
                err = berr.decode("utf-8")
                if not done:
                    report_output(  # pragma: no cover
                        output.split("\n"),  # pragma: no cover
                        err.split("\n"))  # pragma: no cover
                do_sleep(1)
                if p.poll() is None:  # pragma: no cover
                    status(
                        "WARNING: server takes "
                        "unusually long to terminate -- "
                        "coverage might report incorrect results")
                    p.terminate()
                    do_sleep(3)
                    if p.poll() is None:
                        status("WARNING: killed server")
                        p.kill()
        return True

    user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64)"

    def access_url(
            parr: list[Any],
            post: dict[str, Any] | None = None,
            json_response: dict[str, Any] | None = None) -> bool:
        url = f"http://localhost:8000/{parr[0]}"
        status_code = parr[1]
        rest = parr[2] if len(parr) > 2 else None
        headers = {
            "User-Agent": user_agent,
        }
        if rest is not None and "eTag" in rest:
            headers["if-none-match"] = rest["eTag"]
        req = Request(url, headers=headers)
        if post is not None:
            post_str = json.dumps(
                post, indent=2, sort_keys=True, allow_nan=False)
            req.add_header("Content-Type", "application/json")
            req.add_header("Content-Length", f"{len(post_str)}")
            req.data = post_str.encode("utf-8")

        def handle(response: addinfourl) -> bool:
            if rest is not None and "url" in rest:
                expected_url = f"http://localhost:8000/{rest['url']}"
                if response.geturl() != expected_url:
                    bts = to_str(response.read())
                    status(  # pragma: no cover
                        f"HEADERS:\n{response.headers}\n"  # pragma: no cover
                        f"BODY:\n{bts}\n")  # pragma: no cover
                    return fail(  # pragma: no cover
                        "redirection failed! "  # pragma: no cover
                        f"expected \"{expected_url}\" "  # pragma: no cover
                        f"got \"{response.geturl()}\"")  # pragma: no cover
            if response.code != status_code:
                bts = to_str(response.read())
                status(  # pragma: no cover
                    f"HEADERS:\n{response.headers}\n"  # pragma: no cover
                    f"BODY:\n{bts}\n")  # pragma: no cover
                return fail(  # pragma: no cover
                    f"{url} responded with "  # pragma: no cover
                    f"{response.code} "  # pragma: no cover
                    f"({status_code} expected)")  # pragma: no cover
            if json_response is not None:
                json_response["response"] = json.loads(response.read())
            return True

        try:
            with urlopen(req) as response:
                return handle(response)
        except HTTPError as e:
            return handle(e)

    def url_server_run(probes: list[Any], script: str = "example.py") -> bool:
        done = False
        with Popen(
                python + [script],
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as p:
            try:
                do_sleep(1)  # give the server some time to wake up
                for parr in probes:
                    if not access_url(parr):
                        return False  # pragma: no cover
                done = True
            finally:
                boutput, berr = p.communicate(b"quit\n")
                output = boutput.decode("utf-8")
                err = berr.decode("utf-8")
                if not done:
                    report_output(  # pragma: no cover
                        output.split("\n"),  # pragma: no cover
                        err.split("\n"))  # pragma: no cover
                do_sleep(1)
                if p.poll() is None:  # pragma: no cover
                    status(
                        "WARNING: server takes unusually long to terminate -- "
                        "coverage might report incorrect results")
                    p.terminate()
                    do_sleep(3)
                    if p.poll() is None:
                        status("WARNING: killed server")
                        p.kill()
        return True

    def url_response_run(
            probes: list[tuple[str, int, dict[str, str] | None]],
            script: str = "example.py") -> bool:
        done = False
        with Popen(
                python + [script],
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as p:
            try:
                do_sleep(1)  # give the server some time to wake up
                for parr in probes:
                    expect_obj = parr[2]
                    json_res: dict[str, Any] | None = \
                        {} if expect_obj is not None else None
                    if not access_url(
                            [parr[0], parr[1]], json_response=json_res):
                        return False  # pragma: no cover
                    if expect_obj is not None:
                        assert json_res is not None
                        obj = json_res["response"]
                        if sorted(obj.keys()) != sorted(expect_obj.keys()):
                            return fail(  # pragme: no cover
                                "response doesnt match: "
                                f"{obj} != {expect_obj}")
                        for (key, value) in expect_obj.items():
                            if obj[key] != value:
                                return fail(  # pragme: no cover
                                    "response doesnt match: "
                                    f"{obj} != {expect_obj}")
                done = True
            finally:
                boutput, berr = p.communicate(b"quit\n")
                output = boutput.decode("utf-8")
                err = berr.decode("utf-8")
                if not done:
                    report_output(  # pragma: no cover
                        output.split("\n"),  # pragma: no cover
                        err.split("\n"))  # pragma: no cover
                do_sleep(1)
                if p.poll() is None:  # pragma: no cover
                    status(
                        "WARNING: server takes unusually long to terminate -- "
                        "coverage might report incorrect results")
                    p.terminate()
                    do_sleep(3)
                    if p.poll() is None:
                        status("WARNING: killed server")
                        p.kill()
        return True

    def access_worker(
            url: str,
            args: dict[str, Any],
            expected_keys: list[str],
            max_tries: int,
            force_token: bool | None) -> str:

        def rebuild(keys: list[str]) -> str:
            res = ""
            for k in keys:
                ans: dict[str, Any] = {}
                if not access_url(
                        [url, 200],
                        post={
                            "action": "cargo",
                            "token": k,
                        },
                        json_response=ans):
                    raise ValueError(  # pragma: no cover
                        "Error collecting results!")  # pragma: no cover
                ans = ans["response"]
                if ans["token"] != k:
                    raise ValueError(f"Token mismatch {ans['token']} != {k}")
                res += ans["result"]
            return res

        cmd: dict[str, Any] = {
            "action": "start",
            "payload": args,
        }
        tries = 0
        max_tries = max(max_tries, 0)
        while True:
            answer: dict[str, Any] = {}
            if tries > max_tries:
                cmd = {
                    "action": "stop",
                    "token":
                        cmd["token"] if force_token is None else force_token,
                }
            if not access_url([url, 200], post=cmd, json_response=answer):
                return "err"  # pragma: no cover
            if max_tries > 0:
                tries += 1  # NOTE: only increment tries if we have a maximum
            answer = answer["response"]
            cmd = {
                "action": "get",
                "token":
                    answer["token"] if force_token is None else force_token,
            }
            if answer["done"]:
                if answer["result"] is not None:
                    if answer["continue"]:
                        res = rebuild(answer["result"])
                    else:
                        res = answer["result"]
                    for k in expected_keys:
                        if k not in res:
                            return "err"  # pragma: no cover
                    return "normal"
            if not answer["continue"]:
                return "cancel"
            do_sleep(0.1)  # don't spam the server

    def worker_server_run(
            probes: list[Any], script: str = "example.py") -> bool:
        done = False
        with Popen(
                python + [script],
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as p:
            try:
                do_sleep(1)  # give the server some time to wake up
                if not access_url(["js/worker.js", 200]):
                    return False  # pragma: no cover
                for probe in probes:
                    if access_worker(*probe[:-1]) != probe[-1]:
                        return False  # pragma: no cover
                done = True
            finally:
                boutput, berr = p.communicate(b"quit\n")
                output = boutput.decode("utf-8")
                err = berr.decode("utf-8")
                if not done:
                    report_output(  # pragma: no cover
                        output.split("\n"),  # pragma: no cover
                        err.split("\n"))  # pragma: no cover
                do_sleep(1)
                if p.poll() is None:  # pragma: no cover
                    status(
                        "WARNING: server takes unusually long to terminate -- "
                        "coverage might report incorrect results")
                    p.terminate()
                    do_sleep(3)
                    if p.poll() is None:
                        status("WARNING: killed server")
                        p.kill()
        return True

    def report_output(  # pragma: no cover
            output: list[str], error: list[str]) -> None:  # pragma: no cover
        status("STD_OUT>>>")  # pragma: no cover
        for s in output:  # pragma: no cover
            status(f"{s.rstrip()}")  # pragma: no cover
        status("<<<STD_OUT")  # pragma: no cover
        status("STD_ERR>>>")  # pragma: no cover
        for s in error:  # pragma: no cover
            status(f"{s.rstrip()}")  # pragma: no cover
        status("<<<STD_ERR")  # pragma: no cover

    def cmd_url_server_run(
            actions: list[list[Any]],
            required_out: list[str],
            fail_out: list[str],
            required_err: list[str],
            fail_err: list[str],
            exit_code: int = 0,
            script: str = "example.py") -> bool:
        output: list[str] = []
        error: list[str] = []

        def read_all(swrite: str) -> None:
            assert p is not None
            write = swrite.encode("utf-8")
            written = 0
            while True:
                sels = select.select([p.stdout, p.stderr], [p.stdin], [])
                if len(sels[0]) == 0 and written >= len(write):
                    break
                for s in sels[0]:
                    if s == p.stdout:
                        assert p.stdout is not None
                        output.append(
                            os.read(p.stdout.fileno(), 1024).decode("utf-8"))
                    if s == p.stderr:
                        assert p.stderr is not None
                        error.append(
                            os.read(p.stderr.fileno(), 1024).decode("utf-8"))
                try:
                    for s in sels[1]:
                        written += os.write(s.fileno(), write[written:])
                except OSError as e:  # pragma: no cover
                    if e.errno == 32:
                        report_output(output, error)
                    raise e

        p = None
        with Popen(
                python + [script],
                cwd="../example",
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE) as proc:
            try:
                assert proc.stdin is not None
                assert proc.stdout is not None
                assert proc.stderr is not None
                # make pipes non-blocking
                flags = fcntl(proc.stdin, F_GETFL)
                fcntl(proc.stdin, F_SETFL, flags | os.O_NONBLOCK)
                flags = fcntl(proc.stdout, F_GETFL)
                fcntl(proc.stdout, F_SETFL, flags | os.O_NONBLOCK)
                flags = fcntl(proc.stderr, F_GETFL)
                fcntl(proc.stderr, F_SETFL, flags | os.O_NONBLOCK)
                # start-up done
                p = proc
                read_all("")
                do_sleep(1)  # give the server some time to wake up
                read_all("")
                for a in actions:
                    if a[0] == "cmd":
                        status(f"command: {a[1]}")
                        cmd = a[1] + "\n"
                        read_all(cmd)
                        if cmd == "restart\n":
                            read_all("")
                            do_sleep(1)  # give the server some time to restart
                            read_all("")
                    elif a[0] == "url":
                        status(f"url: {a[1]}")
                        a.pop(0)
                        if not access_url(a):  # pragma: no cover
                            read_all("")
                            report_output(output, error)
                            return False
                        read_all("")
                    else:  # pragma: no cover
                        return fail(f"unknown action {a[0]}")
                read_all("")
                do_sleep(1)
            finally:
                okay = True
                if p is not None:
                    read_all("quit\n")
                    do_sleep(1)
                    if p.poll() is None:  # pragma: no cover
                        status(
                            "WARNING: server takes unusually "
                            "long to terminate -- "
                            "coverage might report incorrect results")
                        p.terminate()
                        do_sleep(3)
                        if p.poll() is None:
                            status("WARNING: killed server")
                            p.kill()
                    elif p.returncode != exit_code:
                        okay = fail(  # pragma: no cover
                            f"wrong exit code "  # pragma: no cover
                            f"{p.returncode} "  # pragma: no cover
                            f"expected {exit_code}")  # pragma: no cover
                else:  # pragma: no cover
                    if proc.poll() is None:
                        status("WARNING: kill server during start-up")
                        proc.kill()
        if not okay:
            return False
        output_str = "".join(output)
        error_str = "".join(error)
        if not check_stream(output_str, required_out, fail_out, "STD_OUT"):
            return False  # pragma: no cover
        if not check_stream(error_str, required_err, fail_err, "STD_ERR"):
            return False  # pragma: no cover
        return True

    def token_test() -> bool:
        # pylint: disable=import-outside-toplevel
        from quick_server import QuickServer

        qserve = QuickServer(("", 0))
        tkn = qserve.create_token()
        note(f"time: {get_time()}")

        def chk(name: str, expire: float, live: bool) -> bool:
            # pylint: disable=protected-access

            with qserve.get_token_obj(name, expire, readonly=True) as obj:
                if live and "foo" not in obj:
                    note(f"time: {get_time()}")
                    note(f"{qserve._token_handler}")
                    return fail(f"\"{name}\" expected to live: {obj}")
                if not live and "foo" in obj:
                    note(f"time: {get_time()}")
                    note(f"{qserve._token_handler}")
                    return fail(f"\"{name}\" should be cleared: {obj}")
                return True

        with qserve.get_token_obj(tkn, 0.1) as tmp:
            tmp["foo"] = True
        with qserve.get_token_obj("a", 0) as tmp:
            tmp["foo"] = True
        if not chk(tkn, 0.1, True):
            return False
        if not chk("a", 0, False):
            return False
        note(f"wait: {get_time()}")
        do_sleep(0.2, ensure=True)
        note(f"time: {get_time()}")
        with qserve.get_token_obj("b", None) as tmp:
            tmp["foo"] = True
        if not chk(tkn, 0.1, False):
            return False
        if not chk("b", 0.1, True):
            return False
        note(f"wait: {get_time()}")
        do_sleep(0.2, ensure=True)
        note(f"time: {get_time()}")
        if not chk("b", 0.1, False):
            return False
        return True

    note(f"python: {' '.join(python)}")
    if skip < 1:
        note("basic command check")
        if not cmd_server_run(
                commands=[
                    b"requests uptime",
                ],
                required_out=[],
                fail_out=[],
                required_err=[
                    "requests made to uptime: 0",
                ],
                fail_err=[]):
            sys.exit(1)  # pragma: no cover
    if skip < 2:
        note("url request checks")
        if not url_server_run([
                    # the redirection will not be visible
                    ["example", 200, {"url": "example/"}],
                    ["example/", 200],
                    ["example/index.html", 200],
                    ["example/nothing_here.txt", 404],
                    ["favicon.ico", 200],
                    ["api/uptime/", 200],
                    ["favicon.ico", 304, {"eTag": "8f471f65"}],
                    ["favicon.ico", 200, {"eTag": "deadbeef"}],
                    ["/", 404],
                    ["/../", 404],
                    ["example/example.py", 404],
                    [".git/", 404],
                    [".travis.yml", 404],
                    ["example/", 304, {"eTag": "5a73b4a0"}],
                ]):
            sys.exit(2)  # pragma: no cover
    if skip < 3:
        note("restart test")
        if not cmd_url_server_run([
                    ["url", "example/", 200],
                    ["cmd", "restart"],
                    ["url", "example/", 200],
                    ["cmd", "restart"],
                    ["url", "example/", 200],
                ], [], [], [
                    "starting server at localhost:8000",
                    "\"GET /example/ HTTP/1.1\"",
                    "shutting down..",
                    "starting server at localhost:8000",
                    "\"GET /example/ HTTP/1.1\"",
                    "shutting down..",
                    "starting server at localhost:8000",
                    "\"GET /example/ HTTP/1.1\"",
                ], [
                    "Exception KeyError: KeyError(",
                ]):
            sys.exit(3)  # pragma: no cover
    if skip < 4:
        note("api test")
        if not cmd_url_server_run([
                    ["cmd", "requests uptime"],
                    ["url", "api/uptime/", 200],
                    ["cmd", "requests uptime"],
                ], [], [], [
                    "starting server at localhost:8000",
                    "requests made to uptime: 0",
                    "\"GET /api/uptime/ HTTP/1.1\"",
                    "requests made to uptime: 1",
                ], []):
            sys.exit(4)  # pragma: no cover
    if skip < 5:
        note("restart loop test")
        if not cmd_url_server_run(
                actions=[
                    ["url", "api/uptime/6", 200],
                    ["cmd", "restart"],
                    ["url", "api/uptime/7/", 200],
                    ["cmd", "restart"],
                    ["url", "api/uptime/8/", 200],
                ],
                required_out=[],
                fail_out=[],
                required_err=[
                    "starting server at localhost:8000",
                    (
                        "request takes longer than expected: "
                        "\"GET /api/uptime/6\""
                    ),
                    "shutting down..",
                    "starting server at localhost:8000",
                    (
                        "request takes longer than expected: "
                        "\"GET /api/uptime/7/\""
                    ),
                    "shutting down..",
                    "starting server at localhost:8000",
                    (
                        "request takes longer than expected: "
                        "\"GET /api/uptime/8/\""
                    ),
                ],
                fail_err=[
                    # the server is not supposed to output normal requests
                    "] \"GET",
                    "Exception KeyError: KeyError(",
                ],
                script="example2.py"):
            sys.exit(5)  # pragma: no cover
    if skip < 6:
        note("special value responses")
        if not url_server_run([
                    ["api/uptime/0/?foo=1", 200],
                    ["api/uptime/0/?bar=nan", 200],
                    ["api/uptime/0/?baz=inf", 200],
                    ["api/uptime/0/?fub=-inf&foo=1&bar=1,2,3&baz=string", 200],
                    ["favicon.ico", 200],  # test favicon as well
                ], script="example2.py"):
            sys.exit(6)  # pragma: no cover
    if skip < 7:
        note("worker")
        if not worker_server_run([
                    [
                        "api/uptime_worker", {"time": 1},
                        ["uptime"], -1, None, "normal",
                    ], [
                        "api/uptime_worker", {"time": 0},
                        ["uptime"], 1, None, "normal",
                    ], [
                        "api/uptime_worker", {"time": 1},
                        ["uptime"], 1, None, "cancel",
                    ], [
                        "api/uptime_worker", {"time": 1},
                        None, -1, 0, "cancel",
                    ],
                ], script="example2.py"):
            sys.exit(7)  # pragma: no cover
    if skip < 8:
        note("file uploads")
        if not curl_server_run(
                [
                    # url, fields, required_out, fail_out,
                    # required_err, fail_err
                    [
                        "api/upload",
                        ["foo=@test.upload"],
                        [
                            "foo is 33 bytes",
                            "example file",
                            "meaningless content",
                            "\"\"",
                        ], [
                            "--",
                            "Content-Disposition",
                        ], [], [],
                    ], [
                        "api/upload",
                        ["file=@example2.py"],
                        [
                            "<body>",
                            "413",
                            "Uploaded file is too large!",
                        ], [
                            "--",
                            "Content-Disposition",
                            "#!/usr/bin/env python",
                            "# -*- coding: utf-8 -*-",
                            "from time import clock, sleep",
                        ], [], [],
                    ], [
                        "api/upload",
                        [
                            "name=foo", "abc=@test.upload",
                            "bin=@binary.upload", "def=ghi",
                        ], [
                            "def is ghi",
                            "name is foo",
                            "abc is 33 bytes",
                            "example file",
                            "meaningless content",
                            "\"\"",
                            "bin is 78 bytes",
                            convert_b(
                                b"\x00\x00\x01\x00\x01\x00\x01\x01"
                                b"\x02\x00\x01\x00\x01\x00\x38\x00"),
                            convert_b(
                                b"\xff\xff\xff\x00\x00\x00\x00\x00"
                                b"\x00\x00\x00\x00\x00\x00\x00\x00"),
                        ], [
                            "--",
                            "Content-Disposition",
                        ], [], [],
                    ],
                ], script="example2.py"):
            sys.exit(8)  # pragma: no cover
    if skip < 9:
        note("split worker")
        if not worker_server_run([
                    [
                        "api/message", {"split": False},
                        [
                            "1234567890 the quick brown fox "
                            "jumps over the lazy dog",
                        ],
                        -1, None, "normal",
                    ], [
                        "api/message", {"split": True},
                        [
                            "1234567890 the quick brown fox "
                            "jumps over the lazy dog",
                        ],
                        -1, None, "normal",
                    ], [
                        "api/message", {"split": False},
                        [
                            "1234567890 the quick brown fox "
                            "jumps over the lazy dog",
                        ],
                        -1, None, "normal",
                    ],
                ], script="example2.py"):
            sys.exit(9)  # pragma: no cover
    if skip < 10:
        note("token")
        if not token_test():
            sys.exit(10)  # pragma: no cover
    if skip < 11:
        note("url args")
        if not url_response_run([
                    ("api/:version/a/b/c/d", 200, {"version": ":version"}),
                    ("api/123/a/b/c/d", 200, {"version": "123"}),
                    ("api/123?a/b/c/d", 404, None),
                    ("api/123/a?b/c/d", 404, None),
                    ("api/123/a?b/c/de", 404, None),
                    ("api/api/a/b/c/d?", 200, {"version": "api"}),
                    ("api/abcd/a/b/c/d#", 200, {"version": "abcd"}),
                    ("api/abcd/", 404, None),
                    ("api/abcd/a/b/c/d/", 200, {"version": "abcd"}),
                    ("api/foo/foo/?ignore=me", 200, {"foo": "foo"}),
                    ("api/foo/foo?include=me", 200, {"foo": "foo?include=me"}),
                ]):
            sys.exit(11)  # pragma: no cover
    if skip < 12:
        note("middleware")
        if not url_response_run([
                    ("api/user_details", 401, None),
                    ("api/user_details?token=wrong", 401, None),
                    ("api/user_details?token=secret", 200, {"name": "user"}),
                    ("api/user_details?token=default", 200, {"name": "other"}),
                    ("api/user_details?token=except", 403, None),
                ], script="example2.py"):
            sys.exit(12)  # pragma: no cover

    note("all tests successful!")
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
        print(f"usage: {sys.argv[0]} [skip]", file=sys.stderr)
        sys.exit(1)
    PYTHON_ARR = os.environ.get("PYTHON", sys.executable).split()
    run(
        python=PYTHON_ARR if "-u" in PYTHON_ARR else PYTHON_ARR + ["-u"],
        skip=int(sys.argv[1]) if len(sys.argv) > 1 else 0)
