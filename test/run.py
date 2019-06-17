#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import division

try:
    import coverage
    coverage.process_startup()
# pylint: disable=bare-except
except:  # nopep8
    pass

import os
import sys
import json
import time
import select
try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError  # type: ignore
from fcntl import fcntl, F_GETFL, F_SETFL
from subprocess import Popen, PIPE

try:
    unicode = unicode  # type: ignore
except NameError:
    # python 3
    str = str  # type: ignore
    unicode = str
    bytes = bytes  # type: ignore
    basestring = (str, bytes)
else:
    # python 2
    str = str
    unicode = unicode
    bytes = str
    basestring = basestring

os.chdir(os.path.dirname(os.path.abspath(__file__)))

PYTHON = os.environ.get('PYTHON', sys.executable).split()
if len(sys.argv) > 1 and (sys.argv[1] == '-h' or sys.argv[1] == '--help'):
    print("usage: {0} [skip]".format(sys.argv[0]), file=sys.stderr)
    exit(1)
SKIP = int(sys.argv[1]) if len(sys.argv) > 1 else 0


if hasattr(time, "monotonic"):
    def _time_mono():
        return time.monotonic()

    get_time = _time_mono
    hot_loop = False
else:
    def _time_clock():
        return time.clock()

    get_time = _time_clock
    hot_loop = True


def do_sleep(seconds, ensure=False):
    if not ensure:
        time.sleep(seconds)
        return
    now = get_time()
    while get_time() - now < seconds:
        time.sleep(seconds)
        if hot_loop:
            for _ in range(10000000):
                pass


def convert_b(bdata):
    return repr(bdata).lstrip('b').strip("'\"").replace('\\', '\\\\')


def print_msg(prefix, msg, *args):
    if isinstance(msg, bytes):
        try:
            msg = msg.decode('utf8')
        except UnicodeDecodeError:
            msg = '\n'.join([repr(m) for m in msg.split(b'\n')])
    for line in msg.format(*args).split('\n'):
        print("[{0}] {1}".format(prefix, line), file=sys.stderr)


def status(msg, *args):
    print_msg("TEST", msg, *args)


def note(msg, *args):
    print_msg("NOTE", msg, *args)


def fail(msg, *args):  # pragma: no cover
    status(msg, *args)
    status("test failed!")
    return False


def check_stream(text, requireds, fails, name):
    requireds = requireds[:]
    for line in text.split('\n'):
        for fo in fails:
            if fo in line:
                return fail(  # pragma: no cover
                    "invalid line encountered:"  # pragma: no cover
                    "\n{0}\ncontains {1}",  # pragma: no cover
                    line, fo)  # pragma: no cover
        while len(requireds) and requireds[0] in line:
            requireds.pop(0)
    if len(requireds):
        status("complete output:\n{0}\n", text)  # pragma: no cover
        return fail(  # pragma: no cover
            "not all required lines were "  # pragma: no cover
            "found in {0}:\n{1}",  # pragma: no cover
            name, '\n'.join(requireds))  # pragma: no cover
    return True


def cmd_server_run(
        commands, required_out, fail_out, required_err, fail_err, exit_code=0):
    p = Popen(PYTHON + ["example.py"], cwd='../example',
              stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate(b'\n'.join(commands) + b'\nquit\n')
    output = output.decode('utf8')
    error = error.decode('utf8')
    if p.returncode != exit_code:
        report_output(  # pragma: no cover
            output.split('\n'), error.split('\n'))  # pragma: no cover
        return fail(  # pragma: no cover
            "wrong exit code {0} expected {1}",  # pragma: no cover
            p.returncode, exit_code)  # pragma: no cover
    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False  # pragma: no cover
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False  # pragma: no cover
    return True


def access_curl(url, fields, required_out, fail_out, required_err, fail_err,
                exit_code=0):
    full_url = 'http://localhost:8000/{0}'.format(url)
    call = ["curl", "--output", "-"]
    for f in fields:
        call.append("-F")
        call.append(f)
    call.append(full_url)
    p = Popen(call, cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate()
    output = output.decode('utf8')
    error = error.decode('utf8')
    if p.returncode != exit_code:
        report_output(  # pragma: no cover
            output.split('\n'), error.split('\n'))  # pragma: no cover
        return fail(  # pragma: no cover
            "wrong exit code {0} expected {1}",  # pragma: no cover
            p.returncode, exit_code)  # pragma: no cover
    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False  # pragma: no cover
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False  # pragma: no cover
    return True


def curl_server_run(probes, script="example.py"):
    p = None
    done = False
    try:
        p = Popen(PYTHON + [script], cwd='../example',
                  stdin=PIPE, stdout=PIPE, stderr=PIPE)
        do_sleep(1)  # give the server some time to wake up
        for parr in probes:
            if not access_curl(*parr):
                return False  # pragma: no cover
        done = True
    finally:
        if p is not None:
            output, err = p.communicate(b"quit\n")
            output = output.decode('utf8')
            err = err.decode('utf8')
            if not done:
                report_output(  # pragma: no cover
                    output.split('\n'), err.split('\n'))  # pragma: no cover
            do_sleep(1)
            if p.poll() is None:  # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- "
                       "coverage might report incorrect results")
                p.terminate()
                do_sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
    return True


user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'


def access_url(parr, post=None, json_response=None):
    url = 'http://localhost:8000/{0}'.format(parr[0])
    status_code = parr[1]
    rest = parr[2] if len(parr) > 2 else None
    headers = {
        'User-Agent': user_agent
    }
    if rest is not None and 'eTag' in rest:
        headers["if-none-match"] = rest['eTag']
    req = Request(url, headers=headers)
    if post is not None:
        post_str = json.dumps(post, indent=2, sort_keys=True, allow_nan=False)
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", len(post_str))
        try:
            req.add_data(post_str)
        except AttributeError:
            req.data = post_str.encode('utf8')
    try:
        response = urlopen(req)
    except HTTPError as e:
        response = e
    if rest is not None and 'url' in rest:
        expected_url = 'http://localhost:8000/{0}'.format(rest['url'])
        if response.geturl() != expected_url:
            status(  # pragma: no cover
                "HEADERS:\n{0}\nBODY:\n{1}\n",  # pragma: no cover
                response.headers, response.read())  # pragma: no cover
            return fail(  # pragma: no cover
                "redirection failed! "  # pragma: no cover
                "expected '{0}' got '{1}'",  # pragma: no cover
                expected_url, response.geturl())  # pragma: no cover
    if response.code != status_code:
        status("HEADERS:\n{0}\nBODY:\n{1}\n",  # pragma: no cover
               response.headers, response.read())  # pragma: no cover
        return fail(  # pragma: no cover
            "{0} responded with {1} ({2} expected)",  # pragma: no cover
            url, response.code, status_code)  # pragma: no cover
    if json_response is not None:
        json_response["response"] = json.loads(response.read())
    return True


def url_server_run(probes, script="example.py"):
    p = None
    done = False
    try:
        p = Popen(PYTHON + [script], cwd='../example',
                  stdin=PIPE, stdout=PIPE, stderr=PIPE)
        do_sleep(1)  # give the server some time to wake up
        for parr in probes:
            if not access_url(parr):
                return False  # pragma: no cover
        done = True
    finally:
        if p is not None:
            output, err = p.communicate(b"quit\n")
            output = output.decode('utf8')
            err = err.decode('utf8')
            if not done:
                report_output(  # pragma: no cover
                    output.split('\n'), err.split('\n'))  # pragma: no cover
            do_sleep(1)
            if p.poll() is None:  # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- "
                       "coverage might report incorrect results")
                p.terminate()
                do_sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
    return True


def access_worker(url, args, expected_keys, max_tries, force_token):

    def rebuild(keys):
        res = ""
        for k in keys:
            ans = {}
            if not access_url([url, 200], post={
                        "action": "cargo",
                        "token": k,
                    }, json_response=ans):
                raise ValueError(  # pragma: no cover
                    "Error collecting results!")  # pragma: no cover
            ans = ans["response"]
            if ans["token"] != k:
                raise ValueError(
                    "Token mismatch {0} != {1}".format(ans["token"], k))
            res += ans["result"]
        return res

    cmd = {
        "action": "start",
        "payload": args,
    }
    tries = 0
    while True:
        answer = {}
        if tries > max_tries and max_tries > 0:
            cmd = {
                "action": "stop",
                "token": cmd["token"] if force_token is None else force_token,
            }
        if not access_url([url, 200], post=cmd, json_response=answer):
            return "err"  # pragma: no cover
        tries += 1
        answer = answer["response"]
        cmd = {
            "action": "get",
            "token": answer["token"] if force_token is None else force_token,
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


def worker_server_run(probes, script="example.py"):
    p = None
    done = False
    try:
        p = Popen(PYTHON + [script], cwd='../example',
                  stdin=PIPE, stdout=PIPE, stderr=PIPE)
        do_sleep(1)  # give the server some time to wake up
        if not access_url(['js/worker.js', 200]):
            return False  # pragma: no cover
        for probe in probes:
            if access_worker(*probe[:-1]) != probe[-1]:
                return False  # pragma: no cover
        done = True
    finally:
        if p is not None:
            output, err = p.communicate(b"quit\n")
            output = output.decode('utf8')
            err = err.decode('utf8')
            if not done:
                report_output(  # pragma: no cover
                    output.split('\n'), err.split('\n'))  # pragma: no cover
            do_sleep(1)
            if p.poll() is None:  # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- "
                       "coverage might report incorrect results")
                p.terminate()
                do_sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
    return True


def report_output(output, error):  # pragma: no cover
    status("STD_OUT>>>")
    for s in output:
        status("{0}", s.rstrip())
    status("<<<STD_OUT")
    status("STD_ERR>>>")
    for s in error:
        status("{0}", s.rstrip())
    status("<<<STD_ERR")


def cmd_url_server_run(actions, required_out, fail_out, required_err, fail_err,
                       exit_code=0, script="example.py"):
    output = []
    error = []

    def read_all(write):
        write = write.encode('utf8')
        written = 0
        while True:
            sels = select.select([p.stdout, p.stderr], [p.stdin], [])
            if not len(sels[0]) and written >= len(write):
                break
            for s in sels[0]:
                if s == p.stdout:
                    output.append(
                        os.read(p.stdout.fileno(), 1024).decode('utf8'))
                if s == p.stderr:
                    error.append(
                        os.read(p.stderr.fileno(), 1024).decode('utf8'))
            try:
                for s in sels[1]:
                    written += os.write(s.fileno(), write[written:])
            except OSError as e:  # pragma: no cover
                if e.errno == 32:
                    report_output(output, error)
                raise e

    p = None
    pr = None
    try:
        pr = Popen(PYTHON + [script], cwd='../example',
                   stdin=PIPE, stdout=PIPE, stderr=PIPE)
        # make pipes non-blocking
        flags = fcntl(pr.stdin, F_GETFL)
        fcntl(pr.stdin, F_SETFL, flags | os.O_NONBLOCK)
        flags = fcntl(pr.stdout, F_GETFL)
        fcntl(pr.stdout, F_SETFL, flags | os.O_NONBLOCK)
        flags = fcntl(pr.stderr, F_GETFL)
        fcntl(pr.stderr, F_SETFL, flags | os.O_NONBLOCK)
        # start-up done
        p = pr
        read_all("")
        do_sleep(1)  # give the server some time to wake up
        read_all("")
        for a in actions:
            if a[0] == "cmd":
                status("command: {0}", a[1])
                cmd = a[1] + '\n'
                read_all(cmd)
                if cmd == 'restart\n':
                    read_all("")
                    do_sleep(1)  # give the server some time to restart
                    read_all("")
            elif a[0] == "url":
                status("url: {0}", a[1])
                a.pop(0)
                if not access_url(a):  # pragma: no cover
                    read_all("")
                    report_output(output, error)
                    return False
                read_all("")
            else:  # pragma: no cover
                return fail("unknown action {0}", a[0])
        read_all("")
        do_sleep(1)
    finally:
        if p is not None:
            read_all("quit\n")
            do_sleep(1)
            if p.poll() is None:  # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- "
                       "coverage might report incorrect results")
                p.terminate()
                do_sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
            elif p.returncode != exit_code:
                return fail(  # pragma: no cover
                    "wrong exit code {0} expected {1}",  # pragma: no cover
                    p.returncode, exit_code)  # pragma: no cover
        elif pr is not None:  # pragma: no cover
            if pr.poll() is None:
                status("WARNING: kill server during start-up")
                pr.kill()
    output_str = ''.join(output)
    error_str = ''.join(error)
    if not check_stream(output_str, required_out, fail_out, "STD_OUT"):
        return False  # pragma: no cover
    if not check_stream(error_str, required_err, fail_err, "STD_ERR"):
        return False  # pragma: no cover
    return True


def token_test():
    from quick_server import QuickServer
    qs = QuickServer(("", 0))
    tkn = qs.create_token()
    note("time: {0}", get_time())

    def chk(name, expire, live):
        obj = qs.get_token_obj(name, expire)
        if live and "foo" not in obj:
            note("time: {0}", get_time())
            note("{0}", qs._token_handler)
            return fail("'{0}' expected to live: {1}", name, obj)
        elif not live and "foo" in obj:
            note("time: {0}", get_time())
            note("{0}", qs._token_handler)
            return fail("'{0}' should be cleared: {1}", name, obj)
        return True

    qs.get_token_obj(tkn, 0.1)["foo"] = True
    qs.get_token_obj("a", 0)["foo"] = True
    if not chk(tkn, 0.1, True):
        return False
    if not chk("a", 0, False):
        return False
    note("wait: {0}", get_time())
    do_sleep(0.2, ensure=True)
    note("time: {0}", get_time())
    qs.get_token_obj("b", None)["foo"] = True
    if not chk(tkn, 0.1, False):
        return False
    if not chk("b", 0.1, True):
        return False
    note("wait: {0}", get_time())
    do_sleep(0.2, ensure=True)
    note("time: {0}", get_time())
    if not chk("b", 0.1, False):
        return False
    return True


note("python: {0}".format(" ".join(PYTHON)))
if SKIP < 1:
    note("basic command check")
    if not cmd_server_run([
                b"requests uptime"
            ], [], [], [
                "requests made to uptime: 0"
            ], []):
        exit(1)  # pragma: no cover
if SKIP < 2:
    note("url request checks")
    if not url_server_run([
                # the redirection will not be visible
                ['example', 200, {'url': 'example/'}],
                ['example/', 200],
                ['example/index.html', 200],
                ['example/nothing_here.txt', 404],
                ['favicon.ico', 200],
                ['api/uptime/', 200],
                ['favicon.ico', 304, {'eTag': '8f471f65'}],
                ['favicon.ico', 200, {'eTag': 'deadbeef'}],
                ['/', 404],
                ['/../', 404],
                ['example/example.py', 404],
                ['.git/', 404],
                ['.travis.yml', 404],
                ['example/', 304, {'eTag': '5a73b4a0'}],
            ]):
        exit(2)  # pragma: no cover
if SKIP < 3:
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
        exit(3)  # pragma: no cover
if SKIP < 4:
    note("api test")
    if not cmd_url_server_run([
                ["cmd", "requests uptime"],
                ["url", "api/uptime/", 200],
                ["cmd", "requests uptime"],
            ], [], [], [
                "starting server at localhost:8000",
                "requests made to uptime: 0",
                "\"GET /api/uptime/ HTTP/1.1\"",
                "requests made to uptime: 1"
            ], []):
        exit(4)  # pragma: no cover
if SKIP < 5:
    note("restart loop test")
    if not cmd_url_server_run([
                ["url", "api/uptime/6", 200],
                ["cmd", "restart"],
                ["url", "api/uptime/7/", 200],
                ["cmd", "restart"],
                ["url", "api/uptime/8/", 200],
            ], [], [], [
                "starting server at localhost:8000",
                "request takes longer than expected: \"GET /api/uptime/6\"",
                "shutting down..",
                "starting server at localhost:8000",
                "request takes longer than expected: \"GET /api/uptime/7/\"",
                "shutting down..",
                "starting server at localhost:8000",
                "request takes longer than expected: \"GET /api/uptime/8/\"",
            ], [
                # the server is not supposed to output normal requests
                "] \"GET",
                "Exception KeyError: KeyError(",
            ], script="example2.py"):
        exit(5)  # pragma: no cover
if SKIP < 6:
    note("special value responses")
    if not url_server_run([
                ['api/uptime/0/?foo=1', 200],
                ['api/uptime/0/?bar=nan', 200],
                ['api/uptime/0/?baz=inf', 200],
                ['api/uptime/0/?fub=-inf&foo=1&bar=1,2,3&baz=string', 200],
                ['favicon.ico', 200],  # test favicon as well
            ], script="example2.py"):
        exit(6)  # pragma: no cover
if SKIP < 7:
    note("worker")
    if not worker_server_run([
                [
                    'api/uptime_worker', {"time": 1},
                    ["uptime"], -1, None, "normal"
                ], [
                    'api/uptime_worker', {"time": 0},
                    ["uptime"], 1, None, "normal"
                ], [
                    'api/uptime_worker', {"time": 1},
                    ["uptime"], 1, None, "cancel"
                ], [
                    'api/uptime_worker', {"time": 1},
                    None, -1, 0, "cancel"
                ],
            ], script="example2.py"):
        exit(7)  # pragma: no cover
if SKIP < 8:
    note("file uploads")
    if not curl_server_run([
                # url, fields, required_out, fail_out, required_err, fail_err
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
                        "bin=@binary.upload", "def=ghi"
                    ], [
                        "def is ghi",
                        "name is foo",
                        "abc is 33 bytes",
                        "example file",
                        "meaningless content",
                        "\"\"",
                        "bin is 78 bytes",
                        convert_b(b"\x00\x00\x01\x00\x01\x00\x01\x01"
                                  b"\x02\x00\x01\x00\x01\x00\x38\x00"),
                        convert_b(b"\xff\xff\xff\x00\x00\x00\x00\x00"
                                  b"\x00\x00\x00\x00\x00\x00\x00\x00"),
                    ], [
                        "--",
                        "Content-Disposition",
                    ], [], [],
                ],
            ], script="example2.py"):
        exit(8)  # pragma: no cover
if SKIP < 9:
    note("split worker")
    if not worker_server_run([
                [
                    'api/message', {"split": False},
                    ["1234567890 the quick brown fox jumps over the lazy dog"],
                    -1, None, "normal"
                ], [
                    'api/message', {"split": True},
                    ["1234567890 the quick brown fox jumps over the lazy dog"],
                    -1, None, "normal"
                ], [
                    'api/message', {"split": False},
                    ["1234567890 the quick brown fox jumps over the lazy dog"],
                    -1, None, "normal"
                ],
            ], script="example2.py"):
        exit(9)  # pragma: no cover
if SKIP < 10:
    note("token")
    if not token_test():
        exit(10)

note("all tests successful!")
exit(0)
