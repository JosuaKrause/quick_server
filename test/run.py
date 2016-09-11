#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import division

import os
import sys
import json
import time
import select
try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError
from fcntl import fcntl, F_GETFL, F_SETFL
from subprocess import Popen, PIPE

os.chdir(os.path.dirname(os.path.abspath(__file__)))

PYTHON = os.environ.get('PYTHON', sys.executable).split()
SKIP = int(sys.argv[1]) if len(sys.argv) > 1 else 0

def print_msg(prefix, msg, *args):
    for line in msg.format(*args).split('\n'):
        print("[{0}] {1}".format(prefix, line), file=sys.stderr)

def status(msg, *args):
    print_msg("TEST", msg, *args)

def note(msg, *args):
    print_msg("NOTE", msg, *args)

def fail(msg, *args): # pragma: no cover
    status(msg, *args)
    status("test failed!")
    return False

def check_stream(text, requireds, fails, name):
    for line in text.split('\n'):
        if not len(requireds):
            break
        for fo in fails:
            if fo in line:
                return fail("invalid line encountered:\n{0}\ncontains {1}", line, fo) # pragma: no cover
        if requireds[0] in line:
            requireds.pop(0)
    if len(requireds):
        status("complete output:\n{0}\n", text) # pragma: no cover
        return fail("not all required lines were found in {0}:\n{1}", name, '\n'.join(requireds)) # pragma: no cover
    return True

def cmd_server_run(commands, required_out, fail_out, required_err, fail_err, exit_code=0):
    p = Popen(PYTHON + ["example.py"], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate('\n'.join(commands) + '\nquit\n')
    if p.returncode != exit_code:
        return fail("wrong exit code {0} expected {1}", p.returncode, exit_code) # pragma: no cover
    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False # pragma: no cover
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False # pragma: no cover
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
        req.add_data(post_str)
    try:
        response = urlopen(req)
    except HTTPError as e:
        response = e
    if rest is not None and 'url' in rest:
        expected_url = 'http://localhost:8000/{0}'.format(rest['url'])
        if response.geturl() != expected_url:
            status("HEADERS:\n{0}\nBODY:\n{1}\n", response.headers, response.read()) # pragma: no cover
            return fail("redirection failed! expected '{0}' got '{1}'", expected_url, response.geturl()) # pragma: no cover
    if response.code != status_code:
        status("HEADERS:\n{0}\nBODY:\n{1}\n", response.headers, response.read()) # pragma: no cover
        return fail("{0} responded with {1} ({2} expected)", url, response.code, status_code) # pragma: no cover
    if json_response is not None:
        json_response["response"] = json.loads(response.read())
    return True

def url_server_run(probes, script="example.py"):
    p = None
    done = False
    try:
        p = Popen(PYTHON + [script], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
        time.sleep(1) # give the server some time to wake up
        for parr in probes:
            if not access_url(parr):
                return False # pragma: no cover
        done = True
    finally:
        if p is not None:
            output, err = p.communicate("quit\n")
            if not done:
                report_output(output.split('\n'), err.split('\n')) # pragma: no cover
            time.sleep(1)
            if p.poll() is None: # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- coverage might report incorrect results")
                p.terminate()
                time.sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
    return True

def access_worker(url, args, expected_keys, max_tries, force_token):
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
        if not access_url([ url, 200 ], post=cmd, json_response=answer):
            return "err" # pragma: no cover
        tries += 1
        answer = answer["response"]
        cmd = {
            "action": "get",
            "token": answer["token"] if force_token is None else force_token,
        }
        if answer["done"]:
            if answer["result"] is not None:
                res = answer["result"]
                for k in expected_keys:
                    if k not in res:
                        return "err" # pragma: no cover
                return "normal"
        if not answer["continue"]:
            return "cancel"
        time.sleep(0.1) # don't spam the server

def worker_server_run(probes, script="example.py"):
    p = None
    done = False
    try:
        p = Popen(PYTHON + [script], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
        time.sleep(1) # give the server some time to wake up
        access_url([ 'js/worker.js', 200 ])
        for (url, args, expected_keys, max_tries, force_token, expected) in probes:
            if access_worker(url, args, expected_keys, max_tries, force_token) != expected:
                return False # pragma: no cover
        done = True
    finally:
        if p is not None:
            output, err = p.communicate("quit\n")
            if not done:
                report_output(output.split('\n'), err.split('\n')) # pragma: no cover
            time.sleep(1)
            if p.poll() is None: # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- coverage might report incorrect results")
                p.terminate()
                time.sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
    return True

def report_output(output, error): # pragma: no cover
    status("STD_OUT>>>")
    for s in output:
        status("{0}", s.rstrip())
    status("<<<STD_OUT")
    status("STD_ERR>>>")
    for s in error:
        status("{0}", s.rstrip())
    status("<<<STD_ERR")

def cmd_url_server_run(actions, required_out, fail_out, required_err, fail_err, exit_code=0, script="example.py"):
    output = []
    error = []

    def read_all(write):
        written = 0
        while True:
            sels = select.select([ p.stdout, p.stderr ], [ p.stdin ], [])
            if not len(sels[0]) and written >= len(write):
                break
            for s in sels[0]:
                if s == p.stdout:
                    output.append(os.read(p.stdout.fileno(), 1024))
                if s == p.stderr:
                    error.append(os.read(p.stderr.fileno(), 1024))
            try:
                for s in sels[1]:
                    written += os.write(s.fileno(), write[written:])
            except OSError as e: # pragma: no cover
                if e.errno == 32:
                    report_output(output, error)
                raise e

    p = None
    pr = None
    try:
        pr = Popen(PYTHON + [script], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
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
        time.sleep(1) # give the server some time to wake up
        read_all("")
        for a in actions:
            if a[0] == "cmd":
                status("command: {0}", a[1])
                cmd = a[1] + '\n'
                read_all(cmd)
                if cmd == 'restart\n':
                    read_all("")
                    time.sleep(1) # give the server some time to restart
                    read_all("")
            elif a[0] == "url":
                status("url: {0}", a[1])
                a.pop(0)
                if not access_url(a): # pragma: no cover
                    read_all("")
                    report_output(output, error)
                    return False
                read_all("")
            else: # pragma: no cover
                return fail("unknown action {0}", a[0])
        read_all("")
        time.sleep(1)
    finally:
        if p is not None:
            read_all("quit\n")
            time.sleep(1)
            if p.poll() is None: # pragma: no cover
                status("WARNING: server takes unusually long to terminate -- coverage might report incorrect results")
                p.terminate()
                time.sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
            elif p.returncode != exit_code:
                return fail("wrong exit code {0} expected {1}", p.returncode, exit_code) # pragma: no cover
        elif pr is not None: # pragma: no cover
            if pr.poll() is None:
                status("WARNING: kill server during start-up")
                pr.kill()
    output = ''.join(output)
    error = ''.join(error)
    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False # pragma: no cover
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False # pragma: no cover
    return True

if SKIP < 1:
    note("basic command check")
    if not cmd_server_run([
                "requests uptime"
            ], [], [], [
                "requests made to uptime: 0"
            ], []):
        exit(1) # pragma: no cover
if SKIP < 2:
    note("url request checks")
    if not url_server_run([
            [ 'example', 200, { 'url': 'example/' } ], # the redirection will not be visible
            [ 'example/', 200 ],
            [ 'example/index.html', 200 ],
            [ 'example/nothing_here.txt', 404 ],
            [ 'favicon.ico', 200 ],
            [ 'api/uptime/', 200 ],
            [ 'favicon.ico', 304, { 'eTag': '8f471f65' } ],
            [ 'favicon.ico', 200, { 'eTag': 'deadbeef' } ],
            [ '/', 404 ],
            [ '/../', 404 ],
            [ 'example/example.py', 404 ],
            [ '.git/', 404 ],
            [ '.travis.yml', 404 ],
            [ 'example/', 304, { 'eTag': '5a73b4a0' } ],
        ]):
        exit(2) # pragma: no cover
if SKIP < 3:
    note("restart test")
    if not cmd_url_server_run([
                [ "url", "example/", 200 ],
                [ "cmd", "restart" ],
                [ "url", "example/", 200 ],
                [ "cmd", "restart" ],
                [ "url", "example/", 200 ],
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
        exit(3) # pragma: no cover
if SKIP < 4:
    note("api test")
    if not cmd_url_server_run([
                [ "cmd", "requests uptime"],
                [ "url", "api/uptime/", 200 ],
                [ "cmd", "requests uptime" ],
            ], [], [], [
                "starting server at localhost:8000",
                "requests made to uptime: 0",
                "\"GET /api/uptime/ HTTP/1.1\"",
                "requests made to uptime: 1"
            ], []):
        exit(4) # pragma: no cover
if SKIP < 5:
    note("restart loop test")
    if not cmd_url_server_run([
                [ "url", "api/uptime/6", 200 ],
                [ "cmd", "restart" ],
                [ "url", "api/uptime/7/", 200 ],
                [ "cmd", "restart" ],
                [ "url", "api/uptime/8/", 200 ],
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
                "] \"GET", # the server is not supposed to output normal requests
                "Exception KeyError: KeyError(",
            ], script="example2.py"):
        exit(5) # pragma: no cover
if SKIP < 6:
    note("special value responses")
    if not url_server_run([
            [ 'api/uptime/0/?foo=1', 200 ],
            [ 'api/uptime/0/?bar=nan', 200 ],
            [ 'api/uptime/0/?baz=inf', 200 ],
            [ 'api/uptime/0/?fub=-inf&foo=1&bar=1,2,3&baz=string', 200 ],
            [ 'favicon.ico', 200 ], # test favicon as well
        ], script="example2.py"):
        exit(6) # pragma: no cover
if SKIP < 7:
    note("worker")
    if not worker_server_run([
            [ 'api/uptime_worker', { "time": 1 }, [ "uptime" ], -1, None, "normal" ],
            [ 'api/uptime_worker', { "time": 0 }, [ "uptime" ], 1, None, "normal" ],
            [ 'api/uptime_worker', { "time": 1 }, [ "uptime" ], 1, None, "cancel" ],
            [ 'api/uptime_worker', { "time": 1 }, None, -1, 0, "cancel" ],
        ], script="example2.py"):
        exit(7) # pragma: no cover

note("all tests successful!")
exit(0)
