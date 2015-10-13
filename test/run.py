#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import division

import os
import sys
import time
import select
import urllib2
from fcntl import fcntl, F_GETFL, F_SETFL
from subprocess import Popen, PIPE

os.chdir(os.path.dirname(__file__))

PYTHON = os.environ.get('PYTHON', sys.executable).split()

def status(msg, *args):
    for line in msg.format(*args).split('\n'):
        print("[TEST] {0}".format(line), file=sys.stderr)

def fail(msg, *args):
    status(msg, *args)
    status("test failed!")
    return False

def check_stream(text, requireds, fails, name):
    for line in text.split('\n'):
        if not len(requireds):
            break
        for fo in fails:
            if fo in line:
                return fail("invalid line encountered:\n{0}\ncontains {1}", line, fo)
        if requireds[0] in line:
            requireds.pop(0)
    if len(requireds):
        status("complete output:\n{0}\n", text)
        return fail("not all required lines were found in {0}:\n{1}", name, '\n'.join(requireds))
    return True

def cmd_server_run(commands, required_out, fail_out, required_err, fail_err, exit_code=0):
    p = Popen(PYTHON + ["example.py"], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate('\n'.join(commands) + '\nquit\n')
    if p.returncode != exit_code:
        return fail("wrong exit code {0} expected {1}", p.returncode, exit_code)
    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False
    return True

user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
def access_url(parr):
    url = 'http://localhost:8000/{0}'.format(parr[0])
    status_code = parr[1]
    rest = parr[2] if len(parr) > 2 else None
    headers = {
        'User-Agent': user_agent
    }
    if rest is not None and 'eTag' in rest:
        headers["if-none-match"] = rest['eTag']
    opener = urllib2.build_opener()
    opener.addheaders = headers.items()
    try:
        response = opener.open(url)
    except urllib2.HTTPError as e:
        response = e
    if response.code != status_code:
        status("HEADERS:\n{0}\nBODY:\n{1}\n", response.headers, response.read())
        return fail("{0} responded with {1} ({2} expected)", url, response.code, status_code)
    return True

def url_server_run(probes):
    p = None
    try:
        p = Popen(PYTHON + ["example.py"], cwd='../example', stdin=PIPE)
        time.sleep(1) # give the server some time to wake up
        for parr in probes:
            if not access_url(parr):
                return False
    finally:
        if p is not None:
            p.communicate("quit\n")
            time.sleep(1)
            if p.poll() is None:
                status("WARNING: server takes unusually long to terminate -- coverage might report incorrect results")
                p.terminate()
                time.sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
    return True

def cmd_url_server_run(actions, required_out, fail_out, required_err, fail_err, exit_code=0):
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
            for s in sels[1]:
                written += os.write(s.fileno(), write[written:])

    p = None
    pr = None
    try:
        pr = Popen(PYTHON + ["example.py"], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
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
                if not access_url(a):
                    return False
                read_all("")
            else:
                return fail("unknown action {0}", a[0])
        read_all("")
        time.sleep(1)
    finally:
        if p is not None:
            read_all("quit\n")
            time.sleep(1)
            if p.poll() is None:
                status("WARNING: server takes unusually long to terminate -- coverage might report incorrect results")
                p.terminate()
                time.sleep(3)
                if p.poll() is None:
                    status("WARNING: killed server")
                    p.kill()
            elif p.returncode != exit_code:
                return fail("wrong exit code {0} expected {1}", p.returncode, exit_code)
        elif pr is not None:
            if pr.poll() is None:
                status("WARNING: kill server during start-up")
                pr.kill()
    output = ''.join(output)
    error = ''.join(error)
    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False
    return True

status("basic command check")
if not cmd_server_run([
            "requests uptime"
        ], [], [], [
            "requests made to uptime: 0"
        ], []):
    exit(1)
status("url request checks")
if not url_server_run([
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
    exit(2)
status("restart test")
if not cmd_url_server_run([
            [ "url", "example/", 200 ],
            [ "cmd", "restart" ],
            [ "url", "example/", 200 ]
        ], [], [], [
            "starting server at localhost:8000",
            "\"GET /example/ HTTP/1.1\"",
            "shutting down..",
            "starting server at localhost:8000",
            "\"GET /example/ HTTP/1.1\"",
        ], []):
    exit(3)
status("api test")
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
    exit(4)

status("all tests successful!")
exit(0)
