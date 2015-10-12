#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import division

import os
import sys
import time
import signal
import urllib2
from StringIO import StringIO
from subprocess import Popen, PIPE

os.chdir(os.path.dirname(__file__))

PYTHON = os.environ.get('PYTHON').split()

def status(msg, *args):
    for line in msg.format(*args).split('\n'):
        print("[TEST] {0}".format(line), file=sys.stderr)

def fail(msg, *args):
    status(msg, *args)
    status("test failed!")
    return False

def cmd_server_run(commands, required_out, fail_out, required_err, fail_err, exit_code=0):
    p = Popen(PYTHON + ["example.py"], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
    output, error = p.communicate('\n'.join(commands) + '\nquit\n')
    if p.returncode != exit_code:
        return fail("wrong exit code {0} expected {1}", p.returncode, exit_code)

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
            return fail("not all required lines were found in {0}:\n{1}", name, '\n'.join(requireds))
        return True

    if not check_stream(output, required_out, fail_out, "STD_OUT"):
        return False
    if not check_stream(error, required_err, fail_err, "STD_ERR"):
        return False
    return True

user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64)'
def url_server_run(probes):
    p = None
    try:
        p = Popen(PYTHON + ["example.py"], cwd='../example')
        time.sleep(1) # give the server some time to wake up
        for parr in probes:
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
    finally:
        if p is not None:
            p.terminate()
            time.sleep(3)
            try:
                p.kill()
            except OSError as e:
                if e.errno != 3:
                    raise
    return True

if not cmd_server_run([ "requests uptime" ], [], [], [ "[SERVER] requests made to uptime: 0" ], []):
    exit(1)
if not url_server_run([
        [ 'example/', 200 ],
        [ 'example/index.html', 200 ],
        [ 'example/nothing_here.txt', 404 ],
        [ 'favicon.ico', 200 ],
        [ 'api/uptime/', 200 ],
        [ 'favicon.ico', 304, { 'eTag': '8f471f65' } ],
        # [ 'example/example.py', 404 ], TODO
        # [ 'example/', 304, { 'eTag': '???' } ], TODO
    ]):
    exit(2)

status("all tests successful!")
exit(0)
