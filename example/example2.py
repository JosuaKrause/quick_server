#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    from time import clock
except ImportError:
    from time import monotonic as clock
from time import sleep
import sys
import os

from quick_server import create_server, msg, setup_restart

setup_restart()

addr = ''
port = 8000
server = create_server((addr, port))
server.bind_path('/', '..')
server.add_default_white_list()
server.favicon_fallback = '../quick_server/favicon.ico'
server.suppress_noise = True
server.report_slow_requests = True

server.link_worker_js('/js/worker.js')
server.max_file_size = 78


mcs = server.max_chunk_size
start = clock()
count_uptime = 0


@server.json_get('/api/uptime/', 1)
def uptime(req, args):
    global count_uptime

    # request has one mandatory additional path segment
    sleep(int(args["paths"][0]))
    count_uptime += 1
    res = {
        "uptime": req.log_elapsed_time_string(
            (clock() - start) * 1000.0).strip(),
    }

    def convert(value):
        try:
            return float(value)
        except ValueError:
            return value

    for (key, value) in args["query"].items():
        res[key] = [
            convert(v) for v in value.split(',')
        ] if ',' in value else convert(value)
    return res


@server.json_post('/api/upload')
def upload_file(req, args):
    ix = 0
    res = {}
    for (k, v) in sorted(args['post'].items(), key=lambda e: e[0]):
        res[ix] = "{0} is {1}".format(k, v)
        ix += 1
    for (name, f) in sorted(args['files'].items(), key=lambda e: e[0]):
        fcontent = f.read()
        size = len(fcontent)
        try:
            fcontent = fcontent.decode('utf8')
        except UnicodeDecodeError:
            fcontent = repr(fcontent)
        res[ix] = "{0} is {1} bytes".format(name, size)
        ix += 1
        for line in fcontent.split('\n'):
            res[ix] = line
            ix += 1
    return res


@server.json_worker('/api/uptime_worker')
def uptime_worker(args):
    global count_uptime
    msg("sleep {0}", int(args["time"]))
    sleep(int(args["time"]))
    count_uptime += 1
    return {
        "uptime": (clock() - start) * 1000.0
    }


@server.json_worker('/api/message')
def message(args):
    if args["split"]:
        server.max_chunk_size = 10
    else:
        server.max_chunk_size = mcs
    sleep(2)
    return "1234567890 the quick brown fox jumps over the lazy dog"


def complete_requests(_args, text):
    return ["uptime"] if "uptime".startswith(text) else []


@server.cmd(1, complete_requests)
def requests(args):
    if args[0] != 'uptime':
        msg("unknown request: {0}", args[0])
    else:
        msg("requests made to {0}: {1}", args[0], count_uptime)


msg("starting server at {0}:{1}", addr if addr else 'localhost', port)
server.serve_forever()
msg("shutting down..")
server.server_close()
