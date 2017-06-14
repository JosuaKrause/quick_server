#!/usr/bin/env python
# -*- coding: utf-8 -*-
from time import clock, sleep
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

start = clock()
@server.json_get('/api/uptime/', 1)
def uptime(req, args):
    global count_uptime
    # request has one mandatory additional path segment
    sleep(int(args["paths"][0]))
    count_uptime += 1
    res = {
        "uptime": req.log_elapsed_time_string((clock() - start) * 1000.0).strip()
    }

    def convert(value):
        try:
            return float(value)
        except ValueError:
            return value

    for (key, value) in args["query"].items():
        res[key] = [ convert(v) for v in value.split(',') ] if ',' in value else convert(value)
    return res

@server.json_post('/api/upload')
def upload_file(req, args):
    ix = 0
    res = {}
    for (name, f) in args['files'].items():
        fcontent = f.read().decode('utf8')
        res[ix] = "{0} is {1} bytes\n".format(name, len(fcontent))
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

def complete_requests(_args, text):
  return [ "uptime" ] if "uptime".startswith(text) else []

count_uptime = 0
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
