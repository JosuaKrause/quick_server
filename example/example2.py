#!/usr/bin/env python
# -*- coding: utf-8 -*-
from time import clock, sleep
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from quick_server import create_server, msg, setup_restart

setup_restart()

addr = ''
port = 8000
server = create_server((addr, port))
server.bind_path('/', '..')
server.add_default_white_list()
server.favicon_fallback = 'favicon.ico'
server.suppress_noise = True
server.report_slow_requests = True

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
    for (key, value) in args["query"].items():
        res[key] = value if value != "nan" and value != "inf" and value != "-inf" else float(value)
    return res

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
