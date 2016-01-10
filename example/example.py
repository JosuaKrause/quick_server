#!/usr/bin/env python
# -*- coding: utf-8 -*-
from time import clock
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from quick_server import create_server, msg

addr = ''
port = 8000
server = create_server((addr, port))
server.bind_path('/', '..')
server.add_default_white_list()
server.favicon_fallback = 'favicon.ico'

start = clock()
@server.json_get('/api/uptime/')
def uptime(req, args):
    global count_uptime
    count_uptime += 1
    return {
        "uptime": req.log_elapsed_time_string((clock() - start) * 1000.0).strip()
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
