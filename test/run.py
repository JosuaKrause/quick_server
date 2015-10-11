#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import division

import os
import sys
from subprocess import Popen, PIPE
from StringIO import StringIO

os.chdir(os.path.dirname(__file__))

def status(msg, *args):
  for line in msg.format(*args).split('\n'):
    print("[TEST] {0}".format(line), file=sys.stderr)

def fail(msg, *args):
  status(msg, *args)
  status("test failed!")
  return False

def cmd_server_run(commands, required_out, fail_out, required_err, fail_err, exit_code=0):
  p = Popen(["python", "example.py"], cwd='../example', stdin=PIPE, stdout=PIPE, stderr=PIPE)
  output, error = p.communicate('\n'.join(commands) + '\nquit\n')
  if p.returncode != exit_code:
    return fail("wrong exit code {0} expected {1}", ret, exit_code)

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

if not cmd_server_run([ "requests uptime" ], [], [], [ "[SERVER] requests made to uptime: 0" ], []):
  exit(1)
status("all tests succesful!")
exit(0)
