# -*- coding: utf-8 -*-
"""
Created on 2015-10-10

@author: joschi <josua.krause@gmail.com>

QuickServer is a quick to use and easy to set up server implementation. It has
the following goals / features and is primarily meant to speed up back end
implementation / iteration:

* serve local files as is with basic black-listing
* provide functionality for dynamic requests
* provide a basic command interpret loop for server commands

The best way to start QuickServer is the `serve_forever` method.
Dynamic requests can be added via the `TYPE_METHOD` annotations where
TYPE is the result type of the request (ie. text, json) and METHOD is the HTTP
method (eg. GET, POST). POST requests can contain JSON encoded form data.
You can bind static paths with the `bind_path` method.

Commands can be added via the `cmd` annotation where the function name is
the command. 'help', 'restart', and 'quit' are built-in commands ready to use.

Note: The server is thread based so all callback functions should be thread-safe.

Please refer to the example folder for usage examples.
"""
from __future__ import print_function
from __future__ import division

import os
import sys
import json
import math
import time
import uuid
import zlib
import errno
import atexit
import ctypes
import select
import signal
import socket
import fnmatch
import readline
import posixpath
import threading
import traceback
import collections

try:
    from cStringIO import StringIO
    BytesIO = StringIO
except ModuleNotFoundError:
    from io import StringIO, BytesIO
except ImportError:
    from StringIO import StringIO
    BytesIO = StringIO

try:
    import urlparse
    import urllib
    urlparse_unquote = urllib.unquote
except ImportError:
    from urllib import parse as urlparse
    urlparse_unquote = urlparse.unquote

try:
    from SimpleHTTPServer import SimpleHTTPRequestHandler
    import BaseHTTPServer as http_server
except ModuleNotFoundError:
    from http.server import SimpleHTTPRequestHandler
    import http.server as http_server

try:
    import SocketServer as socketserver
except ModuleNotFoundError:
    import socketserver

try:
    input = raw_input
except NameError:
    pass

try:
    unicode = unicode
except NameError:
    # python 3
    str = str
    unicode = str
    bytes = bytes
    basestring = (str, bytes)
else:
    # python 2
    str = str
    unicode = unicode
    bytes = str
    basestring = basestring


__version__ = "0.4.3"


_getheader = lambda obj, key: _getheader_p2(obj, key)
def _getheader_p2(obj, key):
    global _getheader
    try:
        return obj.getheader(key)
    except AttributeError:
        _getheader = lambda obj, key: obj.get(key)
        return _getheader(obj, key)


def create_server(server_address, parallel=True):
    """Creates the server."""
    if parallel:
        return ParallelQuickServer(server_address)
    return QuickServer(server_address) # pragma: no cover


def json_dumps(obj):
    """A safe JSON dump function that provides correct diverging numbers for a
       ECMAscript consumer.
    """
    try:
        return json.dumps(obj, indent=2, sort_keys=True, allow_nan=False)
    except ValueError:
        pass
    # we don't want to call do_map on the original object since it can
    # contain objects that need to be converted for JSON. after reading
    # in the created JSON we get a limited set of possible types we
    # can encounter
    json_str = json.dumps(obj, indent=2, sort_keys=True, allow_nan=True)
    json_obj = json.loads(json_str)

    def do_map(obj):
        if isinstance(obj, basestring):
            return obj
        if isinstance(obj, dict):
            res = {}
            for (key, value) in obj.items():
                res[key] = do_map(value)
            return res
        if isinstance(obj, collections.Iterable):
            res = []
            for el in obj:
                res.append(do_map(el))
            return res
        # diverging numbers need to be passed as strings otherwise it will throw
        # a parsing error on the ECMAscript consumer side
        if math.isnan(obj):
            return "NaN"
        if math.isinf(obj):
            return "Infinity" if obj > 0 else "-Infinity"
        return obj

    return json.dumps(do_map(json_obj), indent=2, sort_keys=True, allow_nan=False)


log_file = None
def set_log_file(file):
    """Sets the log file. Defaults to STD_ERR."""
    global log_file
    log_file = file


def _caller_trace(frame):
    try:
        if '__file__' not in frame.f_globals:
            return '???', frame.f_lineno
        return frame.f_globals['__file__'], frame.f_lineno
    finally:
        del frame


def caller_trace(): # pragma: no cover
    try:
        raise Exception
    except:
        try:
            frames = [ sys.exc_info()[2].tb_frame ]
            for _ in xrange(2):
                frames.append(frames[-1].f_back)
            return _caller_trace(frames[-1])
        finally:
            del frames
if hasattr(sys, '_getframe'):
    caller_trace = lambda: _caller_trace(sys._getframe(2))


long_msg = True
_msg_stderr = False
def msg(message, *args, **kwargs):
    """Prints a message from the server to the log file."""
    global log_file
    if log_file is None:
        log_file = sys.stderr
    if long_msg:
        file_name, line = caller_trace()
        file_name, file_type = os.path.splitext(file_name)
        if file_name.endswith('/__init__'):
            file_name = os.path.basename(os.path.dirname(file_name))
        elif file_name.endswith('/__main__'):
            file_name = "(-m) {0}".format(os.path.basename(os.path.dirname(file_name)))
        else:
            file_name = os.path.basename(file_name)
        head = '{0}{1} ({2}): '.format(file_name, file_type, line)
    else:
        head = '[SERVER] '
    out = StringIO()
    for line in message.format(*args, **kwargs).split('\n'):
        out.write('{0}{1}\n'.format(head, line))
    out.flush()
    out.seek(0)
    if _msg_stderr:
        sys.stderr.write(out.read())
        sys.stderr.flush()
    else:
        log_file.write(out.read())
        log_file.flush()
    out.close()


# thread local storage for keeping track of request information (eg. time)
thread_local = threading.local()


# if a restart file is set a '1' is written to the file if a restart is requested
# if a restart exit code is set the restart file is ignored
_restart_file = None
def set_restart_file(rf):
    global _restart_file
    _restart_file = rf


_restart_exit_code = 42
def set_restart_exit_code(code):
    global _restart_exit_code
    _restart_exit_code = code


_error_exit_code = 1
def set_error_exit_code(code):
    global _error_exit_code
    _error_exit_code = code


# handling the 'restart' command
_do_restart = False
def _on_exit(): # pragma: no cover
    global _do_restart
    if _do_restart:
        # just to make sure not come into an infinite loop if something breaks
        # we reset the restart flag before we attempt to actually restart
        _do_restart = False
        exit_code = os.environ.get('QUICK_SERVER_RESTART', None)
        if _restart_file is not None and exit_code is None:
            with open(_restart_file, 'w') as rf:
                rf.write('1')
                rf.flush()
        else:
            # restart the executable
            _start_restart_loop(exit_code, in_atexit=True)


try:
    # try to sneak in as first -- this will be the last action
    # the program does before it gets replaced with the new instance.
    # being the first in list ensures that all other exit handlers run before us
    # >>> this won't work in python3 <<<
    atexit._exithandlers.insert(0, (_on_exit, (), {}))
except:
    # otherwise register normally
    atexit.register(_on_exit)


def _start_restart_loop(exit_code, in_atexit):
    try:
        if exit_code is not None:
            # we have a parent process that restarts us
            child_code = int(exit_code)
        else:
            import subprocess

            executable = os.environ.get('PYTHON', sys.executable).split()
            exec_arr = executable + sys.argv
            if in_atexit:
                msg("restarting: {0}", ' '.join(exec_arr))

            exit_code = _restart_exit_code
            child_code = exit_code
            is_subsequent = False
            while child_code == exit_code:
                environ = os.environ.copy()
                environ['QUICK_SERVER_RESTART'] = str(exit_code)
                if is_subsequent:
                    environ['QUICK_SERVER_SUBSEQ'] = "1"
                is_subsequent = True
                try:
                    child_code = subprocess.Popen(exec_arr, env=environ, close_fds=True).wait()
                except KeyboardInterrupt:
                    child_code = _error_exit_code
    except:
        msg("error during restart:\n{0}", traceback.format_exc())
        child_code = _error_exit_code
    finally:
        if in_atexit:
            os._exit(child_code)
        else:
            sys.exit(child_code)


def setup_restart():
    """Sets up restart functionality that doesn't keep the first process alive.
       The function needs to be called before the actual process starts but
       after loading the program. It will restart the program in a child process
       and immediately returns in the child process. The call in the parent
       process never returns. Calling this function is not necessary for using
       restart functionality but avoids potential errors originating from rogue
       threads.
    """
    exit_code = os.environ.get('QUICK_SERVER_RESTART', None)
    if exit_code is None:
        try:
            atexit.unregister(_on_exit)
        except AttributeError:
            atexit._exithandlers = filter(lambda exit_hnd: exit_hnd[0] != _on_exit, atexit._exithandlers)
        _start_restart_loop(None, in_atexit=False)


def is_original():
    """Whether we are in the original process."""
    return 'QUICK_SERVER_RESTART' not in os.environ


def has_been_restarted():
    """Returns whether the process has been restarted in the past. When using a
       restart file the calling process needs to set the environment variable
       "QUICK_SERVER_SUBSEQ" to the value "1" for the second and any subsequent
       call in order to make this function work.
    """
    return os.environ.get('QUICK_SERVER_SUBSEQ', "0") == "1"


class PreventDefaultResponse(Exception):
    """Can be thrown to prevent any further processing of the request and instead
       send a customized response.
    """
    pass


class WorkerDeath(Exception):
    pass


class QuickServerRequestHandler(SimpleHTTPRequestHandler):
    """The request handler for QuickServer. Delegates file requests to
       SimpleHTTPRequestHandler if the request could not be resolved as
       dynamic request. If a dynamic request is resolved but the execution
       fails (ie. None is returned from the callback) a 404 status code is sent.
       If a dynamic request fails with an exception a 500 status code is sent.
    """
    server_version = "QuickServer/" + __version__

    protocol_version = "HTTP/1.1"


    def convert_argmap(self, query):
        """Converts the query string of an URL to a map.

        Parameters
        ----------
        query : string
            The URL to parse.

        Returns
        -------
        A map object containing all fields as keys with their value. Fields without
        '=' in the URL are interpreted as flags and the value is set to True.
        """
        res = {}
        for section in query.split('&'):
            eqs = section.split('=', 1)
            name = urlparse_unquote(eqs[0])
            if len(eqs) > 1:
                res[name] = urlparse_unquote(eqs[1])
            else:
                res[name] = True
        return res


    def convert_args(self, rem_path, args):
        """Splits the rest of a URL into its argument parts. The URL is assumed to
           start with the dynamic request prefix already removed.

        Parameters
        ----------
        rem_path : string
            The URL to parse. The URL must start with the dynamic request prefix
            already removed.

        args : map
            The map to fill.

        Returns
        -------
        args enriched with 'paths', an array containing the remaining path segments,
        'query', a map containing the query fields and flags, and 'fragment' containing
        the fragment part as string.
        """
        fragment_split = rem_path.split('#', 1)
        query_split = fragment_split[0].split('?', 1)
        segs = filter(lambda p: len(p) and p != '.', os.path.normpath(query_split[0]).split('/'))
        paths = [ urlparse_unquote(p) for p in segs ]
        query = self.convert_argmap(query_split[1]) if len(query_split) > 1 else {}
        args['paths'] = paths
        args['query'] = query
        args['fragment'] = urlparse_unquote(fragment_split[1]).decode('utf8') if len(fragment_split) > 1 else ''
        return args


    def get_post_file(self, hdr, f_in, clen, post, files):
        """Reads from a multipart/form-data."""
        lens = {
            'clen': clen,
            'push': [],
        }
        prefix = "boundary="
        if not hdr.startswith(prefix):
            return None
        boundary = hdr[len(prefix):].strip().encode('utf8')
        if not boundary:
            return None
        boundary = b'--' + boundary
        raw_boundary = b'\r\n' + boundary
        end_boundary = boundary + b'--'

        def push_back(line):
            l = BytesIO()
            l.write(line)
            l.flush()
            l.seek(0)
            lens['clen'] += len(line)
            lens['push'].append(l)

        def read_line():
            line = b''
            while not line.endswith(b'\n') and lens['push']:
                br = lens['push'].pop()
                line += br.readline()
                tmp = br.read(1)
                if tmp != b'':
                    br.seek(br.tell() - 1)
                    lens['push'].append(br)
            if not line.endswith(b'\n'):
                line += f_in.readline(lens['clen'])
            lens['clen'] -= len(line)
            if line == b'' or lens['clen'] < 0:
                raise ValueError("Unexpected EOF")
            return line.strip()

        def read(length):
            res = b''
            while len(res) < length and lens['push']:
                br = lens['push'].pop()
                res += br.read(length - len(res))
                tmp = br.read(1)
                if tmp != b'':
                    br.seek(br.tell() - 1)
                    lens['push'].append(br)
            if len(res) < length:
                res += f_in.read(length - len(res))
            lens['clen'] -= len(res)
            if res == b'' or lens['clen'] < 0:
                raise ValueError("Unexpected EOF")
            return res

        def parse_file():
            f = BytesIO()
            buff_size = 10 * 1024

            def write_buff(buff):
                if f.tell() + len(buff) > self.server.max_file_size:
                    self.send_error(413, "Uploaded file is too large! {0} > {1}".format(
                        f.tell() + len(buff), self.server.max_file_size)
                    )
                    raise PreventDefaultResponse()
                f.write(buff)
                f.flush()

            buff = b""
            while True:
                buff += read(min(lens['clen'], buff_size))
                bix = buff.find(raw_boundary)
                if bix >= 0:
                    write_buff(buff[:bix])
                    push_back(buff[bix + len(raw_boundary) - len(boundary):])
                    break
                out_split = max(len(buff) - len(raw_boundary), 0)
                if out_split > 0:
                    write_buff(buff[:out_split])
                    buff = buff[out_split:]
            f.seek(0)
            return f

        def parse_field():
            return parse_file().read().decode('utf8')

        while True:
            line = read_line()
            if line == end_boundary:
                if lens['clen'] > 0:
                    raise ValueError("Expected EOF got: {0}".format(repr(f_in.read(lens['clen']))))
                return
            if line != boundary:
                raise ValueError("Expected boundary got: {0}".format(repr(line)))
            headers = {}
            while True:
                line = read_line()
                if not line:
                    break
                key, value = line.split(b':', 1)
                headers[key.lower()] = value.strip()
            name = None
            if b'content-disposition' in headers:
                cdis = headers[b'content-disposition']
                if not cdis.startswith(b'form-data'):
                    raise ValueError("Unknown content-disposition: {0}".format(repr(cdis)))
                name_field = b'name="'
                ix = cdis.find(name_field)
                if ix >= 0:
                    name = cdis[ix + len(name_field):]
                    name = name[:name.index(b'"')].decode('utf8')
            ctype = None
            if b'content-type' in headers:
                ctype = headers[b'content-type']
            if ctype is not None: # b'application/octet-stream': # we treat all files the same
                files[name] = parse_file()
            else:
                post[name] = parse_field()


    def handle_special(self, send_body, method_str):
        """Handles a dynamic request. If this method returns False the request is
           interpreted as static file request. Methods can be registered using the
           `add_TYPE_METHOD_mask` methods of QuickServer.

        Parameters
        ----------
        send_body : bool
            Whether to actually send the result body. This is False if the URL was
            requested as HEAD.

        method_str : string
            The method as string: POST, GET, or HEAD.

        Returns
        -------
        A bool whether the request was handled. If it was not handled the requested
        URL is interpreted as static file.
        """
        ongoing = True
        if self.server.report_slow_requests:
            path = self.path

            def do_report():
                if not ongoing:
                    return
                msg("request takes longer than expected: \"{0} {1}\"", method_str, path)

            alarm = threading.Timer(5.0, do_report)
            alarm.start()
        else:
            alarm = None
        try:
            return self._handle_special(send_body, method_str)
        finally:
            if alarm is not None:
                alarm.cancel()
            ongoing = False


    def _handle_special(self, send_body, method_str):
        path = self.path
        # interpreting the URL masks to find which method to call
        method = None
        method_mask = None
        rem_path = ""
        for mask, m in self.server._f_mask.get(method_str, []):
            lm = len(mask)
            if path.startswith(mask) and (mask[-1] == '/' or len(path) <= lm + 1 or path[lm] in '#?/'):
                method = m
                method_mask = mask
                rem_path = path[lm:]
                break
        if method is None:
            return False
        files = {}
        args = {}
        try:
            # POST can accept forms encoded in JSON
            if method_str == 'POST':
                ctype = _getheader(self.headers, 'content-type')
                crest = ""
                if ';' in ctype:
                    splix = ctype.index(';')
                    crest = ctype[splix+1:].strip() if len(ctype) > splix + 1 else ""
                    ctype = ctype[:splix].strip()
                clen = int(_getheader(self.headers, 'content-length'))
                if ctype == 'multipart/form-data':
                    post_res = {}
                    args['post'] = {}
                    args['files'] = {}
                    self.get_post_file(crest, self.rfile, clen, args['post'], args['files'])
                else:
                    content = self.rfile.read(clen)
                    post_res = {}
                    if ctype == 'application/json':
                        post_res = json.loads(content)
                    elif ctype == 'application/x-www-form-urlencoded':
                        post_res = self.convert_argmap(content)
                    args['post'] = post_res

            args = self.convert_args(rem_path, args)
            # check for correct path length
            if self.server._f_argc[method_mask] is not None and self.server._f_argc[method_mask] != len(args['paths']):
                return False
            # call the method with the arguments
            try:
                f = None
                f = method(self, args)
                if f is not None and send_body:
                    self.copyfile(f, self.wfile)
                    thread_local.size = f.tell()
            finally:
                if f is not None:
                    f.close()
        finally:
            for f in files.values():
                f.close()
        return True


    # optionally block the listing of directories
    def list_directory(self, path):
        if not self.server.directory_listing:
            self.send_error(404, "No permission to list directory")
            return None
        return SimpleHTTPRequestHandler.list_directory(self, path)


    def translate_path(self, orig_path):
        """Translates a path for a static file request. The server base path could
           be different from our cwd.

        Parameters
        ----------
        path : string
            The path.

        Returns
        -------
        The absolute file path denoted by the original path.
        """
        init_path = orig_path
        orig_path = urlparse.urlparse(orig_path)[2]
        needs_redirect = False
        is_folder = len(orig_path) <= 1 or orig_path[-1] == '/'
        orig_path = posixpath.normpath(urlparse_unquote(orig_path))
        if is_folder:
            orig_path += '/'
        path = None
        for (name, fm) in self.server._folder_masks:
            if not orig_path.startswith(name):
                continue
            cur_base = os.path.abspath(os.path.join(self.server.base_path, fm))
            path = cur_base
            words = orig_path[len(name):].split('/')
            words = filter(None, words)
            for word in words:
                drive, word = os.path.splitdrive(word)
                head, word = os.path.split(word)
                if word in (os.curdir, os.pardir):
                    continue
                if word.startswith('.'): # don't ever allow any hidden files
                    self.send_error(404, "File not found")
                    raise PreventDefaultResponse()
                path = os.path.join(path, word)
            # make path absolute and check if it exists
            path = os.path.abspath(path)
            if os.path.exists(path):
                break
        # if pass is still None here the file cannot be found
        if path is None:
            msg("no matching folder alias: {0}".format(orig_path))
            self.send_error(404, "File not found")
            raise PreventDefaultResponse()
        if os.path.isdir(path):
            if not is_folder:
                needs_redirect = True
            else:
                for orig_index in [ "index.html", "index.htm" ]:
                    index = os.path.join(path, orig_index)
                    if os.path.isfile(index):
                        path = index
                        break
        if os.path.isdir(path):
            # no black-/white-list for directories
            is_white = True
        else:
            # match agains black- and white-list
            is_white = len(self.server._pattern_white) == 0
            for pattern in self.server._pattern_white:
                if fnmatch.fnmatch(path, pattern):
                    is_white = True
                    break
            for pattern in self.server._pattern_black:
                if fnmatch.fnmatch(path, pattern):
                    is_white = False
                    break
        if not is_white:
            self.send_error(404, "File not found")
            raise PreventDefaultResponse()
        # make sure to not accept any trickery to get away from the base path
        if not path.startswith(cur_base):
            raise ValueError("WARNING: attempt to access {0}".format(path))
        # favicon handling
        if self.server.favicon_everywhere and os.path.basename(path) == 'favicon.ico' and not os.path.exists(path):
            for (name, fm) in self.server._folder_masks:
                fav_base = os.path.abspath(os.path.join(self.server.base_path, fm))
                favicon = os.path.join(fav_base, 'favicon.ico')
                if os.path.exists(favicon):
                    path = favicon
                    break
                if self.server.favicon_fallback is not None and os.path.exists(self.server.favicon_fallback):
                    path = os.path.join(self.server.base_path, self.server.favicon_fallback)
                    break
        # redirect improper index requests
        if needs_redirect:
            self.send_response(301, "Use index page with slash")
            location = urlparse.urlunparse(tuple([
                seg if ix != 2 else seg + '/' for (ix, seg) in enumerate(urlparse.urlparse(init_path))
            ]))
            self.send_header("Location", location)
            self.end_headers()
            raise PreventDefaultResponse()
        # handle ETag caching
        if self.request_version >= "HTTP/1.1" and os.path.isfile(path):
            e_tag = None
            with open(path, 'rb') as input_f:
                e_tag = "{0:x}".format(zlib.crc32(input_f.read()) & 0xFFFFFFFF)
                thread_local.size = input_f.tell()
            if e_tag is not None:
                match = _getheader(self.headers, 'if-none-match')
                if match is not None:
                    if self.check_cache(e_tag, match):
                        raise PreventDefaultResponse()
                self.send_header("ETag", e_tag, end_header=True)
                self.send_header("Cache-Control", "max-age={0}".format(self.server.max_age), end_header=True)
        return path


    def check_cache(self, e_tag, match):
        """Checks the ETag and sends a cache match response if it matches."""
        if e_tag != match:
            return False
        self.send_response(304)
        self.send_header("ETag", e_tag)
        self.send_header("Cache-Control", "max-age={0}".format(self.server.max_age))
        self.end_headers()
        thread_local.size = 0
        return True


    def handle_error(self):
        """Tries to send an 500 error after encountering an exception."""
        if self.server.can_ignore_error(self):
            return
        if thread_local.status_code is None:
            msg("ERROR: Cannot send error status code! Header already sent!")
        else:
            msg("ERROR: Error while processing request:\n{0}", traceback.format_exc())
            try:
                self.send_error(500, "Internal Error")
            except:
                if self.server.can_ignore_error(self):
                    return
                msg("ERROR: Cannot send error status code:\n{0}", traceback.format_exc())


    def is_cross_origin(self):
        return self.server.cross_origin


    def cross_origin_headers(self):
        """Sends cross origin headers."""
        if not self.is_cross_origin():
            return False
        # we allow everything
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD")
        allow_headers = _getheader(self.headers, 'access-control-request-headers')
        if allow_headers is not None:
            self.send_header("Access-Control-Allow-Headers", allow_headers)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        return allow_headers is not None


    def do_OPTIONS(self):
        """Handles an OPTIONS request."""
        thread_local.clock_start = time.clock()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        self.send_response(200)
        if self.is_cross_origin():
            no_caching = self.cross_origin_headers()
            self.send_header("Access-Control-Max-Age", 0 if no_caching else 10*60) # ten minutes if no custom headers requested
        self.send_header("Content-Length", 0)
        self.end_headers()
        thread_local.size = 0


    def do_DELETE(self):
        """Handles a DELETE request."""
        thread_local.clock_start = time.clock()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        try:
            self.cross_origin_headers()
            self.handle_special(True, 'DELETE')
        except PreventDefaultResponse:
            pass
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()


    def do_PUT(self):
        """Handles a PUT request."""
        thread_local.clock_start = time.clock()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        try:
            self.cross_origin_headers()
            self.handle_special(True, 'PUT')
        except PreventDefaultResponse:
            pass
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()


    def do_POST(self):
        """Handles a POST request."""
        thread_local.clock_start = time.clock()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        try:
            self.cross_origin_headers()
            self.handle_special(True, 'POST')
        except PreventDefaultResponse:
            pass
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()


    def do_GET(self):
        """Handles a GET request."""
        thread_local.clock_start = time.clock()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        try:
            self.cross_origin_headers()
            if self.handle_special(True, 'GET'):
                return
            SimpleHTTPRequestHandler.do_GET(self)
        except PreventDefaultResponse:
            pass
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()


    def do_HEAD(self):
        """Handles a HEAD request."""
        thread_local.clock_start = time.clock()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        try:
            self.cross_origin_headers()
            if self.handle_special(False, 'GET'):
                return
            SimpleHTTPRequestHandler.do_HEAD(self)
        except PreventDefaultResponse:
            pass
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()


    # responses and headers are not sent until end headers to enable
    # changing them if needed
    def send_response(self, status_code, message=None):
        thread_local.status_code = status_code
        thread_local.message = message


    def send_header(self, key, value, replace=False, end_header=False):
        thread_local.headers = getattr(thread_local, 'headers', [])
        thread_local.end_headers = getattr(thread_local, 'end_headers', [])
        if replace:
            # replaces the last occurrence of the header, otherwise append as specified

            def do_replace(hdrs):
                replace_ix = -1
                for (ix, (k, _)) in enumerate(hdrs):
                    if k == key:
                        # no break -- we want the last index
                        replace_ix = ix
                if replace_ix >= 0:
                    hdrs[replace_ix] = (key, value)
                return replace_ix >= 0

            if do_replace(thread_local.end_headers):
                return
            if do_replace(thread_local.headers):
                return
        if not end_header:
            hd = thread_local.headers
        else:
            hd = thread_local.end_headers
        hd.append((key, value))


    def end_headers(self):
        thread_local.headers = getattr(thread_local, 'headers', [])
        thread_local.end_headers = getattr(thread_local, 'end_headers', [])
        thread_local.clock_start = getattr(thread_local, 'clock_start', time.clock())
        thread_local.status_code = getattr(thread_local, 'status_code', 500)
        thread_local.message = getattr(thread_local, 'message', None)
        thread_local.headers.extend(thread_local.end_headers)
        thread_local.end_headers = thread_local.headers
        thread_local.headers = []
        SimpleHTTPRequestHandler.send_response(self, thread_local.status_code, thread_local.message)
        for (key, value) in thread_local.headers:
            SimpleHTTPRequestHandler.send_header(self, key, value)
        for (key, value) in thread_local.end_headers:
            SimpleHTTPRequestHandler.send_header(self, key, value)
        SimpleHTTPRequestHandler.end_headers(self)
        thread_local.status_code = None
        thread_local.message = None
        thread_local.end_headers = []


    def log_date_time_string(self):
        """Server log date time format."""
        return time.strftime("%Y-%m-%d %H:%M:%S")


    def _convert_unit(self, fmt, value, units):
        cur = ''
        for (conv, unit) in units:
            if value / conv >= 1 or not len(cur):
                cur = fmt.format(value / conv) + unit
            else:
                break
        return cur


    # time units for logging request durations
    elapsed_units = [
        (1e-3, 'ms'),
        (1, 's'),
        (60, 'min'),
        (60*60, 'h'),
        (60*60*24, 'd')
    ]


    def log_elapsed_time_string(self, elapsed):
        """Convert elapsed time into a readable string."""
        return self._convert_unit("{0:8.3f}", elapsed, self.elapsed_units)


    # size units for logging request sizes
    size_units = [
        (1, ' B'),
        (1024, ' kB'),
        (1024*1024, ' MB'),
        (1024*1024*1024, ' GB')
    ]


    def log_size_string(self, size):
        """Convert buffer sizes into a readable string."""
        return self._convert_unit("{0:.3g}", size, self.size_units)


    def log_message(self, format, *args):
        """Logs a message. All messages get prefixed with '[SERVER]'
           and the arguments act like `format`.
        """
        clock_start = getattr(thread_local, 'clock_start', None)
        thread_local.clock_start = None
        timing = self.log_elapsed_time_string(time.clock() - clock_start) if clock_start is not None else ''
        msg("%s[%s] %s" % (timing + ' ' if len(timing) else '', self.log_date_time_string(), format % args))


    def log_request(self, code='-', size='-'):
        """Logs the current request."""
        print_size = getattr(thread_local, 'size', -1)
        if size != '-':
            size_str = ' (%s)' % size
        elif print_size >= 0:
            size_str = self.log_size_string(print_size) + ' '
        else:
            size_str = ''
        if not self.server.suppress_noise or (code != 200 and code != 304):
            self.log_message('%s"%s" %s', size_str, self.requestline, str(code))
        if print_size >= 0:
            thread_local.size = -1


class Response():
    def __init__(self, response, code=200, ctype=None):
        """Constructs a response."""
        self.response = response
        self.code = code
        self._ctype = ctype


    def get_ctype(self, ctype):
        """Returns the content type with the given default value."""
        if self._ctype is not None:
            return self._ctype
        return ctype


_token_default = "DEFAULT"
class QuickServer(http_server.HTTPServer):
    def __init__(self, server_address):
        """Creates a new QuickServer.

        Parameters
        ----------
        server_address : (addr : string, port : int)
            The server address as interpreted by HTTPServer.

        Attributes
        ----------
        base_path : path
            The base path of the server. All static files are server relative to this
            path. The server won't serve any file whose absolute path does not have
            this prefix. The base_path can be set automatically by `init_paths`.

        directory_listing : bool
            Whether to allow listing the directory if the 'index.html' is missing.
            Defaults to `False`.

        shutdown_latency : float
            The number of seconds as float to tolerate waiting for actually shutting
            down after a shutdown command was issued.

        history_file : filename
            Where to store / read the command line history.

        prompt : string
            The prompt shown in the command line input.

        favicon_everywhere : bool
            If True any path ending with 'favicon.ico' will try to serve the favicon
            file found at any root.

        favicon_fallback : string or None
            If set points to the fallback 'favicon.ico' file.

        max_age : number
            The content of the 'max-age' directive for the 'Cache-Control' header
            used by cached responses. Defaults to 0.

        max_file_size : number
            The maximal size for uploaded files. Defaults to 50MB.

        cross_origin : bool
            Whether to allow cross origin requests. Defaults to False.

        suppress_noise : bool
            If set only messages with a non-trivial status code (ie. not 200 nor 304)
            are reported. Defaults to False.

        report_slow_requests : bool
            If set request that take longer than 5 seconds are reported. Defaults to False.

        verbose_workers : bool
            If set messages about worker requests are printed.

        no_command_loop : bool
            If set the command loop won't be started.

        cache : quick_cache object or None
            The cache object used when caching worker results. The API must be
            similar to https://github.com/JosuaKrause/quick_cache
            The cache object should use the "string" method for best performance.
            Worker results can be cached when providing a `cache_id` function.

        done : bool
            If set to True the server will terminate.
        """
        http_server.HTTPServer.__init__(self, server_address, QuickServerRequestHandler)
        self.init = False
        self.base_path = os.path.abspath(".")
        self.directory_listing = False
        self.shutdown_latency = 0.1
        self.history_file = '.cmd_history'
        self.prompt = '> '
        self.favicon_everywhere = True
        self.favicon_fallback = None
        self.max_age = 0
        self.max_file_size = 50 * 1024 * 1024
        self.cross_origin = False
        self.suppress_noise = False
        self.report_slow_requests = False
        self.verbose_workers = False
        self.no_command_loop = False
        self.cache = None
        self.done = False
        self._folder_masks = []
        self._f_mask = {}
        self._f_argc = {}
        self._pattern_black = []
        self._pattern_white = []
        self._cmd_methods = {}
        self._cmd_argc = {}
        self._cmd_complete = {}
        self._cmd_lock = threading.Lock()
        self._cmd_start = False
        self._clean_up_call = None
        self._token_lock = threading.Lock()
        self._token_map = {}
        self._token_timings = []
        self._token_expire = 3600


    ### mask methods ###


    def add_file_patterns(self, patterns, blacklist):
        """Adds a list of file patterns to either the black- or white-list.
           Note that this pattern is applied to the absolute path of the file
           that will be delivered. For including or excluding folders use
           `add_folder_mask` or `add_folder_fallback`.
        """
        bl = self._pattern_black if blacklist else self._pattern_white
        for pattern in patterns:
            bl.append(pattern)


    def add_default_white_list(self):
        """Adds a list of common file patterns to the white-list."""
        self.add_file_patterns([
            '*.css',
            '*.csv',
            '*.eot',
            '*.gif',
            '*.htm',
            '*.html',
            '*.ico',
            '*.jpeg',
            '*.jpg',
            '*.js',
            '*.json',
            '*.json',
            '*.md',
            '*.otf',
            '*.pdf',
            '*.png',
            '*.svg',
            '*.tsv',
            '*.ttf',
            '*.txt',
            '*.woff',
            '*.woff2',
        ], blacklist=False)


    def bind_path(self, name, folder):
        """Adds a mask that maps to a given folder relative to `base_path`."""
        if not len(name) or name[0] != '/' or name[-1] != '/':
            raise ValueError("name must start and end with '/': {0}".format(name))
        self._folder_masks.insert(0, (name, folder))


    def bind_path_fallback(self, name, folder):
        """Adds a fallback for a given folder relative to `base_path`."""
        if not len(name) or name[0] != '/' or name[-1] != '/':
            raise ValueError("name must start and end with '/': {0}".format(name))
        self._folder_masks.append((name, folder))


    def add_cmd_method(self, name, method, argc=None, complete=None):
        """Adds a command to the command line interface loop.

        Parameters
        ----------
        name : string
            The command.

        method : function(args)
            The function to execute when this command is issued. The argument of the
            function is a list of space separated arguments to the command.

        argc : int, optional (default=None)
            The number of expected further arguments. If None arguments are not restricted.

        complete : function(args, text), optional (default=None)
            A function that is called to complete further arguments. If None no suggestions
            are made. The function gets the arguments up to the incomplete argument (args).
            text contains the to be completed argument. The function must returns a
            list of suggestions or None if text is valid already and there are no further
            suggestions.
        """
        if ' ' in name:
            raise ValueError("' ' cannot be in command name {0}".format(name))
        self._cmd_methods[name] = method
        self._cmd_argc[name] = argc
        self._cmd_complete[name] = complete


    def set_file_argc(self, mask, argc):
        """Sets the number of allowed further path segments to a request.

        Parameters
        ----------
        mask : string
            The mask of the request.

        argc : number or None
            The exact number of allowed further path segments or None if the number
            may be arbitrary.
        """
        self._f_argc[mask] = argc


    def _add_file_mask(self, start, method_str, method):
        """Adds a raw file mask for dynamic requests.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        method : function(esrh, args)
            The function to execute to perform the request. The function takes two
            arguments. esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', the fragment string 'fragment', and if the
            method was a POST the JSON form content 'post'). The function must return
            a file object containing the response (preferably BytesIO). If the
            result is None no response body is sent. In this case make sure to send
            an appropriate error code.
        """
        fm = self._f_mask.get(method_str, [])
        fm.append((start, method))
        fm.sort(key=lambda k: len(k[0]), reverse=True)
        self._f_mask[method_str] = fm
        self._f_argc[method_str] = None


    def add_json_mask(self, start, method_str, json_producer):
        """Adds a handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The function takes two
            arguments. esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', the fragment string 'fragment', and if the
            method was a POST the JSON form content 'post'). If the result is None
            a 404 error is sent.
        """
        def send_json(drh, rem_path):
            obj = json_producer(drh, rem_path)
            if not isinstance(obj, Response):
                obj = Response(obj)
            ctype = obj.get_ctype("application/json")
            code = obj.code
            obj = obj.response
            if obj is None:
                drh.send_error(404, "File not found")
                return None
            f = BytesIO()
            json_str = json_dumps(obj)
            if isinstance(json_str, (str, unicode)):
                try:
                    json_str = json_str.decode('utf8')
                except AttributeError:
                    pass
                json_str = json_str.encode('utf8')
            f.write(json_str)
            f.flush()
            size = f.tell()
            f.seek(0)
            # handle ETag caching
            if drh.request_version >= "HTTP/1.1":
                e_tag = "{0:x}".format(zlib.crc32(f.read()) & 0xFFFFFFFF)
                f.seek(0)
                match = _getheader(drh.headers, 'if-none-match')
                if match is not None:
                    if drh.check_cache(e_tag, match):
                        f.close()
                        return None
                drh.send_header("ETag", e_tag, end_header=True)
                drh.send_header("Cache-Control", "max-age={0}".format(self.max_age), end_header=True)
            drh.send_response(code)
            drh.send_header("Content-Type", ctype)
            drh.send_header("Content-Length", size)
            drh.end_headers()
            return f
        self._add_file_mask(start, method_str, send_json)


    def add_json_get_mask(self, start, json_producer):
        """Adds a GET handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The function takes two
            arguments. esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', and the fragment string 'fragment'). If the
            result is None a 404 error is sent.
        """
        self.add_json_mask(start, 'GET', json_producer)


    def add_json_put_mask(self, start, json_producer):
        """Adds a PUT handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The function takes two
            arguments. esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', and the fragment string 'fragment'). If the
            result is None a 404 error is sent.
        """
        self.add_json_mask(start, 'PUT', json_producer)


    def add_json_delete_mask(self, start, json_producer):
        """Adds a DELETE handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The function takes two
            arguments. esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', and the fragment string 'fragment'). If the
            result is None a 404 error is sent.
        """
        self.add_json_mask(start, 'DELETE', json_producer)


    def add_json_post_mask(self, start, json_producer):
        """Adds a POST handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The function takes two
            arguments. esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', the fragment string 'fragment', and the JSON
            form content 'post'). If the result is None a 404 error is sent.
        """
        self.add_json_mask(start, 'POST', json_producer)


    def add_text_mask(self, start, method_str, text_producer):
        """Adds a handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', the fragment string 'fragment', and if the
            method was a POST the JSON form content 'post'). If the result is None
            a 404 error is sent.
        """
        def send_text(drh, rem_path):
            text = text_producer(drh, rem_path)
            if not isinstance(text, Response):
                text = Response(text)
            ctype = text.get_ctype("text/plain")
            code = text.code
            text = text.response
            if text is None:
                drh.send_error(404, "File not found")
                return None
            f = BytesIO()
            if isinstance(text, (str, unicode)):
                try:
                    text = text.decode('utf8')
                except AttributeError:
                    pass
                text = text.encode('utf8')
            f.write(text)
            f.flush()
            size = f.tell()
            f.seek(0)
            # handle ETag caching
            if drh.request_version >= "HTTP/1.1":
                e_tag = "{0:x}".format(zlib.crc32(f.read()) & 0xFFFFFFFF)
                f.seek(0)
                match = _getheader(drh.headers, 'if-none-match')
                if match is not None:
                    if drh.check_cache(e_tag, match):
                        f.close()
                        return None
                drh.send_header("ETag", e_tag, end_header=True)
                drh.send_header("Cache-Control", "max-age={0}".format(self.max_age), end_header=True)
            drh.send_response(code)
            drh.send_header("Content-Type", ctype)
            drh.send_header("Content-Length", size)
            drh.end_headers()
            return f
        self._add_file_mask(start, method_str, send_text)


    def add_text_get_mask(self, start, text_producer):
        """Adds a GET handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', and the fragment string 'fragment').
            If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'GET', text_producer)


    def add_text_put_mask(self, start, text_producer):
        """Adds a PUT handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', and the fragment string 'fragment').
            If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'PUT', text_producer)


    def add_text_delete_mask(self, start, text_producer):
        """Adds a DELETE handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', and the fragment string 'fragment').
            If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'DELETE', text_producer)


    def add_text_post_mask(self, start, text_producer):
        """Adds a POST handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request (ie.
            the rest of the URL as path segment array 'paths', a map of all query
            fields / flags 'query', the fragment string 'fragment', and the JSON
            form content 'post'). If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'POST', text_producer)


    ### wrappers ###


    def cmd(self, argc=None, complete=None, no_replace=False):
        def wrapper(fun):
            name = fun.__name__
            if not no_replace or name not in self._cmd_methods:
                self.add_cmd_method(name, fun, argc, complete)
            return fun
        return wrapper


    def json_get(self, mask, argc=None):
        def wrapper(fun):
            self.add_json_get_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def json_put(self, mask, argc=None):
        def wrapper(fun):
            self.add_json_put_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def json_delete(self, mask, argc=None):
        def wrapper(fun):
            self.add_json_delete_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def json_post(self, mask, argc=None):
        def wrapper(fun):
            self.add_json_post_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def text_get(self, mask, argc=None):
        def wrapper(fun):
            self.add_text_get_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def text_put(self, mask, argc=None):
        def wrapper(fun):
            self.add_text_put_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def text_delete(self, mask, argc=None):
        def wrapper(fun):
            self.add_text_delete_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    def text_post(self, mask, argc=None):
        def wrapper(fun):
            self.add_text_post_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun
        return wrapper


    ### special files ###


    def add_special_file(self, mask, path, from_quick_server, ctype=None):
        """Adds a special file that might have a different actual path than
           its address.

        Parameters
        ----------
        mask : string
            The URL that must be matched to perform this request.

        path : string
            The actual file path.

        from_quick_server : bool
            If set the file path is relative to *this* script otherwise it is
            relative to the process.

        ctype : string
            Optional content type.
        """
        full_path = path if not from_quick_server else os.path.join(os.path.dirname(__file__), path)

        def read_file(_req, _args):
            with open(full_path, 'rb') as f_out:
                return Response(f_out.read(), ctype=ctype)

        self.add_text_get_mask(mask, read_file)
        self.set_file_argc(mask, 0)


    def link_empty_favicon_fallback(self):
        """Links the empty favicon as default favicon."""
        self.favicon_fallback = os.path.join(os.path.dirname(__file__), 'favicon.ico')


    ### worker based ###


    def link_worker_js(self, mask):
        """Links the worker javascript.

        Parameters
        ----------
        mask : string
            The URL that must be matched to get the worker javascript.
        """
        self.add_special_file(mask, 'worker.js', from_quick_server=True, ctype='application/javascript; charset=utf-8')


    def json_worker(self, mask, cache_id=None, cache_method="string", cache_section="www"):
        """A function annotation that adds a worker request. A worker request is
           a POST request that is computed asynchronously. That is, the actual
           task is performed in a different thread and the network request
           returns immediately. The client side uses polling to fetch the result
           and can also cancel the task. The worker javascript client side must
           be linked and used for accessing the request.

        Parameters
        ----------
        mask : string
            The URL that must be matched to perform this request.

        cache_id : function(args) or None
            Optional function for caching the result. If set the worker must be
            idempotent. Requires a `cache` object for the server. The function
            needs to return an object constructed from the function arguments
            to uniquely identify the result. Results are cached verbatim.

        cache_method : string or None
            Optional cache method string. Gets passed to get_hnd() of the cache.
            Defaults to "string" which requires a JSON serializable cache_id.

        cache_section : string or None
            Optional cache section string. Gets passed to get_hnd() of the cache.
            Defaults to "www".

        fun : function(args); (The annotated function)
            A function returning a (JSON-able) object. The function takes one
            argument which is the dictionary containing the payload from the
            client side. If the result is None a 404 error is sent.
        """
        use_cache = cache_id is not None

        def wrapper(fun):
            lock = threading.RLock()
            tasks = {}

            def is_done(cur_key):
                try:
                    lock.acquire()
                    if cur_key not in tasks:
                        return True
                    if "running" not in tasks[cur_key]:
                        return False
                    return not tasks[cur_key]["running"]
                finally:
                    lock.release()

            def remove_worker(cur_key):
                try:
                    lock.acquire()
                    task = tasks.pop(cur_key, None)
                    if task is None:
                        return None, (ValueError("Task {0} not found!".format(cur_key)), None)
                    if task["running"]:
                        th = task["thread"]
                        if th.is_alive():
                            # kill the thread
                            tid = None
                            for tk, tobj in threading._active.items():
                                if tobj is th:
                                    tid = tk
                                    break
                            if tid is not None:
                                res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), ctypes.py_object(WorkerDeath))
                                if res == 0:
                                    # invalid thread id -- the thread might be done already
                                    msg("invalid thread id for killing worker {0}", cur_key)
                                elif res != 1:
                                    # roll back
                                    ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(tid), None)
                                    msg("killed too many ({0}) workers? {1}", res, cur_key)
                                else:
                                    if self.verbose_workers:
                                        msg("killed worker {0}", cur_key)
                        return None, (ValueError("Task {0} is still running!".format(cur_key)), None)
                    return task["result"], task["exception"]
                finally:
                    lock.release()

            def start_worker(args, cur_key, get_thread):
                try:
                    try:
                        lock.acquire()
                        task = {
                            "running": True,
                            "result": None,
                            "exception": None,
                            "thread": get_thread(),
                        }
                        tasks[cur_key] = task
                    finally:
                        lock.release()
                    if use_cache:
                        cache_obj = cache_id(args)
                        if cache_obj is not None and self.cache is not None:
                            with self.cache.get_hnd(cache_obj, section=cache_section, method=cache_method) as hnd:
                                if hnd.has():
                                    result = hnd.read()
                                else:
                                    result = hnd.write(json_dumps(fun(args)))
                        else:
                            result = json_dumps(fun(args))
                    else:
                        result = json_dumps(fun(args))
                    try:
                        lock.acquire()
                        task["running"] = False
                        task["result"] = result
                    finally:
                        lock.release()
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as e:
                    try:
                        lock.acquire()
                        task["running"] = False
                        task["exception"] = (e, traceback.format_exc())
                    finally:
                        lock.release()
                    return
                # make sure the result does not get stored forever
                try:
                    time.sleep(120) # remove 2 minutes after not reading the result
                finally:
                    _result, err = remove_worker(cur_key)
                    if err is not None:
                        e, tb = err
                        if tb is not None:
                            msg("Error in purged worker for {0}: {1}\n{2}", cur_key, e, tb)
                            raise ValueError("proceeding from error")
                        return
                    msg("purged result that was never read ({0})", cur_key)

            def reserve_worker():
                try:
                    lock.acquire()
                    cur_key = int(zlib.crc32(repr(time.clock()).encode('utf8')) & 0xFFFFFFFF)
                    while cur_key in tasks:
                        key = int(cur_key + 1)
                        if key == cur_key:
                            key = 0
                        cur_key = key
                    tasks[cur_key] = {} # put marker
                    return cur_key
                finally:
                    lock.release()

            def run_worker(req, args):
                post = args["post"]
                try:
                    action = post["action"]
                    if action == "stop":
                        cur_key = post["token"]
                        remove_worker(cur_key) # throw away the result
                        return {
                            "token": cur_key,
                            "done": True,
                            "result": None,
                            "continue": False,
                        }
                    if action == "start":
                        cur_key = reserve_worker()
                        inner_post = post.get("payload", {})
                        th = []
                        worker = threading.Thread(target=start_worker, name="{0}-Worker-{1}".format(self.__class__, cur_key), args=(inner_post, cur_key, lambda: th[0]))
                        th.append(worker)
                        worker.start()
                        time.sleep(0.1) # give fast tasks a way to immediately return results
                    if action == "get":
                        cur_key = post["token"]
                    if is_done(cur_key):
                        result, exception = remove_worker(cur_key)
                        if exception is not None:
                            e, tb = exception
                            if tb is None:
                                # token does not exist anymore
                                return {
                                    "token": cur_key,
                                    "done": False,
                                    "result": None,
                                    "continue": False,
                                }
                            msg("Error in worker for {0}: {1}\n{2}", cur_key, e, tb)
                            raise ValueError("proceeding from error")
                        return {
                            "token": cur_key,
                            "done": True,
                            "result": result,
                            "continue": False,
                        }
                    return {
                        "token": cur_key,
                        "done": False,
                        "result": None,
                        "continue": True,
                    }
                except:
                    msg("Error processing worker command: {0}", post)
                    raise

            self.add_json_post_mask(mask, run_worker)
            self.set_file_argc(mask, 0)
            return fun
        return wrapper


    ### tokens ###


    def create_token(self):
        return uuid.uuid4().hex


    def set_default_token_expiration(self, expire):
        self._token_expire = expire


    def get_default_token_expiration(self):
        return self._token_expire


    def get_token_obj(self, token, expire=_token_default):
        """Returns or creates the object associaten with the given token.

        Parameters
        ----------
        token : string
            The token for the object as returned by `create_token`.

        expire : number or None
            The number of seconds until the object associated with the token
            expires or `None` if it should not expire. If the argument is
            omitted the value returned by `get_default_token_expiration` is
            used. The expiration of an object is lazy. That means the memory
            of the expired object is not freed until the next call of
            `get_token_obj`. An expiration of 0 or less immediately frees
            the memory of the token.
        """
        if expire == _token_default:
            expire = self.get_default_token_expiration()
        now = time.clock()
        until = now + expire if expire is not None else None
        with self._token_lock:
            # _token_timings is keys sorted by time
            first_valid = None
            for (pos, k) in enumerate(self._token_timings):
                t = self._token_map[k][0]
                if t is None or t > now:
                    first_valid = pos
                    break
            for k in self._token_timings[:first_valid]:
                del self._token_map[k]
            self._token_timings = self._token_timings[first_valid:]
            if until is None or until > now:
                if token not in self._token_map:
                    self._token_map[token] = (until, {})
                    self._token_timings.append(token)
                else:
                    self._token_map[token] = (until, self._token_map[token][1])
                self._token_timings.sort(key=lambda k: (
                    1 if self._token_map[k][0] is None else 0,
                    self._token_map[k][0]
                ))
                return self._token_map[token][1]
            else:
                if token in self._token_map:
                    self._token_timings = [ k for k in self._token_timings if k != token ]
                    del self._token_map[token]
                return {}


    ### miscellaneous ###


    def handle_cmd(self, cmd):
        """Handles a single server command."""
        cmd = cmd.strip()
        segments = []
        for s in cmd.split():
            # remove bash-like comments
            if s.startswith('#'):
                break
            # TODO implement escape sequences (also for \#)
            segments.append(s)
        args = []
        if not len(segments):
            return
        # process more specific commands first
        while segments:
            cur_cmd = "_".join(segments)
            if cur_cmd in self._cmd_methods:
                argc = self._cmd_argc[cur_cmd]
                if argc is not None and len(args) != argc:
                    msg('command {0} expects {1} argument(s), got {2}', " ".join(segments), argc, len(args))
                    return
                self._cmd_methods[cur_cmd](args)
                return
            args.insert(0, segments.pop())
        # invalid command
        prefix = '_'.join(args) + '_'
        matches = filter(lambda cmd: cmd.startswith(prefix), self._cmd_methods.keys())
        candidates = set([])
        for m in matches:
            if len(m) <= len(prefix):
                continue
            m = m[len(prefix):]
            if '_' in m:
                m = m[:m.index('_')]
            candidates.add(m)
        if len(candidates):
            msg('command "{0}" needs more arguments:', ' '.join(args))
            for c in candidates:
                msg('    {0}', c)
        else:
            msg('command "{0}" invalid; type help or use <TAB> for a list of commands', ' '.join(args))


    def start_cmd_loop(self):
        """Starts the command line loop. This method is called automatically by the
           serve_forever method. The function call is idempotent so you can call the
           method before or after that without worrying or extra side-effect. An EOF
           terminates the loop but does not close the server. A `KeyboardInterrupt`
           terminates the server as well.
        """
        # thread-safe check if the loop is already running
        try:
            self._cmd_lock.acquire()
            cmd_start = self._cmd_start
            self._cmd_start = True
        finally:
            self._cmd_lock.release()

        if cmd_start:
            return

        cmd_state = {
            'suggestions': [],
            'clean_up_lock': threading.Lock(),
            'clean': False,
            'line': '',
        }

        # setup internal commands (no replace)
        @self.cmd(argc=0, no_replace=True)
        def help(args):
            msg('available commands:')
            for key in self._cmd_methods.keys():
                msg('    {0}', key.replace('_', ' '))

        @self.cmd(argc=0, no_replace=True)
        def restart(args):
            global _do_restart
            _do_restart = True
            self.done = True

        @self.cmd(argc=0, no_replace=True)
        def quit(args):
            self.done = True

        # loading the history
        hfile = self.history_file
        try:
            readline.read_history_file(hfile)
        except IOError:
            pass

        # set up command completion
        def complete(text, state):
            if state == 0:
                origline = readline.get_line_buffer()
                line = origline.lstrip()
                stripped = len(origline) - len(line)
                begidx = readline.get_begidx() - stripped
                endidx = readline.get_endidx() - stripped
                prefix = line[:begidx].replace(' ', '_')
                matches = filter(
                    lambda cmd: cmd.startswith(prefix) and cmd[begidx:].startswith(text),
                    self._cmd_methods.keys()
                )
                candidates = [
                    m[
                        begidx : m.find('_', endidx)+1 if m.find('_', endidx) >= 0 else len(m)
                    ].replace('_', ' ') for m in matches
                ]
                rest_cmd = line[:begidx].split()
                args = []
                while rest_cmd:
                    cur_cmd = '_'.join(rest_cmd)
                    if cur_cmd in self._cmd_complete and self._cmd_complete[cur_cmd] is not None:
                        cc = self._cmd_complete[cur_cmd](args, text)
                        if cc is not None:
                            candidates.extend(cc)
                    args.insert(0, rest_cmd.pop())
                cmd_state['suggestions'] = sorted(set(candidates))
                cmd_state['line'] = line
            suggestions = cmd_state['suggestions']
            if len(suggestions) == 1 and text == suggestions[0]:
                probe_cmd = cmd_state['line'].replace(' ', '_')
                if probe_cmd in self._cmd_argc and self._cmd_argc[probe_cmd] != 0:
                    cmd_state['line'] = ""
                    return text + ' '
                return None
            if state < len(suggestions):
                return suggestions[state]
            return None

        old_completer = readline.get_completer()
        readline.set_completer(complete)
        # be mac compatible
        if readline.__doc__ is not None and 'libedit' in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

        # remember to clean up before exit -- the call must be idempotent!
        def clean_up():
            try:
                cmd_state['clean_up_lock'].acquire()
                clean = cmd_state['clean']
                cmd_state['clean'] = True
            finally:
                cmd_state['clean_up_lock'].release()

            if clean:
                return

            readline.write_history_file(hfile)
            readline.set_completer(old_completer)
        atexit.register(clean_up)
        self._clean_up_call = clean_up

        # start the server
        server = self

        class CmdLoop(threading.Thread):
            def __init__(self):
                threading.Thread.__init__(self)
                self.daemon = True

            def run(self):
                close = False
                kill = True
                try:
                    while not server.done and not close and not server.no_command_loop:
                        line = ""
                        try:
                            try:
                                line = input(server.prompt)
                            except IOError as e:
                                if e.errno == errno.EBADF:
                                    close = True
                                    kill = False
                                elif e.errno == errno.EWOULDBLOCK or e.errno == errno.EAGAIN or e.errno == errno.EINTR:
                                    continue
                                else:
                                    raise e
                            server.handle_cmd(line)
                        except EOFError:
                            close = True
                            kill = False
                        except KeyboardInterrupt:
                            close = True
                        except Exception:
                            msg("{0}", traceback.format_exc())
                            msg("^ exception executing command {0} ^", line)
                finally:
                    if kill:
                        server.done = True
                    else:
                        msg("no command loop - use CTRL-C to terminate")
                        server.no_command_loop = True
                    clean_up()

        if not server.no_command_loop:
            threading.Thread.start(CmdLoop())


    def handle_request(self):
        """Handles an HTTP request.The actual HTTP request is handled using a
           different thread.
        """
        timeout = self.socket.gettimeout()
        if timeout is None:
            timeout = self.timeout
        elif self.timeout is not None:
            timeout = min(timeout, self.timeout)
        ctime = time.clock()
        done_req = False
        shutdown_latency = self.shutdown_latency
        if timeout is not None:
            shutdown_latency = min(shutdown_latency, timeout) if shutdown_latency is not None else timeout
        while not (self.done or done_req) and (timeout is None or timeout == 0 or (time.clock() - ctime) < timeout):
            try:
                fd_sets = select.select([ self ], [], [], shutdown_latency)
            except (OSError, select.error) as e:
                if e.args[0] != errno.EINTR:
                    raise
                # treat EINTR as shutdown_latency timeout
                fd_sets = [[], [], []]
            for fd in fd_sets[0]:
                done_req = True
                self._handle_request_noblock()
            if timeout == 0:
                break
        if not (self.done or done_req):
            # don't handle timeouts if we should shut down the server instead
            self.handle_timeout()


    def serve_forever(self):
        """Starts the server handling commands and HTTP requests.
           The server will loop until done is True or a KeyboardInterrupt is
           received.
        """
        self.start_cmd_loop()
        try:
            while not self.done:
                self.handle_request()
        except KeyboardInterrupt:
            # clean error output if log file is STD_ERR
            if log_file == sys.stderr:
                log_file.write("\n")
        finally:
            if self._clean_up_call is not None:
                self._clean_up_call()
            self.done = True


    def can_ignore_error(self, reqhnd=None):
        """Tests if the error is worth reporting.
        """
        if not self.done:
            return False
        value = sys.exc_info()[1]
        if not isinstance(value, socket.error):
            return False
        need_close = value.errno == 9
        if need_close and reqhnd is not None:
            reqhnd.close_connection = 1
        return need_close


    def handle_error(self, request, client_address):
        """Handle an error gracefully.
        """
        if self.can_ignore_error():
            return
        thread = threading.current_thread()
        msg("Error in request ({0}): {1} in {2}\n{3}", client_address, repr(request), thread.name, traceback.format_exc())


class ParallelQuickServer(socketserver.ThreadingMixIn, QuickServer):
    daemon_threads = True
