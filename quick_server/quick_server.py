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
TYPE is the result type of the request (i.e., text, json) and METHOD is the
HTTP method (e.g., GET, POST). POST requests can contain JSON encoded form
data. You can bind static paths with the `bind_path` method.

Commands can be added via the `cmd` annotation where the function name is
the command. 'help', 'restart', and 'quit' are built-in commands ready to use.

Note: The server is thread based so all callback functions should be
thread-safe.

Please refer to the example folder for usage examples.
"""
from typing import (
    Any,
    BinaryIO,
    Callable,
    ContextManager,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    TextIO,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)
from typing_extensions import TypedDict, Literal

import os
import sys
import json
import math
import time
import uuid
import zlib
import errno
import shlex
import atexit
import ctypes
import select
import shutil
import signal
import socket
import fnmatch
import posixpath
import threading
import traceback
import collections
import contextlib

from io import StringIO, BytesIO

from urllib import parse as urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import readline

from http.server import SimpleHTTPRequestHandler
import http.server as http_server
import socketserver


WorkerArgs = Dict[str, Any]
TokenObj = Dict[str, Any]
CacheIdObj = Dict[str, Any]

CmdF = TypeVar("CmdF", bound=Callable[[List[str]], None])

ReqArgs = TypedDict('ReqArgs', {
    'paths': List[str],
    'query': Dict[str, Union[str, float, int, bool]],
    'post': WorkerArgs,
    'files': Dict[str, BytesIO],
    'fragment': str,
    'segments': Dict[str, str],
}, total=False)

ReqF = TypeVar(
    "ReqF", bound=Callable[['QuickServerRequestHandler', ReqArgs], Any])

WorkerF = TypeVar(
    "WorkerF",
    bound=Callable[[WorkerArgs], Any])

PostFileLens = TypedDict('PostFileLens', {
    'clen': int,
    'push': List[BytesIO],
})

WorkerTask = TypedDict('WorkerTask', {
    'running': bool,
    'result': Optional[str],
    'exception': Optional[Tuple[str, Optional[str]]],
    'thread': Optional[threading.Thread],
})

WorkerResponse = TypedDict('WorkerResponse', {
    "token": str,
    "done": bool,
    "result": Optional[Union[List[str], str]],
    "continue": bool,
})

MirrorObj = TypedDict('MirrorObj', {
    "impl": Literal["poll", "symlink", "none"],
    "files": List[Tuple[str, str, float]],
    "lock": threading.RLock,
})

DispatchObj = TypedDict('DispatchObj', {
    "map": Dict[str, Any],
    "fun": Callable[..., Any],
    "value": Any,
    "type": str,
    "child": Dict[str, Any],
}, total=False)

ActionObj = TypedDict('ActionObj', {
    "queries": List[Any],
    "type": str,
    "value": Any,
})

CmdState = TypedDict('CmdState', {
    'suggestions': List[str],
    'clean_up_lock': threading.Lock,
    'clean': bool,
    'line': str,
})


basestring = (str, bytes)
urlparse_unquote = urlparse.unquote


def get_time() -> float:
    return time.monotonic()


__version__ = "0.7.12"


def _getheader_fallback(obj: Any, key: str) -> Any:
    return obj.get(key)


def _getheader_p2(obj: Any, key: str) -> Any:
    global _getheader
    try:
        return obj.getheader(key)
    except AttributeError:
        _getheader = _getheader_fallback
        return _getheader(obj, key)


_getheader = _getheader_p2


def create_server(
        server_address: Tuple[str, int],
        parallel: bool = True,
        thread_factory: Optional[Callable[..., threading.Thread]] = None,
        token_handler: Optional['TokenHandler'] = None,
        worker_constructor: Optional[Callable[..., 'BaseWorker']] = None,
        soft_worker_death: bool = False) -> 'QuickServer':
    """Creates the server."""
    return QuickServer(
        server_address, parallel, thread_factory, token_handler,
        worker_constructor, soft_worker_death)


def json_dumps(obj: Any) -> str:
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

    def do_map(obj: Any) -> Any:
        if obj is None:
            return None
        if isinstance(obj, basestring):
            return obj
        if isinstance(obj, dict):
            res_obj = {}
            for (key, value) in obj.items():
                res_obj[key] = do_map(value)
            return res_obj
        if isinstance(obj, collections.Iterable):
            res_list = []
            for el in obj:
                res_list.append(do_map(el))
            return res_list
        # diverging numbers need to be passed as strings otherwise it
        # will throw a parsing error on the ECMAscript consumer side
        if math.isnan(obj):
            return "NaN"
        if math.isinf(obj):
            return "Infinity" if obj > 0 else "-Infinity"
        return obj

    return json.dumps(
        do_map(json_obj), indent=2, sort_keys=True, allow_nan=False)


log_file: Optional[TextIO] = None


def set_log_file(fname: TextIO) -> None:
    """Sets the log file. Defaults to STD_ERR."""
    global log_file

    log_file = fname


def _caller_trace(frame: Any) -> Tuple[str, int]:
    try:
        if '__file__' not in frame.f_globals:
            return '???', frame.f_lineno
        return frame.f_globals['__file__'], frame.f_lineno
    finally:
        del frame


def caller_trace() -> Tuple[str, int]:  # pragma: no cover
    try:
        raise Exception()
    except:  # nopep8
        try:
            frames = [sys.exc_info()[2].tb_frame]  # type: ignore
            for _ in range(2):
                frames.append(frames[-1].f_back)
            return _caller_trace(frames[-1])
        finally:
            del frames


if hasattr(sys, '_getframe'):
    def _caller_trace_gf() -> Tuple[str, int]:
        return _caller_trace(sys._getframe(2))

    caller_trace = _caller_trace_gf


long_msg = True
_msg_stderr = False


def msg(message: str, *args: Any, **kwargs: Any) -> None:
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
            file_name = "(-m) {0}".format(
                os.path.basename(os.path.dirname(file_name)))
        else:
            file_name = os.path.basename(file_name)
        head = '{0}{1} ({2}): '.format(file_name, file_type, line)
    else:
        head = '[SERVER] '
    out = StringIO()
    try:
        full_message = message.format(*args, **kwargs)
    except (ValueError, KeyError):
        full_message = str(message)
        for arg in args:
            full_message += '\n'
            full_message += str(arg)
        for (key, value) in kwargs.items():
            full_message += '\n'
            full_message += str(key)
            full_message += '='
            full_message += str(value)
    for curline in full_message.splitlines():
        out.write('{0}{1}\n'.format(head, curline))
    out.flush()
    out.seek(0)
    if _msg_stderr:
        sys.stderr.write(out.read())
        sys.stderr.flush()
    else:
        log_file.write(out.read())
        log_file.flush()
    out.close()


ERR_SOURCE_COMMAND = "err_command"
ERR_SOURCE_GENERAL_QS = "err_quick_server"
ERR_SOURCE_REQUEST = "err_request"
ERR_SOURCE_RESTART = "err_restart"
ERR_SOURCE_WORKER = "err_worker"


ERR_HND: Optional[Callable[[str, str, List[str]], None]] = None


def set_global_error_handler(
        fun: Optional[Callable[[str, str, List[str]], None]]) -> None:
    global ERR_HND

    ERR_HND = fun


def global_handle_error(source: str,
                        errmsg: str,
                        tb: str,
                        mfun: Callable[[str], None]) -> None:
    if ERR_HND is None:
        mfun(f"ERROR in {source}: {errmsg}\n{tb}")
        return
    ERR_HND(source, errmsg, tb.splitlines())


READLINE_IO: Optional[Tuple[TextIO, TextIO]] = None


def set_readline_io(stdout: TextIO, stderr: TextIO) -> None:
    global READLINE_IO

    READLINE_IO = (stdout, stderr)


def clear_readline_io() -> None:
    global READLINE_IO

    READLINE_IO = None


DEBUG: Optional[bool] = None


def debug(fun: Callable[[], Any]) -> None:
    global DEBUG
    if DEBUG is None:
        DEBUG = bool(int(os.environ.get('QUICK_SERVER_DEBUG', '0')))
    if DEBUG:
        msg("[DEBUG] {0}", fun())


debug(lambda: sys.version)


# thread local storage for keeping track of request information (e.g., time)
thread_local = threading.local()


# if a restart file is set a '1' is written to the file if a restart is
# requested if a restart exit code is set the restart file is ignored
_restart_file: Optional[str] = None


def set_restart_file(rf: Optional[str]) -> None:
    global _restart_file

    _restart_file = rf


_restart_exit_code = 42


def set_restart_exit_code(code: int) -> None:
    global _restart_exit_code

    _restart_exit_code = code


_error_exit_code = 1


def set_error_exit_code(code: int) -> None:
    global _error_exit_code

    _error_exit_code = code


def get_exec_arr() -> List[str]:
    executable = sys.executable
    if not executable:
        executable = os.environ.get('PYTHON', "")
    if not executable:
        raise ValueError("could not retrieve executable")
    exex_arr = shlex.split(executable)
    script = [sys.argv[0]]
    if script[0].endswith("/__main__.py"):
        script = [
            "-m", os.path.basename(script[0][:-len("/__main__.py")]),
        ]
    args = sys.argv[1:]
    return exex_arr + script + args


# handling the 'restart' command
_do_restart = False


def _on_exit() -> None:  # pragma: no cover
    global _do_restart

    if _do_restart:
        # avoid potential infinite loop when running atexit handlers
        _do_restart = False
        exit_code = os.environ.get('QUICK_SERVER_RESTART', None)
        if _restart_file is not None and exit_code is None:
            with open(_restart_file, 'w') as rf:
                rf.write('1')
                rf.flush()
        else:
            # restart the executable
            _start_restart_loop(exit_code, in_atexit=True)


atexit.register(_on_exit)


def _start_restart_loop(exit_code: Optional[str], in_atexit: bool) -> None:
    try:
        if exit_code is not None:
            # we have a parent process that restarts us
            child_code = int(exit_code)
        else:
            import subprocess

            exec_arr = get_exec_arr()
            if in_atexit:
                msg("restarting: {0}", ' '.join(exec_arr))

            debug(lambda: exec_arr)
            exit_code = str(_restart_exit_code)
            child_code = int(exit_code)
            is_subsequent = False
            while child_code == int(exit_code):
                environ = os.environ.copy()
                environ['QUICK_SERVER_RESTART'] = exit_code
                if is_subsequent:
                    environ['QUICK_SERVER_SUBSEQ'] = "1"
                is_subsequent = True
                try:
                    child_code = subprocess.Popen(
                        exec_arr, env=environ, close_fds=True).wait()
                except KeyboardInterrupt:
                    child_code = _error_exit_code
    except:  # nopep8
        global_handle_error(
            ERR_SOURCE_RESTART,
            "error during restart:", traceback.format_exc(), msg)
        child_code = _error_exit_code
    finally:
        if in_atexit:
            try:
                if not os.environ.get('RUN_ATEXIT', None):
                    atexit._run_exitfuncs()
            finally:
                os._exit(child_code)
        else:
            sys.exit(child_code)


def setup_restart() -> None:
    """Sets up restart functionality that doesn't keep the first process alive.
       The function needs to be called before the actual process starts but
       after loading the program. It will restart the program in a child
       process and immediately returns in the child process. The call in the
       parent process never returns. Calling this function is not necessary for
       using restart functionality but avoids potential errors originating from
       rogue threads.
    """
    exit_code = os.environ.get('QUICK_SERVER_RESTART', None)
    if exit_code is None:
        atexit.unregister(_on_exit)
        _start_restart_loop(None, in_atexit=False)


def is_original() -> bool:
    """Whether we are in the original process."""
    return 'QUICK_SERVER_RESTART' not in os.environ


def has_been_restarted() -> bool:
    """Returns whether the process has been restarted in the past. When using a
       restart file the calling process needs to set the environment variable
       "QUICK_SERVER_SUBSEQ" to the value "1" for the second and any subsequent
       call in order to make this function work.
    """
    return os.environ.get('QUICK_SERVER_SUBSEQ', "0") == "1"


PDR_MARK = "__pdr"


class PreventDefaultResponse(Exception):
    """Can be thrown to prevent any further processing of the request and
       instead send a customized response.
    """
    def __init__(self, code: Optional[int] = None, msg: Optional[str] = None):
        super().__init__()
        self.code = code
        self.msg = msg if msg else ""

    def __str__(self) -> str:
        return "{0}".format(self.__class__.__name__)


class WorkerDeath(Exception):
    def __str__(self) -> str:
        return "{0}".format(self.__class__.__name__)


def kill_thread(
        th: threading.Thread,
        cur_key: str,
        msg: Callable[..., None],
        is_verbose_workers: Callable[[], bool]) -> None:
    if not th.is_alive():
        return
    # kill the thread
    tid = None
    for tk, tobj in threading._active.items():  # type: ignore
        if tobj is th:
            tid = tk
            break
    if tid is not None:
        papi = ctypes.pythonapi
        pts_sae = papi.PyThreadState_SetAsyncExc
        res = pts_sae(ctypes.c_long(tid), ctypes.py_object(WorkerDeath))
        if res == 0:
            # invalid thread id -- the thread might
            # be done already
            msg("invalid thread id for killing worker {0}", cur_key)
        elif res != 1:
            # roll back
            pts_sae(ctypes.c_long(tid), None)
            msg("killed too many ({0}) workers? {1}", res, cur_key)
        else:
            if is_verbose_workers():
                msg("killed worker {0}", cur_key)


class QuickServerRequestHandler(SimpleHTTPRequestHandler):
    """The request handler for QuickServer. Delegates file requests to
       SimpleHTTPRequestHandler if the request could not be resolved as
       dynamic request. If a dynamic request is resolved but the execution
       fails (i.e., None is returned from the callback) a 404 status code is
       sent. If a dynamic request fails with an exception a 500 status code
       is sent.
    """
    server: 'QuickServer'

    def copyfile(self, source: BytesIO, outputfile: BinaryIO) -> None:
        """Copy all data between two file objects.
        The SOURCE argument is a file object open for reading
        (or anything with a read() method) and the DESTINATION
        argument is a file object open for writing (or
        anything with a write() method).
        The only reason for overriding this would be to change
        the block size or perhaps to replace newlines by CRLF
        -- note however that this the default server uses this
        to copy binary data as well.
        """
        shutil.copyfileobj(source, outputfile)

    server_version = "QuickServer/" + __version__

    protocol_version = "HTTP/1.1"

    def __str__(self) -> str:
        return "{0}[{1} {2}]".format(
            self.__class__.__name__, self.command, self.path)

    def convert_argmap(self,
                       query: Union[str, bytes],
                       ) -> Dict[str, Union[str, bool, int, float]]:
        """Converts the query string of an URL to a map.

        Parameters
        ----------
        query : string
            The URL to parse.

        Returns
        -------
        A map object containing all fields as keys with their value. Fields
        without '=' in the URL are interpreted as flags and the value is set
        to True.
        """
        res: Dict[str, Union[str, bool, int, float]] = {}
        if isinstance(query, bytes):
            query = query.decode('utf8')
        for section in query.split('&'):
            eqs = section.split('=', 1)
            name = urlparse_unquote(eqs[0])
            if len(eqs) > 1:
                res[name] = urlparse_unquote(eqs[1])
            else:
                res[name] = True
        return res

    def convert_args(
            self, rem_path: str, args: ReqArgs) -> ReqArgs:
        """Splits the rest of a URL into its argument parts. The URL is assumed
           to start with the dynamic request prefix already removed.

        Parameters
        ----------
        rem_path : string
            The URL to parse. The URL must start with the dynamic request
            prefix already removed.

        args : map
            The map to fill.

        Returns
        -------
        args enriched with 'paths', an array containing the remaining path
        segments, 'query', a map containing the query fields and flags, and
        'fragment' containing the fragment part as string.
        """
        fragment_split = rem_path.split('#', 1)
        query_split = fragment_split[0].split('?', 1)
        segs = filter(
            lambda p: len(p) and p != '.',
            os.path.normpath(query_split[0]).split('/'))
        paths = [urlparse_unquote(p) for p in segs]
        query = self.convert_argmap(query_split[1]) \
            if len(query_split) > 1 else {}
        args['paths'] = paths
        args['query'] = query
        args['fragment'] = urlparse_unquote(fragment_split[1]) \
            if len(fragment_split) > 1 else ''
        return args

    def get_post_file(
            self,
            hdr: str,
            f_in: BinaryIO,
            clen: int,
            post: Dict[str, str],
            files: Dict[str, BytesIO]) -> None:
        """Reads from a multipart/form-data."""
        lens: PostFileLens = {
            'clen': clen,
            'push': [],
        }
        prefix = "boundary="
        if not hdr.startswith(prefix):
            return
        boundary = hdr[len(prefix):].strip().encode('utf8')
        if not boundary:
            return
        boundary = b'--' + boundary
        raw_boundary = b'\r\n' + boundary
        end_boundary = boundary + b'--'

        def push_back(line: bytes) -> None:
            ln = BytesIO()
            ln.write(line)
            ln.flush()
            ln.seek(0)
            lens['clen'] += len(line)
            lens['push'].append(ln)

        def read_line() -> bytes:
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

        def read(length: int) -> bytes:
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

        def parse_file() -> BytesIO:
            f = BytesIO()
            buff_size = 10 * 1024

            def write_buff(buff: bytes) -> None:
                if f.tell() + len(buff) > self.server.max_file_size:
                    raise PreventDefaultResponse(
                        413, "Uploaded file is too large! {0} > {1}".format(
                            f.tell() + len(buff), self.server.max_file_size))
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

        def parse_field() -> str:
            return parse_file().read().decode('utf8')

        while True:
            line = read_line()
            if line == end_boundary:
                if lens['clen'] > 0:
                    raise ValueError(
                        "Expected EOF got: {0}".format(
                            repr(f_in.read(lens['clen']))))
                return
            if line != boundary:
                raise ValueError(
                    "Expected boundary got: {0}".format(repr(line)))
            headers = {}
            while True:
                line = read_line()
                if not line:
                    break
                key, value = line.split(b':', 1)
                headers[key.lower()] = value.strip()
            name: Optional[str] = None
            if b'content-disposition' in headers:
                cdis = headers[b'content-disposition']
                if not cdis.startswith(b'form-data'):
                    raise ValueError(
                        "Unknown content-disposition: {0}".format(repr(cdis)))
                name_field = b'name="'
                ix = cdis.find(name_field)
                if ix >= 0:
                    bname = cdis[ix + len(name_field):]
                    name = bname[:bname.index(b'"')].decode('utf8')
            ctype = None
            if b'content-type' in headers:
                ctype = headers[b'content-type']
            if name is None:
                raise ValueError("field name not set")
            # b'application/octet-stream': # we treat all files the same
            if ctype is not None:
                files[name] = parse_file()
            else:
                post[name] = parse_field()

    def handle_special(self, send_body: bool, method_str: str) -> bool:
        """Handles a dynamic request. If this method returns False the request
           is interpreted as static file request. Methods can be registered
           using the `add_TYPE_METHOD_mask` methods of QuickServer.

        Parameters
        ----------
        send_body : bool
            Whether to actually send the result body. This is False if the URL
            was requested as HEAD.

        method_str : string
            The method as string: POST, GET, or HEAD.

        Returns
        -------
        A bool whether the request was handled. If it was not handled the
        requested URL is interpreted as static file.
        """
        ongoing = True
        report_slow_requests = self.server.report_slow_requests
        if report_slow_requests:
            path = self.path

            def do_report() -> None:
                if not ongoing:
                    return
                if callable(report_slow_requests):
                    report_slow_requests(method_str, path)
                else:
                    msg("request takes longer than expected: \"{0} {1}\"",
                        method_str, path)

            alarm_init = threading.Timer(5.0, do_report)
            alarm_init.start()
            alarm: Optional[threading.Timer] = alarm_init
        else:
            alarm = None
        try:
            return self._handle_special(send_body, method_str)
        finally:
            if alarm is not None:
                alarm.cancel()
            ongoing = False

    def _handle_special(self, send_body: bool, method_str: str) -> bool:
        path = self.path
        # interpreting the URL masks to find which method to call
        method: Optional[Callable[
            [QuickServerRequestHandler, ReqArgs], Optional[BytesIO],
        ]] = None
        method_mask = None
        rem_path = ""
        segments: Dict[str, str] = {}

        def is_match(mask: str,
                     cur_path: str) -> Tuple[bool, str, Dict[str, str]]:
            is_m = True
            segs = {}
            for seg in mask.split("/"):
                if not seg:
                    continue
                if not cur_path or cur_path[0] != "/":
                    is_m = False
                    break
                cur_path = cur_path[1:]
                if seg.startswith(":"):
                    seg = seg[1:]
                    delim = cur_path.find("/")
                    if delim >= 0:
                        seg_value = cur_path[:delim]
                        cur_path = cur_path[delim:]
                    else:
                        seg_value = cur_path
                        cur_path = ""
                    segs[seg] = seg_value
                    continue
                if not cur_path.startswith(seg):
                    is_m = False
                    break
                cur_path = cur_path[len(seg):]
                if cur_path and cur_path[0] not in "#?/":
                    is_m = False
                    break
            return is_m, cur_path, segs

        for mask, m in self.server._f_mask.get(method_str, []):
            is_m, path_rest, segs = is_match(mask, path)
            if is_m:
                method = m
                method_mask = mask
                rem_path = path_rest
                segments = segs
                break
        if method is None:
            return False
        assert method_mask is not None
        files: Dict[str, BytesIO] = {}
        args: ReqArgs = {
            "segments": segments,
        }
        try:
            # POST can accept forms encoded in JSON
            if method_str in ['POST', 'DELETE', 'PUT']:
                ctype = _getheader(self.headers, 'content-type')
                crest = ""
                if ctype is None:
                    ctype = ""
                if ';' in ctype:
                    splix = ctype.index(';')
                    crest = ctype[splix+1:].strip() \
                        if len(ctype) > splix + 1 else ""
                    ctype = ctype[:splix].strip()
                clen = int(_getheader(self.headers, 'content-length'))
                if ctype == 'multipart/form-data':
                    args['post'] = {}
                    args['files'] = {}
                    self.get_post_file(
                        crest, self.rfile, clen, args['post'], args['files'])
                else:
                    content = self.rfile.read(clen)
                    post_res: WorkerArgs = {}
                    if ctype == 'application/json':
                        try:
                            post_res = json.loads(content)
                        except json.decoder.JSONDecodeError as json_err:
                            raise ValueError(
                                "request is not JSON formatted!",
                                content) from json_err
                    elif ctype == 'application/x-www-form-urlencoded':
                        post_res = self.convert_argmap(content)
                    args['post'] = post_res

            args = self.convert_args(rem_path, args)
            # check for correct path length
            if self.server._f_argc[method_mask] is not None and \
                    self.server._f_argc[method_mask] != len(args['paths']):
                return False
            # call the method with the arguments
            try:
                f: Optional[BytesIO] = None
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
    def list_directory(self, path: str) -> Optional[StringIO]:
        if not self.server.directory_listing:
            self.send_error(404, "No permission to list directory")
            return None
        return SimpleHTTPRequestHandler.list_directory(  # type: ignore
            self, path)

    def translate_path(self, orig_path: str) -> str:
        """Translates a path for a static file request. The server base path
           could be different from our cwd.

        Parameters
        ----------
        orig_path : string
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
        mpath: Optional[str] = None
        try:
            for (name, fm) in self.server._folder_masks:
                if not orig_path.startswith(name):
                    continue
                cur_base = os.path.abspath(
                    os.path.join(self.server.base_path, fm))
                mpath = cur_base
                words = filter(None, orig_path[len(name):].split('/'))
                for word in words:
                    _drive, word = os.path.splitdrive(word)
                    _head, word = os.path.split(word)
                    if word in (os.curdir, os.pardir):
                        continue
                    # don't ever allow any hidden files
                    if word.startswith('.'):
                        raise PreventDefaultResponse(404, "File not found")
                    mpath = os.path.join(mpath, word)
                # make path absolute and check if it exists
                mpath = os.path.abspath(mpath)
                if os.path.exists(mpath):
                    break
            # if pass is still None here the file cannot be found
            if mpath is None:
                # try proxies
                for (name, pxy) in self.server._folder_proxys:
                    if not orig_path.startswith(name):
                        continue
                    remain = orig_path[len(name) - 1:]
                    proxy = urlparse.urlparse(pxy)
                    reala = urlparse.urlparse(init_path)
                    pxya = urlparse.urlunparse((
                        proxy[0],  # scheme
                        proxy[1],  # netloc
                        "{0}{1}".format(proxy[2], remain),  # path
                        reala[3],  # params
                        reala[4],  # query
                        reala[5],  # fragment
                    ))
                    self.send_to_proxy(pxya)  # raises PreventDefaultResponse
                msg("no matching folder alias: {0}".format(orig_path))
                raise PreventDefaultResponse(404, "File not found")
            path: str = mpath
            if os.path.isdir(path):
                if not is_folder:
                    needs_redirect = True
                else:
                    for orig_index in ["index.html", "index.htm"]:
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
                raise PreventDefaultResponse(404, "File not found")
            # make sure to not accept any trickery to get away
            # from the base path
            if not path.startswith(cur_base):
                raise ValueError("WARNING: attempt to access {0}".format(path))
            # favicon handling
            if self.server.favicon_everywhere and \
                    os.path.basename(path) == 'favicon.ico' and \
                    not os.path.exists(path):
                for (name, fm) in self.server._folder_masks:
                    fav_base = os.path.abspath(
                        os.path.join(self.server.base_path, fm))
                    favicon = os.path.join(fav_base, 'favicon.ico')
                    if os.path.exists(favicon):
                        path = favicon
                        break
                    if self.server.favicon_fallback is not None and \
                            os.path.exists(self.server.favicon_fallback):
                        path = os.path.join(
                            self.server.base_path,
                            self.server.favicon_fallback)
                        break
            # redirect improper index requests
            if needs_redirect:
                self.send_response(301, "Use index page with slash")
                location = urlparse.urlunparse(tuple([
                    seg if ix != 2 else seg + '/'
                    for (ix, seg) in enumerate(urlparse.urlparse(init_path))
                ]))
                self.send_header("Location", location)
                self.end_headers()
                raise PreventDefaultResponse()
        except PreventDefaultResponse as pdr:
            ffcb = self.server._file_fallback_cb
            if ffcb is not None and pdr.code == 404:
                path = ffcb(orig_path)
            else:
                raise
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
                self.send_header("Cache-Control",
                                 "max-age={0}".format(self.server.max_age),
                                 end_header=True)
        return path

    def check_cache(self, e_tag: str, match: str) -> bool:
        """Checks the ETag and sends a cache match response if it matches."""
        if e_tag != match:
            return False
        self.send_response(304)
        self.send_header("ETag", e_tag)
        self.send_header("Cache-Control",
                         "max-age={0}".format(self.server.max_age))
        self.end_headers()
        thread_local.size = 0
        return True

    def send_to_proxy(self, proxy_url: str) -> None:
        clen = _getheader(self.headers, 'content-length')
        clen = int(clen) if clen is not None else 0
        if clen > 0:
            payload: Optional[bytes] = self.rfile.read(clen)
        else:
            payload = None

        req = Request(proxy_url,
                      data=payload,
                      headers=dict(self.headers.items()),
                      method=thread_local.method)
        try:
            response = urlopen(req)
        except HTTPError as e:
            response = e
        self.send_response(response.code)
        for (hk, hv) in response.headers.items():
            self.send_header(hk, hv)
        self.end_headers()
        if _getheader(response.headers, 'transfer-encoding') == 'chunked':
            # FIXME implement proper
            while True:
                cur = response.read(1024)
                if cur:
                    self.wfile.write(cur)
                    self.wfile.flush()
                else:
                    break  # FIXME no better solution now..
        else:
            self.wfile.write(response.read())
            self.wfile.flush()
        raise PreventDefaultResponse()

    def handle_error(self) -> None:
        """Tries to send an 500 error after encountering an exception."""
        if self.server.can_ignore_error(self):
            return
        if thread_local.status_code is None:
            global_handle_error(ERR_SOURCE_REQUEST,
                                "ERROR: Cannot send error status code! "
                                "Header already sent!",
                                traceback.format_exc(), msg)
        else:
            global_handle_error(
                ERR_SOURCE_REQUEST,
                "ERROR: Error while processing request:",
                traceback.format_exc(), msg)
            try:
                self.send_error(500, "Internal Error")
            except:  # nopep8
                if self.server.can_ignore_error(self):
                    return
                global_handle_error(
                    ERR_SOURCE_REQUEST,
                    "ERROR: Cannot send error status code:",
                    traceback.format_exc(), msg)

    def is_cross_origin(self) -> bool:
        return self.server.cross_origin

    def cross_origin_headers(self) -> bool:
        """Sends cross origin headers."""
        if not self.is_cross_origin():
            return False
        # we allow everything
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, PUT, DELETE, HEAD")
        allow_headers = _getheader(self.headers,
                                   'access-control-request-headers')
        if allow_headers is not None:
            self.send_header("Access-Control-Allow-Headers", allow_headers)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        return allow_headers is not None

    def do_OPTIONS(self) -> None:
        """Handles an OPTIONS request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = 'OPTIONS'
        self.send_response(200)
        if self.is_cross_origin():
            no_caching = self.cross_origin_headers()
            # ten minutes if no custom headers requested
            self.send_header("Access-Control-Max-Age",
                             0 if no_caching else 10*60)
        self.send_header("Content-Length", 0)
        self.end_headers()
        thread_local.size = 0

    def do_DELETE(self) -> None:
        """Handles a DELETE request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = 'DELETE'
        try:
            self.cross_origin_headers()
            self.handle_special(True, 'DELETE')
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_PUT(self) -> None:
        """Handles a PUT request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = 'PUT'
        try:
            self.cross_origin_headers()
            self.handle_special(True, 'PUT')
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_POST(self) -> None:
        """Handles a POST request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = 'POST'
        try:
            self.cross_origin_headers()
            self.handle_special(True, 'POST')
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_GET(self) -> None:
        """Handles a GET request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = 'GET'
        try:
            self.cross_origin_headers()
            if self.handle_special(True, 'GET'):
                return
            SimpleHTTPRequestHandler.do_GET(self)
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_HEAD(self) -> None:
        """Handles a HEAD request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = 'HEAD'
        try:
            self.cross_origin_headers()
            if self.handle_special(False, 'GET'):
                return
            SimpleHTTPRequestHandler.do_HEAD(self)
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    # responses and headers are not sent until end headers to enable
    # changing them if needed
    def send_response(
            self, status_code: int, message: Optional[str] = None) -> None:
        thread_local.status_code = status_code
        thread_local.message = message

    def send_header(self,
                    key: str,
                    value: Union[int, str],
                    replace: bool = False,
                    end_header: bool = False) -> None:
        thread_local.headers = getattr(thread_local, 'headers', [])
        thread_local.end_headers = getattr(thread_local, 'end_headers', [])
        if replace:
            # replaces the last occurrence of the header,
            # otherwise append as specified

            def do_replace(hdrs: List[Tuple[str, Union[str, int]]]) -> bool:
                replace_ix = -1
                for (ix, (k, _)) in enumerate(hdrs):
                    if k == key:
                        # no break -- we want the last index
                        replace_ix = ix
                did_replace = replace_ix >= 0
                if did_replace:
                    hdrs[replace_ix] = (key, value)
                return did_replace

            if do_replace(thread_local.end_headers):
                return
            if do_replace(thread_local.headers):
                return
        if not end_header:
            hd = thread_local.headers
        else:
            hd = thread_local.end_headers
        hd.append((key, value))

    def end_headers(self) -> None:
        thread_local.headers = getattr(thread_local, 'headers', [])
        thread_local.end_headers = getattr(thread_local, 'end_headers', [])
        thread_local.clock_start = getattr(thread_local,
                                           'clock_start',
                                           get_time())
        thread_local.status_code = getattr(thread_local, 'status_code', 500)
        thread_local.message = getattr(thread_local, 'message', None)
        thread_local.headers.extend(thread_local.end_headers)
        thread_local.end_headers = thread_local.headers
        thread_local.headers = []
        SimpleHTTPRequestHandler.send_response(
            self, thread_local.status_code, thread_local.message)
        for (key, value) in thread_local.headers:
            SimpleHTTPRequestHandler.send_header(self, key, value)
        for (key, value) in thread_local.end_headers:
            SimpleHTTPRequestHandler.send_header(self, key, value)
        SimpleHTTPRequestHandler.end_headers(self)
        thread_local.status_code = None
        thread_local.message = None
        thread_local.end_headers = []

    def log_date_time_string(self) -> str:
        """Server log date time format."""
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def _convert_unit(self,
                      fmt: str,
                      value: Union[float, int],
                      units: List[Tuple[Union[int, float], str]]) -> str:
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
        (60*60*24, 'd'),
    ]

    def log_elapsed_time_string(self, elapsed: float) -> str:
        """Convert elapsed time into a readable string."""
        return self._convert_unit("{0:8.3f}", elapsed, self.elapsed_units)

    # size units for logging request sizes
    size_units = [
        (1.0, ' B'),
        (1024, ' kB'),
        (1024*1024, ' MB'),
        (1024*1024*1024, ' GB'),
    ]

    def log_size_string(self, size: int) -> str:
        """Convert buffer sizes into a readable string."""
        return self._convert_unit("{0:.3g}", size, self.size_units)

    def log_message(self, format: str, *args: Any) -> None:
        """Logs a message. All messages get prefixed with '[SERVER]'
           and the arguments act like `format`.
        """
        clock_start = getattr(thread_local, 'clock_start', None)
        thread_local.clock_start = None
        timing = self.log_elapsed_time_string(
            get_time() - clock_start) if clock_start is not None else ''
        msg("%s[%s] %s" % (
            timing + ' ' if len(timing) else '', self.log_date_time_string(),
            format % args))

    def log_request(self,
                    code: Union[int, str] = '-',
                    size: Union[int, str] = '-') -> None:
        """Logs the current request."""
        print_size = getattr(thread_local, 'size', -1)
        if size != '-':
            size_str = ' (%s)' % size
        elif print_size >= 0:
            size_str = self.log_size_string(print_size) + ' '
        else:
            size_str = ''
        if not self.server.suppress_noise or (code != 200 and code != 304):
            self.log_message(
                '%s"%s" %s', size_str, self.requestline, str(code))
        if print_size >= 0:
            thread_local.size = -1


class TokenHandler:
    def __str__(self) -> str:
        return "{0}".format(self.__class__.__name__)

    def lock(self, key: Optional[str]) -> ContextManager:
        """The lock for token handler operations."""
        raise NotImplementedError()

    def ttl(self, key: str) -> Optional[float]:
        """Returns the time in seconds until the given key expires.
           If the key never expires it should return None. If the key doesn't
           exist it should return 0. The function must not update the
           expiration time.
        """
        raise NotImplementedError()  # pragma: no cover

    def flush_old_tokens(self) -> None:
        """Ensures that all expired tokens get removed."""
        raise NotImplementedError()  # pragma: no cover

    def add_token(self, key: str, expire: Optional[float]) -> TokenObj:
        """Returns the content of a token and updates the expiration in seconds
           of the token. Unknown tokens get initialized.
           `flush_old_tokens` is called immediately before this function.
        """
        raise NotImplementedError()  # pragma: no cover

    def put_token(self, key: str, obj: TokenObj) -> None:
        """Writes the given content to the given key.
           If the key does not exist the behavior is undefined.
        """
        raise NotImplementedError()  # pragma: no cover

    def delete_token(self, key: str) -> None:
        """Deletes a token.
           `flush_old_tokens` is called immediately before this function.
        """
        raise NotImplementedError()  # pragma: no cover

    def get_tokens(self) -> List[str]:
        """Returns a list of current tokens.
           `flush_old_tokens` is called immediately before this function.
        """
        raise NotImplementedError()  # pragma: no cover


class DefaultTokenHandler(TokenHandler):
    def __init__(self) -> None:
        # _token_timings is keys sorted by time
        self._token_map: Dict[str, Tuple[Optional[float], TokenObj]] = {}
        self._token_timings: List[str] = []
        self._token_lock = threading.Lock()

    def lock(self, key: Optional[str]) -> ContextManager:
        return self._token_lock

    def ttl(self, key: str) -> Optional[float]:
        # NOTE: has _token_lock
        try:
            until = self._token_map[key][0]
            if until is None:
                return None
            return until - get_time()
        except KeyError:
            return 0

    def flush_old_tokens(self) -> None:
        # NOTE: has _token_lock
        now = get_time()
        first_valid = None
        for (pos, k) in enumerate(self._token_timings):
            t = self._token_map[k][0]
            if t is None or t > now:
                first_valid = pos
                break
        if first_valid is None:
            self._token_map = {}
            self._token_timings = []
        else:
            for k in self._token_timings[:first_valid]:
                del self._token_map[k]
            self._token_timings = self._token_timings[first_valid:]

    def add_token(self, key: str, expire: Optional[float]) -> TokenObj:
        # NOTE: has _token_lock
        now = get_time()
        until = now + expire if expire is not None else None
        if key not in self._token_map:
            self._token_map[key] = (until, {})
            self._token_timings.append(key)
        else:
            tup = self._token_map[key]
            self._token_map[key] = (until, tup[1])
        self._token_timings.sort(key=lambda k: (
            1 if self._token_map[k][0] is None else 0,
            self._token_map[k][0],
        ))
        return self._token_map[key][1]

    def put_token(self, key: str, obj: TokenObj) -> None:
        tup = self._token_map[key]
        self._token_map[key] = (tup[0], obj)

    def delete_token(self, key: str) -> None:
        # NOTE: has _token_lock
        if key in self._token_map:
            self._token_timings = [
                k for k in self._token_timings if k != key
            ]
            del self._token_map[key]

    def get_tokens(self) -> List[str]:
        # NOTE: has _token_lock
        return list(self._token_timings)

    def __str__(self) -> str:
        return "{0}: {1}\n{2}".format(
            self.__class__.__name__, self._token_timings, self._token_map)


def get_worker_check() -> Callable[[], bool]:
    """Returns a function to determine whether the current worker is still
       active and has not been cancelled. This function needs to be called
       from the worker thread itself. It will always return True otherwise.
    """
    def jupp() -> bool:
        return True

    return getattr(thread_local, "worker_check", jupp)


def is_worker_alive() -> bool:
    """Whether the current worker is still active and has not been cancelled.
       This function needs to be called from the worker thread itself. It
       will always return True otherwise.
    """

    check = get_worker_check()
    return check()


class BaseWorker:
    def __init__(self, mask: str, fun: Callable[[WorkerArgs], str],
                 msg: Callable[..., None],
                 cache_id: Optional[Callable[[CacheIdObj], Any]],
                 cache: Any, cache_method: str, cache_section: str,
                 thread_factory: Callable[..., threading.Thread],
                 name_prefix: str, soft_worker_death: bool,
                 get_max_chunk_size: Callable[[], int],
                 is_verbose_workers: Callable[[], bool]):
        self._mask = mask
        self._fun = fun
        self._msg = msg
        self._use_cache = cache_id is not None
        self._cache_id = cache_id
        self._cache = cache
        self._cache_method = cache_method
        self._cache_section = cache_section
        self._thread_factory = thread_factory
        self._name_prefix = name_prefix
        self._soft_worker_death = soft_worker_death
        self._get_max_chunk_size = get_max_chunk_size
        self._is_verbose_workers = is_verbose_workers

    def __str__(self) -> str:
        return "{0}[{1}]".format(
            self.__class__.__name__, self._mask)

    def is_done(self, cur_key: str) -> bool:
        """Returns whether the task with the given key has finished."""
        raise NotImplementedError()  # pragma: no cover

    def add_cargo(self, content: str) -> List[str]:
        """Splits content into chunks and returns a list of keys to retrieve
           them. This function also ensures that chunks get cleaned up after
           10min of no reads. The size of the chunks is
           `_get_max_chunk_size()`.
        """
        raise NotImplementedError()  # pragma: no cover

    def remove_cargo(self, cur_key: str) -> str:
        """Removes the cargo with the given key and returns its chunk content.
        """
        raise NotImplementedError()  # pragma: no cover

    def remove_worker(self,
                      cur_key: str) -> Tuple[
                          Optional[str],
                          Optional[Tuple[str, Optional[str]]]]:
        """Removes the task with the given key and returns its result.
           The result is a tuple `(result, exception)` where result is the
           response if not None else exception is a tuple `(msg, trace)` where
           msg is the message of the exception and trace is the formatted
           stacktrace. In case of a PreventDefaultResponse exception the
           message uses the `PDR_MARK` prefix and the status code after.
           `trace` in this case is the message of the response.
        """
        raise NotImplementedError()  # pragma: no cover

    def get_key(self) -> str:
        """Creates a key that is currently not in use."""
        raise NotImplementedError()  # pragma: no cover

    def reserve_worker(self) -> str:
        """Allocates a key via `get_key` and occupies the space until
           `add_task` is called. The used key is returned.
        """
        raise NotImplementedError()  # pragma: no cover

    def add_task(self,
                 cur_key: str,
                 get_thread: Callable[..., threading.Thread],
                 soft_death: bool) -> None:
        """Marks a key as actually running. The thread executing the worker
           can be retrieved via `get_thread`. `soft_death` indicates whether
           an exception should be thrown when canceling a worker.
        """
        raise NotImplementedError()  # pragma: no cover

    def set_task_result(self, cur_key: str, result: str) -> None:
        """Sets the result for the given task."""
        raise NotImplementedError()  # pragma: no cover

    def set_task_pdr(self, cur_key: str, p: PreventDefaultResponse) -> None:
        """Sets the prevent default response values for the given task."""
        raise NotImplementedError()  # pragma: no cover

    def set_task_err(self, cur_key: str, e: Exception) -> None:
        """Sets the error for the given task."""
        raise NotImplementedError()  # pragma: no cover

    def remove_from_cancelled(self, cur_key: str) -> None:
        """Removes the cancelation indicator of the key if the task was
           previously cancelled.
        """
        raise NotImplementedError()  # pragma: no cover

    def start_worker(self,
                     args: WorkerArgs,
                     cur_key: str,
                     get_thread: Callable[[], threading.Thread]) -> None:
        try:
            self.add_task(cur_key, get_thread, self._soft_worker_death)
            if self._use_cache:
                assert self._cache_id is not None
                cache_obj = self._cache_id(args)
                if cache_obj is not None and self._cache is not None:
                    with self._cache.get_hnd(
                            cache_obj,
                            section=self._cache_section,
                            method=self._cache_method) as hnd:
                        if hnd.has():
                            result = hnd.read()
                        else:
                            result = hnd.write(json_dumps(self._fun(args)))
                else:
                    result = json_dumps(self._fun(args))
            else:
                result = json_dumps(self._fun(args))
            self.set_task_result(cur_key, result)
        except (KeyboardInterrupt, SystemExit):
            self.remove_worker(cur_key)  # remove key
            raise
        except PreventDefaultResponse as p:
            self.set_task_pdr(cur_key, p)
        except Exception as e:
            self.set_task_err(cur_key, e)
        finally:
            self.remove_from_cancelled(cur_key)
        # make sure the result does not get stored forever
        try:
            # remove 2 minutes after not reading the result
            time.sleep(120)
        finally:
            _result, err = self.remove_worker(cur_key)
            if err is not None:
                result, tb = err
                if tb is not None:
                    global_handle_error(
                        ERR_SOURCE_WORKER,
                        f"Error in purged worker for {cur_key}: {result}",
                        tb, self._msg)
                return
            self._msg("purged result that was never read ({0})", cur_key)

    def compute_worker(self,
                       req: QuickServerRequestHandler,
                       post: WorkerArgs) -> WorkerResponse:
        action = post["action"]
        cur_key = None
        if action == "stop":
            cur_key = post["token"]
            self.remove_worker(cur_key)  # throw away the result
            return {
                "token": cur_key,
                "done": True,
                "result": None,
                "continue": False,
            }
        if action == "start":
            cur_key = self.reserve_worker()
            inner_post = post.get("payload", {})
            th: List[threading.Thread] = []

            def start_worker(*args: Any) -> None:
                self.start_worker(*args)

            wname = "{0}-Worker-{1}".format(self._name_prefix, cur_key)
            worker = self._thread_factory(
                target=start_worker,
                name=wname,
                args=(inner_post, cur_key, lambda: th[0]))
            th.append(worker)
            worker.start()
            # give fast tasks a way to immediately return results
            time.sleep(0.1)
        if action == "cargo":
            cur_key = post["token"]
            result = self.remove_cargo(cur_key)
            return {
                "token": cur_key,
                "done": True,
                "result": result,
                "continue": False,
            }
        if action == "get":
            cur_key = post["token"]
        if cur_key is None:
            raise ValueError("invalid action: {0}".format(action))
        if self.is_done(cur_key):
            mresult, exception = self.remove_worker(cur_key)
            if exception is not None:
                err, tb = exception
                if tb is None:
                    # token does not exist anymore
                    return {
                        "token": cur_key,
                        "done": False,
                        "result": None,
                        "continue": False,
                    }
                if err.startswith(PDR_MARK):
                    # e encodes code, tb encodes message
                    raise PreventDefaultResponse(int(err[len(PDR_MARK):]), tb)
                global_handle_error(
                    ERR_SOURCE_WORKER,
                    f"Error in worker for {self._mask} ({cur_key}): {err}",
                    tb, self._msg)
                raise PreventDefaultResponse(500, "worker error")
            if mresult is not None and \
                    len(mresult) > self._get_max_chunk_size():
                cargo_keys = self.add_cargo(mresult)
                return {
                    "token": cur_key,
                    "done": True,
                    "result": cargo_keys,
                    "continue": True,
                }
            return {
                "token": cur_key,
                "done": True,
                "result": mresult,
                "continue": False,
            }
        return {
            "token": cur_key,
            "done": False,
            "result": None,
            "continue": True,
        }

    def on_error(self, post: WorkerArgs) -> None:
        self._msg("Error processing worker command: {0}", post)


class DefaultWorker(BaseWorker):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        BaseWorker.__init__(self, *args, **kwargs)
        self._lock = threading.RLock()
        self._tasks: Dict[str, WorkerTask] = {}
        self._cargo: Dict[str, Tuple[float, str]] = {}
        self._cargo_cleaner: Optional[threading.Thread] = None
        self._cancelled: Set[str] = set()

    def remove_from_cancelled(self, cur_key: str) -> None:
        with self._lock:
            if cur_key in self._cancelled:
                self._cancelled.remove(cur_key)

    def is_cancelled(self, cur_key: str) -> bool:
        with self._lock:
            return cur_key in self._cancelled

    def start_cargo_cleaner(self) -> None:

        def clean() -> None:
            while True:
                next_ttl = self.get_next_cargo()
                if next_ttl is None:
                    if self.remove_cleaner():
                        break
                    else:
                        continue
                time_until = next_ttl - time.time()
                if time_until > 0:
                    time.sleep(time_until)
                self.clean_for(time.time())

        with self._lock:
            if self._cargo_cleaner is not None:
                return
            cleaner = self._thread_factory(
                target=clean,
                name="{0}-Cargo-Cleaner".format(self._name_prefix))
            cleaner.daemon = True
            self._cargo_cleaner = cleaner
            cleaner.start()

    def get_next_cargo(self) -> Optional[float]:
        with self._lock:
            next_ttl = None
            for value in self._cargo.values():
                ttl, _ = value
                if next_ttl is None or ttl < next_ttl:
                    next_ttl = ttl
            return next_ttl

    def clean_for(self, timestamp: float) -> None:
        with self._lock:
            keys = []
            for (key, value) in self._cargo.items():
                ttl, _ = value
                if ttl > timestamp:
                    continue
                keys.append(key)
            for k in keys:
                self._cargo.pop(k)
                self._msg("purged cargo that was never read ({0})", k)

    def remove_cleaner(self) -> bool:
        with self._lock:
            if self.get_next_cargo() is not None:
                return False
            self._cargo_cleaner = None
            return True

    def add_cargo(self, content: str) -> List[str]:
        with self._lock:
            mcs = self._get_max_chunk_size()
            if mcs < 1:
                raise ValueError("invalid chunk size: {0}".format(mcs))
            ttl = time.time() + 10 * 60  # 10 minutes
            chunks = []
            while len(content) > 0:
                chunk = content[:mcs]
                content = content[mcs:]
                cur_key = self.get_key()
                self._cargo[cur_key] = (ttl, chunk)
                chunks.append(cur_key)
            self.start_cargo_cleaner()
            return chunks

    def remove_cargo(self, cur_key: str) -> str:
        with self._lock:
            _, result = self._cargo.pop(cur_key)
            return result

    def remove_worker(
            self,
            cur_key: str,
            ) -> Tuple[Optional[str], Optional[Tuple[str, Optional[str]]]]:
        with self._lock:
            task = self._tasks.pop(cur_key, None)
            if task is None:
                err_msg = "Error: Task {0} not found!".format(cur_key)
                return None, (err_msg, None)
            if task["running"]:
                th = task["thread"]
                err_msg = "Error: Task {0} is still running!".format(cur_key)
                if th is not None:
                    kill_thread(
                        th, cur_key, self._msg, self._is_verbose_workers)
                else:
                    self._cancelled.add(cur_key)
                return None, (err_msg, None)
            return task["result"], task["exception"]

    def is_done(self, cur_key: str) -> bool:
        with self._lock:
            if cur_key not in self._tasks or self.is_cancelled(cur_key):
                return True
            return not self._tasks[cur_key]["running"]

    def get_key(self) -> str:
        with self._lock:
            crc32 = zlib.crc32(repr(get_time()).encode('utf8'))
            cur_key = int(crc32 & 0xFFFFFFFF)

            def exists_somewhere(key: str) -> bool:
                return key in self._tasks \
                    or key in self._cargo \
                    or key in self._cancelled

            while exists_somewhere(str(cur_key)):
                key = cur_key + 1
                if key == cur_key:
                    key = 0
                cur_key = key
            return str(cur_key)

    def add_task(self,
                 cur_key: str,
                 get_thread: Callable[[], threading.Thread],
                 soft_death: bool) -> None:
        with self._lock:
            task: WorkerTask = {
                "running": True,
                "result": None,
                "exception": None,
                "thread": get_thread() if not soft_death else None,
            }
            if soft_death:

                def worker_check() -> bool:
                    return not self.is_cancelled(cur_key)

                thread_local.worker_check = worker_check
            self._tasks[cur_key] = task

    def set_task_result(self, cur_key: str, result: str) -> None:
        with self._lock:
            if cur_key not in self._tasks or self.is_cancelled(cur_key):
                return
            task = self._tasks[cur_key]
            task["running"] = False
            task["result"] = result

    def set_task_pdr(self, cur_key: str, p: PreventDefaultResponse) -> None:
        with self._lock:
            if cur_key not in self._tasks or self.is_cancelled(cur_key):
                return
            task = self._tasks[cur_key]
            task["running"] = False
            task["exception"] = ("{0}{1}".format(PDR_MARK, p.code), p.msg)

    def set_task_err(self, cur_key: str, e: Exception) -> None:
        with self._lock:
            if cur_key not in self._tasks or self.is_cancelled(cur_key):
                return
            task = self._tasks[cur_key]
            task["running"] = False
            task["exception"] = ("{0}".format(e), traceback.format_exc())

    def reserve_worker(self) -> str:
        with self._lock:
            cur_key = self.get_key()
            # put marker
            self._tasks[cur_key] = {
                "running": True,
                "result": None,
                "exception": None,
                "thread": None,
            }
            return cur_key


class Response:
    def __init__(self,
                 response: Union[str, bytes, StringIO, BytesIO],
                 code: int = 200,
                 ctype: Optional[str] = None) -> None:
        """Constructs a response."""
        self.response = response
        self.code = code
        self._ctype = ctype

    def __str__(self) -> str:
        return "{0}[{1}{2}]".format(
            self.__class__.__name__,
            self.code,
            " {0}".format(self._ctype) if self._ctype is not None else "")

    def get_ctype(self, ctype: str) -> str:
        """Returns the content type with the given default value."""
        if self._ctype is not None:
            return self._ctype
        return ctype


def construct_multipart_response(
        obj: Dict[Union[bytes, str], Any]) -> Tuple[BytesIO, str]:
    boundary = "qsboundary{0}".format(uuid.uuid4().hex)

    def binary(text: Union[str, bytes]) -> bytes:
        try:
            text = text.decode('utf8')  # type: ignore
        except AttributeError:
            pass
        return text.encode('utf8')  # type: ignore

    bbound = binary(boundary)
    resp = BytesIO()
    for (skey, value) in obj.items():
        key = binary(skey)
        resp.write(b"--")
        resp.write(bbound)
        resp.write(b"\r\n")
        resp.write(b"Content-Disposition: form-data; name=\"")
        resp.write(key)
        resp.write(b"\"; filename=\"")
        resp.write(key)
        resp.write(b"\"\r\n")
        if hasattr(value, "read"):
            if hasattr(value, "seek"):
                value.seek(0)
            resp.write(b"Content-Type: application/octet-stream\r\n")
            resp.write(b"\r\n")
            shutil.copyfileobj(value, resp, length=16*1024)
        elif isinstance(value, (str, bytes)):
            resp.write(b"Content-Type: text/plain\r\n")
            resp.write(b"\r\n")
            resp.write(binary(value))
        else:
            resp.write(b"Content-Type: application/json\r\n")
            resp.write(b"\r\n")
            resp.write(binary(json_dumps(value)))
        resp.write(b"\r\n")
    resp.write(b"--")
    resp.write(bbound)
    resp.write(b"--\r\n")
    resp.seek(0)
    return resp, "multipart/form-data; boundary=\"{0}\"".format(boundary)


class MultipartResponse(Response):
    def __init__(self, obj: Any) -> None:
        response, ctype = construct_multipart_response(obj)
        Response.__init__(self, response=response, code=200, ctype=ctype)


_token_default: Literal["DEFAULT"] = "DEFAULT"


class QuickServer(http_server.HTTPServer):
    def __init__(self, server_address: Tuple[str, int], parallel: bool = True,
                 thread_factory: Callable[..., threading.Thread] = None,
                 token_handler: Optional[TokenHandler] = None,
                 worker_constructor: Optional[Callable[[], BaseWorker]] = None,
                 soft_worker_death: bool = False):
        """Creates a new QuickServer.

        Parameters
        ----------
        server_address : (addr : string, port : int)
            The server address as interpreted by HTTPServer.

        parallel : bool
            Whether requests should be processed in parallel.

        thread_factory : lambda *args
            A callback to create a thread or None to use the standard thread.

        token_handler : TokenHandler
            The TokenHandler. None for default handler.

        worker_constructor : BaseWorker
            Constructor that creates a BaseWorker. None for default worker.

        soft_worker_death : bool
            Whether killing a worker should be handled through polling (true)
            or via exception (false; default)

        Attributes
        ----------
        base_path : path
            The base path of the server. All static files are server relative
            to this path. The server won't serve any file whose absolute path
            does not have this prefix. The base_path can be set automatically
            by `init_paths`.

        directory_listing : bool
            Whether to allow listing the directory if the 'index.html'
            is missing. Defaults to `False`.

        shutdown_latency : float
            The number of seconds as float to tolerate waiting for actually
            shutting down after a shutdown command was issued.

        history_file : filename
            Where to store / read the command line history.

        prompt : string
            The prompt shown in the command line input.

        favicon_everywhere : boolean
            If True any path ending with 'favicon.ico' will try to serve the
            favicon file found at any root.

        favicon_fallback : string or None
            If set points to the fallback 'favicon.ico' file.

        max_age : number
            The content of the 'max-age' directive for the 'Cache-Control'
            header used by cached responses. Defaults to 0.

        max_file_size : number
            The maximal size for uploaded files. Defaults to 50MB.

        max_chunk_size : number
            The maximal chunk size for worker responses. Defaults to 100MB.

        cross_origin : bool
            Whether to allow cross origin requests. Defaults to False.

        suppress_noise : bool
            If set only messages with a non-trivial status code
            (i.e., not 200 nor 304) are reported. Defaults to False.

        report_slow_requests : bool or function
            If set request that take longer than 5 seconds are reported.
            Defaults to False. If the value is callable the method_str and
            path are provided as arguments.

        verbose_workers : bool
            If set messages about worker requests are printed.

        no_command_loop : bool
            If set the command loop won't be started.

        cache : quick_cache object or None
            The cache object used when caching worker results. The API must be
            similar to https://github.com/JosuaKrause/quick_cache
            The cache object should use the "string" method for best
            performance. Worker results can be cached when providing a
            `cache_id` function.

        object_path : string
            The path to connect to the object interface.

        done : bool
            If set to True the server will terminate.
        """
        super().__init__(server_address, QuickServerRequestHandler)
        self.init = False
        self.base_path = os.path.abspath(".")
        self.directory_listing = False
        self.shutdown_latency = 0.1
        self.history_file = '.cmd_history'
        self.prompt = '> '
        self.favicon_everywhere = True
        self.favicon_fallback: Optional[str] = None
        self.max_age = 0
        self.max_file_size = 50 * 1024 * 1024
        self.max_chunk_size = 10 * 1024 * 1024
        self.cross_origin = False
        self.suppress_noise = False
        self.report_slow_requests: \
            Union[bool, Callable[[str, str], None]] = False
        self.verbose_workers = False
        self.no_command_loop = False
        self.cache: Optional[Any] = None
        self.object_path = "/objects/"
        self.done = False
        self._parallel = parallel
        if thread_factory is None:
            def _thread_factory_impl(
                    *args: Any, **kwargs: Any) -> threading.Thread:
                return threading.Thread(*args, **kwargs)

            self._thread_factory = _thread_factory_impl
        else:
            self._thread_factory = thread_factory
        if worker_constructor is None:
            self._worker_constructor: Callable[..., BaseWorker] = DefaultWorker
        else:
            self._worker_constructor = worker_constructor
        self._soft_worker_death = soft_worker_death
        self._folder_masks: List[Tuple[str, str]] = []
        self._folder_proxys: List[Tuple[str, str]] = []
        self._f_mask: Dict[str, List[Tuple[str, Callable[
            [QuickServerRequestHandler, ReqArgs], Optional[BytesIO]],
        ]]] = {}
        self._f_argc: Dict[str, Optional[int]] = {}
        self._pattern_black: List[str] = []
        self._pattern_white: List[str] = []
        self._cmd_methods: Dict[str, Callable[[List[str]], None]] = {}
        self._cmd_argc: Dict[str, Optional[int]] = {}
        self._cmd_complete: Dict[str, Optional[
            Callable[[List[str], str], Optional[List[str]]]
        ]] = {}
        self._cmd_lock = threading.Lock()
        self._cmd_start = False
        self._clean_up_call: Optional[Callable[[], None]] = None
        if token_handler is None:
            token_handler = DefaultTokenHandler()
        self._token_handler = token_handler
        self._token_expire = 3600
        self._mirror: MirrorObj = {
            "impl": "none",
            "files": [],
            "lock": threading.RLock(),
        }
        self._object_dispatch: Optional[Dict[str, DispatchObj]] = None
        self._file_fallback_cb: Optional[Callable[[str], str]] = None

    def __str__(self) -> str:
        return "{0}[{1}{2}]".format(
            self.__class__.__name__,
            self.server_address,
            " parallel" if self._parallel else "")

    # request processing #

    def _process_request(self,
                         request: bytes,
                         client_address: Tuple[str, int]) -> None:
        """Actually processes the request."""
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)  # type: ignore

    def process_request(self,
                        request: bytes,
                        client_address: Tuple[str, int]) -> None:
        """Processes the request by delegating to `_process_request`."""
        if not self._parallel:
            self._process_request(request, client_address)
            return
        t = self._thread_factory(
            target=self._process_request, args=(request, client_address))
        t.daemon = True
        t.start()

    # mask methods #

    def set_file_fallback_hook(
            self, callback: Optional[Callable[[str], str]]) -> None:
        """Allows to rewrite the returned filename in case a path could not
           be resolved. This is useful for returning the index file everywhere.
           If callback is None a 404 response will be generated. The callback
           is a function that accepts the path as argument and returns a new
           path. No white / blacklisting is performed on the returned path.
        """
        self._file_fallback_cb = callback

    def add_file_patterns(self, patterns: List[str], blacklist: bool) -> None:
        """Adds a list of file patterns to either the black- or white-list.
           Note that this pattern is applied to the absolute path of the file
           that will be delivered. For including or excluding folders use
           `bind_path` or `bind_path_fallback`.
        """
        bl = self._pattern_black if blacklist else self._pattern_white
        for pattern in patterns:
            bl.append(pattern)

    def add_default_white_list(self) -> None:
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

    def bind_path(self, name: str, folder: str) -> None:
        """Adds a mask that maps to a given folder relative to `base_path`."""
        if not len(name) or name[0] != '/' or name[-1] != '/':
            raise ValueError(
                "name must start and end with '/': {0}".format(name))
        self._folder_masks.insert(0, (name, folder))

    def bind_path_fallback(self, name: str, folder: str) -> None:
        """Adds a fallback for a given folder relative to `base_path`."""
        if not len(name) or name[0] != '/' or name[-1] != '/':
            raise ValueError(
                "name must start and end with '/': {0}".format(name))
        self._folder_masks.append((name, folder))

    def bind_proxy(self, name: str, proxy: str) -> None:
        """Adds a mask that maps to a given proxy."""
        if not len(name) or name[0] != '/' or name[-1] != '/':
            raise ValueError(
                "name must start and end with '/': {0}".format(name))
        self._folder_proxys.insert(0, (name, proxy))

    def add_cmd_method(self,
                       name: str,
                       method: Callable[[List[str]], None],
                       argc: Optional[int] = None,
                       complete: Optional[
                           Callable[[List[str], str], Optional[List[str]]]
                       ] = None) -> None:
        """Adds a command to the command line interface loop.

        Parameters
        ----------
        name : string
            The command.

        method : function(args)
            The function to execute when this command is issued. The argument
            of the function is a list of space separated arguments to the
            command.

        argc : int, optional (default=None)
            The number of expected further arguments. If None arguments are
            not restricted.

        complete : function(args, text), optional (default=None)
            A function that is called to complete further arguments. If None
            no suggestions are made. The function gets the arguments up to the
            incomplete argument (args). text contains the to be completed
            argument. The function must returns a list of suggestions or None
            if text is valid already and there are no further suggestions.
        """
        if ' ' in name:
            raise ValueError("' ' cannot be in command name {0}".format(name))
        self._cmd_methods[name] = method
        self._cmd_argc[name] = argc
        self._cmd_complete[name] = complete

    def set_file_argc(self, mask: str, argc: Optional[int]) -> None:
        """Sets the number of allowed further path segments to a request.

        Parameters
        ----------
        mask : string
            The mask of the request.

        argc : number or None
            The exact number of allowed further path segments or None if the
            number may be arbitrary.
        """
        self._f_argc[mask] = argc

    def _add_file_mask(
            self,
            start: str,
            method_str: str,
            method: Callable[
                [QuickServerRequestHandler, ReqArgs], Optional[BytesIO],
            ]) -> None:
        """Adds a raw file mask for dynamic requests.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        method : function(esrh, args)
            The function to execute to perform the request. The function takes
            two arguments. esrh is the QuickServerRequestHandler object that
            called the function. args is a map containing the arguments to the
            request (i.e., the rest of the URL as path segment array 'paths', a
            map of all query fields / flags 'query', the fragment string
            'fragment', and if the method was a POST the JSON form content
            'post'). The function must return a file object containing the
            response (preferably BytesIO). If the result is None no response
            body is sent. In this case make sure to send an appropriate error
            code.
        """
        fm = self._f_mask.get(method_str, [])
        fm.append((start, method))
        fm.sort(key=lambda k: len(k[0]), reverse=True)
        self._f_mask[method_str] = fm
        self._f_argc[method_str] = None

    def add_json_mask(
            self,
            start: str,
            method_str: str,
            json_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. esrh is the QuickServerRequestHandler
            object that called the function. args is a map containing the
            arguments to the request (i.e., the rest of the URL as path segment
            array 'paths', a map of all query fields / flags 'query', the
            fragment string 'fragment', and if the method was a POST the JSON
            form content 'post'). If the result is None a 404 error is sent.
        """

        def send_json(
                drh: QuickServerRequestHandler,
                rem_path: ReqArgs) -> Optional[BytesIO]:
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
            if isinstance(json_str, (str, bytes)):
                try:
                    json_str = json_str.decode('utf8')  # type: ignore
                except AttributeError:
                    pass
                json_str = json_str.encode('utf8')  # type: ignore
            f.write(json_str)  # type: ignore
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
                drh.send_header("Cache-Control",
                                "max-age={0}".format(self.max_age),
                                end_header=True)
            drh.send_response(code)
            drh.send_header("Content-Type", ctype)
            drh.send_header("Content-Length", size)
            drh.end_headers()
            return f

        self._add_file_mask(start, method_str, send_json)

    def add_json_get_mask(
            self, start: str, json_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a GET handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. esrh is the QuickServerRequestHandler
            object that called the function. args is a map containing the
            arguments to the request (i.e., the rest of the URL as path segment
            array 'paths', a map of all query fields / flags 'query', and the
            fragment string 'fragment'). If the result is None a 404 error is
            sent.
        """
        self.add_json_mask(start, 'GET', json_producer)

    def add_json_put_mask(
            self, start: str, json_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a PUT handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. esrh is the QuickServerRequestHandler
            object that called the function. args is a map containing the
            arguments to the request (i.e., the rest of the URL as path segment
            array 'paths', a map of all query fields / flags 'query', and the
            fragment string 'fragment'). If the result is None a 404 error is
            sent.
        """
        self.add_json_mask(start, 'PUT', json_producer)

    def add_json_delete_mask(
            self, start: str, json_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a DELETE handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. esrh is the QuickServerRequestHandler
            object that called the function. args is a map containing the
            arguments to the request (i.e., the rest of the URL as path segment
            array 'paths', a map of all query fields / flags 'query', and the
            fragment string 'fragment'). If the result is None a 404 error is
            sent.
        """
        self.add_json_mask(start, 'DELETE', json_producer)

    def add_json_post_mask(
            self, start: str, json_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a POST handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. esrh is the QuickServerRequestHandler
            object that called the function. args is a map containing the
            arguments to the request (i.e., the rest of the URL as path segment
            array 'paths', a map of all query fields / flags 'query', the
            fragment string 'fragment', and the JSON form content 'post'). If
            the result is None a 404 error is sent.
        """
        self.add_json_mask(start, 'POST', json_producer)

    def add_text_mask(
            self, start: str, method_str: str, text_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
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
            function. args is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array 'paths', a map of
            all query fields / flags 'query', the fragment string 'fragment',
            and if the method was a POST the JSON form content 'post'). If the
            result is None a 404 error is sent.
        """

        def send_text(
                drh: QuickServerRequestHandler,
                rem_path: ReqArgs) -> Optional[BytesIO]:
            text = text_producer(drh, rem_path)
            if not isinstance(text, Response):
                text = Response(text)
            ctype = text.get_ctype("text/plain")
            code = text.code
            text = text.response
            if text is None:
                drh.send_error(404, "File not found")
                return None
            if hasattr(text, "read"):
                if hasattr(text, "seek"):
                    f = text
                    size = f.seek(0, os.SEEK_END)
                    f.seek(0)
                else:
                    f = BytesIO()
                    shutil.copyfileobj(text, f, length=16*1024)
                    size = f.tell()
                    f.seek(0)
            else:
                f = BytesIO()
                if isinstance(text, (str, bytes)):
                    try:
                        text = text.decode('utf8')  # type: ignore
                    except AttributeError:
                        pass
                    text = text.encode('utf8')
                f.write(text)
                f.flush()
                size = f.tell()
                f.seek(0)
            # handle ETag caching
            if drh.request_version >= "HTTP/1.1" and hasattr(f, "seek"):
                e_tag = "{0:x}".format(zlib.crc32(f.read()) & 0xFFFFFFFF)
                f.seek(0)
                match = _getheader(drh.headers, 'if-none-match')
                if match is not None:
                    if drh.check_cache(e_tag, match):
                        f.close()
                        return None
                drh.send_header("ETag", e_tag, end_header=True)
                drh.send_header("Cache-Control",
                                "max-age={0}".format(self.max_age),
                                end_header=True)
            drh.send_response(code)
            drh.send_header("Content-Type", ctype)
            drh.send_header("Content-Length", size)
            drh.end_headers()
            return f

        self._add_file_mask(start, method_str, send_text)

    def add_text_get_mask(
            self, start: str, text_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a GET handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array 'paths', a map of
            all query fields / flags 'query', and the fragment string
            'fragment'). If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'GET', text_producer)

    def add_text_put_mask(
            self, start: str, text_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a PUT handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array 'paths', a map of
            all query fields / flags 'query', and the fragment string
            'fragment'). If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'PUT', text_producer)

    def add_text_delete_mask(
            self, start: str, text_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a DELETE handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array 'paths', a map of
            all query fields / flags 'query', and the fragment string
            'fragment'). If the result is None a 404 error is sent.
        """
        self.add_text_mask(start, 'DELETE', text_producer)

    def add_text_post_mask(
            self, start: str, text_producer: Callable[
                [QuickServerRequestHandler, ReqArgs], Any,
            ]) -> None:
        """Adds a POST handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            esrh is the QuickServerRequestHandler object that called the
            function. args is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array 'paths', a map of
            all query fields / flags 'query', the fragment string 'fragment',
            and the JSON form content 'post'). If the result is None a 404
            error is sent.
        """
        self.add_text_mask(start, 'POST', text_producer)

    # wrappers #

    def cmd(self,
            argc: Optional[int] = None,
            complete: Optional[Callable[[List[str], str], List[str]]] = None,
            no_replace: bool = False) -> Callable[[CmdF], CmdF]:

        def wrapper(fun: CmdF) -> CmdF:
            name = fun.__name__
            if not no_replace or name not in self._cmd_methods:
                self.add_cmd_method(name, fun, argc, complete)
            return fun

        return wrapper

    def json_get(self,
                 mask: str,
                 argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_json_get_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def json_put(self,
                 mask: str,
                 argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_json_put_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def json_delete(self,
                    mask: str,
                    argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_json_delete_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def json_post(self,
                  mask: str,
                  argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_json_post_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_get(self,
                 mask: str,
                 argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_text_get_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_put(self,
                 mask: str,
                 argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_text_put_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_delete(self,
                    mask: str,
                    argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_text_delete_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_post(self,
                  mask: str,
                  argc: Optional[int] = None) -> Callable[[ReqF], ReqF]:

        def wrapper(fun: ReqF) -> ReqF:
            self.add_text_post_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    # special files #

    def add_special_file(
            self,
            mask: str,
            path: str,
            from_quick_server: bool,
            ctype: Optional[str] = None) -> None:
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
        full_path = path if not from_quick_server else os.path.join(
            os.path.dirname(__file__), path)

        def read_file(_req: QuickServerRequestHandler,
                      _args: ReqArgs) -> Response:
            with open(full_path, 'rb') as f_out:
                return Response(f_out.read(), ctype=ctype)

        self.add_text_get_mask(mask, read_file)
        self.set_file_argc(mask, 0)

    def mirror_file(self,
                    path_to: str,
                    path_from: str,
                    from_quick_server: bool = True) -> None:
        """Mirrors a file to a different location. Each time the file changes
           while the process is running it will be copied to 'path_to',
           overwriting the destination.

        Parameters
        ----------
        path_to : string
            The mirror destination.

        path_from : string
            The mirror origin.

        from_quick_server : bool
            If set the origin path is relative to *this* script otherwise it is
            relative to the process.
        """
        full_path = path_from if not from_quick_server else os.path.join(
            os.path.dirname(__file__), path_from)
        impl = self._mirror["impl"]
        if impl:
            if not self._symlink_mirror(path_to, full_path, init=True):
                self._poll_mirror(path_to, full_path, init=True)
        elif impl == "symlink":
            self._symlink_mirror(path_to, full_path, init=False)
        elif impl == "poll":
            self._poll_mirror(path_to, full_path, init=False)
        else:
            raise ValueError("unknown mirror implementation: {0}".format(impl))

    def _symlink_mirror(
            self, path_to: str, path_from: str, init: bool) -> bool:
        if init:
            os_symlink = getattr(os, "symlink", None)
            if not callable(os_symlink):
                return False
            self._mirror["impl"] = "symlink"
        if os.path.lexists(path_to):
            os.remove(path_to)
        os.symlink(path_from, path_to)
        return True

    def _poll_mirror(self, path_to: str, path_from: str, init: bool) -> bool:

        def get_time(path: str) -> float:
            return os.path.getmtime(path)

        if init:
            self._mirror["impl"] = "poll"

            def act(ix: int, f_from: str, f_to: str) -> None:
                with self._mirror["lock"]:
                    shutil.copyfile(f_from, f_to)
                    self._mirror["files"][ix] = \
                        (f_from, f_to, get_time(f_from))

            def monitor() -> None:
                while True:
                    time.sleep(1)
                    with self._mirror["lock"]:
                        for (ix, f) in enumerate(self._mirror["files"]):
                            f_from, f_to, f_time = f
                            if f_time < get_time(f_from):
                                act(ix, f_from, f_to)

            poll_monitor = self._thread_factory(
                target=monitor,
                name="{0}-Poll-Monitor".format(self.__class__.__name__))
            poll_monitor.daemon = True
            poll_monitor.start()
        if not os.path.exists(path_from):
            raise ValueError("file does not exist: {0}".format(path_from))
        if path_from == path_to:
            raise ValueError("cannot mirror itself: {0}".format(path_from))
        with self._mirror["lock"]:
            for f in self._mirror["files"]:
                # sanity checks
                f_from, f_to, _f_time = f
                if f_to == path_to:
                    if f_from == path_from:
                        return True  # nothing to do here!
                    raise ValueError("cannot point two different " +
                                     "files to the same location: " +
                                     "({0} != {1}) -> {2}".format(
                                         f_from, path_from, f_to))
                if f_to == path_from:
                    raise ValueError("cannot chain mirrors: " +
                                     "{0} -> {1} -> {2}".format(
                                         f_from, f_to, path_to))
                if f_from == path_to:
                    raise ValueError("cannot chain mirrors: " +
                                     "{0} -> {1} -> {2}".format(
                                         path_from, path_to, f_to))
            # forces an initial write
            self._mirror["files"].append((path_from, path_to, 0))
        return True

    def link_empty_favicon_fallback(self) -> None:
        """Links the empty favicon as default favicon."""
        self.favicon_fallback = os.path.join(
            os.path.dirname(__file__), 'favicon.ico')

    # worker based #

    def link_worker_js(self, mask: str) -> None:
        """Links the worker javascript.

        Parameters
        ----------
        mask : string
            The URL that must be matched to get the worker javascript.
        """
        self.add_special_file(mask,
                              'worker.js',
                              from_quick_server=True,
                              ctype='application/javascript; charset=utf-8')

    def mirror_worker_js(self, path: str) -> None:
        """Mirrors the worker javascript.

        Parameters
        ----------
        path : string
            The path to mirror to.
        """
        self.mirror_file(path, 'worker.js', from_quick_server=True)

    def link_legacy_worker_js(self, mask: str) -> None:
        """Links the legacy worker javascript.

        Parameters
        ----------
        mask : string
            The URL that must be matched to get the worker javascript.
        """
        self.add_special_file(mask,
                              'worker.legacy.js',
                              from_quick_server=True,
                              ctype='application/javascript; charset=utf-8')

    def mirror_legacy_worker_js(self, path: str) -> None:
        """Mirrors the legacy worker javascript.

        Parameters
        ----------
        path : string
            The path to mirror to.
        """
        self.mirror_file(path, 'worker.legacy.js', from_quick_server=True)

    def json_worker(self,
                    mask: str,
                    cache_id: Optional[Callable[[CacheIdObj], Any]] = None,
                    cache_method: str = "string",
                    cache_section: str = "www",
                    ) -> Callable[[WorkerF], WorkerF]:
        """A function annotation that adds a worker request. A worker request
           is a POST request that is computed asynchronously. That is, the
           actual task is performed in a different thread and the network
           request returns immediately. The client side uses polling to fetch
           the result and can also cancel the task. The worker javascript
           client side must be linked and used for accessing the request.

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
            Optional cache method string. Gets passed to get_hnd() of the
            cache. Defaults to "string" which requires a JSON serializable
            cache_id.

        cache_section : string or None
            Optional cache section string. Gets passed to get_hnd() of the
            cache. Defaults to "www".

        fun : function(args); (The annotated function)
            A function returning a (JSON-able) object. The function takes one
            argument which is the dictionary containing the payload from the
            client side. If the result is None a 404 error is sent.
        """

        def wrapper(fun: WorkerF) -> WorkerF:
            worker = self._worker_constructor(
                mask, fun, msg, cache_id, self.cache, cache_method,
                cache_section, self._thread_factory, self.__class__.__name__,
                self._soft_worker_death, lambda: self.max_chunk_size,
                lambda: self.verbose_workers)

            def run_worker(req: QuickServerRequestHandler,
                           args: ReqArgs) -> WorkerResponse:
                post = args["post"]
                # NOTE: path segment variables overwrite sent arguments
                payload = post.get("payload", {})
                for (key, value) in args["segments"].items():
                    payload[key] = value
                post["payload"] = payload
                try:
                    return worker.compute_worker(req, post)
                except:  # nopep8
                    worker.on_error(post)
                    raise

            self.add_json_post_mask(mask, run_worker)
            self.set_file_argc(mask, 0)
            return fun

        return wrapper

    # tokens #

    def create_token(self) -> str:
        return uuid.uuid4().hex

    def set_default_token_expiration(self, expire: int) -> None:
        self._token_expire = expire

    def get_default_token_expiration(self) -> int:
        return self._token_expire

    @contextlib.contextmanager
    def get_token_obj(
            self,
            token: str,
            expire: Union[float, None, Literal["DEFAULT"]] = _token_default,
            readonly: bool = False) -> Iterator[TokenObj]:
        """Returns or creates the object associaten with the given token.
           Must be used in a `with` block. After the block ends the content
           is written back to the token object if the expiration is `None` or
           in the future. Note that all changes need to be performed on the
           original object.

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

        readonly : bool
            If true all operations are performed on a copy and no writebacks
            happen.
        """
        if expire == _token_default:
            aexpire: Optional[float] = self.get_default_token_expiration()
        else:
            aexpire = cast(Optional[float], expire)
        write_back = False
        try:
            with self._token_handler.lock(token):
                self._token_handler.flush_old_tokens()
                if aexpire is None or aexpire > 0:
                    res = self._token_handler.add_token(token, aexpire)
                    if readonly:
                        res = res.copy()
                    else:
                        write_back = True
                else:
                    self._token_handler.delete_token(token)
                    res = {}
            yield res
        finally:
            if write_back:
                with self._token_handler.lock(token):
                    self._token_handler.put_token(token, res)

    def get_tokens(self) -> List[str]:
        with self._token_handler.lock(None):
            self._token_handler.flush_old_tokens()
            return self._token_handler.get_tokens()

    def get_token_ttl(self, token: str) -> Optional[float]:
        with self._token_handler.lock(token):
            try:
                ttl = self._token_handler.ttl(token)
            except KeyError:
                ttl = 0
            if ttl is None:
                return ttl
            return max(ttl, 0)

    # objects #

    def _init_object_dispatch(self) -> None:
        if self._object_dispatch is not None:
            return
        self._object_dispatch = {}

        def do_dispatch(
                query_obj: Dict[str, ActionObj],
                od: Dict[str, DispatchObj],
                parent: Optional[DispatchObj]) -> Any:
            res: Dict[str, DispatchObj] = {}
            for (curq, action) in query_obj.items():
                if curq not in od:
                    raise ValueError("unknown object name: '{0}'".format(curq))
                atype = action["type"]
                obj = od[curq]
                otype = obj["type"]
                if otype == "value":
                    if atype == "set":
                        obj["value"] = action["value"]
                    elif atype != "get":
                        raise ValueError("invalid action: '{0}'".format(atype))
                    res[curq] = {
                        "value": obj["value"],
                    }
                elif otype == "lazy_value":
                    fun = obj["fun"]
                    if atype == "set":
                        res[curq] = {
                            "value": fun(
                                parent, set_value=True, value=action["value"]),
                        }
                    elif atype == "get":
                        res[curq] = {
                            "value": fun(parent),
                        }
                    else:
                        raise ValueError("invalid action: '{0}'".format(atype))
                elif otype == "lazy_map":
                    fun = obj["fun"]
                    if atype != "get":
                        raise ValueError("invalid action: '{0}'".format(atype))
                    cur_res = {}
                    for (name, query) in action["queries"]:
                        next_level = fun(parent, name)
                        cur_res[name] = do_dispatch(
                            query, obj["child"], next_level)
                    res[curq] = {
                        "map": cur_res,
                    }
                else:
                    raise ValueError(
                        "invalid object type: '{0}'".format(otype))
            return res

        def dispatch(args: WorkerArgs) -> Any:
            query_obj = args["query"]
            assert self._object_dispatch is not None
            od = self._object_dispatch
            return do_dispatch(query_obj, od, {})

        self.json_worker(self.object_path)(dispatch)

    def _add_object_dispatch(
            self,
            path: List[str],
            otype: str,
            fun: Optional[Callable[..., Any]] = None,
            value: Any = None) -> None:
        self._init_object_dispatch()
        assert self._object_dispatch is not None
        od = self._object_dispatch
        cur_p = []
        while len(path):
            p = path.pop(0)
            cur_p.append(p)
            if p not in od:
                if path:
                    raise ValueError(
                        "path prefix must exist: {0}".format(cur_p))
                new_od: DispatchObj = {
                    "type": otype,
                }
                if otype == "value":
                    new_od["value"] = value
                elif otype == "lazy_value":
                    if fun is None:
                        raise ValueError("must set function")
                    new_od["fun"] = fun
                elif otype == "lazy_map":
                    if fun is None:
                        raise ValueError("must set function")
                    new_od["fun"] = fun
                    new_od["child"] = {}
                else:
                    raise ValueError(
                        "invalid object type: '{0}'".format(otype))
                od[p] = new_od
            else:
                od = od[p]["child"]

    def add_value_object(
            self, path: List[str], default_value: Any = None) -> None:
        self._add_object_dispatch(path, "value", value=default_value)

    def add_lazy_value_object(
            self, path: List[str], fun: Callable[..., Any]) -> None:
        self._add_object_dispatch(path, "lazy_value", fun=fun)

    def add_lazy_map_object(
            self, path: List[str], fun: Callable[..., Any]) -> None:
        self._add_object_dispatch(path, "lazy_map", fun=fun)

    # miscellaneous #

    def handle_cmd(self, cmd: str) -> None:
        """Handles a single server command."""
        cmd = cmd.strip()
        segments = []
        for s in cmd.split():
            # remove bash-like comments
            if s.startswith('#'):
                break
            # TODO implement escape sequences (also for \#)
            segments.append(s)
        args: List[str] = []
        if not len(segments):
            return
        # process more specific commands first
        while segments:
            cur_cmd = "_".join(segments)
            if cur_cmd in self._cmd_methods:
                argc = self._cmd_argc[cur_cmd]
                if argc is not None and len(args) != argc:
                    msg('command {0} expects {1} argument(s), got {2}',
                        " ".join(segments), argc, len(args))
                    return
                self._cmd_methods[cur_cmd](args)
                return
            args.insert(0, segments.pop())
        # invalid command
        prefix = '_'.join(args) + '_'
        matches = filter(
            lambda cmd: cmd.startswith(prefix), self._cmd_methods.keys())
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
            msg('command "{0}" invalid; type ' +
                'help or use <TAB> for a list of commands',
                ' '.join(args))

    def start_cmd_loop(self) -> None:
        """Starts the command line loop. This method is called automatically by
           the serve_forever method. The function call is idempotent so you can
           call the method before or after that without worrying or extra
           side-effect. An EOF terminates the loop but does not close the
           server. A `KeyboardInterrupt` terminates the server as well.
        """
        # thread-safe check if the loop is already running
        with self._cmd_lock:
            cmd_start = self._cmd_start
            self._cmd_start = True

        if cmd_start:
            return

        cmd_state: CmdState = {
            'suggestions': [],
            'clean_up_lock': threading.Lock(),
            'clean': False,
            'line': '',
        }

        # setup internal commands (no replace)
        @self.cmd(argc=0, no_replace=True)
        def help(args: List[str]) -> None:  # pylint: disable=unused-variable
            msg('available commands:')
            for key in self._cmd_methods.keys():
                msg('    {0}', key.replace('_', ' '))

        @self.cmd(argc=0, no_replace=True)
        def restart(  # pylint: disable=unused-variable
                args: List[str]) -> None:
            global _do_restart
            _do_restart = True
            self.done = True

        @self.cmd(argc=0, no_replace=True)
        def quit(args: List[str]) -> None:  # pylint: disable=unused-variable
            self.done = True

        # set up command completion
        def complete(text: str, state: int) -> Optional[str]:
            if state == 0:
                origline = readline.get_line_buffer()
                line = origline.lstrip()
                stripped = len(origline) - len(line)
                begidx = readline.get_begidx() - stripped
                endidx = readline.get_endidx() - stripped
                prefix = line[:begidx].replace(' ', '_')

                def match_cmd(cmd: str) -> bool:
                    return cmd.startswith(prefix) and \
                           cmd[begidx:].startswith(text)

                matches = filter(match_cmd, self._cmd_methods.keys())

                def _endidx(m: str) -> int:
                    eix = m.find('_', endidx)
                    return eix + 1 if eix >= 0 else len(m)

                candidates = [
                    m[begidx:_endidx(m)].replace('_', ' ') for m in matches
                ]
                rest_cmd = line[:begidx].split()
                args: List[str] = []
                while rest_cmd:
                    cur_cmd = '_'.join(rest_cmd)
                    compl = self._cmd_complete.get(cur_cmd, None)
                    if compl is not None:
                        cc = compl(args, text)
                        if cc is not None:
                            candidates.extend(cc)
                    args.insert(0, rest_cmd.pop())
                cmd_state['suggestions'] = sorted(set(candidates))
                cmd_state['line'] = line
            suggestions: List[str] = cmd_state['suggestions']
            if len(suggestions) == 1 and text == suggestions[0]:
                probe_cmd = cmd_state['line'].replace(' ', '_')
                if probe_cmd in self._cmd_argc and \
                        self._cmd_argc[probe_cmd] != 0:
                    cmd_state['line'] = ""
                    return text + ' '
                return None
            if state < len(suggestions):
                return suggestions[state]
            return None

        # remember to clean up before exit -- the call must be idempotent!
        def clean_up() -> None:
            with cmd_state['clean_up_lock']:
                clean = cmd_state['clean']
                cmd_state['clean'] = True

            if clean:
                return

            readline.write_history_file(hfile)
            readline.set_completer(old_completer)

        if READLINE_IO is not None:
            stdout, stderr = READLINE_IO
        else:
            stdout, stderr = sys.stdout, sys.stderr

        def cmd_loop() -> None:
            close = False
            kill = True
            with contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr):
                try:
                    while not self.done and \
                            not close and not self.no_command_loop:
                        line = ""
                        try:
                            try:
                                line = input(self.prompt)
                            except IOError as e:
                                if e.errno == errno.EBADF:
                                    close = True
                                    kill = False
                                elif (
                                        e.errno == errno.EWOULDBLOCK or
                                        e.errno == errno.EAGAIN or
                                        e.errno == errno.EINTR):
                                    continue
                                else:
                                    raise e
                            self.handle_cmd(line)
                        except EOFError:
                            close = True
                            kill = False
                        except KeyboardInterrupt:
                            close = True
                        except Exception:
                            global_handle_error(
                                ERR_SOURCE_COMMAND,
                                f"exception executing command {line}",
                                traceback.format_exc(), msg)
                finally:
                    if kill:
                        self.done = True
                    else:
                        msg("no command loop - use CTRL-C to terminate")
                        self.no_command_loop = True
                    clean_up()

        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            # loading the history
            hfile = self.history_file
            try:
                readline.read_history_file(hfile)
            except IOError:
                pass

            old_completer = readline.get_completer()
            readline.set_completer(complete)
            # be mac compatible
            if readline.__doc__ is not None and 'libedit' in readline.__doc__:
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")

            atexit.register(clean_up)
            self._clean_up_call = clean_up

            if not self.no_command_loop:
                t = self._thread_factory(target=cmd_loop)
                t.daemon = True
                t.start()

    def handle_request(self) -> None:
        """Handles an HTTP request.The actual HTTP request is handled using a
           different thread.
        """
        timeout = self.socket.gettimeout()
        if timeout is None:
            timeout = self.timeout
        elif self.timeout is not None:
            timeout = min(timeout, self.timeout)
        ctime = get_time()
        done_req = False
        shutdown_latency = self.shutdown_latency
        if timeout is not None:
            shutdown_latency = min(shutdown_latency, timeout) \
                if shutdown_latency is not None else timeout
        while not (self.done or done_req) and (timeout is None or
                                               timeout == 0 or
                                               (get_time() - ctime) < timeout):
            try:
                fd_sets = select.select([self], [], [], shutdown_latency)
            except (OSError, select.error) as e:
                if e.args[0] != errno.EINTR:
                    raise
                # treat EINTR as shutdown_latency timeout
                fd_sets = ([], [], [])
            for _fd in fd_sets[0]:
                done_req = True
                self._handle_request_noblock()  # type: ignore
            if timeout == 0:
                break
        if not (self.done or done_req):
            # don't handle timeouts if we should shut down the server instead
            self.handle_timeout()

    def serve_forever(self, poll_interval: float = 0.5) -> None:
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

    def can_ignore_error(
            self,
            reqhnd: Optional[QuickServerRequestHandler] = None) -> bool:
        """Tests if the error is worth reporting.
        """
        value = sys.exc_info()[1]
        try:
            if isinstance(value, BrokenPipeError) or \
                    isinstance(value, ConnectionResetError):
                return True
        except NameError:
            pass
        if not self.done:
            return False
        if not isinstance(value, socket.error):
            return False
        need_close = value.errno == 9
        if need_close and reqhnd is not None:
            reqhnd.close_connection = True
        return need_close

    def handle_error(self,
                     request: bytes,
                     client_address: Tuple[str, int]) -> None:
        """Handle an error gracefully.
        """
        if self.can_ignore_error():
            return
        thread = threading.current_thread()
        global_handle_error(
            ERR_SOURCE_GENERAL_QS,
            f"Error in request ({client_address}): "
            f"{repr(request)} in {thread.name}", traceback.format_exc(), msg)
