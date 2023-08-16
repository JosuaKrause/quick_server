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
the command. "help", "restart", and "quit" are built-in commands ready to use.

Note: The server is thread based so all callback functions should be
thread-safe.

Please refer to the example folder for usage examples.
"""
import atexit
import contextlib
import ctypes
import errno
import fnmatch
import http.server as http_server
import json
import math
import os
import posixpath
import readline
import select
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zlib
from http.server import SimpleHTTPRequestHandler
from io import BytesIO, StringIO
from typing import (
    Any,
    BinaryIO,
    Callable,
    cast,
    ContextManager,
    Generic,
    Iterator,
    Protocol,
    Set,
    TextIO,
    TypeVar,
)
from urllib import parse as urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from typing_extensions import Literal, TypedDict


try:
    # NOTE: avoid pyarrow atexit error
    import pyarrow  # type: ignore  # pylint: disable=unused-import
except (ModuleNotFoundError, ImportError) as _:
    pass


WorkerArgs = dict[str, Any]
TokenObj = dict[str, Any]
CacheIdObj = dict[str, Any]


class CmdF(Protocol):  # pylint: disable=too-few-public-methods
    def __call__(self, args: list[str], /) -> None: ...


class CmdCompleteF(Protocol):  # pylint: disable=too-few-public-methods
    def __call__(self, args: list[str], text: str, /) -> list[str] | None: ...


ReqArgs = TypedDict('ReqArgs', {
    "paths": list[str],
    "query": dict[str, str | float | int | bool],
    "post": WorkerArgs,
    "files": dict[str, BytesIO],
    "fragment": str,
    "segments": dict[str, str],
    "meta": dict[str, Any],
})


class ReqNext:  # pylint: disable=too-few-public-methods
    pass


A_co = TypeVar('A_co', covariant=True)
B_co = TypeVar('B_co', covariant=True)
R_co = TypeVar('R_co', covariant=True)


class ReqF(Protocol, Generic[R_co]):  # pylint: disable=too-few-public-methods
    def __call__(
            self, req: 'QuickServerRequestHandler', args: ReqArgs, /) -> R_co:
        ...


class MiddlewareF(  # pylint: disable=too-few-public-methods
        Protocol, Generic[R_co]):
    def __call__(
            self,
            req: 'QuickServerRequestHandler',
            args: ReqArgs,
            okay: ReqNext,
            /) -> R_co:
        ...


class WorkerF(  # pylint: disable=too-few-public-methods
        Protocol, Generic[R_co]):
    def __call__(
            self, args: WorkerArgs, /) -> R_co:
        ...


PostFileLens = TypedDict('PostFileLens', {
    "clen": int,
    "push": list[BytesIO],
})

WorkerTask = TypedDict('WorkerTask', {
    "running": bool,
    "result": str | None,
    "exception": tuple[str, str | None] | None,
    "thread": threading.Thread | None,
})

WorkerResponse = TypedDict('WorkerResponse', {
    "token": str,
    "done": bool,
    "result": list[str] | str | None,
    "continue": bool,
})

MirrorObj = TypedDict('MirrorObj', {
    "impl": Literal["poll", "symlink", "none"],
    "files": list[tuple[str, str, float]],
    "lock": threading.RLock,
})

CmdState = TypedDict('CmdState', {
    "suggestions": list[str],
    "clean_up_lock": threading.Lock,
    "clean": bool,
    "line": str,
})

ErrHandler = Callable[[str, str, list[str]], None]
PrintF = Callable[[str], None]
ThreadFactory = Callable[..., threading.Thread]
WorkerThreadFactory = Callable[[], threading.Thread]


class Response:
    def __init__(
            self,
            response: str | bytes | StringIO | BytesIO | None,
            code: int = 200,
            ctype: str | None = None) -> None:
        """Constructs a response."""
        self.response = response
        self.code = code
        self._ctype = ctype

    def __str__(self) -> str:
        ctype = f" {self._ctype}" if self._ctype is not None else ""
        return (
            f"{self.__class__.__name__}"
            f"[{self.code}{ctype}]"
        )

    def get_ctype(self, ctype: str) -> str:
        """Returns the content type with the given default value."""
        if self._ctype is not None:
            return self._ctype
        return ctype


AnyStrResponse = TypeVar(
    'AnyStrResponse', bound=bytes | str | Response | BytesIO | StringIO | None)


def get_time() -> float:
    """Returns a monotonically ascending time."""
    return time.monotonic()


__version__ = "0.8.0"


def _getheader_fallback(obj: Any, key: str) -> Any:
    return obj.get(key)


def _getheader_p2(obj: Any, key: str) -> Any:
    global _GETHEADER

    try:
        return obj.getheader(key)
    except AttributeError:
        _GETHEADER = _getheader_fallback
        return _GETHEADER(obj, key)


_GETHEADER = _getheader_p2


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
            res: Any = None
        elif isinstance(obj, (str, bytes)):
            res = obj
        elif isinstance(obj, dict):
            res_obj = {}
            for (key, value) in obj.items():
                res_obj[key] = do_map(value)
            res = res_obj
        elif isinstance(obj, (list, tuple)):
            res_list = []
            for elem in obj:
                res_list.append(do_map(elem))
            res = res_list
        # diverging numbers need to be passed as strings otherwise it
        # will throw a parsing error on the ECMAscript consumer side
        elif math.isnan(obj):
            res = "NaN"
        elif math.isinf(obj):
            res = "Infinity" if obj > 0 else "-Infinity"
        else:
            res = obj
        return res

    return json.dumps(
        do_map(json_obj), indent=2, sort_keys=True, allow_nan=False)


LOG_FILE: TextIO | None = None


def set_log_file(fname: TextIO) -> None:
    """Sets the log file. Defaults to STD_ERR."""
    global LOG_FILE

    LOG_FILE = fname


def _caller_trace(frame: Any) -> tuple[str, int]:
    try:
        if "__file__" not in frame.f_globals:
            return "???", frame.f_lineno
        return frame.f_globals["__file__"], frame.f_lineno
    finally:
        del frame


def caller_trace() -> tuple[str, int]:  # pragma: no cover
    """Gets the stack trace of the calling function."""
    try:
        raise Exception()
    except:  # nopep8  # pylint: disable=bare-except
        frames: list[Any] | None = None
        try:
            frames = [sys.exc_info()[2].tb_frame]  # type: ignore
            for _ in range(2):
                frames.append(frames[-1].f_back)
            return _caller_trace(frames[-1])
        finally:
            if frames is not None:
                del frames


if hasattr(sys, "_getframe"):

    def _caller_trace_gf() -> tuple[str, int]:
        # pylint: disable=protected-access
        return _caller_trace(sys._getframe(2))

    caller_trace = _caller_trace_gf


LONG_MSG = True
MSG_STDERR = False


def msg(message: str) -> None:
    """Prints a message from the server to the log file."""
    global LOG_FILE

    if LOG_FILE is None:
        LOG_FILE = sys.stderr
    if LONG_MSG:
        file_name, line = caller_trace()
        file_name, file_type = os.path.splitext(file_name)
        if file_name.endswith("/__init__"):
            file_name = os.path.basename(os.path.dirname(file_name))
        elif file_name.endswith("/__main__"):
            file_name = f"(-m) {os.path.basename(os.path.dirname(file_name))}"
        else:
            file_name = os.path.basename(file_name)
        head = f"{file_name}{file_type} ({line}): "
    else:
        head = "[SERVER] "
    out = StringIO()
    for curline in message.splitlines():
        out.write(f"{head}{curline}\n")
    out.flush()
    out.seek(0)
    if MSG_STDERR:
        sys.stderr.write(out.read())
        sys.stderr.flush()
    else:
        LOG_FILE.write(out.read())
        LOG_FILE.flush()
    out.close()


ERR_SOURCE_COMMAND = "err_command"
ERR_SOURCE_GENERAL_QS = "err_quick_server"
ERR_SOURCE_REQUEST = "err_request"
ERR_SOURCE_RESTART = "err_restart"
ERR_SOURCE_WORKER = "err_worker"


ERR_HND: ErrHandler | None = None


def set_global_error_handler(fun: ErrHandler | None) -> None:
    """Sets the error handler."""
    global ERR_HND

    ERR_HND = fun


def global_handle_error(
        source: str,
        errmsg: str,
        tback: str,
        mfun: PrintF) -> None:
    """The default error handler."""
    if ERR_HND is None:
        mfun(f"ERROR in {source}: {errmsg}\n{tback}")
        return
    ERR_HND(source, errmsg, tback.splitlines())


DEBUG: bool | None = None


def debug(fun: Callable[[], Any]) -> None:
    """Prints a message if the env QUICK_SERVER_DEBUG is not 0 or empty."""
    global DEBUG

    if DEBUG is None:
        DEBUG = bool(int(os.environ.get("QUICK_SERVER_DEBUG", "0")))
    if DEBUG:
        msg(f"[DEBUG] {fun()}")


debug(lambda: sys.version)


# thread local storage for keeping track of request information (e.g., time)
thread_local = threading.local()


_RESTART_EXIT_CODE = 42


def set_restart_exit_code(code: int) -> None:
    """Sets the exit code used to indicate a restart request."""
    global _RESTART_EXIT_CODE

    _RESTART_EXIT_CODE = code


_ERROR_EXIT_CODE = 1


def set_error_exit_code(code: int) -> None:
    """Sets the exit code to indicate an error in the child process."""
    global _ERROR_EXIT_CODE

    _ERROR_EXIT_CODE = code


def get_exec_arr() -> list[str]:
    """Gets the full process command."""
    executable = sys.executable
    if not executable:
        executable = os.environ.get("PYTHON", "")
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


# handling the "restart" command
_DO_RESTART = False


def _on_exit() -> None:  # pragma: no cover
    global _DO_RESTART

    if _DO_RESTART:
        # avoid potential infinite loop when running atexit handlers
        _DO_RESTART = False
        exit_code = os.environ.get("QUICK_SERVER_RESTART")
        # restart the executable
        _start_restart_loop(exit_code, in_atexit=True)


atexit.register(_on_exit)


def _start_restart_loop(exit_code: str | None, in_atexit: bool) -> None:

    def handle_exit() -> None:
        # pylint: disable=protected-access

        if in_atexit:
            try:
                if not os.environ.get("RUN_ATEXIT"):
                    atexit._run_exitfuncs()
            finally:
                os._exit(child_code)
        else:
            sys.exit(child_code)

    try:
        if exit_code is not None:
            # we have a parent process that restarts us
            child_code = int(exit_code)
        else:
            exec_arr = get_exec_arr()
            if in_atexit:
                msg(f"restarting: {' '.join(exec_arr)}")

            debug(lambda: exec_arr)
            exit_code = str(_RESTART_EXIT_CODE)
            child_code = int(exit_code)
            is_subsequent = False
            while child_code == int(exit_code):
                environ = os.environ.copy()
                environ["QUICK_SERVER_RESTART"] = exit_code
                if is_subsequent:
                    environ["QUICK_SERVER_SUBSEQ"] = "1"
                is_subsequent = True
                try:
                    with subprocess.Popen(
                            exec_arr, env=environ, close_fds=True) as proc:
                        child_code = proc.wait()
                except KeyboardInterrupt:
                    child_code = _ERROR_EXIT_CODE
    except:  # nopep8  # pylint: disable=bare-except
        global_handle_error(
            ERR_SOURCE_RESTART,
            "error during restart:", traceback.format_exc(), msg)
        child_code = _ERROR_EXIT_CODE
    finally:
        handle_exit()


def setup_restart() -> None:
    """Sets up restart functionality that doesn't keep the first process alive.
       The function needs to be called before the actual process starts but
       after loading the program. It will restart the program in a child
       process and immediately returns in the child process. The call in the
       parent process never returns. Calling this function is not necessary for
       using restart functionality but avoids potential errors originating from
       rogue threads.
    """
    exit_code = os.environ.get("QUICK_SERVER_RESTART")
    if exit_code is None:
        atexit.unregister(_on_exit)
        _start_restart_loop(None, in_atexit=False)


def is_original() -> bool:
    """Whether we are in the original process."""
    return "QUICK_SERVER_RESTART" not in os.environ


def has_been_restarted() -> bool:
    """Returns whether the process has been restarted in the past. When using a
       restart file the calling process needs to set the environment variable
       "QUICK_SERVER_SUBSEQ" to the value "1" for the second and any subsequent
       call in order to make this function work.
    """
    return os.environ.get("QUICK_SERVER_SUBSEQ", "0") == "1"


_PDR_MARK = "__pdr"


class PreventDefaultResponse(Exception):
    """Can be thrown to prevent any further processing of the request and
       instead send a customized response.
    """
    def __init__(
            self,
            code: int | None = None,
            message: str | None = None) -> None:
        super().__init__()
        self.code = code
        self.msg = message if message else ""

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"


class WorkerDeath(Exception):
    """Exception to terminate a worker."""
    def __str__(self) -> str:
        return f"{self.__class__.__name__}"


def kill_thread(
        th: threading.Thread,
        cur_key: str,
        msgout: PrintF,
        is_verbose_workers: Callable[[], bool]) -> None:
    """Kills a running thread."""
    # pylint: disable=protected-access

    if not th.is_alive():
        return
    # kill the thread
    tid = None
    for tkey, tobj in threading._active.items():  # type: ignore
        if tobj is th:
            tid = tkey
            break
    if tid is not None:
        papi = ctypes.pythonapi
        pts_sae = papi.PyThreadState_SetAsyncExc
        res = pts_sae(ctypes.c_long(tid), ctypes.py_object(WorkerDeath))
        if res == 0:
            # invalid thread id -- the thread might
            # be done already
            msgout(f"invalid thread id for killing worker {cur_key}")
        elif res != 1:
            # roll back
            pts_sae(ctypes.c_long(tid), None)
            msgout(f"killed too many ({res}) workers? {cur_key}")
        else:
            if is_verbose_workers():
                msgout(f"killed worker {cur_key}")


class QuickServerRequestHandler(SimpleHTTPRequestHandler):
    """The request handler for QuickServer. Delegates file requests to
       SimpleHTTPRequestHandler if the request could not be resolved as
       dynamic request. If a dynamic request is resolved but the execution
       fails (i.e., None is returned from the callback) a 404 status code is
       sent. If a dynamic request fails with an exception a 500 status code
       is sent.
    """
    server: "QuickServer"

    def copyfile(  # type: ignore
            self, source: BytesIO, outputfile: BinaryIO) -> None:
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

    server_version = f"QuickServer/{__version__}"

    protocol_version = "HTTP/1.1"

    def __str__(self) -> str:
        return f"{self.__class__.__name__}[{self.command} {self.path}]"

    def convert_argmap(
            self,
            query: str | bytes,
            ) -> dict[str, str | bool | int | float]:
        """Converts the query string of an URL to a map.

        Parameters
        ----------
        query : string
            The URL to parse.

        Returns
        -------
        A map object containing all fields as keys with their value. Fields
        without "=" in the URL are interpreted as flags and the value is set
        to True.
        """
        res: dict[str, str | bool | int | float] = {}
        if isinstance(query, bytes):
            query = query.decode("utf-8")
        for section in query.split("&"):
            eqs = section.split("=", 1)
            name = urlparse.unquote(eqs[0])
            if len(eqs) > 1:
                res[name] = urlparse.unquote(eqs[1])
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
        args enriched with "paths", an array containing the remaining path
        segments, "query", a map containing the query fields and flags, and
        "fragment" containing the fragment part as string.
        """
        fragment_split = rem_path.split("#", 1)
        query_split = fragment_split[0].split("?", 1)
        segs = filter(
            lambda p: len(p) and p != ".",
            os.path.normpath(query_split[0]).split("/"))
        paths = [urlparse.unquote(p) for p in segs]
        query = self.convert_argmap(query_split[1]) \
            if len(query_split) > 1 else {}
        args["paths"] = paths
        args["query"] = query
        args["fragment"] = (
            urlparse.unquote(fragment_split[1])
            if len(fragment_split) > 1 else
            ""
        )
        return args

    def get_post_file(
            self,
            *,
            hdr: str,
            f_in: BinaryIO,
            clen: int,
            post: dict[str, str],
            files: dict[str, BytesIO]) -> None:
        """Reads from a multipart/form-data."""
        lens: PostFileLens = {
            "clen": clen,
            "push": [],
        }
        prefix = "boundary="
        if not hdr.startswith(prefix):
            return
        boundary = hdr[len(prefix):].strip().encode("utf-8")
        if not boundary:
            return
        boundary = b"--" + boundary
        raw_boundary = b"\r\n" + boundary
        end_boundary = boundary + b"--"

        def read(length: int) -> bytes:
            res = b""
            while len(res) < length and lens["push"]:
                buffr = lens["push"].pop()
                res += buffr.read(length - len(res))
                if buffr.read(1) != b"":
                    buffr.seek(buffr.tell() - 1)
                    lens["push"].append(buffr)
            if len(res) < length:
                res += f_in.read(length - len(res))
            lens["clen"] -= len(res)
            if res == b"" or lens["clen"] < 0:
                raise ValueError("Unexpected EOF")
            return res

        def parse_file() -> BytesIO:
            f = BytesIO()
            buff_size = 10 * 1024

            def push_back(line: bytes) -> None:
                buffl = BytesIO()
                buffl.write(line)
                buffl.flush()
                buffl.seek(0)
                lens["clen"] += len(line)
                lens["push"].append(buffl)

            def write_buff(buff: bytes) -> None:
                if f.tell() + len(buff) > self.server.max_file_size:
                    raise PreventDefaultResponse(
                        413,
                        f"Uploaded file is too large! {f.tell() + len(buff)} "
                        f"> {self.server.max_file_size}")
                f.write(buff)
                f.flush()

            buff = b""
            while True:
                buff += read(min(lens["clen"], buff_size))
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

        def process() -> None:

            def read_line() -> bytes:
                line = b""
                while not line.endswith(b"\n") and lens["push"]:
                    buffr = lens["push"].pop()
                    line += buffr.readline()
                    tmp = buffr.read(1)
                    if tmp != b"":
                        buffr.seek(buffr.tell() - 1)
                        lens["push"].append(buffr)
                if not line.endswith(b"\n"):
                    line += f_in.readline(lens["clen"])
                lens["clen"] -= len(line)
                if line == b"" or lens["clen"] < 0:
                    raise ValueError("Unexpected EOF")
                return line.strip()

            while True:
                line = read_line()
                if line == end_boundary:
                    if lens["clen"] > 0:
                        raise ValueError(
                            "Expected EOF got: "
                            f"{repr(f_in.read(lens['clen']))}")
                    return
                if line != boundary:
                    raise ValueError(
                        f"Expected boundary got: {repr(line)}")
                headers = {}
                while True:
                    line = read_line()
                    if not line:
                        break
                    key, value = line.split(b":", 1)
                    headers[key.lower()] = value.strip()
                name: str | None = None
                if b"content-disposition" in headers:
                    cdis = headers[b"content-disposition"]
                    if not cdis.startswith(b"form-data"):
                        raise ValueError(
                            f"Unknown content-disposition: {repr(cdis)}")
                    name_field = b"name=\""
                    ix = cdis.find(name_field)
                    if ix >= 0:
                        bname = cdis[ix + len(name_field):]
                        name = bname[:bname.index(b"\"")].decode("utf-8")
                ctype = headers.get(b"content-type")
                if name is None:
                    raise ValueError("field name not set")
                # b"application/octet-stream": # we treat all files the same
                if ctype is not None:
                    files[name] = parse_file()
                else:
                    post[name] = parse_file().read().decode("utf-8")

        process()

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
                    msg(
                        "request takes longer than expected: "
                        f"\"{method_str} {path}\"")

            alarm_init = threading.Timer(5.0, do_report)
            alarm_init.start()
            alarm: threading.Timer | None = alarm_init
        else:
            alarm = None
        try:
            return self._handle_special(send_body, method_str)
        finally:
            if alarm is not None:
                alarm.cancel()
            ongoing = False

    def _handle_special(self, send_body: bool, method_str: str) -> bool:
        # pylint: disable=protected-access

        path = self.path
        # interpreting the URL masks to find which method to call
        method: ReqF[BytesIO | None] | None = None
        method_mask = None
        rem_path = ""
        segments: dict[str, str] = {}

        def is_match(
                mask: str,
                cur_path: str) -> tuple[bool, str, dict[str, str]]:
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

        def execute(
                method: ReqF[BytesIO | None],
                args: ReqArgs) -> None:
            f: BytesIO | None = None
            try:
                f = method(self, args)
                if f is not None and send_body:
                    self.copyfile(f, self.wfile)
                    thread_local.size = f.tell()
            finally:
                if f is not None:
                    f.close()

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
        files: dict[str, BytesIO] = {}
        args: ReqArgs = {
            "paths": [],
            "query": {},
            "post": {},
            "files": {},
            "fragment": "",
            "segments": segments,
            "meta": {},
        }
        try:
            # POST can accept forms encoded in JSON
            if method_str in ["POST", "DELETE", "PUT"]:
                ctype = _GETHEADER(self.headers, "content-type")
                crest = ""
                if ctype is None:
                    ctype = ""
                if ";" in ctype:
                    splix = ctype.index(";")
                    crest = ctype[splix+1:].strip() \
                        if len(ctype) > splix + 1 else ""
                    ctype = ctype[:splix].strip()
                clen = int(_GETHEADER(self.headers, "content-length"))
                if ctype == "multipart/form-data":
                    self.get_post_file(
                        hdr=crest,
                        f_in=self.rfile,
                        clen=clen,
                        post=args["post"],
                        files=args["files"])
                else:
                    content = self.rfile.read(clen)
                    post_res: WorkerArgs = {}
                    if ctype == "application/json":
                        try:
                            post_res = json.loads(content)
                        except json.decoder.JSONDecodeError as json_err:
                            raise ValueError(
                                "request is not JSON formatted!",
                                content) from json_err
                    elif ctype == "application/x-www-form-urlencoded":
                        post_res = self.convert_argmap(content)
                    args["post"] = post_res

            args = self.convert_args(rem_path, args)
            # check for correct path length
            if (self.server._f_argc[method_mask] is not None and
                    self.server._f_argc[method_mask] != len(args["paths"])):
                return False
            # call the method with the arguments
            execute(method, args)
        finally:
            for f in files.values():
                f.close()
        return True

    # optionally block the listing of directories
    def list_directory(
            self, path: str | os.PathLike[str]) -> BytesIO | None:
        if not self.server.directory_listing:
            self.send_error(404, "No permission to list directory")
            return None
        return SimpleHTTPRequestHandler.list_directory(  # type: ignore
            self, path)

    def translate_path(self, path: str) -> str:
        """Translates a path for a static file request. The server base path
           could be different from our cwd.

        Parameters
        ----------
        path : string
            The path.

        Returns
        -------
        The absolute file path denoted by the original path.
        """
        return self._translate_path(path)

    def _translate_path(self, orig_path: str) -> str:
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
        # pylint: disable=protected-access

        init_path = orig_path
        orig_path = urlparse.urlparse(orig_path)[2]
        needs_redirect = False
        is_folder = len(orig_path) <= 1 or orig_path[-1] == "/"
        orig_path = posixpath.normpath(urlparse.unquote(orig_path))
        if is_folder:
            orig_path += "/"
        mpath: str | None = None
        try:
            cur_base = None
            for (name, fmask) in self.server._folder_masks:
                if not orig_path.startswith(name):
                    continue
                cur_base = os.path.abspath(
                    os.path.join(self.server.base_path, fmask))
                mpath = cur_base
                words = filter(None, orig_path[len(name):].split("/"))
                for word in words:
                    _drive, word = os.path.splitdrive(word)
                    _head, word = os.path.split(word)
                    if word in (os.curdir, os.pardir):
                        continue
                    # don't ever allow any hidden files
                    if word.startswith("."):
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
                        f"{proxy[2]}{remain}",  # path
                        reala[3],  # params
                        reala[4],  # query
                        reala[5],  # fragment
                    ))
                    self.send_to_proxy(pxya)  # raises PreventDefaultResponse
                msg(f"no matching folder alias: {orig_path}")
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
            if cur_base is None or not path.startswith(cur_base):
                raise ValueError(f"WARNING: attempt to access {path}")
            # favicon handling
            if (
                    self.server.favicon_everywhere
                    and os.path.basename(path) == "favicon.ico"
                    and not os.path.exists(path)):
                for (name, fmask) in self.server._folder_masks:
                    fav_base = os.path.abspath(
                        os.path.join(self.server.base_path, fmask))
                    favicon = os.path.join(fav_base, "favicon.ico")
                    if os.path.exists(favicon):
                        path = favicon
                        break
                    if (
                            self.server.favicon_fallback is not None
                            and os.path.exists(self.server.favicon_fallback)):
                        path = os.path.join(
                            self.server.base_path,
                            self.server.favicon_fallback)
                        break
            # redirect improper index requests
            if needs_redirect:
                self.send_response(301, "Use index page with slash")
                location = urlparse.urlunparse(tuple(
                    seg if ix != 2 else f"{seg}/"
                    for (ix, seg) in enumerate(urlparse.urlparse(init_path))
                ))
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
            with open(path, "rb") as input_f:
                e_tag = f"{zlib.crc32(input_f.read()) & 0xFFFFFFFF:x}"
                thread_local.size = input_f.tell()
            if e_tag is not None:
                match = _GETHEADER(self.headers, "if-none-match")
                if match is not None:
                    if self.check_cache(e_tag, match):
                        raise PreventDefaultResponse()
                self.send_header("ETag", e_tag, end_header=True)
                self.send_header(
                    "Cache-Control",
                    f"max-age={self.server.max_age}",
                    end_header=True)
        return path

    def check_cache(self, e_tag: str, match: str) -> bool:
        """Checks the ETag and sends a cache match response if it matches."""
        if e_tag != match:
            return False
        self.send_response(304)
        self.send_header("ETag", e_tag)
        self.send_header(
            "Cache-Control",
            f"max-age={self.server.max_age}")
        self.end_headers()
        thread_local.size = 0
        return True

    def send_to_proxy(self, proxy_url: str) -> None:
        clen = _GETHEADER(self.headers, "content-length")
        clen = int(clen) if clen is not None else 0
        if clen > 0:
            payload: bytes | None = self.rfile.read(clen)
        else:
            payload = None

        req = Request(
            proxy_url,
            data=payload,
            headers=dict(self.headers.items()),
            method=thread_local.method)

        def process(response: Any) -> None:
            self.send_response(response.code)
            for (hkey, hval) in response.headers.items():
                self.send_header(hkey, hval)
            self.end_headers()
            if _GETHEADER(response.headers, "transfer-encoding") == "chunked":
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

        try:
            with urlopen(req) as response:
                process(response)
        except HTTPError as e:
            process(e)
        raise PreventDefaultResponse()

    def handle_error(self) -> None:
        """Tries to send an 500 error after encountering an exception."""
        if self.server.can_ignore_error(self):
            return
        if thread_local.status_code is None:
            global_handle_error(
                ERR_SOURCE_REQUEST,
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
            except:  # nopep8  # pylint: disable=bare-except
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
        self.send_header(
            "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD")
        allow_headers = _GETHEADER(
            self.headers, "access-control-request-headers")
        if allow_headers is not None:
            self.send_header("Access-Control-Allow-Headers", allow_headers)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        return allow_headers is not None

    def do_OPTIONS(self) -> None:  # pylint: disable=invalid-name
        """Handles an OPTIONS request."""
        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = "OPTIONS"
        self.send_response(200)
        if self.is_cross_origin():
            no_caching = self.cross_origin_headers()
            # ten minutes if no custom headers requested
            self.send_header(
                "Access-Control-Max-Age", 0 if no_caching else 10*60)
        self.send_header("Content-Length", 0)
        self.end_headers()
        thread_local.size = 0

    def do_DELETE(self) -> None:  # pylint: disable=invalid-name
        """Handles a DELETE request."""
        # pylint: disable=try-except-raise,broad-except

        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = "DELETE"
        try:
            self.cross_origin_headers()
            self.handle_special(True, "DELETE")
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_PUT(self) -> None:  # pylint: disable=invalid-name
        """Handles a PUT request."""
        # pylint: disable=try-except-raise,broad-except

        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = "PUT"
        try:
            self.cross_origin_headers()
            self.handle_special(True, "PUT")
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_POST(self) -> None:  # pylint: disable=invalid-name
        """Handles a POST request."""
        # pylint: disable=try-except-raise,broad-except

        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = "POST"
        try:
            self.cross_origin_headers()
            self.handle_special(True, "POST")
        except PreventDefaultResponse as pdr:
            if pdr.code:
                self.send_error(pdr.code, pdr.msg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            self.handle_error()

    def do_GET(self) -> None:
        """Handles a GET request."""
        # pylint: disable=try-except-raise,broad-except

        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = "GET"
        try:
            self.cross_origin_headers()
            if self.handle_special(True, "GET"):
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
        # pylint: disable=try-except-raise,broad-except

        thread_local.clock_start = get_time()
        thread_local.status_code = 200
        thread_local.message = None
        thread_local.headers = []
        thread_local.end_headers = []
        thread_local.size = -1
        thread_local.method = "HEAD"
        try:
            self.cross_origin_headers()
            if self.handle_special(False, "GET"):
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
            self, code: int, message: str | None = None) -> None:
        thread_local.status_code = code
        thread_local.message = message

    def send_header(
            self,
            keyword: str,
            value: int | str,
            replace: bool = False,
            end_header: bool = False) -> None:
        thread_local.headers = getattr(thread_local, "headers", [])
        thread_local.end_headers = getattr(thread_local, "end_headers", [])
        if replace:
            # replaces the last occurrence of the header,
            # otherwise append as specified

            def do_replace(hdrs: list[tuple[str, str | int]]) -> bool:
                replace_ix = -1
                for (ix, (k, _)) in enumerate(hdrs):
                    if k == keyword:
                        # no break -- we want the last index
                        replace_ix = ix
                did_replace = replace_ix >= 0
                if did_replace:
                    hdrs[replace_ix] = (keyword, value)
                return did_replace

            if do_replace(thread_local.end_headers):
                return
            if do_replace(thread_local.headers):
                return
        if not end_header:
            hdr = thread_local.headers
        else:
            hdr = thread_local.end_headers
        hdr.append((keyword, value))

    def end_headers(self) -> None:
        thread_local.headers = getattr(thread_local, "headers", [])
        thread_local.end_headers = getattr(thread_local, "end_headers", [])
        thread_local.clock_start = getattr(
            thread_local,
            "clock_start",
            get_time())
        thread_local.status_code = getattr(thread_local, "status_code", 500)
        thread_local.message = getattr(thread_local, "message", None)
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
        return time.strftime(r"%Y-%m-%d %H:%M:%S")

    def _convert_unit(
            self,
            fmt: str,
            value: float | int,
            units: list[tuple[int | float, str]]) -> str:
        cur = ""
        for (conv, unit) in units:
            if value / conv >= 1 or len(cur) == 0:
                cur = fmt.format(value / conv) + unit
            else:
                break
        return cur

    # time units for logging request durations
    elapsed_units = [
        (1e-3, "ms"),
        (1, "s"),
        (60, "min"),
        (60*60, "h"),
        (60*60*24, "d"),
    ]

    def log_elapsed_time_string(self, elapsed: float) -> str:
        """Convert elapsed time into a readable string."""
        return self._convert_unit("{0:8.3f}", elapsed, self.elapsed_units)

    # size units for logging request sizes
    size_units = [
        (1.0, " B"),
        (1024, " kB"),
        (1024*1024, " MB"),
        (1024*1024*1024, " GB"),
    ]

    def log_size_string(self, size: int) -> str:
        """Convert buffer sizes into a readable string."""
        return self._convert_unit("{0:.3g}", size, self.size_units)

    def log_message(self, format: str, *args: Any) -> None:
        """Logs a message. All messages get prefixed with "[SERVER]"
           and the arguments act like `format`.
        """
        # pylint: disable=redefined-builtin

        clock_start = getattr(thread_local, "clock_start", None)
        thread_local.clock_start = None
        timing = (
            self.log_elapsed_time_string(get_time() - clock_start)
            if clock_start is not None
            else ""
        )
        msg(
            f"{timing + ' ' if len(timing) > 0 else ''}"
            f"[{self.log_date_time_string()}] "
            f"{format % args}")

    def log_request(
            self,
            code: int | str = "-",
            size: int | str = "-") -> None:
        """Logs the current request."""
        print_size = getattr(thread_local, "size", -1)
        if size != "-":
            size_str = f"({size}) "
        elif print_size >= 0:
            size_str = f"{self.log_size_string(print_size)} "
        else:
            size_str = ""
        if not self.server.suppress_noise or code not in (200, 304):
            self.log_message(f"{size_str}\"{self.requestline}\" {code}")
        if print_size >= 0:
            thread_local.size = -1


class TokenHandler:
    def __str__(self) -> str:
        return f"{self.__class__.__name__}"

    def lock(self, key: str | None) -> ContextManager:
        """The lock for token handler operations."""
        raise NotImplementedError()

    def ttl(self, key: str) -> float | None:
        """Returns the time in seconds until the given key expires.
           If the key never expires it should return None. If the key doesn't
           exist it should return 0. The function must not update the
           expiration time.
        """
        raise NotImplementedError()  # pragma: no cover

    def flush_old_tokens(self) -> None:
        """Ensures that all expired tokens get removed."""
        raise NotImplementedError()  # pragma: no cover

    def add_token(self, key: str, expire: float | None) -> TokenObj:
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

    def get_tokens(self) -> list[str]:
        """Returns a list of current tokens.
           `flush_old_tokens` is called immediately before this function.
        """
        raise NotImplementedError()  # pragma: no cover


class DefaultTokenHandler(TokenHandler):
    def __init__(self) -> None:
        # _token_timings is keys sorted by time
        self._token_map: dict[str, tuple[float | None, TokenObj]] = {}
        self._token_timings: list[str] = []
        self._token_lock = threading.Lock()

    def lock(self, key: str | None) -> ContextManager:
        return self._token_lock

    def ttl(self, key: str) -> float | None:
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

    def add_token(self, key: str, expire: float | None) -> TokenObj:
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

    def get_tokens(self) -> list[str]:
        # NOTE: has _token_lock
        return list(self._token_timings)

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}: "
            f"{self._token_timings}\n{self._token_map}"
        )


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
    def __init__(
            self,
            mask: str,
            fun: WorkerF[str],
            *,
            log: PrintF,
            cache_id: Callable[[CacheIdObj], Any] | None,
            cache: Any,
            cache_method: str,
            cache_section: str,
            thread_factory: ThreadFactory,
            name_prefix: str,
            soft_worker_death: bool,
            get_max_chunk_size: Callable[[], int],
            is_verbose_workers: Callable[[], bool]):
        self._mask = mask
        self._fun = fun
        self._msg = log
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
        return f"{self.__class__.__name__}[{self._mask}]"

    def is_done(self, cur_key: str) -> bool:
        """Returns whether the task with the given key has finished."""
        raise NotImplementedError()  # pragma: no cover

    def add_cargo(self, content: str) -> list[str]:
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

    def remove_worker(
            self,
            cur_key: str,
            ) -> tuple[str | None, tuple[str, str | None] | None]:
        """Removes the task with the given key and returns its result.
           The result is a tuple `(result, exception)` where result is the
           response if not None else exception is a tuple `(msg, trace)` where
           msg is the message of the exception and trace is the formatted
           stacktrace. In case of a PreventDefaultResponse exception the
           message uses the `_PDR_MARK` prefix and the status code after.
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

    def add_task(
            self,
            cur_key: str,
            get_thread: ThreadFactory,
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

    def start_worker(
            self,
            args: WorkerArgs,
            cur_key: str,
            get_thread: WorkerThreadFactory) -> None:
        try:
            self.add_task(cur_key, get_thread, self._soft_worker_death)
            if self._cache_id is not None:
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
        except Exception as e:  # pylint: disable=broad-except
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
                result, tback = err
                if tback is not None:
                    global_handle_error(
                        ERR_SOURCE_WORKER,
                        f"Error in purged worker for {cur_key}: {result}",
                        tback, self._msg)
            else:
                self._msg(f"purged result that was never read ({cur_key})")

    def compute_worker(
            self,
            _req: QuickServerRequestHandler,
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
            th: list[threading.Thread] = []

            def start_worker(*args: Any) -> None:
                self.start_worker(*args)

            wname = f"{self._name_prefix}-Worker-{cur_key}"
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
            raise ValueError(f"invalid action: {action}")
        if self.is_done(cur_key):
            mresult, exception = self.remove_worker(cur_key)
            if exception is not None:
                err, tback = exception
                if tback is None:
                    # token does not exist anymore
                    return {
                        "token": cur_key,
                        "done": False,
                        "result": None,
                        "continue": False,
                    }
                if err.startswith(_PDR_MARK):
                    # e encodes code, tb encodes message
                    raise PreventDefaultResponse(
                        int(err[len(_PDR_MARK):]), tback)
                global_handle_error(
                    ERR_SOURCE_WORKER,
                    f"Error in worker for {self._mask} ({cur_key}): {err}",
                    tback, self._msg)
                raise PreventDefaultResponse(500, "worker error")
            if (
                    mresult is not None
                    and len(mresult) > self._get_max_chunk_size()):
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
        self._msg(f"Error processing worker command: {post}")


class DefaultWorker(BaseWorker):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        BaseWorker.__init__(self, *args, **kwargs)
        self._lock = threading.RLock()
        self._tasks: dict[str, WorkerTask] = {}
        self._cargo: dict[str, tuple[float, str]] = {}
        self._cargo_cleaner: threading.Thread | None = None
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
                name=f"{self._name_prefix}-Cargo-Cleaner")
            cleaner.daemon = True
            self._cargo_cleaner = cleaner
            cleaner.start()

    def get_next_cargo(self) -> float | None:
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
                self._msg(f"purged cargo that was never read ({k})")

    def remove_cleaner(self) -> bool:
        with self._lock:
            if self.get_next_cargo() is not None:
                return False
            self._cargo_cleaner = None
            return True

    def add_cargo(self, content: str) -> list[str]:
        with self._lock:
            mcs = self._get_max_chunk_size()
            if mcs < 1:
                raise ValueError(f"invalid chunk size: {mcs}")
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
            ) -> tuple[str | None, tuple[str, str | None] | None]:
        with self._lock:
            task = self._tasks.pop(cur_key, None)
            if task is None:
                err_msg = f"Error: Task {cur_key} not found!"
                return None, (err_msg, None)
            if task["running"]:
                th = task["thread"]
                err_msg = f"Error: Task {cur_key} is still running!"
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
            crc32 = zlib.crc32(repr(get_time()).encode("utf-8"))
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

    def add_task(
            self,
            cur_key: str,
            get_thread: WorkerThreadFactory,
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
            task["exception"] = (f"{_PDR_MARK}{p.code}", p.msg)

    def set_task_err(self, cur_key: str, e: Exception) -> None:
        with self._lock:
            if cur_key not in self._tasks or self.is_cancelled(cur_key):
                return
            task = self._tasks[cur_key]
            task["running"] = False
            task["exception"] = (f"{e}", traceback.format_exc())

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


def construct_multipart_response(
        obj: dict[str | bytes, Any]) -> tuple[BytesIO, str]:
    boundary = f"qsboundary{uuid.uuid4().hex}"

    def binary(text: str | bytes) -> bytes:
        try:
            text = text.decode("utf-8")  # type: ignore
        except AttributeError:
            pass
        return text.encode("utf-8")  # type: ignore

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
    return resp, f"multipart/form-data; boundary=\"{boundary}\""


class MultipartResponse(Response):  # pylint: disable=too-few-public-methods
    def __init__(self, obj: Any) -> None:
        response, ctype = construct_multipart_response(obj)
        Response.__init__(self, response=response, code=200, ctype=ctype)


_token_default: Literal["DEFAULT"] = "DEFAULT"


class QuickServer(http_server.HTTPServer):
    def __init__(
            self,
            server_address: tuple[str, int],
            parallel: bool = True,
            thread_factory: ThreadFactory | None = None,
            token_handler: TokenHandler | None = None,
            worker_constructor: Callable[[], BaseWorker] | None = None,
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
            Whether to allow listing the directory if the "index.html"
            is missing. Defaults to `False`.

        shutdown_latency : float
            The number of seconds as float to tolerate waiting for actually
            shutting down after a shutdown command was issued.

        history_file : filename
            Where to store / read the command line history.

        prompt : string
            The prompt shown in the command line input.

        favicon_everywhere : boolean
            If True any path ending with "favicon.ico" will try to serve the
            favicon file found at any root.

        favicon_fallback : string or None
            If set points to the fallback "favicon.ico" file.

        max_age : number
            The content of the "max-age" directive for the "Cache-Control"
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
        self.history_file = ".cmd_history"
        self.prompt = "> "
        self.favicon_everywhere = True
        self.favicon_fallback: str | None = None
        self.max_age = 0
        self.max_file_size = 50 * 1024 * 1024
        self.max_chunk_size = 10 * 1024 * 1024
        self.cross_origin = False
        self.suppress_noise = False
        self.report_slow_requests: bool | Callable[[str, str], None] = False
        self.verbose_workers = False
        self.no_command_loop = False
        self.cache: Any | None = None
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
        self._folder_masks: list[tuple[str, str]] = []
        self._folder_proxys: list[tuple[str, str]] = []
        self._f_mask: dict[str, list[tuple[str, ReqF[BytesIO | None]]]] = {}
        self._f_argc: dict[str, int | None] = {}
        self._pattern_black: list[str] = []
        self._pattern_white: list[str] = []
        self._cmd_methods: dict[str, CmdF] = {}
        self._cmd_argc: dict[str, int | None] = {}
        self._cmd_complete: dict[str, CmdCompleteF | None] = {}
        self._cmd_lock = threading.Lock()
        self._cmd_start = False
        self._clean_up_call: Callable[[], None] | None = None
        if token_handler is None:
            token_handler = DefaultTokenHandler()
        self._token_handler = token_handler
        self._token_expire = 3600
        self._mirror: MirrorObj = {
            "impl": "none",
            "files": [],
            "lock": threading.RLock(),
        }
        self._file_fallback_cb: Callable[[str], str] | None = None

    def __str__(self) -> str:
        parallel = " parallel" if self._parallel else ""
        return f"{self.__class__.__name__}[{self.server_address}{parallel}]"

    # request processing #

    def _process_request(
            self,
            request: bytes,
            client_address: tuple[str, int]) -> None:
        """Actually processes the request."""
        try:
            self.finish_request(request, client_address)  # type: ignore
        except Exception:  # pylint: disable=broad-except
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)  # type: ignore

    def process_request(  # type: ignore
            self,
            request: bytes,
            client_address: tuple[str, int]) -> None:
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
            self, callback: Callable[[str], str] | None) -> None:
        """Allows to rewrite the returned filename in case a path could not
           be resolved. This is useful for returning the index file everywhere.
           If callback is None a 404 response will be generated. The callback
           is a function that accepts the path as argument and returns a new
           path. No white / blacklisting is performed on the returned path.
        """
        self._file_fallback_cb = callback

    def add_file_patterns(self, patterns: list[str], blacklist: bool) -> None:
        """Adds a list of file patterns to either the black- or white-list.
           Note that this pattern is applied to the absolute path of the file
           that will be delivered. For including or excluding folders use
           `bind_path` or `bind_path_fallback`.
        """
        blist = self._pattern_black if blacklist else self._pattern_white
        for pattern in patterns:
            blist.append(pattern)

    def add_default_white_list(self) -> None:
        """Adds a list of common file patterns to the white-list."""
        self.add_file_patterns([
            "*.css",
            "*.csv",
            "*.eot",
            "*.gif",
            "*.htm",
            "*.html",
            "*.ico",
            "*.jpeg",
            "*.jpg",
            "*.js",
            "*.json",
            "*.md",
            "*.otf",
            "*.pdf",
            "*.png",
            "*.svg",
            "*.tsv",
            "*.ttf",
            "*.txt",
            "*.woff",
            "*.woff2",
        ], blacklist=False)

    def bind_path(self, name: str, folder: str) -> None:
        """Adds a mask that maps to a given folder relative to `base_path`."""
        if len(name) == 0 or name[0] != "/" or name[-1] != "/":
            raise ValueError(f"name must start and end with \"/\": {name}")
        self._folder_masks.insert(0, (name, folder))

    def bind_path_fallback(self, name: str, folder: str) -> None:
        """Adds a fallback for a given folder relative to `base_path`."""
        if len(name) == 0 or name[0] != "/" or name[-1] != "/":
            raise ValueError(f"name must start and end with \"/\": {name}")
        self._folder_masks.append((name, folder))

    def bind_proxy(self, name: str, proxy: str) -> None:
        """Adds a mask that maps to a given proxy."""
        if len(name) == 0 or name[0] != "/" or name[-1] != "/":
            raise ValueError(f"name must start and end with \"/\": {name}")
        self._folder_proxys.insert(0, (name, proxy))

    def add_cmd_method(
            self,
            name: str,
            method: CmdF,
            argc: int | None = None,
            complete: CmdCompleteF | None = None) -> None:
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
        if " " in name:
            raise ValueError(f"\" \" cannot be in command name {name}")
        self._cmd_methods[name] = method
        self._cmd_argc[name] = argc
        self._cmd_complete[name] = complete

    def set_file_argc(self, mask: str, argc: int | None) -> None:
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
            method: ReqF[BytesIO | None]) -> None:
        """Adds a raw file mask for dynamic requests.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        method : function(esrh, args)
            The function to execute to perform the request. The function takes
            two arguments. `esrh` is the QuickServerRequestHandler object that
            called the function. `args` is a map containing the arguments to
            the request (i.e., the rest of the URL as path segment array
            "paths", a map of all query fields / flags "query", the fragment
            string "fragment", and if the method was a POST the JSON form
            content "post"). The function must return a file object containing
            the response (preferably BytesIO). If the result is None no
            response body is sent. In this case make sure to send an
            appropriate error code.
        """
        fmask = self._f_mask.get(method_str, [])
        fmask.append((start, method))
        fmask.sort(key=lambda k: len(k[0]), reverse=True)
        self._f_mask[method_str] = fmask
        self._f_argc[method_str] = None

    def add_json_mask(
            self,
            start: str,
            method_str: str,
            json_producer: ReqF) -> None:
        """Adds a handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. `esrh` is the
            QuickServerRequestHandler object that called the function. `args`
            is a map containing the arguments to the request (i.e., the rest of
            the URL as path segment array "paths", a map of all query
            fields / flags "query", the fragment string "fragment", and if the
            method was a POST the JSON form content "post"). If the result is
            `None` a 404 error is sent.
        """

        def send_json(
                req: QuickServerRequestHandler,
                args: ReqArgs) -> BytesIO | None:
            obj = json_producer(req, args)
            if not isinstance(obj, Response):
                obj = Response(obj)
            ctype = obj.get_ctype("application/json")
            code = obj.code
            obj = obj.response
            if obj is None:
                req.send_error(404, "File not found")
                return None
            f = BytesIO()
            json_str = json_dumps(obj)
            if isinstance(json_str, (str, bytes)):
                try:
                    json_str = json_str.decode("utf-8")  # type: ignore
                except AttributeError:
                    pass
                json_str = json_str.encode("utf-8")  # type: ignore
            f.write(json_str)  # type: ignore
            f.flush()
            size = f.tell()
            f.seek(0)
            # handle ETag caching
            if req.request_version >= "HTTP/1.1":
                e_tag = f"{zlib.crc32(f.read()) & 0xFFFFFFFF:x}"
                f.seek(0)
                match = _GETHEADER(req.headers, "if-none-match")
                if match is not None:
                    if req.check_cache(e_tag, match):
                        f.close()
                        return None
                req.send_header("ETag", e_tag, end_header=True)
                req.send_header(
                    "Cache-Control",
                    f"max-age={self.max_age}",
                    end_header=True)
            req.send_response(code)
            req.send_header("Content-Type", ctype)
            req.send_header("Content-Length", size)
            req.end_headers()
            return f

        self._add_file_mask(start, method_str, send_json)

    def add_json_get_mask(self, start: str, json_producer: ReqF) -> None:
        """Adds a GET handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. `esrh` is the
            QuickServerRequestHandler object that called the function. `args`
            is a map containing the arguments to the request (i.e., the rest of
            the URL as path segment array "paths", a map of all query
            fields / flags "query", and the fragment string "fragment"). If the
            result is `None` a 404 error is sent.
        """
        self.add_json_mask(start, "GET", json_producer)

    def add_json_put_mask(self, start: str, json_producer: ReqF) -> None:
        """Adds a PUT handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. `esrh` is the
            QuickServerRequestHandler object that called the function. `args`
            is a map containing the arguments to the request (i.e., the rest of
            the URL as path segment array "paths", a map of all query
            fields / flags "query", and the fragment string "fragment"). If the
            result is `None` a 404 error is sent.
        """
        self.add_json_mask(start, "PUT", json_producer)

    def add_json_delete_mask(self, start: str, json_producer: ReqF) -> None:
        """Adds a DELETE handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. `esrh` is the
            QuickServerRequestHandler object that called the function. `args`
            is a map containing the arguments to the request (i.e., the rest of
            the URL as path segment array "paths", a map of all query
            fields / flags "query", and the fragment string "fragment"). If the
            result is `None` a 404 error is sent.
        """
        self.add_json_mask(start, "DELETE", json_producer)

    def add_json_post_mask(self, start: str, json_producer: ReqF) -> None:
        """Adds a POST handler that produces a JSON response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        json_producer : function(esrh, args)
            A function returning an object that can be converted to JSON. The
            function takes two arguments. `esrh` is the
            QuickServerRequestHandler object that called the function. `args`
            is a map containing the arguments to the request (i.e., the rest of
            the URL as path segment array "paths", a map of all query
            fields / flags "query", and the fragment string "fragment"). If the
            result is `None` a 404 error is sent.
        """
        self.add_json_mask(start, "POST", json_producer)

    def add_text_mask(
            self,
            start: str,
            method_str: str,
            text_producer: ReqF[AnyStrResponse]) -> None:
        """Adds a handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        method_str : string
            The HTTP method for which to trigger the request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            `esrh` is the QuickServerRequestHandler object that called the
            function. `args` is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array "paths", a map of
            all query fields / flags "query", the fragment string "fragment",
            and if the method was a POST the JSON form content "post"). If the
            result is `None` a 404 error is sent.
        """

        def send_text(
                req: QuickServerRequestHandler,
                args: ReqArgs) -> BytesIO | None:
            text = text_producer(req, args)
            if isinstance(text, Response):
                resp = text
            else:
                resp = Response(
                    cast(str | bytes | StringIO | BytesIO | None, text))
            ctype = resp.get_ctype("text/plain")
            code = resp.code
            val = resp.response
            if val is None:
                req.send_error(404, "File not found")
                return None
            if hasattr(val, "read"):
                if hasattr(val, "seek"):
                    f = val
                    size = f.seek(0, os.SEEK_END)  # type: ignore
                    f.seek(0)  # type: ignore
                else:
                    f = BytesIO()
                    shutil.copyfileobj(val, f, length=16*1024)  # type: ignore
                    size = f.tell()
                    f.seek(0)
            else:
                f = BytesIO()
                if isinstance(val, (str, bytes)):
                    try:
                        val = val.decode("utf-8")  # type: ignore
                    except AttributeError:
                        pass
                    val = val.encode("utf-8")  # type: ignore
                f.write(val)  # type: ignore
                f.flush()
                size = f.tell()
                f.seek(0)
            # handle ETag caching
            if req.request_version >= "HTTP/1.1" and hasattr(f, "seek"):
                e_tag = \
                    f"{zlib.crc32(f.read()) & 0xFFFFFFFF:x}"  # type: ignore
                f.seek(0)  # type: ignore
                match = _GETHEADER(req.headers, "if-none-match")
                if match is not None:
                    if req.check_cache(e_tag, match):
                        f.close()  # type: ignore
                        return None
                req.send_header("ETag", e_tag, end_header=True)
                req.send_header(
                    "Cache-Control",
                    f"max-age={self.max_age}",
                    end_header=True)
            req.send_response(code)
            req.send_header("Content-Type", ctype)
            req.send_header("Content-Length", size)
            req.end_headers()
            return f  # type: ignore

        self._add_file_mask(start, method_str, send_text)

    def add_text_get_mask(
            self, start: str, text_producer: ReqF[AnyStrResponse]) -> None:
        """Adds a GET handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            `esrh` is the QuickServerRequestHandler object that called the
            function. `args` is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array "paths", a map of
            all query fields / flags "query", and the fragment string
            "fragment"). If the result is `None` a 404 error is sent.
        """
        self.add_text_mask(start, "GET", text_producer)

    def add_text_put_mask(
            self, start: str, text_producer: ReqF[AnyStrResponse]) -> None:
        """Adds a PUT handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            `esrh` is the QuickServerRequestHandler object that called the
            function. `args` is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array "paths", a map of
            all query fields / flags "query", and the fragment string
            "fragment"). If the result is `None` a 404 error is sent.
        """
        self.add_text_mask(start, "PUT", text_producer)

    def add_text_delete_mask(
            self, start: str, text_producer: ReqF[AnyStrResponse]) -> None:
        """Adds a DELETE handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            `esrh` is the QuickServerRequestHandler object that called the
            function. `args` is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array "paths", a map of
            all query fields / flags "query", and the fragment string
            "fragment"). If the result is `None` a 404 error is sent.
        """
        self.add_text_mask(start, "DELETE", text_producer)

    def add_text_post_mask(
            self, start: str, text_producer: ReqF[AnyStrResponse]) -> None:
        """Adds a POST handler that produces a plain text response.

        Parameters
        ----------
        start : string
            The URL prefix that must be matched to perform this request.

        text_producer : function(esrh, args)
            A function returning a string. The function takes two arguments.
            `esrh` is the QuickServerRequestHandler object that called the
            function. `args` is a map containing the arguments to the request
            (i.e., the rest of the URL as path segment array "paths", a map of
            all query fields / flags "query", the fragment string "fragment",
            and the JSON form content "post"). If the result is None a 404
            error is sent.
        """
        self.add_text_mask(start, "POST", text_producer)

    # wrappers #

    def cmd(
            self,
            argc: int | None = None,
            complete: CmdCompleteF | None = None,
            no_replace: bool = False) -> Callable[[CmdF], CmdF]:

        def wrapper(fun: CmdF) -> CmdF:
            name = getattr(fun, "__name__")
            if not no_replace or name not in self._cmd_methods:
                self.add_cmd_method(name, fun, argc, complete)
            return fun

        return wrapper

    def json_get(
            self,
            mask: str,
            argc: int | None = None) -> Callable[[ReqF[R_co]], ReqF[R_co]]:

        def wrapper(fun: ReqF[R_co]) -> ReqF[R_co]:
            self.add_json_get_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def json_put(
            self,
            mask: str,
            argc: int | None = None) -> Callable[[ReqF[R_co]], ReqF[R_co]]:

        def wrapper(fun: ReqF[R_co]) -> ReqF[R_co]:
            self.add_json_put_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def json_delete(
            self,
            mask: str,
            argc: int | None = None) -> Callable[[ReqF[R_co]], ReqF[R_co]]:

        def wrapper(fun: ReqF[R_co]) -> ReqF[R_co]:
            self.add_json_delete_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def json_post(
            self,
            mask: str,
            argc: int | None = None) -> Callable[[ReqF[R_co]], ReqF[R_co]]:

        def wrapper(fun: ReqF[R_co]) -> ReqF[R_co]:
            self.add_json_post_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_get(
            self,
            mask: str,
            argc: int | None = None,
            ) -> Callable[[ReqF[AnyStrResponse]], ReqF[AnyStrResponse]]:

        def wrapper(fun: ReqF[AnyStrResponse]) -> ReqF[AnyStrResponse]:
            self.add_text_get_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_put(
            self,
            mask: str,
            argc: int | None = None,
            ) -> Callable[[ReqF[AnyStrResponse]], ReqF[AnyStrResponse]]:

        def wrapper(fun: ReqF[AnyStrResponse]) -> ReqF[AnyStrResponse]:
            self.add_text_put_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_delete(
            self,
            mask: str,
            argc: int | None = None,
            ) -> Callable[[ReqF[AnyStrResponse]], ReqF[AnyStrResponse]]:

        def wrapper(fun: ReqF[AnyStrResponse]) -> ReqF[AnyStrResponse]:
            self.add_text_delete_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def text_post(
            self,
            mask: str,
            argc: int | None = None,
            ) -> Callable[[ReqF[AnyStrResponse]], ReqF[AnyStrResponse]]:

        def wrapper(fun: ReqF[AnyStrResponse]) -> ReqF[AnyStrResponse]:
            self.add_text_post_mask(mask, fun)
            self.set_file_argc(mask, argc)
            return fun

        return wrapper

    def middleware(
            self,
            mwfun: MiddlewareF[A_co],
            ) -> Callable[[ReqF[B_co]], ReqF[A_co | B_co]]:

        def wrapper(fun: ReqF[B_co]) -> ReqF[A_co | B_co]:

            def compute(req: QuickServerRequestHandler, args: ReqArgs) -> Any:
                next_token = ReqNext()
                intermediate = mwfun(req, args, next_token)
                if intermediate is next_token:
                    return fun(req, args)
                return intermediate

            return compute

        return wrapper

    # special files #

    def add_special_file(
            self,
            mask: str,
            path: str,
            from_quick_server: bool,
            ctype: str | None = None) -> None:
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

        def read_file(
                _req: QuickServerRequestHandler,
                _args: ReqArgs) -> Response:
            with open(full_path, "rb") as f_out:
                return Response(f_out.read(), ctype=ctype)

        self.add_text_get_mask(mask, read_file)
        self.set_file_argc(mask, 0)

    def mirror_file(
            self,
            path_to: str,
            path_from: str,
            from_quick_server: bool = True) -> None:
        """Mirrors a file to a different location. Each time the file changes
           while the process is running it will be copied to "path_to",
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
            raise ValueError(f"unknown mirror implementation: {impl}")

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

        def get_mtime(path: str) -> float:
            return os.path.getmtime(path)

        if init:
            self._mirror["impl"] = "poll"

            def act(ix: int, f_from: str, f_to: str) -> None:
                with self._mirror["lock"]:
                    shutil.copyfile(f_from, f_to)
                    self._mirror["files"][ix] = \
                        (f_from, f_to, get_mtime(f_from))

            def monitor() -> None:
                while True:
                    time.sleep(1)
                    with self._mirror["lock"]:
                        for (ix, f) in enumerate(self._mirror["files"]):
                            f_from, f_to, f_time = f
                            if f_time < get_mtime(f_from):
                                act(ix, f_from, f_to)

            poll_monitor = self._thread_factory(
                target=monitor,
                name=f"{self.__class__.__name__}-Poll-Monitor")
            poll_monitor.daemon = True
            poll_monitor.start()
        if not os.path.exists(path_from):
            raise ValueError(f"file does not exist: {path_from}")
        if path_from == path_to:
            raise ValueError(f"cannot mirror itself: {path_from}")
        with self._mirror["lock"]:
            for f in self._mirror["files"]:
                # sanity checks
                f_from, f_to, _f_time = f
                if f_to == path_to:
                    if f_from == path_from:
                        return True  # nothing to do here!
                    raise ValueError(
                        "cannot point two different "
                        "files to the same location: "
                        f"({f_from} != {path_from}) -> {f_to}")
                if f_to == path_from:
                    raise ValueError(
                        "cannot chain mirrors: "
                        f"{f_from} -> {f_to} -> {path_to}")
                if f_from == path_to:
                    raise ValueError(
                        "cannot chain mirrors: "
                        f"{path_from} -> {path_to} -> {f_to}")
            # forces an initial write
            self._mirror["files"].append((path_from, path_to, 0))
        return True

    def link_empty_favicon_fallback(self) -> None:
        """Links the empty favicon as default favicon."""
        self.favicon_fallback = os.path.join(
            os.path.dirname(__file__), "favicon.ico")

    # worker based #

    def link_worker_js(self, mask: str) -> None:
        """Links the worker javascript.

        Parameters
        ----------
        mask : string
            The URL that must be matched to get the worker javascript.
        """
        self.add_special_file(
            mask,
            "worker.js",
            from_quick_server=True,
            ctype="application/javascript; charset=utf-8")

    def mirror_worker_js(self, path: str) -> None:
        """Mirrors the worker javascript.

        Parameters
        ----------
        path : string
            The path to mirror to.
        """
        self.mirror_file(path, "worker.js", from_quick_server=True)

    def link_legacy_worker_js(self, mask: str) -> None:
        """Links the legacy worker javascript.

        Parameters
        ----------
        mask : string
            The URL that must be matched to get the worker javascript.
        """
        self.add_special_file(
            mask,
            "worker.legacy.js",
            from_quick_server=True,
            ctype="application/javascript; charset=utf-8")

    def mirror_legacy_worker_js(self, path: str) -> None:
        """Mirrors the legacy worker javascript.

        Parameters
        ----------
        path : string
            The path to mirror to.
        """
        self.mirror_file(path, "worker.legacy.js", from_quick_server=True)

    def json_worker(
            self,
            mask: str,
            cache_id: Callable[[CacheIdObj], Any] | None = None,
            cache_method: str = "string",
            cache_section: str = "www",
            ) -> Callable[[WorkerF[R_co]], WorkerF[R_co]]:
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
                mask,
                fun,
                log=msg,
                cache_id=cache_id,
                cache=self.cache,
                cache_method=cache_method,
                cache_section=cache_section,
                thread_factory=self._thread_factory,
                name_prefix=self.__class__.__name__,
                soft_worker_death=self._soft_worker_death,
                get_max_chunk_size=lambda: self.max_chunk_size,
                is_verbose_workers=lambda: self.verbose_workers)

            def run_worker(
                    req: QuickServerRequestHandler,
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
            expire: float | Literal["DEFAULT"] | None = _token_default,
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
            aexpire: float | None = self.get_default_token_expiration()
        else:
            aexpire = cast(float | None, expire)
        write_back = False
        res = {}
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

    def get_tokens(self) -> list[str]:
        with self._token_handler.lock(None):
            self._token_handler.flush_old_tokens()
            return self._token_handler.get_tokens()

    def get_token_ttl(self, token: str) -> float | None:
        with self._token_handler.lock(token):
            try:
                ttl = self._token_handler.ttl(token)
            except KeyError:
                ttl = 0
            if ttl is None:
                return ttl
            return max(ttl, 0)

    # miscellaneous #

    def handle_cmd(self, cmd: str) -> None:
        """Handles a single server command."""
        cmd = cmd.strip()
        segments = []
        for s in cmd.split():
            # remove bash-like comments
            if s.startswith("#"):
                break
            # TODO implement escape sequences (also for \#)
            segments.append(s)
        args: list[str] = []
        if len(segments) == 0:
            return
        # process more specific commands first
        while segments:
            cur_cmd = "_".join(segments)
            if cur_cmd in self._cmd_methods:
                argc = self._cmd_argc[cur_cmd]
                if argc is not None and len(args) != argc:
                    msg(
                        f"command {' '.join(segments)} "
                        f"expects {argc} argument(s), "
                        f"got {len(args)}")
                    return
                self._cmd_methods[cur_cmd](args)
                return
            args.insert(0, segments.pop())
        # invalid command
        prefix = "_".join(args) + "_"
        matches = filter(
            lambda cmd: cmd.startswith(prefix), self._cmd_methods.keys())
        candidates = set([])
        for m in matches:
            if len(m) <= len(prefix):
                continue
            m = m[len(prefix):]
            if "_" in m:
                m = m[:m.index("_")]
            candidates.add(m)
        if len(candidates) > 0:
            msg(f"command \"{' '.join(args)}\" needs more arguments:")
            for c in candidates:
                msg(f"    {c}")
        else:
            msg(
                f"command \"{' '.join(args)}\" invalid; type "
                "help or use <TAB> for a list of commands")

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
            "suggestions": [],
            "clean_up_lock": threading.Lock(),
            "clean": False,
            "line": "",
        }

        # setup internal commands (no replace)
        @self.cmd(argc=0, no_replace=True)
        def help(  # pylint: disable=redefined-builtin
                _args: list[str]) -> None:
            msg("available commands:")
            for key in dict(self._cmd_methods):
                msg(f"    {key.replace('_', ' ')}")

        @self.cmd(argc=0, no_replace=True)
        def restart(_args: list[str]) -> None:
            global _DO_RESTART

            _DO_RESTART = True
            self.done = True

        @self.cmd(argc=0, no_replace=True)
        def quit(  # pylint: disable=redefined-builtin
                _args: list[str]) -> None:
            self.done = True

        # set up command completion
        def complete(text: str, state: int) -> str | None:
            if state == 0:
                origline = readline.get_line_buffer()
                line = origline.lstrip()
                stripped = len(origline) - len(line)
                begidx = readline.get_begidx() - stripped
                endidx = readline.get_endidx() - stripped
                prefix = line[:begidx].replace(" ", "_")

                def match_cmd(cmd: str) -> bool:
                    return (
                        cmd.startswith(prefix)
                        and cmd[begidx:].startswith(text))

                matches = filter(match_cmd, self._cmd_methods.keys())

                def _endidx(m: str) -> int:
                    eix = m.find("_", endidx)
                    return eix + 1 if eix >= 0 else len(m)

                candidates = [
                    m[begidx:_endidx(m)].replace("_", " ") for m in matches
                ]
                rest_cmd = line[:begidx].split()
                args: list[str] = []
                while rest_cmd:
                    cur_cmd = "_".join(rest_cmd)
                    compl = self._cmd_complete.get(cur_cmd)
                    if compl is not None:
                        ccan = compl(args, text)
                        if ccan is not None:
                            candidates.extend(ccan)
                    args.insert(0, rest_cmd.pop())
                cmd_state["suggestions"] = sorted(set(candidates))
                cmd_state["line"] = line
            suggestions: list[str] = cmd_state["suggestions"]
            if len(suggestions) == 1 and text == suggestions[0]:
                probe_cmd = cmd_state["line"].replace(" ", "_")
                if probe_cmd in self._cmd_argc and \
                        self._cmd_argc[probe_cmd] != 0:
                    cmd_state["line"] = ""
                    return f"{text} "
                return None
            if state < len(suggestions):
                return suggestions[state]
            return None

        # remember to clean up before exit -- the call must be idempotent!
        def clean_up() -> None:
            with cmd_state["clean_up_lock"]:
                clean = cmd_state["clean"]
                cmd_state["clean"] = True

            if clean:
                return

            readline.write_history_file(hfile)
            readline.set_completer(old_completer)

        def cmd_loop() -> None:
            close = False
            kill = True
            try:
                while (
                        not self.done
                        and not close
                        and not self.no_command_loop):
                    line = ""
                    try:
                        try:
                            # pylint: disable=using-constant-test
                            if sys.stdin.closed:
                                self.done = True
                                continue
                            line = input(self.prompt)
                        except IOError as e:
                            if e.errno == errno.EBADF:
                                close = True
                                kill = False
                            elif e.errno in (
                                    errno.EWOULDBLOCK,
                                    errno.EAGAIN,
                                    errno.EINTR):
                                continue
                            else:
                                raise e
                        self.handle_cmd(line)
                    except EOFError:
                        close = True
                        kill = False
                    except KeyboardInterrupt:
                        close = True
                    except WorkerDeath:
                        close = True
                        kill = True
                        self.done = True
                        continue
                    except Exception:  # pylint: disable=broad-except
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

        # loading the history
        hfile = self.history_file
        try:
            readline.read_history_file(hfile)
        except IOError:
            pass

        old_completer = readline.get_completer()
        readline.set_completer(complete)
        # be mac compatible
        if readline.__doc__ is not None and "libedit" in readline.__doc__:
            readline.parse_and_bind("python:bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

        atexit.register(clean_up)
        self._clean_up_call = clean_up

        if not self.no_command_loop:
            t = self._thread_factory(target=cmd_loop, daemon=True)
            t.start()

            def no_log(_: str) -> None:
                pass

            def not_verbose() -> bool:
                return False

            def end_loop() -> None:
                atexit.unregister(end_loop)
                self.done = True
                # NOTE: we need to wait until the command loop is done before
                # proceeding with atexit handlers
                while t.is_alive():
                    kill_thread(t, "cmd loop", no_log, not_verbose)
                    time.sleep(0.1)

            atexit.register(end_loop)

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
        while (
                not (self.done or done_req)
                and (
                    timeout is None
                    or timeout == 0
                    or (get_time() - ctime) < timeout)):
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
            if LOG_FILE is not None and LOG_FILE == sys.stderr:
                LOG_FILE.write("\n")
        finally:
            if self._clean_up_call is not None:
                self._clean_up_call()
            self.done = True

    def can_ignore_error(
            self,
            reqhnd: QuickServerRequestHandler | None = None) -> bool:
        """Tests if the error is worth reporting.
        """
        value = sys.exc_info()[1]
        try:
            if isinstance(value, (BrokenPipeError, ConnectionResetError)):
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

    def handle_error(  # type: ignore
            self,
            request: bytes,
            client_address: tuple[str, int]) -> None:
        """Handle an error gracefully.
        """
        if self.can_ignore_error():
            return
        thread = threading.current_thread()
        global_handle_error(
            ERR_SOURCE_GENERAL_QS,
            f"Error in request ({client_address}): "
            f"{repr(request)} in {thread.name}",
            traceback.format_exc(),
            msg)


def create_server(
        server_address: tuple[str, int],
        *,
        parallel: bool = True,
        thread_factory: ThreadFactory | None = None,
        token_handler: TokenHandler | None = None,
        worker_constructor: Callable[..., BaseWorker] | None = None,
        soft_worker_death: bool = False) -> QuickServer:
    """Creates the server."""
    return QuickServer(
        server_address,
        parallel,
        thread_factory,
        token_handler,
        worker_constructor,
        soft_worker_death)
