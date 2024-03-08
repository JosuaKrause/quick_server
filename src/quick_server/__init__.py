# -*- coding: utf-8 -*-
#
# Copyright 2024 Josua Krause
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
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
from .quick_server import (
    __version__,
    AnyStrResponse,
    BaseWorker,
    CacheIdObj,
    CmdCompleteF,
    CmdF,
    CmdState,
    create_server,
    debug,
    DefaultTokenHandler,
    DefaultWorker,
    ErrHandler,
    get_exec_arr,
    get_time,
    get_worker_check,
    has_been_restarted,
    is_original,
    is_worker_alive,
    json_dumps,
    LONG_MSG,
    MiddlewareF,
    msg,
    MSG_STDERR,
    MultipartResponse,
    PostFileLens,
    PreventDefaultResponse,
    PrintF,
    QuickServer,
    QuickServerRequestHandler,
    ReqArgs,
    ReqF,
    ReqNext,
    Response,
    set_error_exit_code,
    set_global_error_handler,
    set_log_file,
    set_restart_exit_code,
    setup_restart,
    ThreadFactory,
    TokenHandler,
    TokenObj,
    WorkerArgs,
    WorkerDeath,
    WorkerF,
    WorkerResponse,
    WorkerTask,
    WorkerThreadFactory,
)
from .worker_request import worker_request, WorkerError


__all__ = [
    "__version__",
    "AnyStrResponse",
    "BaseWorker",
    "CacheIdObj",
    "CmdCompleteF",
    "CmdF",
    "CmdState",
    "create_server",
    "debug",
    "DefaultTokenHandler",
    "DefaultWorker",
    "ErrHandler",
    "get_exec_arr",
    "get_time",
    "get_worker_check",
    "has_been_restarted",
    "is_original",
    "is_worker_alive",
    "json_dumps",
    "LONG_MSG",
    "MiddlewareF",
    "MSG_STDERR",
    "msg",
    "MultipartResponse",
    "PostFileLens",
    "PreventDefaultResponse",
    "PrintF",
    "QuickServer",
    "QuickServerRequestHandler",
    "ReqArgs",
    "ReqF",
    "ReqNext",
    "Response",
    "set_error_exit_code",
    "set_global_error_handler",
    "set_log_file",
    "set_restart_exit_code",
    "setup_restart",
    "ThreadFactory",
    "TokenHandler",
    "TokenObj",
    "worker_request",
    "WorkerArgs",
    "WorkerDeath",
    "WorkerError",
    "WorkerF",
    "WorkerResponse",
    "WorkerTask",
    "WorkerThreadFactory",
]
