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
"""Provides a python interface to access worker endpoints."""
import json
import time
from typing import Any


try:
    import requests
except ImportError:
    pass


DELAY_INIT = 500.0
DELAY_MAX = 60 * 1000
DELAY_INC = 10.0
DELAY_MUL = 1.01


class WorkerError(ValueError):
    """An error indicating that the worker has failed."""
    def __init__(self, msg: str, status_code: int):
        super().__init__(msg)
        self._status_code = status_code

    def get_status_code(self) -> int:
        """The status code of the failed request."""
        return self._status_code


def _single_request(url: str, data: dict[str, Any]) -> dict[str, Any]:
    assert requests
    req = requests.post(url, json=data, timeout=10)
    if req.status_code == 200:
        return json.loads(req.text)
    raise WorkerError(
        f"error {req.status_code} in worker request:\n{req.text}",
        req.status_code)


def worker_request(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Issues a worker request to the given url. This call blocks until the
       request finishes.

    Args:
    url : string
        The URL.

    payload : dict
        The arguments to the worker request call.

    Raises:
        RuntimeError: If the requests library is not installed.
        ValueError: If the request has timed out.
        WorkerError: Raises a WorkerError if the request's statu
            code is not 200.

    Returns:
        The response of the worker request.
    """
    try:
        assert requests
    except (NameError, AssertionError) as e:
        raise RuntimeError(
            "this function requires the package 'requests' to be installed!",
            ) from e
    done = False
    token = None
    try:
        res = _single_request(url, {
            "action": "start",
            "payload": payload,
        })
        delay = DELAY_INIT
        while not res["done"]:
            if not res["continue"]:
                raise ValueError("request has timed out")
            token = res["token"]
            time.sleep(delay / 1000.0)
            res = _single_request(url, {
                "action": "get",
                "token": token,
            })
            delay = min(max(delay * DELAY_MUL, delay + DELAY_INC), DELAY_MAX)
        if res["continue"]:
            cargo_tokens = res["result"]

            def check(ctoken: str, response: dict[str, Any]) -> str:
                if response["token"] != ctoken:
                    raise ValueError(
                        f"token mismatch {response['token']} != {ctoken}")
                return response["result"]

            final = json.loads("".join(
                check(ctoken, _single_request(url, {
                    "action": "cargo",
                    "token": ctoken,
                }))
                for ctoken in cargo_tokens
            ))
        else:
            final = json.loads(res["result"])
        done = True
        return final
    finally:
        if not done and token is not None:
            while True:
                res = _single_request(url, {
                    "action": "stop",
                    "token": token,
                })
                if not res["continue"]:
                    break
