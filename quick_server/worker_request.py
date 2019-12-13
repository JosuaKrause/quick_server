from typing import Any, Dict

import json
import time
try:
    import requests
except ImportError:
    pass


DELAY_INIT = 500.0
DELAY_MAX = 60 * 1000
DELAY_INC = 10.0
DELAY_MUL = 1.01


class WorkerError(ValueError):
    def __init__(self, msg: str, status_code: int):
        super().__init__(msg)
        self._status_code = status_code

    def get_status_code(self) -> int:
        """The status code of the failed request."""
        return self._status_code


def _single_request(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    req = requests.post(url, json=data)
    if req.status_code == 200:
        return json.loads(req.text)
    raise WorkerError(
        f"error {req.status_code} in worker request:\n{req.text}",
        req.status_code)


def worker_request(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Issues a worker request to the given url. This call blocks until the
       request finishes.

    Parameters
    ----------
    url : string
        The URL.

    payload : dict
        The arguments to the worker request call.

    Returns
    -------
        The response of the worker request.

    Exceptions
    ----------
        Raises a WorkerError if the request's status code is not 200.
    """
    try:
        requests
    except NameError:
        raise RuntimeError(
            "this function requires the package 'requests' to be installed!")
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

            def check(ctoken: str, response: Dict[str, Any]) -> str:
                if response["token"] != ctoken:
                    raise ValueError("token mismatch {0} != {1}".format(
                        response["token"], ctoken))
                return response["result"]

            # TODO: async would be better
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
