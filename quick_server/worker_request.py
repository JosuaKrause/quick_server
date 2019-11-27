from typing import Any, Dict

import json
import time
import requests


DELAY_INIT = 500.0
DELAY_MAX = 60 * 1000
DELAY_INC = 10.0
DELAY_MUL = 1.01


def _single_request(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    req = requests.post(url, headers={
        "Content-Type": "application/json",
    }, data=json.dumps(data))
    if req.status_code == 200:
        return json.loads(req.text)
    raise ValueError(
        "error {0} in worker request:\n{1}".format(req.status_code, req.text))


def worker_request(url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
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
