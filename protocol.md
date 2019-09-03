# WORKER protocol

The `WORKER` (aka `LONGPOST`) protocol enables longrunning computations with
`quick_server`. All requests described below are `POST` requests with
`application/json` argument formatting. The response body is likewise formatted
as `application/json`. There are only four commands:

- `"start"`
    The `"start"` command initiates a new `WORKER` request. The request body
    should be:

    ```javascript
    {
        "action": "start",
        "payload": {...} // custom argument dictionary
    }
    ```

    All responses have the same format and are described below. If the result
    is immediately available it will be sent in this response to avoid further
    API calls.

- `"stop"`
    The `"stop"` command terminates a `WORKER` request. It should be called
    if the client does not intend to further query for results. Note, that
    calling `"stop"` enables the server to release used resources and
    potentially cancel the ongoing operation. The request body looks like:

    ```javascript
    {
        "action": "stop",
        "token": ... // the task token
    }
    ```

- `"get"`
    The `"get"` command queries the server for the result of the pending
    computation. The request body looks like:

    ```javascript
    {
        "action": "get",
        "token": ... // the task token
    }
    ```

    The delay between two consecutive calls to `"get"` should follow the
    following formula. The initial delay between two calls should be `500ms`.
    From there any subsequent delay should follow
    `max(prevDelay * 1.01, prevDelay + 10)` in `ms`. The delay must be capped
    at `60000ms = 60s` as otherwise the server is running the risk of
    accidentally removing results. The exact delays can be tweaked for better
    performance but note that earlier requests should be more frequent than
    later ones and the delay should not be longer than half the expiration
    time.

    If a result was returned resources on the server get released immediately
    so subsequent calls will result in errors.

- `"cargo"`
    If a response becomes too big `quick_server` might split the response in
    multiple parts. How this is indicated is described below. If this occurs
    the servers responds with a list of keys that can be queried using
    `"cargo"`. The order of the keys in the list determines how the response
    needs to be joined together. The request body looks like:

    ```javascript
    {
        "action": "cargo",
        "token": ... // a cargo token from the list
    }
    ```

    All cargo tokens can be accessed only once.

The response format always contains four fields:

```javascript
{
    "continue": true,
    "done": false,
    "result": null,
    "token": ... // the key to reference the request
}
```

The `continue` field indicates whether the client should keep querying the API.
The recommended delay between two subsequent queries is described above. Note,
that `continue` can also mean that there was an error on the server side or the
request timed out.

The `token` field indicates the unique identifier of the request and must be
provided for all requests except `"start"`. Note, that `"cargo"` uses different
tokens than the original request token.

The `done` field indicates whether the computation has finished. If `done` is
`true` the `result` field contains the result. In the case that the result was
too big for a single response both `continue` and `done` will be set and the
`result` field will contain a list of tokens in the order in which their
resulting `"cargo"` calls must be joined. The responses of `"cargo"` calls
only contain their `token` and the `result` field. In case of a `"stop"` call
`done` will be `true`, `continue` will be `false`, and result will be `null`.
Note, that the `result` field will be a string that needs to be parsed as json.
