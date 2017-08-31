QuickServer
===========

*quick\_server* is a quick to use and easy to set up server
implementation. It has the following goals / features and is primarily
meant to speed up back end implementation / iteration:

-  serve local files as is with basic black- and white-listing
-  provide functionality for dynamic requests
-  provide easy access to worker threads (and caching)
-  provide a basic command interpret loop for server commands

|Build Status| |codecov.io|

Usage
-----

You can install *quick\_server* with pip:

.. code:: sh

    pip install --user quick_server

Import it in python via:

.. code:: python

    from quick_server import create_server, msg, setup_restart

Setting up a basic file server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Following we will set up a basic *quick\_server*. Please refer to the
`inline documentation <https://github.com/JosuaKrause/quick_server/blob/master/quick_server/quick_server.py>`__ of the methods for
full information.

.. code:: python

    setup_restart() # sets up restart functionality (if not called the `restart` command of the server needs external help to work)
    # should be the first real executed command in the script
    # some services, like heroku, don't play well with this command and it should not be called if in such an environment

    addr = '' # empty address is equivalent to 'localhost'
    port = 8080
    server = create_server((addr, port), parallel=True) # parallel is recommended unless your code is not thread-safe
    server.bind_path('/', 'www') # binds the 'www' directory to the server's root
    server.add_default_white_list() # adds typical file types to the list of files that will be served; you can use server.add_file_patterns to add more file types
    server.favicon_fallback = 'favicon.ico' # sets the default favicon file to the given file on disk (you'll need a file called 'favicon.ico')
    # you can also use server.link_empty_favicon_fallback()

    server.suppress_noise = True # don't report successful requests (turn off if you want to measure performance)
    server.report_slow_requests = True # reports requests that take longer than 5s

Starting the actual server:

.. code:: python

    msg("{0}", " ".join(sys.argv)) # prints how the script was started
    msg("starting server at {0}:{1}", addr if addr else 'localhost', port)
    try:
        server.serve_forever() # starts the server -- only returns when the server stops (e.g., by typing `quit`, `restart`, or `CTRL-C`)
    finally:
        msg("shutting down..")
        msg("{0}", " ".join(sys.argv)) # print how the script was called before exit -- this way you don't have to scroll up to remember when the server was running for a while
        server.server_close() # make sure to clean up all resources

Adding dynamic requests
~~~~~~~~~~~~~~~~~~~~~~~

Dynamic requests can be set up by annotating a function. The annotation
consists of *return-type* and *http-method*.

A ``POST`` request in ``JSON`` format:

.. code:: python

    @server.json_post('/json_request', 0) # creates a request at http://localhost:8080/json_request -- 0 additional path segments are allowed
    def json_request(req, args):
        return {
            "post": args["post"],
        }

A ``GET`` request as ``plain text``:

.. code:: python

    @server.text_get('/text_request') # creates a request at http://localhost:8080/text_request -- additional path segments are allowed
    def text_request(req, args):
        return "plain text"

Other forms of requests are also supported, namely ``DELETE`` and ``PUT``.

``args`` is an object holding all request arguments.
``args['query']`` contains URL query arguments.
``args['fragment']`` contains the URL fragment part.
``args['paths']`` contains the remaining path segments.
``args['post']`` contains the posted content.
``args['files']`` contains uploaded files.

Worker threads and caching
~~~~~~~~~~~~~~~~~~~~~~~~~~

Worker threads are long running server side computations.
The client can start a request, gets an immediate response,
and will check periodically if the computation has finished.
From the client's perspective it looks like a normal request.

Worker threads require support from the client side.

First, provide the necessary JavaScript file via

.. code:: python

    server.link_worker_js('/js/worker.js')

and load it on the client side:

.. code:: html

    <script src="js/worker.js" charset="utf-8"></script>

A worker request can be set up on the server side with

.. code:: python

    @server.json_worker('/json_worker')
    def json_worker(post):
        # post contains all post arguments
        # ...
        # long, slow computation
        return myresult # myresult must be JSON convertible

and accessed from the client. An instance of the ``Worker`` class is
needed:

.. code:: javascript

    var work = new quick_server.Worker();
    work.status((req) => {
      // req contains the number of currently active requests (-1 indicates an error state)
      // it can be used to tell the user that something is happening
    });

Accessing the worker:

.. code:: javascript

    // the first argument identifies worker jobs
    // jobs with the same name get replaced when a new one has been started
    // the second argument is the URL
    work.post("worker_name", "json_worker", {
      // this object will appear as args on the server side
    }, (data) => {
      // data is the result of the worker function of the server side
      // this function is only called if the request was successful
    });

A worker can be cancelled using its name:

.. code:: javascript

    work.cancel("worker_name");

Note that all running workers are cancelled when the page is unloaded.

Workers can automatically cache the server response using
`quick\_cache <https://pypi.python.org/pypi/quick-cache>`__. The
server needs to be set up for this:

.. code:: python

    cache = QuickCache(base_file, quota=500, ram_quota=100, warnings=msg)
    server.cache = cache

Then caching can be used for workers:

.. code:: python

    @server.json_worker('/json_worker', cache_id=lambda args: {
            # uniquely identify the task from its arguments (must be JSON convertible)
        })
    def json_worker(post):
        # ...
        # long, slow computation
        return myresult # myresult must be JSON convertible

Note that caching can also be used for other types of requests.

Using workers with babel or react
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you're using *babel* (e.g., with *react*) you can also
mirror the file into your source folder:

.. code:: python

    server.mirror_worker_js('src/worker.js')

and then import it:

.. code:: javascript

    import './worker.js';

    const WORKER = new window.quick_server.Worker();
    export function registerStatus(cb) {
      WORKER.status(cb);
    }

    export function fetchWorker(ref, url, post, cb) {
      WORKER.post(ref, url, post, cb);
    }

    export function cancelWorker(ref) {
      WORKER.cancel(ref);
    }

Note that for a build you need to actually copy
``worker.js`` into you source folder since the build
system gets confused with filesystem links.
To use *quick\_server* with a build bind the build folder:

.. code:: python

    server.bind_path('/', 'build/')

During development it is recommended to forward
requests from the *react* server to *quick\_server*.
For this add the following line to your ``package.json``:

.. code:: javascript

    "proxy": "http://localhost:8080"

where the proxy field redirects to the *quick\_server*.

Tokens
~~~~~~

Tokens are means to store client information on the server.
For that the server must send the token-id to the client:

.. code:: python

    server.create_token() # creates a new token -- send this to the client

The server can now access (read / write) data associated with this token:

.. code:: python

    @server.json_post('/json_request', 0)
    def json_request(req, args):
        # assuming the token-id was sent via post
        # expire can be the expiration time in seconds of a token,
        # None for no expiration, or be omitted for the default expiration (1h)
        obj = server.get_token_obj(args['post']['token'], expire=None)
        # do stuff with obj
        # ...

CORS and proxying
~~~~~~~~~~~~~~~~~

CORS can be activated with:

.. code:: python

    server.cross_origin = True

and requests can be redirected via proxy (if you want to avoid CORS):

.. code:: python

    server.bind_proxy('/foo/', 'http://localhost:12345')

redirects every request that begins with ``/foo/`` and
has not been handled by *quick\_server* to ``http://localhost:12345``.

Custom server commands
~~~~~~~~~~~~~~~~~~~~~~

By default *quick\_server* provides the commands ``help`` (list of
available commands), ``restart`` (restart the server), and ``quit``
(terminates the server). You can add own commands via

.. code:: python

    @server.cmd()
    def name(args): # creates the command name
        if not args:
            msg("hello")
        else:
            msg("hi {0}", " ".join(args)) # words typed after name are printed here

A common command to add when having caching functionality (e.g.,
provided by
`quick\_cache <https://pypi.python.org/pypi/quick-cache>`__) is to
clear caches. This show-cases also auto-complete functionality:

.. code:: python

    def complete_cache_clear(args, text): # args contains already completed arguments; text the currently started one
        if args: # we only allow up to one argument
            return []
        return [ section for section in cache.list_sections() if section.startswith(text) ] # cache is the quick_cache object

    @server.cmd(complete=complete_cache_clear)
    def cache_clear(args):
        if len(args) > 1: # we only allow up to one argument
          msg("too many extra arguments! expected one got {0}", ' '.join(args))
          return
        msg("clear {0}cache{1}{2}", "" if args else "all ", " " if args else "s", args[0] if args else "")
        cache.clean_cache(args[0] if args else None)

Server without command loop
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The easiest way to start the server without a command loop (e.g., when
started as service) is to stop the loop with an EOF by calling the
script like this:

.. code:: sh

    cat /dev/null | python yourscript.py

or use the ``no_command_loop`` flag and run the script normally:

.. code:: python

    server.no_command_loop = True

HTTPS
~~~~~

You can wrap the server socket to support HTTPS:

.. code:: python

    import ssl

    addr = '' # empty address is equivalent to 'localhost'
    port = 443 # the HTTPS default port 443 might require root privileges
    server = create_server((addr, port), parallel=True)
    server.socket = ssl.wrap_socket(server.socket, certfile='path/to/localhost.pem', server_side=True)

    # setup your server

    try:
        server.serve_forever()
    finally:
        server.server_close()

More examples
~~~~~~~~~~~~~

`example.py <https://github.com/JosuaKrause/quick_server/blob/master/example/example.py>`__ and
`example2.py <https://github.com/JosuaKrause/quick_server/blob/master/example/example2.py>`__ also contain minimal example
servers. You can run them with ``./example.py`` and ``./example2.py``
respectively from the examples directory. Then you can browse to
http://localhost:8000/example/.

Contributing
------------

Pull requests are highly appreciated :) Also, feel free to open
`issues <https://github.com/JosuaKrause/quick_server/issues>`__ for any
questions or bugs you may encounter.

.. |Build Status| image:: https://travis-ci.org/JosuaKrause/quick_server.svg?branch=master
   :target: https://travis-ci.org/JosuaKrause/quick_server
.. |codecov.io| image:: https://codecov.io/github/JosuaKrause/quick_server/coverage.svg?branch=master
   :target: https://codecov.io/github/JosuaKrause/quick_server?branch=master
