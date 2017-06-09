QuickServer
===========

*QuickServer* is a quick to use and easy to set up server
implementation. It has the following goals / features and is primarily
meant to speed up back end implementation / iteration:

-  serve local files as is with basic black-listing
-  provide functionality for dynamic requests
-  provide easy access to worker threads (and caching)
-  provide a basic command interpret loop for server commands

|Build Status| |codecov.io|

Usage
-----

You can install *quick\_server* with pip:

.. code:: sh

    pip install --user quick-server

Import it in python via:

.. code:: python

    from quick_server import create_server, msg, setup_restart

Setting up a basic file server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Following we will set up a basic *quick\_server*. Please refer to the
`inline documentation <https://github.com/JosuaKrause/quick_server/blob/master/quick_server/__init__.py>`__ of the methods for
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
    server.serve_forever() # starts the server -- only returns when the server stops (e.g., by typing `quit`, `restart`, or `CTRL-C`)
    msg("shutting down..")
    server.server_close() # make sure to clean up all resources

Adding dynamic requests
~~~~~~~~~~~~~~~~~~~~~~~

Dynamic requests can be set up by annotating a function. The annotation
consists of *return-type* and *http-method*.

A ``POST`` request in ``JSON`` format:

.. code:: python

    @server.json_post('/json_request', 0) # creates a request at http://localhost:8080/json_request
    def json_request(req, args):
        return {
            "post": args["post"],
        }

A ``GET`` request as ``plain text``:

.. code:: python

    @server.text_get('/text_request', 0) # creates a request at http://localhost:8080/text_request
    def text_request(req, args):
        return "plain text"

Worker threads and caching
~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    def json_worker(args):
        # ...
        # long, slow computation
        return myresult # myresult must be JSON convertible

and accessed from the client. An instance of the ``Worker`` class is
needed:

.. code:: javascript

    var work = new quick_server.Worker();
    work.status(function(req) {
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
    }, function(data) {
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
    def json_worker(args):
        # ...
        # long, slow computation
        return myresult # myresult must be JSON convertible

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

or use the ``no_command_loop`` flag and run the script normally.

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
