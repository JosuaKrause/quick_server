# QuickServer

*QuickServer* is a quick to use and easy to set up server implementation. It has
the following goals / features and is primarily meant to speed up back end
implementation / iteration:

* serve local files as is with basic black-listing
* provide functionality for dynamic requests
* provide a basic command interpret loop for server commands

[![Build Status](https://travis-ci.org/JosuaKrause/quick_server.svg?branch=master)](https://travis-ci.org/JosuaKrause/quick_server)
[![codecov.io](https://codecov.io/github/JosuaKrause/quick_server/coverage.svg?branch=master)](https://codecov.io/github/JosuaKrause/quick_server?branch=master)

## Usage

[example.py](example/example.py) contains a minimal example server.
You can run it with

```bash
./example.py
```

from the examples directory.
Then you can browse to [http://localhost:8000/example/](http://localhost:8000/example/).

## Contributing

Pull requests are highly appreciated :)
Also, feel free to open [issues](https://github.com/JosuaKrause/quick_server/issues) for any questions or bugs you may encounter.
