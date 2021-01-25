from quick_server import setup_restart, create_server, msg
import quick_server
import argparse
import sys

if __name__ == "__main__":
    setup_restart()

    parser = argparse.ArgumentParser(
        prog="quick_server", description='Quick Server')
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=f"quick_server version {quick_server.__version__}")
    parser.add_argument(
        '-a',
        type=str,
        default="localhost",
        help="specifies the server address")
    parser.add_argument(
        '-p',
        type=int,
        default=8080,
        help="specifies the server port")
    parser.add_argument(
        '--www',
        type=str,
        default='..',
        help="the folder to serve files from (defaults to parent folder)")
    args = parser.parse_args()

    addr = args.a
    port = args.p
    www = args.www

    server = create_server((addr, port))
    server.bind_path('/', www)

    server.directory_listing = True
    server.add_default_white_list()
    server.link_empty_favicon_fallback()

    server.suppress_noise = True
    server.report_slow_requests = True

    msg("{0}", " ".join(sys.argv))
    msg("starting server at {0}:{1}", addr if addr else 'localhost', port)
    server.serve_forever()
    msg("shutting down..")
    server.server_close()
