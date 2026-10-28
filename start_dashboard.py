"""Start the local MedSeg website on Windows, macOS or Linux; no lab dependencies."""
import argparse
from http.server import ThreadingHTTPServer
import webbrowser

from dashboard.serve import make_handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8088)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Port must be in 1024..65535')
    url = f'http://127.0.0.1:{args.port}'
    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(18080))
    except OSError as exc:
        parser.exit(1, f'Cannot start dashboard: {exc}. Stop the existing server or choose --port=8089.\n')
    with server:
        print(f'MedSeg: {url}', flush=True)
        print('Guided simulation and report viewer. This does not start Mininet or Docker.', flush=True)
        print('Leave this terminal open. Press Ctrl+C to stop.', flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
