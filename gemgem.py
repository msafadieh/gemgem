"""
Minimalistic Gemini server

!!! WARNING: Do not use in production !!!
"""
from argparse import ArgumentParser
import pathlib
from queue import Queue
import socket
import ssl
from threading import Thread
from urllib.request import url2pathname
from urllib.parse import urljoin, urlparse
import magic

# Gemini request is <URL><CR><LF> where <URL> is 1024-bytes
MAX_REQUEST_SIZE = 1026

DEFAULT_QSIZE = 32
DEFAULT_THREADS = 4

DEFAULT_HOST = ""
DEFAULT_PORT = 1965
DEFAULT_HOST_V6 = "::1"
DEFAULT_CERTFILE = "cert.pem"
DEFAULT_KEYFILE = "key.pem"
DEFAULT_WEBROOT = "."


def create_context(certfile, keyfile):
    """
    Creates SSL context for use in sessions

    certfile: path to SSL certificate
    keyfile: path to SSL private key
    """
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def create_socket(host, port, ipv6=False):
    """
    Creates TCP socket and starts listening

    host: host to bind to
    port: port to bind to
    ipv6: whether to create IPv6 socket or not
    """
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    gemsocket = socket.socket(family=family)
    gemsocket.bind(
        (
            host,
            port,
        )
    )
    gemsocket.listen()
    return gemsocket


def create_response(status, meta, body=b""):
    """
    Create byte-encoded gemini response in the form
    of <STATUS><SPACE><META><CR><LF><BODY>

    status: two-digit gemini status code
    meta: response info depending on status
    body: optional body to include in response
    """
    response = f"{status} {meta}\r\n".encode() + body
    return response


def parse_url(raw_url, webroot):
    """
    Parses URL in Gemini response headers and returns
    a Path object

    raw_url: URL in the gemini headers with the CRLF sequence
    webroot: string representation of webroot path
    """
    print(raw_url)
    parsed_url = urlparse(raw_url)

    url_path = parsed_url.path
    if not parsed_url.path.endswith("/"):
        url_path += "/"

    resolved_path = urljoin(url2pathname(url_path), ".")
    path_obj = pathlib.Path(webroot + "/" + resolved_path)

    while path_obj.is_dir():
        path_obj = pathlib.Path(path_obj, "index.gmi")

    return path_obj


def get_mimetype(filename):
    """
    Get mimetype for local file

    filename: string representation of file's path
    """
    magic_obj = magic.open(magic.MAGIC_MIME)
    magic_obj.load()

    mime = magic_obj.file(filename)

    if mime.startswith("text/plain"):
        if filename.endswith(".gmi") or filename.endswith(".gemini"):
            mime = "text/gemini; charset=utf-8"
        else:
            mime = "text/plain; charset=utf-8"

    return mime


def handle_request(stream, webroot):
    """
    Handle one request and send response

    stream: file descriptor for request
    webroot: string representation of webroot path
    """
    data = stream.recv(MAX_REQUEST_SIZE)
    try:
        path = parse_url(data.decode("utf-8").rstrip("\r\n"), webroot)

        if not path.exists():
            resp = create_response(51, "Not found")

        else:

            mime = get_mimetype(str(path))

            with path.open("rb") as file_stream:
                content = file_stream.read()
                resp = create_response(20, mime, content)

    except PermissionError:
        resp = create_response(51, "Access denied")

    stream.sendall(resp)


def thread_loop(queue, webroot):
    """
    Worker thread

    queue: file descriptor queue for open connections
    webroot: string representation of webroot path
    """
    while True:
        stream = queue.get()

        if stream is None:
            break

        with stream:
            handle_request(stream, webroot)


def start_threads(count, queue, webroot):
    """
    Starts workers threads

    count: number of threads
    queue: file descriptor queue for open connections
    webroot: string representation of webroot path
    """
    for _ in range(count):
        Thread(
            target=thread_loop,
            args=(
                queue,
                webroot,
            ),
        ).start()


def stop_threads(count, queue):
    """
    Stops workers threads

    count: number of threads
    queue: file descriptor queue for open connections
    """
    for _ in range(count):
        queue.put_nowait(None)


def server_loop(gemsocket, ssl_context, queue):
    """
    Main server thread, handles TLS & queueing

    gemsocket: main listener socket
    ssl_context: SSL context to use during sessions
    queue: file descriptor queue for open connections
    """
    while True:

        try:
            connsocket, _ = gemsocket.accept()
            stream = ssl_context.wrap_socket(connsocket, server_side=True)

            queue.put(stream)
        except OSError:
            break


def parse_args():
    """
    Parses command line arguments
    """
    parser = ArgumentParser(description="A multi-threaded gemini server")
    parser.add_argument("-b", "--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("-p", "--port", default=DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("-6", "--ipv6", action="store_true", help="Enable IPv6")
    parser.add_argument("-b6", "--host-v6", default=DEFAULT_HOST_V6, help="IPv6 host to bind to")
    parser.add_argument("-p6", "--port-v6", default=DEFAULT_PORT, help="IPv6 port to bind to")
    parser.add_argument(
        "-c", "--cert", default=DEFAULT_CERTFILE, help="SSL certificate in PEM format"
    )
    parser.add_argument(
        "-k", "--key", default=DEFAULT_KEYFILE, help="SSL private key in PEM format"
    )
    parser.add_argument(
        "-w", "--webroot", default=DEFAULT_WEBROOT, help="Webroot directory"
    )
    parser.add_argument(
        "-q", "--queue", default=DEFAULT_QSIZE, help="Size of request queue"
    )
    parser.add_argument(
        "-t", "--threads", default=DEFAULT_THREADS, help="Number of threads"
    )
    return parser.parse_args()


def main():
    """
    Entrypoint function.
    """
    gemsocketv6 = None

    args = parse_args()
    queue = Queue(maxsize=args.queue)
    context = create_context(args.cert, args.key)
    try:
        start_threads(args.threads, queue, args.webroot)
        gemsocket = create_socket(args.host, args.port)
        if args.ipv6:
            gemsocketv6 = create_socket(args.host_v6, args.port_v6, True)
            Thread(target=server_loop, args=(gemsocketv6, context, queue, )).start()
        server_loop(gemsocket, context, queue)
    except (KeyboardInterrupt, SystemExit):
        print("Received SIGINT. Shutting down...")
    finally:
        stop_threads(args.threads, queue)
        gemsocket.shutdown(socket.SHUT_RDWR)
        gemsocket.close()
        if args.ipv6 and gemsocketv6:
            gemsocketv6.shutdown(socket.SHUT_RDWR)
            gemsocketv6.close()


if __name__ == "__main__":
    main()
