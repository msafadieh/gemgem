#! /usr/bin/env python3
"""
Minimalistic Gemini server

!!! WARNING: Do not use in production !!!
"""
from argparse import ArgumentParser
import mimetypes
from os import setgid, setuid
import pathlib
from queue import Queue
import socket
import ssl
from threading import Thread
from urllib.request import url2pathname
from urllib.parse import urljoin, urlparse

# Gemini request is <URL><CR><LF> where <URL> is 1024-bytes
MAX_REQUEST_SIZE = 1026

DEFAULT_QSIZE = 32
DEFAULT_THREADS = 4

DEFAULT_HOST = ""
DEFAULT_PORT = 1965
DEFAULT_CERTFILE = "cert.pem"
DEFAULT_KEYFILE = "key.pem"
DEFAULT_WEBROOT = "."

mimetypes.add_type("text/gemini", ".gmi")
mimetypes.add_type("text/gemini", ".gemini")


def create_context(certfile, keyfile):
    """
    Creates SSL context for use in sessions

    certfile: path to SSL certificate
    keyfile: path to SSL private key
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def create_socket(host, port):
    """
    Creates TCP socket and starts listening

    host: host to bind to
    port: port to bind to
    """
    addr = (
        host,
        port,
    )
    if socket.has_dualstack_ipv6():
        gemsocket = socket.create_server(
            addr, family=socket.AF_INET6, dualstack_ipv6=True
        )
    else:
        gemsocket = socket.create_server(addr)
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
    a tuple (path, err). On success, path is a Path object
    and err is None. On failure, path is None and err is
    a byte-string representing a Gemini response

    raw_url: URL in the gemini headers with the CRLF sequence
    webroot: string representation of webroot path
    """

    try:
        parsed_url = urlparse(raw_url)
    except ValueError:
        return None, create_response(59, "Malformed URI")

    if parsed_url.scheme not in (None, "", "gemini"):
        return None, create_response(53, "Proxying is not supported")

    url_path = parsed_url.path
    if not parsed_url.path.endswith("/"):
        url_path += "/"

    decoded_path = url2pathname(url_path)
    safe_path = urljoin(decoded_path, ".")
    path_obj = pathlib.Path(webroot + "/" + safe_path)

    while path_obj.is_dir():
        path_obj = pathlib.Path(path_obj, "index.gmi")

    print(f"{raw_url} => {path_obj}")

    return path_obj, None


def get_mimetype(filename):
    """
    Get mimetype for local file

    filename: string representation of file's path
    """
    mime, mime_sub = mimetypes.guess_type(filename)

    if not mime:
        mime = "application/octet-stream"
    elif mime_sub:
        mime = f"{mime}+{mime_sub}"

    return mime


def handle_request(stream, webroot):
    """
    Handle one request and send response

    stream: file descriptor for request
    webroot: string representation of webroot path
    """
    data = stream.recv(MAX_REQUEST_SIZE)
    try:
        path, err = parse_url(data.decode("utf-8").rstrip("\r\n"), webroot)

        if err:
            resp = err

        elif not path.exists():
            resp = create_response(51, "Not found")

        else:

            mime = get_mimetype(str(path))

            with path.open("rb") as file_stream:
                content = file_stream.read()
                resp = create_response(20, mime, content)

    except UnicodeError:
        resp = create_response(59, "Bad encoding")

    except PermissionError:
        resp = create_response(51, "Access denied")

    return resp


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
            try:
                resp = handle_request(stream, webroot)
            except OSError:
                resp = create_response(59, "Malformed request")
            finally:
                stream.sendall(resp)


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

        connsocket, _ = gemsocket.accept()
        stream = ssl_context.wrap_socket(connsocket, server_side=True)
        queue.put(stream)


def parse_args():
    """
    Parses command line arguments
    """
    parser = ArgumentParser(description="A multi-threaded gemini server")
    parser.add_argument("-b", "--host", default=DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("-p", "--port", default=DEFAULT_PORT, help="Port to bind to")
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
    parser.add_argument(
        "-u",
        "--uid",
        default=0,
        type=int,
        help="uid to use after loading SSL certificate",
    )
    parser.add_argument(
        "-g",
        "--gid",
        default=0,
        type=int,
        help="gid to use after loading SSL certificate",
    )
    return parser.parse_args()


def main():
    """
    Entrypoint function.
    """
    args = parse_args()
    context = create_context(args.cert, args.key)

    if args.gid:
        setgid(args.gid)

    if args.uid:
        setuid(args.uid)

    queue = Queue(maxsize=args.queue)
    try:
        start_threads(args.threads, queue, args.webroot)
        with create_socket(args.host, args.port) as gemsocket:
            server_loop(gemsocket, context, queue)

    except (KeyboardInterrupt, SystemExit):
        print("Received SIGINT. Shutting down...")
    finally:
        stop_threads(args.threads, queue)


if __name__ == "__main__":
    main()
