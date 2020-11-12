# gemgem

A basic, multi-threaded gemini server

## WARNING

Do not use in production. I only wrote this to learn more about TCP/IP and Python sockets.

## Requirements

- Python 3.7+
- python-magic

## Usage

An SSL certificate and private key are mandatory per the Gemini specifications. By default, the server will bind to all available interfaces on **port 1965**. The default queue size is 32 and the default thread count is 4.

```
usage: gemgem.py [-h] [-b HOST] [-p PORT] [-6] [-b6 HOST_V6] [-p6 PORT_V6]
                 [-c CERT] [-k KEY] [-w WEBROOT] [-q QUEUE] [-t THREADS]

A multi-threaded gemini server

optional arguments:
  -h, --help            show this help message and exit
  -b HOST, --host HOST  Host to bind to
  -p PORT, --port PORT  Port to bind to
  -6, --ipv6            Enable IPv6
  -b6 HOST_V6, --host-v6 HOST_V6
                        IPv6 host to bind to
  -p6 PORT_V6, --port-v6 PORT_V6
                        IPv6 port to bind to
  -c CERT, --cert CERT  SSL certificate in PEM format
  -k KEY, --key KEY     SSL private key in PEM format
  -w WEBROOT, --webroot WEBROOT
                        Webroot directory
  -q QUEUE, --queue QUEUE
                        Size of request queue
  -t THREADS, --threads THREADS
                        Number of threads
```
