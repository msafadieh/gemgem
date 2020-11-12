# gemgem

A basic, multi-threaded gemini server

## WARNING

Do not use in production. I only wrote this to learn more about TCP/IP and Python sockets.

## Requirements

- Python 3.8+
- python-magic

## Usage

An SSL certificate and private key are mandatory per the Gemini specifications. By default, the server will bind to all available interfaces on **port 1965**. The default queue size is 32 and the default thread count is 4.

```
usage: gemgem.py [-h] [-b HOST] [-p PORT] [-c CERT] [-k KEY] [-w WEBROOT]
                 [-q QUEUE] [-t THREADS]

A multi-threaded gemini server

optional arguments:
  -h, --help            show this help message and exit
  -b HOST, --host HOST  Host to bind to
  -p PORT, --port PORT  Port to bind to
  -c CERT, --cert CERT  SSL certificate in PEM format
  -k KEY, --key KEY     SSL private key in PEM format
  -w WEBROOT, --webroot WEBROOT
                        Webroot directory
  -q QUEUE, --queue QUEUE
                        Size of request queue
  -t THREADS, --threads THREADS
                        Number of threads
```
