import os
import socket
import fcntl


from typing import Tuple


def parse_netloc(netloc: str) -> Tuple[str, int]:
    ip, _, port = netloc.rpartition(':')
    return ip, int(port)


def set_non_blocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def format_addr(addr):
    return '{}:{}'.format(*addr)


def create_listening_sock(addr):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(addr)
    sock.listen(16)
    sock.setblocking(False)
    return sock
