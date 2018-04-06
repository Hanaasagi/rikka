import os
import fcntl


def parse_netloc(netloc):
    ip, _, port = netloc.rpartition(':')
    return ip, int(port)


def set_non_blocking(fd):
    flags = fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
    fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def format_addr(addr):
    return '{}:{}'.format(*addr)
