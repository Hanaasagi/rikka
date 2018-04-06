import os
import socket
import signal
import selectors
import argparse
from collections import deque
from bidict import bidict
from logger import logger, name2level
from utils import parse_netloc, set_non_blocking, format_addr
from protocol import Protocol, PKGBuilder


class Master:

    def __init__(self, pkgbuilder, tunnel_addr, expose_addr):
        self.pkgbuilder = pkgbuilder
        self._stopping = False
        self._ready = deque()
        self.tunnel_pool = deque()
        self.work_pool = bidict()
        self._sel = selectors.DefaultSelector()
        self._buffer = []
        self._listen_fds = []

        self.init_wake_fds()
        self.init_signal()

        self.expose_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.expose_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.expose_sock.bind(expose_addr)
        self.expose_sock.listen(16)
        self.expose_sock.setblocking(False)
        self._sel.register(self.expose_sock, selectors.EVENT_READ, self.accept_expose)

        self.tunnel_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tunnel_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tunnel_sock.bind(tunnel_addr)
        self.tunnel_sock.listen(16)
        self.tunnel_sock.setblocking(False)
        self._sel.register(self.tunnel_sock, selectors.EVENT_READ,
                           self.accept_tunnel)
        self._listen_fds.append(self.tunnel_sock)

    def accept_tunnel(self, tunnel_sock, mask):
        """accept tunnel connection"""
        conn, addr = tunnel_sock.accept()
        conn.setblocking(False)

        self.tunnel_pool.append(conn)

        logger.info(f'accept tunnel connection from {format_addr(addr)}, '
                    f'poolsize is {len(self.tunnel_pool)}')

    def accept_expose(self, expose_sock, mask):
        """accept user connection"""
        conn, addr = expose_sock.accept()  # Should be ready
        conn.setblocking(False)

        logger.info(f'accepted user connection from {format_addr(addr)}')

        self._sel.register(conn, selectors.EVENT_READ, self.transfer_from_expose)

    def transfer_from_expose(self, r_conn, mask):
        w_conn = self.work_pool.get(r_conn)
        if w_conn is None:
            try:
                w_conn = self.tunnel_pool.popleft()
            except IndexError:
                # no available tunnel connection, just return
                # do not need to wait in a loop, because we work in LT Mode
                return

            if not self._handshake(w_conn):  # handshake first
                w_conn.close()
                r_conn.close()
                return

            self.work_pool[r_conn] = w_conn
            self._sel.register(w_conn, selectors.EVENT_READ,
                               self.transfer_from_tunnel)

        data = r_conn.recv(1024)
        if not data:
            logger.info(f'closing {r_conn}')
            self._sel.unregister(r_conn)
            r_conn.close()
            return
        logger.debug(f'tranfering {data!r} to {w_conn}')
        w_conn.send(data)

    def transfer_from_tunnel(self, r_conn, mask):
        w_conn = self.work_pool.inv.get(r_conn)
        data = r_conn.recv(1024)
        if not data:
            logger.info(f'closing {r_conn}')
            self._sel.unregister(r_conn)
            r_conn.close()
            return
        logger.debug(f'tranfering {data!r} to {w_conn}')
        w_conn.send(data)

    def exit(self):
        """close all listening fds"""
        # TODO

    def run_forever(self):
        """main loop"""
        while not self._stopping:
            events = self._sel.select(timeout=1)
            # logger.debug(events)
            self._ready.extend(events)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
        logger.info('stopping now ...')
        self.exit()

    def init_wake_fds(self):
        self._wake_fds = socket.socketpair()
        for p in self._wake_fds:
            set_non_blocking(p)

    def init_signal(self):
        signal.signal(signal.SIGINT, lambda *args: None)
        signal.set_wakeup_fd(self._wake_fds[1].fileno())
        self._sel.register(self._wake_fds[0], selectors.EVENT_READ,
                           self.handle_signal)

    def handle_signal(self, expose_sock, mask):
        sig = self._wake_fds[0].recv(1)
        logger.info('recving signal {}'.format(sig))
        self._stopping = True

    def _handshake(self, conn_slaver):
        conn_slaver.setblocking(True)  # TODO use nonblocking IO
        conn_slaver.send(self.pkgbuilder.pbuild_hs_m2s())
        buff = conn_slaver.recv(self.pkgbuilder.PACKAGE_SIZE)
        conn_slaver.setblocking(False)
        if buff == b'':  # empty response
            return False
        return self.pkgbuilder.decode_verify(buff, self.pkgbuilder.PTYPE_HS_S2M)  # noqa


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-c', '--config', default=None, help='config path')
    parser.add_argument('-t', '--tunnel', required=True,
                        metavar='host:port', help='')
    parser.add_argument('-b', '--bind', required=True,
                        metavar='host:port', help='')
    parser.add_argument('-k', '--secretkey', default='secretkey', help='')
    parser.add_argument('-l', '--level', default='info', help='')
    parser.add_argument('--ttl', default=300, type=int, dest='ttl', help='')

    return parser.parse_args()


def main():
    args = parse_args()
    tunnel_addr = parse_netloc(args.tunnel)
    expose_addr= parse_netloc(args.bind)
    logger.setLevel(name2level(args.level))

    Protocol.set_secret_key(args.secretkey)
    Protocol.recalc_crc32()
    pkgbuilder = PKGBuilder(Protocol)

    master = Master(pkgbuilder, tunnel_addr, expose_addr)
    logger.debug('PID: {}'.format(os.getpid()))
    logger.info('init successful, running as master')
    master.run_forever()


if __name__ == '__main__':
    main()
