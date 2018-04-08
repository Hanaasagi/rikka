import os
import socket
import signal
import selectors
import argparse
from bidict import bidict
from collections import deque
from functools import partial
from itertools import chain
from logger import logger, name2level
from protocol import Protocol, PKGBuilder
from utils import parse_netloc, set_non_blocking, \
    format_addr, create_listening_sock


class Master:

    def __init__(self, pkgbuilder, tunnel_addr, expose_addr):
        self.pkgbuilder = pkgbuilder
        self._stopping = False
        # self._ready = deque()  # task queue
        self.tunnel_pool = deque()
        self.work_pool = bidict()
        self._sel = selectors.DefaultSelector()
        self._buffer = []

        self.init_signal()

        self.expose_sock = create_listening_sock(expose_addr)
        self._sel.register(self.expose_sock, selectors.EVENT_READ,
                           self.accept_expose)

        self.tunnel_sock = create_listening_sock(tunnel_addr)
        self._sel.register(self.tunnel_sock, selectors.EVENT_READ,
                           self.accept_tunnel)

    def accept_expose(self, expose_sock, mask):
        """accept user connection"""
        conn, addr = expose_sock.accept()
        conn.setblocking(False)

        q = (deque(), deque())
        self._sel.register(conn, selectors.EVENT_READ,
                           partial(self.transfer_from_expose, q=q))

        logger.info(f'accept user connection from {format_addr(addr)}')

    def accept_tunnel(self, tunnel_sock, mask):
        """accept tunnel connection"""
        conn, addr = tunnel_sock.accept()
        conn.setblocking(False)

        self.tunnel_pool.append(conn)

        logger.info(f'accept tunnel connection from {format_addr(addr)}, '
                    f'poolsize is {len(self.tunnel_pool)}')

    def transfer_from_expose(self, r_conn, mask, q):
        w_conn = self.work_pool.get(r_conn)
        if w_conn is None:
            w_conn = self.find_available_tunnel()
            if w_conn is None:
                return
            self.work_pool[r_conn] = w_conn
            # self._sel.register(w_conn, selectors.EVENT_READ,
                               # self.transfer_from_tunnel)
            self._sel.register(w_conn, selectors.EVENT_WRITE,
                               partial(self.send_to_tunnel, q=q))

        data = r_conn.recv(4096)  # TODO ConnectionResetError
        if data == b'':
            peer = r_conn.getpeername()
            logger.info(f'closing user connection from {format_addr(peer)}')
            self._sel.unregister(r_conn)
            # self._sel.unregister(w_conn)
            r_conn.close()
            # w_conn.close()
            del self.work_pool[r_conn]
            return
        logger.debug(f'tranfering {data!r} to {w_conn}')
        q[0].append(data)
        self._sel.modify(w_conn, selectors.EVENT_WRITE,
                         partial(self.send_to_tunnel, q=q))
        # w_conn.send(data)

    def transfer_from_tunnel(self, r_conn, mask, q):
        w_conn = self.work_pool.inv.get(r_conn)
        if w_conn is None:  # tunnel connection timeout
            self._sel.unregister(r_conn)
            r_conn.close()
            return

        data = r_conn.recv(4096)
        if data == b'':
            peer = r_conn.getpeername()
            logger.info(f'closing tunnel connection from {format_addr(peer)}')
            self._sel.unregister(r_conn)
            # self._sel.unregister(w_conn)
            r_conn.close()
            # w_conn.close()
            del self.work_pool.inv[r_conn]
            return
        logger.debug(f'tranfering {data!r} to {w_conn}')

        q[1].append(data)
        self._sel.modify(w_conn, selectors.EVENT_WRITE,
                         partial(self.send_to_expose, q=q))

    def send_to_tunnel(self, w_conn, mask, q):
        while len(q[0]):
            try:
                data = q[0].popleft()
                w_conn.send(data)
            except socket.error as e:
                if e.args[0] == socket.errno.EWOULDBLOCK:
                    logger.info('EWOULDBLOCK occur')
                    q[0].appendleft(data)
                    break

        self._sel.modify(w_conn, selectors.EVENT_READ,
                         partial(self.transfer_from_tunnel, q=q))

    def send_to_expose(self, w_conn, mask, q):
        while len(q[1]):
            try:
                data = q[1].popleft()
                w_conn.send(data)
            except socket.error as e:
                if e.args[0] == socket.errno.EWOULDBLOCK:
                    logger.info('EWOULDBLOCK occur')
                    q[1].appendleft(data)
                    break

        self._sel.modify(w_conn, selectors.EVENT_READ,
                         partial(self.transfer_from_tunnel, q=q))

    def _handshake(self, conn_slaver):
        conn_slaver.setblocking(True)  # TODO use nonblocking IO
        conn_slaver.send(self.pkgbuilder.pbuild_hs_m2s())
        buff = conn_slaver.recv(self.pkgbuilder.PACKAGE_SIZE)
        conn_slaver.setblocking(False)
        if buff == b'':  # empty response
            return False
        return self.pkgbuilder.decode_verify(buff,
                                             self.pkgbuilder.PTYPE_HS_S2M)

    def find_available_tunnel(self):
        while True:
            try:
                conn = self.tunnel_pool.popleft()
            except IndexError:
                # no available tunnel connection, just return
                # do not need to wait in a loop, because we work in LT Mode
                logger.info('no available tunnel connection, waiting')
                return

            if not self._handshake(conn):  # handshake first
                conn.close()
                return
            return conn

    def run_forever(self):
        """main loop"""
        while not self._stopping:
            events = self._sel.select(timeout=1)
            # self._ready.extend(events)  # TODO heartbeat
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
        logger.info('stopping now ...')
        self.exit()

    def exit(self):
        """close all listening fds"""
        all_fds = chain(self._wake_fds, self.tunnel_pool,
                        self.work_pool.keys())
        for s in all_fds:
            peer = s.getpeername()
            if peer:  # socket.socketpair have empty peername
                logger.info(f'closing conn from {format_addr(peer)}')
            s.close()

    def init_wake_fds(self):
        self._wake_fds = socket.socketpair()
        for p in self._wake_fds:
            set_non_blocking(p)  # epoll need non-blocking fd

    def init_signal(self):
        self.init_wake_fds()
        signal.signal(signal.SIGINT, lambda *args: None)
        signal.set_wakeup_fd(self._wake_fds[1].fileno())
        self._sel.register(self._wake_fds[0], selectors.EVENT_READ,
                           self.handle_signal)

    def handle_signal(self, expose_sock, mask):
        sig = self._wake_fds[0].recv(1)
        logger.info('recving signal {}'.format(sig))
        self._stopping = True


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
