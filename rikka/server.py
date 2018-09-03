import os
import errno
import socket
import signal
import random
import selectors
import argparse
from bidict import bidict
from collections import deque
from functools import partial
from itertools import chain
from rikka.config import Config, ConfigAttribute
from rikka.exceptions import ConfigMissing
from rikka.logger import logger, name2level
from rikka.protocol import Protocol, PKGBuilder, BUF_SIZE, \
    sentinel
from rikka.utils import parse_netloc, set_non_blocking, \
    format_addr, create_listening_sock


from argparse import Namespace
from socket import socket as socket_t
from typing import List, Optional

POS = 0  # expose to tunnel
NEG = 1  # tunnel to expose


class Server:

    tunnel_addr = ConfigAttribute('tunnel', parse_netloc)
    expose_addr = ConfigAttribute('bind', parse_netloc)

    def __init__(self, pkgbuilder: PKGBuilder, config: Config) -> None:
        self._ready: deque = deque()  # task queue
        self._config = config
        self._stopping = False
        self._pkgbuilder = pkgbuilder
        self._sel = selectors.DefaultSelector()

        self.tunnel_pool: deque = deque()
        self.work_pool = bidict()

        # reinstall signal
        self.init_signal()
        # select timeout
        self.reset_timeout()

        self.start_listen()

    @property
    def config(self) -> Config:
        return self._config

    def start_listen(self) -> None:
        """listen expose conn and tunnel conn"""
        self.expose_sock = create_listening_sock(self.expose_addr)
        self._sel.register(self.expose_sock, selectors.EVENT_READ,
                           self.accept_expose)

        self.tunnel_sock = create_listening_sock(self.tunnel_addr)
        self._sel.register(self.tunnel_sock, selectors.EVENT_READ,
                           self.accept_tunnel)

        self._listening_sock = [
            self.expose_sock,
            self.tunnel_sock,
        ]

    def next_timeout(self) -> None:
        """binary exponential backoff"""
        self._timeout_count += 1
        upper_bound = (2 ** min(self._timeout_count, 7)) - 1
        self._timeout = random.randint(1, upper_bound)

    def reset_timeout(self) -> None:
        """reset timeout to initial value"""
        self._timeout: int = 1  # mypy need this variable type
        self._timeout_count: int = 0

    def accept_expose(self, expose_sock: socket_t, mask: int) -> None:
        """accept user connection"""
        conn, addr = expose_sock.accept()
        conn.setblocking(False)

        self._sel.register(conn, selectors.EVENT_READ, self.prepare_transfer)

        logger.info(f'accept user connection from {format_addr(addr)}')

    def accept_tunnel(self, tunnel_sock: socket_t, mask: int) -> None:
        """accept tunnel connection"""
        conn, addr = tunnel_sock.accept()
        conn.setblocking(False)

        self.tunnel_pool.append(conn)

        logger.info(f'accept tunnel connection from {format_addr(addr)}, '
                    f'poolsize is {len(self.tunnel_pool)}')

    def prepare_transfer(self, expose_conn: socket_t, mask: int) -> None:
        tunnel_conn = self.find_available_tunnel()
        if tunnel_conn is None:  # non-available tunnel_conn
            self._sel.unregister(expose_conn)
            # delay
            self._ready.append(
                lambda: self._sel.register(
                    expose_conn, selectors.EVENT_READ,
                    self.prepare_transfer
                )
            )
            return
        self.work_pool[expose_conn] = tunnel_conn
        buf: List[deque] = [deque(), deque()]
        self._sel.register(tunnel_conn,
                           selectors.EVENT_WRITE | selectors.EVENT_READ,
                           partial(self.dispatch_tunnel, buf=buf))
        self._sel.modify(expose_conn,
                         selectors.EVENT_WRITE | selectors.EVENT_READ,
                         partial(self.dispatch_expose, buf=buf))

    def dispatch_tunnel(self, conn: socket_t,
                        mask: int, buf: List[deque]) -> None:
        """schedule tunnel events"""
        if mask & selectors.EVENT_WRITE:
            self.send_to_tunnel(conn, mask, buf)
        if mask & selectors.EVENT_READ:
            self.transfer_from_tunnel(conn, mask, buf)

    def dispatch_expose(self, conn: socket_t,
                        mask: int, buf: List[deque]) -> None:
        """schedule expose events"""
        if mask & selectors.EVENT_WRITE:
            self.send_to_expose(conn, mask, buf)
        if mask & selectors.EVENT_READ:
            self.transfer_from_expose(conn, mask, buf)

    def transfer_from_expose(self, r_conn: socket_t,
                             mask: int, buf: List[deque]) -> None:
        """receive data from expose and store in buffer"""
        w_conn = self.work_pool.get(r_conn)
        if w_conn is None:
            self._sel.unregister(r_conn)
            r_conn.close()
            return

        data = b''
        need_close = False

        try:
            data = r_conn.recv(BUF_SIZE)  # Connection may be close
        except ConnectionError:
            need_close = True

        if data == b'' or need_close:
            try:
                peer = r_conn.getpeername()
                logger.info(f'closing user connection from {format_addr(peer)}')  # noqa
            except OSError as e:
                logger.warn(e)
            self._sel.unregister(r_conn)
            r_conn.close()
            buf[POS].append(sentinel)
            del self.work_pool[r_conn]
            return

        buf[POS].append(data)

    def transfer_from_tunnel(self, r_conn: socket_t,
                             mask: int, buf: List[deque]) -> None:
        """receive data from tunnel and store in buffer"""
        w_conn = self.work_pool.inv.get(r_conn)
        if w_conn is None:
            self._sel.unregister(r_conn)
            r_conn.close()
            return

        data = b''
        need_close = False

        try:
            data = r_conn.recv(BUF_SIZE)
        except ConnectionError:
            need_close = True

        if data == b'' or need_close:
            try:
                peer = r_conn.getpeername()
                logger.info(f'closing tunnel connection from {format_addr(peer)}')  # noqa
            except OSError as e:
                logger.warn(e)
            self._sel.unregister(r_conn)
            r_conn.close()
            buf[NEG].append(sentinel)
            del self.work_pool.inv[r_conn]
            return

        buf[NEG].append(data)

    def send_to_tunnel(self, w_conn: socket_t,
                       mask: int, buf: List[deque]) -> None:
        """send buffer data to tunnel"""
        if not len(buf[POS]):
            return
        try:
            data = buf[POS].popleft()
            if data is sentinel:
                self._sel.unregister(w_conn)
                w_conn.close()
                return
            byte = w_conn.send(data)
        except socket.error as e:
            if e.args[0] == errno.EWOULDBLOCK:
                logger.info('EWOULDBLOCK occur in send to tunnel')
                buf[POS].appendleft(data[byte:])

    def send_to_expose(self, w_conn: socket_t,
                       mask: int, buf: List[deque]) -> None:
        """send buffer data to expose"""
        if not len(buf[NEG]):
            return
        try:
            data = buf[NEG].popleft()
            if data is sentinel:
                self._sel.unregister(w_conn)
                w_conn.close()
                return
            byte = w_conn.send(data)
        except socket.error as e:
            if e.args[0] == errno.EWOULDBLOCK:
                logger.info('EWOULDBLOCK occur in send to expose')
                buf[NEG].appendleft(data[byte:])

    def _handshake(self, conn_slaver: socket_t) -> bool:
        """handshake"""
        conn_slaver.setblocking(True)  # TODO use nonblocking IO
        conn_slaver.send(self._pkgbuilder.pbuild_hs_m2s())
        buff = conn_slaver.recv(self._pkgbuilder.PACKAGE_SIZE)
        conn_slaver.setblocking(False)
        if buff == b'':  # empty response
            return False
        return self._pkgbuilder.decode_verify(buff,
                                              self._pkgbuilder.PTYPE_HS_S2M)

    def find_available_tunnel(self) -> Optional[socket_t]:
        while True:
            try:
                conn = self.tunnel_pool.popleft()
            except IndexError:
                # no available tunnel connection, just return
                # do not need to wait in a loop, because we work in LT Mode
                self.next_timeout()
                logger.info('no available tunnel connection, waiting')
                return None
            else:
                self.reset_timeout()

            if not self._handshake(conn):  # handshake first
                conn.close()
                continue
            return conn

    def run_forever(self) -> None:
        """main loop"""
        while not self._stopping:
            events = self._sel.select(timeout=self._timeout)
            for job in self._ready:  # TODO heartbeat
                job()
            self._ready.clear()

            # from pprint import pprint
            # pprint(events)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
        logger.info('stopping now ...')
        self.exit()

    def exit(self) -> None:
        """close all listening fds"""
        all_fds = chain(self._wake_fds, self.tunnel_pool,
                        self.work_pool.keys(), self._listening_sock)
        for s in all_fds:
            s.close()

    def init_wake_fds(self) -> None:
        self._wake_fds = socket.socketpair()
        for p in self._wake_fds:
            set_non_blocking(p.fileno())  # epoll need non-blocking fd

    def init_signal(self) -> None:
        self.init_wake_fds()
        signal.signal(signal.SIGINT, lambda *args: None)
        signal.set_wakeup_fd(self._wake_fds[1].fileno())
        self._sel.register(self._wake_fds[0], selectors.EVENT_READ,
                           self.handle_signal)

    def handle_signal(self, expose_sock: socket_t, mask: int) -> None:
        sig = self._wake_fds[0].recv(1)
        logger.info('recving signal {}'.format(sig))
        self._stopping = True


def parse_args() -> Namespace:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-c', '--config', default=None, help='config path')
    parser.add_argument('-t', '--tunnel', metavar='host:port', help='')
    parser.add_argument('-b', '--bind', metavar='host:port', help='')
    parser.add_argument('-k', '--secretkey', default='secretkey', help='')
    parser.add_argument('-l', '--level', default='info', help='')
    # parser.add_argument('--ttl', default=300, type=int, dest='ttl', help='')

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = args.config
    delattr(args, 'config')

    config = Config()
    if config_path is not None:
        config.load_file(config_path)
    config.from_object(args)
    try:
        config.validate([
            'tunnel',
            'bind',
            'secretkey',
        ])
    except ConfigMissing as e:
        logger.error(e)
        exit()

    logger.setLevel(name2level(config.level))

    Protocol.set_secret_key(config.secretkey)
    Protocol.recalc_crc32()
    pkgbuilder = PKGBuilder(Protocol)

    master = Server(pkgbuilder, config)
    logger.debug('PID: {}'.format(os.getpid()))
    logger.info('init successful, running as master')
    master.run_forever()


if __name__ == '__main__':
    main()
