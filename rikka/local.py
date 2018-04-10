import os
import socket
import signal
import random
import selectors
import argparse
from bidict import bidict
from collections import deque
from functools import partial
from itertools import chain
from rikka.logger import logger, name2level
from rikka.protocol import Protocol, PKGBuilder, BUF_SIZE
from rikka.utils import parse_netloc, set_non_blocking, format_addr

POS = 0  # from tunnel to dest
NEG = 1  # from dest to tunnel


class Local:

    def __init__(self, pkgbuilder, tunnel_addr, dest_addr, max_spare_count=5):
        self._ready = deque()
        self._stopping = False
        self._pkgbuilder = pkgbuilder
        self.max_spare_count = max_spare_count
        self._sel = selectors.DefaultSelector()

        self.tunnel_addr = tunnel_addr
        self.dest_addr = dest_addr
        self.tunnel_pool = deque()
        self.working_pool = bidict()

        self.init_signal()
        self.reset_timeout()

    def next_timeout(self):
        """binary exponential backoff"""
        self._timeout_count += 1
        upper_bound = (2 ** min(self._timeout_count, 7)) - 1
        self._timeout = random.randint(1, upper_bound)

    def reset_timeout(self):
        """reset timeout to initial value"""
        self._timeout = 1
        self._timeout_count = 0

    def _connect_tunnel(self):
        """establish tunnel connection"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(self.tunnel_addr)
        except ConnectionError:
            self.next_timeout()
            logger.warn(f'master is unreachable, '
                        f'retry after {self._timeout}sec...')  # noqa
            return False

        self.reset_timeout()
        self._sel.register(sock, selectors.EVENT_READ, self.prepare_transfer)
        self.tunnel_pool.append(sock)
        logger.info(f'connect to tunnel {format_addr(self.tunnel_addr)}, '
                    f'poolsize is {len(self.tunnel_pool)}')
        return True

    def _connect_dest(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(self.dest_addr)
        except socket.timeout:
            logger.info('connect dest timeout')
            return
        except ConnectionRefusedError:
            logger.info('dest refused connection')
            return

        logger.info('connected to dest {} at {}'.format(
            format_addr(sock.getpeername()),
            format_addr(sock.getsockname()),
        ))
        return sock

    def _handshake(self, conn):
        buff = conn.recv(self._pkgbuilder.PACKAGE_SIZE)
        if (buff == b'' or not
                self._pkgbuilder.decode_verify(buff, self._pkgbuilder.PTYPE_HS_M2S)):
            logger.info('handshake failed')
            conn.close()
            return False

        logger.debug('handshake successful')
        conn.setblocking(True)  # TODO
        conn.send(self._pkgbuilder.pbuild_hs_s2m())
        conn.setblocking(False)
        return True

    def prepare_transfer(self, conn, mask):
        self.tunnel_pool.remove(conn)
        if not self._handshake(conn):
            self._sel.unregister(conn)
            conn.close()
            return

        # connect dest after handshake successed
        sock = self._connect_dest()
        if sock is None:
            self._sel.unregister(conn)
            conn.close()
            return

        self.working_pool[conn] = sock

        buf = (deque(), deque())
        self._sel.modify(conn, selectors.EVENT_WRITE | selectors.EVENT_READ,
                         partial(self.dispatch_tunnel, buf=buf))
        self._sel.register(sock, selectors.EVENT_WRITE | selectors.EVENT_READ,
                           partial(self.dispatch_dest, buf=buf))

    def dispatch_tunnel(self, conn, mask, buf):
        """schedule tunnel events"""
        if mask & selectors.EVENT_WRITE:
            self.send_to_tunnel(conn, mask, buf)
        if mask & selectors.EVENT_READ:
            self.transfer_from_tunnel(conn, mask, buf)

    def dispatch_dest(self, conn, mask, buf):
        """schedule dest events"""
        if mask & selectors.EVENT_WRITE:
            self.send_to_dest(conn, mask, buf)
        if mask & selectors.EVENT_READ:
            self.transfer_from_dest(conn, mask, buf)

    def transfer_from_tunnel(self, r_conn, mask, buf):
        """receive data from tunnel and store in buffer"""
        w_conn = self.working_pool.get(r_conn)
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
                logger.info(f'closing tunnel connection from {format_addr(peer)}')
            except OSError as e:
                logger.warn(e)
            self._sel.unregister(r_conn)
            self._sel.modify(w_conn, selectors.EVENT_WRITE,
                             partial(self.send_to_dest, buf=buf))
            r_conn.close()
            buf[POS].append(None)
            del self.working_pool[r_conn]
            return

        buf[POS].append(data)

    def transfer_from_dest(self, r_conn, mask, buf):
        """receive data from dest and store in buffer"""
        w_conn = self.working_pool.inv.get(r_conn)
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
                logger.info(f'closing dest connection from {format_addr(peer)}')
            except OSError as e:
                logger.warn(e)
            self._sel.unregister(r_conn)
            self._sel.modify(w_conn, selectors.EVENT_WRITE,
                             partial(self.send_to_tunnel, buf=buf))
            r_conn.close()
            buf[NEG].append(None)
            del self.working_pool.inv[r_conn]
            return

        buf[NEG].append(data)

    def send_to_dest(self, w_conn, mask, buf):
        if not len(buf[POS]):
            return
        try:
            data = buf[POS].popleft()
            if data is None:
                self._sel.unregister(w_conn)
                w_conn.close()
                return
            byte = w_conn.send(data)
        except socket.error as e:
            if e.args[0] == socket.errno.EWOULDBLOCK:
                logger.info('EWOULDBLOCK occur in send to dest')
                buf[POS].appendleft(data[byte:])

    def send_to_tunnel(self, w_conn, mask, buf):
        if not len(buf[NEG]):
            return
        try:
            data = buf[NEG].popleft()
            if data is None:
                self._sel.unregister(w_conn)
                w_conn.close()
                return
            byte = w_conn.send(data)
        except socket.error as e:
            if e.args[0] == socket.errno.EWOULDBLOCK:
                logger.info('EWOULDBLOCK occur in send to tunnel')
                buf[NEG].appendleft(data[byte:])

    def manage_tunnel(self):
        while len(self.tunnel_pool) < self.max_spare_count:
            if not self._connect_tunnel():  # connect failed
                break

    def run_forever(self):
        while not self._stopping:
            self.manage_tunnel()
            events = self._sel.select(timeout=self._timeout)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

        logger.info('stopping now ...')
        self.exit()

    def exit(self):
        """close all listening fds"""
        all_fds = chain(self._wake_fds, self.tunnel_pool,
                        *zip(*self.working_pool.items()))
        for s in all_fds:
            s.close()

    def init_wake_fds(self):
        self._wake_fds = socket.socketpair()
        for p in self._wake_fds:
            set_non_blocking(p)

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
    parser.add_argument('-d', '--dest', required=True,
                        metavar='host:port', help='')
    parser.add_argument('-k', '--secretkey', default='secretkey', help='')
    parser.add_argument('-l', '--level', default='info', help='verbose output')
    parser.add_argument('--ttl', default=300, type=int, dest='ttl', help='')
    parser.add_argument('--max-standby', default=5, type=int,
                        dest='max_spare_count', help='')

    return parser.parse_args()


def main():
    args = parse_args()
    tunnel_addr = parse_netloc(args.tunnel)
    dest_addr = parse_netloc(args.dest)
    max_spare_count = args.max_spare_count
    logger.setLevel(name2level(args.level))

    Protocol.set_secret_key(args.secretkey)
    Protocol.recalc_crc32()
    pkgbuilder = PKGBuilder(Protocol)

    slaver = Local(pkgbuilder, tunnel_addr, dest_addr, max_spare_count)
    logger.debug('PID: {}'.format(os.getpid()))
    logger.info('init successful, running as slaver')

    slaver.run_forever()


if __name__ == '__main__':
    main()