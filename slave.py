import os
import socket
import signal
import selectors
import argparse
from collections import deque
from bidict import bidict
from protocol import Protocol, PKGBuilder
from utils import parse_netloc, set_non_blocking, format_addr
from logger import logger, name2level


class Slaver:

    def __init__(self, pkgbuilder, tunnel_addr, dest_addr, max_spare_count=5):
        self.pkgbuilder = pkgbuilder
        self._stopping = False
        self._ready = deque()
        self.tunnel_addr = tunnel_addr
        self.dest_addr = dest_addr
        self.max_spare_count = max_spare_count
        self.tunnel_pool = deque()
        self.working_pool = bidict()
        self._sel = selectors.DefaultSelector()
        self.init_signal()

    def _connect_tunnel(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.tunnel_addr)
        self._sel.register(sock, selectors.EVENT_READ,
                           self._handshake)
        self.tunnel_pool.append(sock)
        logger.info(f'connect to tunnel {format_addr(self.tunnel_addr)}, '
                    f'poolsize is {len(self.tunnel_pool)}')

    def _connect_dest(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.dest_addr)

        logger.info('connected to dest {} at: {}'.format(
            format_addr(sock.getpeername()),
            format_addr(sock.getsockname()),
        ))
        self._sel.register(sock, selectors.EVENT_READ, self.transfer_from_dest)
        return sock

    def _handshake(self, conn, mask):
        self.tunnel_pool.remove(conn)
        buff = conn.recv(self.pkgbuilder.PACKAGE_SIZE)
        if buff == b'' or not \
                self.pkgbuilder.decode_verify(buff, self.pkgbuilder.PTYPE_HS_M2S):
            logger.info('handshake failed')
            conn.close()
            return False
        logger.debug('handshake successful')
        conn.setblocking(True)
        conn.send(self.pkgbuilder.pbuild_hs_s2m())
        conn.setblocking(False)
        self._sel.modify(conn, selectors.EVENT_READ, self.transfer_from_tunnel)

    def transfer_from_tunnel(self, r_conn, mask):
        data = r_conn.recv(4096)
        if data == b'':
            logger.info(f'closing {r_conn.getpeername()}')
            del self.working_pool[r_conn]
            self._sel.unregister(r_conn)
            r_conn.close()
            return
        sock = self._connect_dest()
        self.working_pool[r_conn] = sock
        sock.send(data)

    def transfer_from_dest(self, r_conn, mask):
        w_conn = self.working_pool.inv.get(r_conn)
        if w_conn is None:
            return
        data = r_conn.recv(4096)
        if data == b'':
            logger.info(f'closing {format_addr(r_conn.getpeername())}')
            self._sel.unregister(r_conn)
            w_conn.close()
            r_conn.close()
            return
        logger.debug(f'tranfering {data!r} to '
                     f'{format_addr(w_conn.getpeername())}')
        w_conn.send(data)

    def manage_tunnel(self):
        while len(self.tunnel_pool) < self.max_spare_count:
            self._connect_tunnel()

    def run_forever(self):
        while not self._stopping:
            self.manage_tunnel()
            events = self._sel.select(timeout=1)
            # self._ready.extend(events)
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)

        logger.info('stopping now ...')
        self.exit()

    def exit(self):
        pass

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

    slaver = Slaver(pkgbuilder, tunnel_addr, dest_addr, max_spare_count)
    logger.debug('PID: {}'.format(os.getpid()))
    logger.info('init successful, running as slaver')

    slaver.run_forever()


if __name__ == '__main__':
    main()
