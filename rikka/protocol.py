import struct
import binascii

from typing import Any, Tuple, Sequence, Dict, Type, Optional

INTERNAL_VERSION = 0x000D
BUF_SIZE = 4096


class Protocol:

    PACKAGE_SIZE = 2 ** 6  # 64 bytes
    CTRL_PKG_TIMEOUT = 5   # Protocol recv timeout, in second

    SECRET_KEY = ''
    SECRET_KEY_CRC32 = 0
    SECRET_KEY_REVERSED_CRC32 = 0

    # Package Type
    PTYPE_HS_S2M = -1  # handshake pkg, slaver to master
    PTYPE_HEART_BEAT = 0  # heart beat pkg
    PTYPE_HS_M2S = +1  # handshake pkg, Master to Slaver

    TYPE_NAME_MAP = {
        PTYPE_HS_S2M: "PTYPE_HS_S2M",
        PTYPE_HEART_BEAT: "PTYPE_HEART_BEAT",
        PTYPE_HS_M2S: "PTYPE_HS_M2S",
    }

    FORMAT_PKG = "!b b H 20x 40s"
    FORMATS_DATA = {
        PTYPE_HS_S2M: "!I 36x",
        PTYPE_HEART_BEAT: "!40x",
        PTYPE_HS_M2S: "!I 36x",
    }

    @classmethod
    def set_secret_key(cls, secretkey: str) -> None:
        cls.SECRET_KEY = secretkey

    @classmethod
    def recalc_crc32(cls) -> None:
        cls.SECRET_KEY_CRC32 = binascii.crc32(
            cls.SECRET_KEY.encode('utf-8')
        ) & 0XFFFFFFFF
        cls.SECRET_KEY_REVERSED_CRC32 = binascii.crc32(
            cls.SECRET_KEY[::-1].encode('utf-8')
        ) & 0XFFFFFFFF


class PKGBuilder:

    # how to express subclass of Protocol
    def __init__(self,
                 protocol: Type[Protocol] = Protocol) -> None:
        self.protocol = protocol

    def __getattr__(self, name: str) -> Any:
        return getattr(self.protocol, name)

    def _build_bytes(self, pkg_ver: int = 0x01, pkg_type: int = 0,
                     prgm_ver: int = INTERNAL_VERSION,
                     data: Tuple = (), raw: Optional[bytes] = None) -> bytes:
        return struct.pack(
            self.protocol.FORMAT_PKG,
            pkg_ver,
            pkg_type,
            prgm_ver,
            raw or self.data_encode(pkg_type, data),
        )

    def data_decode(self, ptype: int, data_raw: bytes) -> Tuple:
        return struct.unpack(self.protocol.FORMATS_DATA[ptype], data_raw)

    def data_encode(self, ptype: int, data: Sequence) -> bytes:
        return struct.pack(self.protocol.FORMATS_DATA[ptype], *data)

    def pbuild_hs_m2s(self) -> bytes:
        return self._build_bytes(
            pkg_type=self.protocol.PTYPE_HS_M2S,
            data=(self.protocol.SECRET_KEY_CRC32,)
        )

    def pbuild_hs_s2m(self) -> bytes:
        return self._build_bytes(
            pkg_type=self.protocol.PTYPE_HS_S2M,
            data=(self.protocol.SECRET_KEY_REVERSED_CRC32,)
        )

    def pbuild_heart_beat(self) -> bytes:
        return self._build_bytes(pkg_type=self.PTYPE_HEART_BEAT)

    def decode_only(self, raw: bytes) -> Dict:
        if not raw or len(raw) != self.protocol.PACKAGE_SIZE:
            raise ValueError("package size should be {}, but {}".format(
                self.protocol.PACKAGE_SIZE, len(raw)
            ))
        pkg_ver, pkg_type, prgm_ver, data_raw = struct.unpack(
            self.protocol.FORMAT_PKG, raw
        )
        data = self.data_decode(pkg_type, data_raw)

        return dict(
            pkg_ver=pkg_ver,
            pkg_type=pkg_type,
            prgm_ver=prgm_ver,
            data=data,
            raw=raw,
        )

    def decode_verify(self, raw: bytes,
                      pkg_type: Optional[int] = None) -> bool:
        try:
            pkg = self.decode_only(raw)
        except ValueError:
            return False
        return self.verify(pkg=pkg)

    def verify(self, pkg: Dict) -> bool:
        pkg_type = pkg['pkg_type']
        if pkg_type == self.PTYPE_HS_S2M:
            return pkg['data'][0] == self.SECRET_KEY_REVERSED_CRC32
        elif pkg_type == self.PTYPE_HEART_BEAT:
            return True
        elif pkg_type == self.PTYPE_HS_M2S:
            return pkg['data'][0] == self.SECRET_KEY_CRC32
        return True


# use for stop
sentinel = type('Sentinel', (object,), {})
