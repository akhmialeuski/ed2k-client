"""eMule protocol obfuscation of client to client TCP connections.

Specification from the comment at the top of ``EncryptedStreamSocket.cpp`` in aMule, lines 26 to 82 at commit
6a1105634d81242a581a0f36a7e00379b12a83f3. The initiator A knows the user hash of the receiver B and a random 32-bit
key part of its own choosing:

* A sends with RC4 keyed by ``MD5(hash_B + 34 + key_part)`` and receives with ``MD5(hash_B + 203 + key_part)``,
  B the other way round, and both discard the first 1024 bytes of each key stream.
* A sends a semi-random marker byte that is no protocol byte, then the key part, both in the clear, then the
  encrypted ``0x835E6FC4`` sync value, the supported and preferred method (0, obfuscation) and random padding.
* B answers with the encrypted sync value, the selected method and its own padding.

Obfuscation hides the protocol from traffic classification. It gives no protection against an active attacker,
as the specification itself says, so nothing in the client relies on it for security.
"""

import secrets
import struct
from dataclasses import dataclass
from hashlib import md5
from typing import TYPE_CHECKING

from Crypto.Cipher import ARC4

from ed2k_client.constants import Protocol
from ed2k_client.errors import ProtocolError

if TYPE_CHECKING:
    import asyncio

# https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/EncryptedStreamSocket.cpp#L98
MAGIC_REQUESTER: int = 34
MAGIC_SERVER: int = 203
MAGIC_SYNC: int = 0x835E_6FC4
METHOD_OBFUSCATION: int = 0x00

# RC4 leaks its key in the first bytes of the stream, so both sides throw 1024 of them away: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/EncryptedStreamSocket.cpp#L34
KEYSTREAM_DROP: int = 1024
SYNC = struct.Struct('<I')
KEY_PART = struct.Struct('<I')
PROTOCOL_BYTES: frozenset[int] = frozenset({Protocol.EDONKEY, Protocol.EMULE, Protocol.PACKED})


class StreamCipher:
    """One direction of an RC4 stream with the first 1024 bytes discarded."""

    def __init__(self, key: bytes) -> None:
        """Key the stream.

        :param key: the 16-byte MD5 key.
        :type key: bytes
        """
        self._rc4 = ARC4.new(key, drop=KEYSTREAM_DROP)

    def apply(self, data: bytes) -> bytes:
        """Encrypt or decrypt the next bytes of the stream.

        :param data: the input.
        :type data: bytes
        :returns: the output of the same length.
        :rtype: bytes
        """
        return self._rc4.encrypt(data)


@dataclass(frozen=True, slots=True)
class CipherPair:
    """Both directions of an obfuscated connection.

    :ivar send: the stream applied to outgoing bytes.
    :ivar receive: the stream applied to incoming bytes.
    """

    send: StreamCipher
    receive: StreamCipher


def derive_ciphers(*, receiver_hash: bytes, key_part: int, initiator: bool) -> CipherPair:
    """Derive the two RC4 streams of one connection.

    :param receiver_hash: the user hash of the side that accepted the connection.
    :type receiver_hash: bytes
    :param key_part: the initiator's random key part.
    :type key_part: int
    :param initiator: whether the caller opened the connection.
    :type initiator: bool
    :returns: the ciphers of the caller.
    :rtype: CipherPair
    """
    # Both keys hang off the receiver's hash, and the magic byte tells the two directions apart: https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/EncryptedStreamSocket.cpp#L29
    requester = StreamCipher(md5(receiver_hash + bytes([MAGIC_REQUESTER]) + KEY_PART.pack(key_part)).digest())
    server = StreamCipher(md5(receiver_hash + bytes([MAGIC_SERVER]) + KEY_PART.pack(key_part)).digest())
    return CipherPair(send=requester, receive=server) if initiator else CipherPair(send=server, receive=requester)


def semi_random_marker() -> int:
    """Pick a random first byte that cannot be mistaken for an open eD2k packet.

    :returns: the marker byte.
    :rtype: int
    """
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/EncryptedStreamSocket.cpp#L768
    while (marker := secrets.randbelow(256)) in PROTOCOL_BYTES:
        pass
    return marker


def _padding(max_padding: int) -> bytes:
    """Draw random padding of random length, as aMule draws it from its CryptTCPPaddingLength setting.

    :param max_padding: the longest padding.
    :type max_padding: int
    :returns: the padding.
    :rtype: bytes
    """
    # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/EncryptedStreamSocket.cpp#L387
    return secrets.token_bytes(secrets.randbelow(max_padding + 1))


async def _read_handshake_tail(reader: asyncio.StreamReader, cipher: StreamCipher, *, fields: int) -> None:
    """Read and check the encrypted sync value, the method byte or bytes and the padding.

    :param reader: the connection reader.
    :type reader: asyncio.StreamReader
    :param cipher: the receiving stream.
    :type cipher: StreamCipher
    :param fields: method bytes before the padding length, 2 from an initiator and 1 from a receiver.
    :type fields: int
    :raises ProtocolError: on a wrong sync value or an unsupported method.
    """
    # A wrong sync value means the two sides derived different keys, usually from a stale user hash
    sync = SYNC.unpack(cipher.apply(await reader.readexactly(SYNC.size)))[0]
    if sync != MAGIC_SYNC:
        err_msg = 'obfuscation handshake failed: wrong sync value'
        raise ProtocolError(err_msg)

    method_and_padding = cipher.apply(await reader.readexactly(fields + 1))
    if method_and_padding[0] != METHOD_OBFUSCATION:
        err_msg = f'unsupported encryption method {method_and_padding[0]}'
        raise ProtocolError(err_msg)

    # The padding is read through the cipher too, because it advances the key stream on both sides
    cipher.apply(await reader.readexactly(method_and_padding[-1]))


async def open_obfuscated(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, receiver_hash: bytes, max_padding: int
) -> CipherPair:
    """Run the initiator side of the handshake on a fresh connection.

    :param reader: the connection's reader.
    :type reader: asyncio.StreamReader
    :param writer: the connection's writer.
    :type writer: asyncio.StreamWriter
    :param receiver_hash: the user hash of the peer being dialled.
    :type receiver_hash: bytes
    :param max_padding: the longest random padding to send.
    :type max_padding: int
    :returns: the ciphers for the rest of the connection.
    :rtype: CipherPair
    """
    key_part = secrets.randbits(32)
    ciphers = derive_ciphers(receiver_hash=receiver_hash, key_part=key_part, initiator=True)

    # The marker and the key part go in the clear, because B needs the key part to derive its keys
    padding = _padding(max_padding)
    body = SYNC.pack(MAGIC_SYNC) + bytes([METHOD_OBFUSCATION, METHOD_OBFUSCATION, len(padding)]) + padding
    writer.write(bytes([semi_random_marker()]) + KEY_PART.pack(key_part) + ciphers.send.apply(body))
    await writer.drain()

    await _read_handshake_tail(reader, ciphers.receive, fields=1)
    return ciphers


async def accept_obfuscated(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, own_hash: bytes, max_padding: int
) -> CipherPair:
    """Run the receiving side of the handshake after the marker byte was read.

    :param reader: the connection's reader, positioned after the marker byte.
    :type reader: asyncio.StreamReader
    :param writer: the connection's writer.
    :type writer: asyncio.StreamWriter
    :param own_hash: this client's user hash.
    :type own_hash: bytes
    :param max_padding: the longest random padding to send.
    :type max_padding: int
    :returns: the ciphers for the rest of the connection.
    :rtype: CipherPair
    """
    key_part = KEY_PART.unpack(await reader.readexactly(KEY_PART.size))[0]
    ciphers = derive_ciphers(receiver_hash=own_hash, key_part=key_part, initiator=False)
    await _read_handshake_tail(reader, ciphers.receive, fields=2)

    padding = _padding(max_padding)
    writer.write(ciphers.send.apply(SYNC.pack(MAGIC_SYNC) + bytes([METHOD_OBFUSCATION, len(padding)]) + padding))
    await writer.drain()
    return ciphers
