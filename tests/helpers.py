"""Shared helpers of the integration tests: configs, payloads, sources and spies on what a seeder serves."""

import random
import socket
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from ed2k_client import ClientConfig, DownloadSettings, SecurityError, Source
from ed2k_client.constants import CryptOption
from ed2k_client.share import SharedFile
from ed2k_client.sources import SourceOrigin, client_id_from_host

if TYPE_CHECKING:
    from pathlib import Path

    from ed2k_client import Client
    from ed2k_client.share import SharedLibrary

LOOPBACK = '127.0.0.1'
PDF_HEADER = b'%PDF-1.7\n'
DJVU_HEADER = b'AT&TFORM\x00\x00\x00\x00DJVM'
PATTERN = bytes(range(251))
STREAM_TAIL = b'\nendstream\nendobj\n'
FAST = DownloadSettings(max_peers=4, queue_wait=10.0, reask_interval=1.0, source_refresh=2.0, deadline=60.0)


def free_port() -> int:
    """Return a TCP port that is free on loopback right now."""
    with socket.socket() as probe:
        probe.bind((LOOPBACK, 0))
        port: int = probe.getsockname()[1]
        return port


def make_config(root: Path, name: str, **overrides: object) -> ClientConfig:
    """Build a client config that keeps every file under ``root / name``."""
    config = ClientConfig(
        state_dir=root / name / 'state',
        download_dir=root / name / 'downloads',
        tcp_port=0,
        udp_port=0,
        allow_private_peers=True,
        download=FAST,
    )
    return replace(config, **overrides)


def compressible(size: int, *, header: bytes = PDF_HEADER) -> bytes:
    """Bytes that start with a document header and compress well."""
    return (header + PATTERN * (size // len(PATTERN) + 1))[:size]


def incompressible(size: int, *, header: bytes = PDF_HEADER, seed: int = 7) -> bytes:
    """Bytes that do not compress, so blocks travel raw; a PDF wraps them in a stream object as real PDFs do."""
    noise = random.Random(seed).randbytes(size)
    if header != PDF_HEADER:
        return (header + noise)[:size]
    body = header + b'1 0 obj\n<< /Length 0 >>\nstream\n'
    return (
        (body + noise)[: size - len(STREAM_TAIL)] + STREAM_TAIL if size > len(body) + len(STREAM_TAIL) else body[:size]
    )


def write_file(path: Path, data: bytes) -> Path:
    """Write ``data`` to ``path``, creating the parent directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def source_of(seeder: Client, *, obfuscate: bool = False) -> Source:
    """Describe a sharing client as a High ID source on loopback."""
    assert seeder.listening_port is not None
    return Source(
        client_id=client_id_from_host(LOOPBACK),
        port=seeder.listening_port,
        user_hash=seeder.identity.user_hash if obfuscate else None,
        crypt=CryptOption.SUPPORTED if obfuscate else CryptOption(0),
        origin=SourceOrigin.LINK,
    )


type ReadHook = Callable[[SharedFile, int, int, bytes], bytes]


@dataclass(slots=True)
class ServeSpy:
    """Counts the bytes a seeder serves and optionally changes or stops them.

    :ivar served: bytes served so far.
    :ivar hook: called with the file, the range and the true bytes, returns what is sent.
    """

    served: int = 0
    hook: ReadHook | None = None
    _ranges: list[tuple[int, int]] = field(default_factory=list)

    def install(self, library: SharedLibrary) -> None:
        """Wrap the library's read method."""
        original = library.read

        def read(*, shared: SharedFile, start: int, end: int) -> bytes:
            data = original(shared=shared, start=start, end=end)
            if self.hook is not None:
                data = self.hook(shared, start, end, data)
            self.served += len(data)
            self._ranges.append((start, end))
            return data

        library.read = read


def corrupting(shared: SharedFile, start: int, end: int, data: bytes) -> bytes:
    """Flip every byte, as a hostile or broken peer would."""
    del shared, start, end
    return bytes(byte ^ 0xFF for byte in data)


def failing_after(limit: int) -> ReadHook:
    """Serve ``limit`` bytes, then behave as if the file vanished from disk."""
    sent = 0

    def hook(shared: SharedFile, start: int, end: int, data: bytes) -> bytes:
        nonlocal sent
        del shared, start, end
        if sent >= limit:
            err_msg = 'file vanished'
            raise SecurityError(err_msg)
        sent += len(data)
        return data

    return hook
