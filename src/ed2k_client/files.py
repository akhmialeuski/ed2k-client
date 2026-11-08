"""Owner-only files of the client's state: the server memory, the hash cache and the download progress.

Each is written beside its target and renamed over it, so a crash or a full disk leaves either the old or the new
content and never a half-written file, and each is created readable by its owner only.
"""

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

FILE_MODE: int = 0o600
TEMPORARY_SUFFIX: str = '.tmp'


def write_private(path: Path, data: bytes) -> None:
    """Write a file readable by its owner only, replacing it atomically.

    :param path: the file.
    :type path: Path
    :param data: the content.
    :type data: bytes
    """
    temporary = path.with_name(path.name + TEMPORARY_SUFFIX)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
    temporary.replace(path)
