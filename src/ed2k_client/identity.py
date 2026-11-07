"""The client's persistent identity: its user hash and its Kad ID.

The user hash names the client to every peer, and eMule ties upload credits and bans to it, so it is created once
and reused: a client whose hash changes between connections from the same address is banned by eMule and its
forks as a credit thief. Bytes 5 and 14 carry eMule's marker values 14 and 111, as every eMule-family client
writes them. Both values are random, contain nothing about the machine, and live in a file readable by its owner
only.
"""

import json
import os
import secrets
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Self

from ed2k_client.constants import HASH_LENGTH, USER_HASH_MARKERS

if TYPE_CHECKING:
    from pathlib import Path

IDENTITY_FILE: str = 'identity.json'
ENCODING: str = 'utf-8'
DIRECTORY_MODE: int = 0o700
FILE_MODE: int = 0o600


@dataclass(frozen=True, slots=True)
class Identity:
    """User hash and Kad ID of this client.

    :ivar user_hash: the 16-byte eD2k user hash.
    :ivar kad_id: the 16-byte Kad node ID as raw bytes in big-endian order.
    """

    user_hash: bytes
    kad_id: bytes

    @classmethod
    def generate(cls) -> Self:
        """Create a fresh random identity.

        :returns: the identity.
        :rtype: Self
        """
        user_hash = bytearray(secrets.token_bytes(HASH_LENGTH))
        for index, value in USER_HASH_MARKERS.items():
            user_hash[index] = value

        return cls(user_hash=bytes(user_hash), kad_id=secrets.token_bytes(HASH_LENGTH))

    @classmethod
    def load_or_create(cls, state_dir: Path) -> Self:
        """Read the identity from the state directory, creating it on first use.

        The file is created with ``O_EXCL`` and mode 0600, so two processes starting at once cannot overwrite each
        other's identity and no other user can read it.

        :param state_dir: the client's state directory.
        :type state_dir: Path
        :returns: the identity.
        :rtype: Self
        """
        state_dir.mkdir(mode=DIRECTORY_MODE, parents=True, exist_ok=True)
        path = state_dir / IDENTITY_FILE
        if path.exists():
            stored = json.loads(path.read_text(encoding=ENCODING))
            return cls(**{name: bytes.fromhex(value) for name, value in stored.items()})

        # A new hash for a known address reads as a stolen identity, and aMule bans it:
        # https://github.com/amule-project/amule/blob/6a1105634d81242a581a0f36a7e00379b12a83f3/src/BaseClient.cpp#L684
        identity = cls.generate()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        with os.fdopen(descriptor, 'w', encoding=ENCODING) as stream:
            json.dump({name: value.hex() for name, value in asdict(identity).items()}, stream)
        return identity
