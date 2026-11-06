"""Exception hierarchy of the client.

Every error the package raises on purpose derives from :class:`Ed2kError`, so a caller can catch the whole family
in one place and still tell a malformed packet from a refused download.
"""


class Ed2kError(Exception):
    """Base class of every error the client raises on purpose."""


class ProtocolError(Ed2kError):
    """A peer, a server or a Kad node sent data that breaks the protocol or a safety limit."""


class ConnectionFailedError(Ed2kError):
    """A TCP or UDP exchange did not complete: refused, timed out or closed early."""


class NotConnectedError(Ed2kError):
    """An operation needs a server or Kad connection that the client does not have."""


class StateInUseError(Ed2kError):
    """Another client process already uses the same state directory and therefore the same user hash."""


class SecurityError(Ed2kError):
    """Untrusted input was refused because it could harm the local machine."""


class DownloadError(Ed2kError):
    """A download could not be completed from any of its sources."""


class HashMismatchError(DownloadError):
    """A downloaded part does not match its eD2k part hash.

    :ivar part: the index of the part that failed.
    """

    def __init__(self, message: str, *, part: int) -> None:
        """Record which part failed.

        :param message: the description.
        :type message: str
        :param part: the index of the part that failed.
        :type part: int
        """
        super().__init__(message)
        self.part = part
