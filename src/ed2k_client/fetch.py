"""Download a bootstrap list (``server.met`` or ``nodes.dat``) over HTTPS with a size cap."""

import urllib.request

from ed2k_client.errors import ProtocolError

HTTPS_PREFIX: str = 'https://'
DOWNLOAD_TIMEOUT: float = 30.0


def fetch_https(url: str, *, limit: int) -> bytes:
    """Fetch a URL over HTTPS and refuse a body larger than ``limit``.

    HTTPS is required because these lists decide which hosts the client talks to, and a list fetched in the clear
    could be swapped for one that points at hostile servers.

    :param url: the HTTPS URL.
    :type url: str
    :param limit: the largest accepted body in bytes.
    :type limit: int
    :returns: the body.
    :rtype: bytes
    :raises ProtocolError: when the URL is not HTTPS or the body is too large.
    """
    if not url.startswith(HTTPS_PREFIX):
        err_msg = f'bootstrap lists are fetched over HTTPS only, not {url}'
        raise ProtocolError(err_msg)
    with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as response:
        data = bytes(response.read(limit + 1))
    if len(data) > limit:
        err_msg = f'{url} is larger than {limit} bytes'
        raise ProtocolError(err_msg)
    return data
