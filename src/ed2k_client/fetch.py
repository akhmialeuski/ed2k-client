"""Download a bootstrap list (``server.met`` or ``nodes.dat``) over HTTPS with a size cap."""

import urllib.request

from ed2k_client.errors import ProtocolError

HTTPS_PREFIX: str = 'https://'


def fetch_https(url: str, *, limit: int, timeout: float) -> bytes:
    """Fetch a URL over HTTPS and refuse a body larger than ``limit``.

    HTTPS is required because these lists decide which hosts the client talks to, and a list fetched in the clear
    could be swapped for one that points at hostile servers.

    :param url: the HTTPS URL.
    :type url: str
    :param limit: the largest accepted body in bytes.
    :type limit: int
    :param timeout: seconds for the connection and for each read.
    :type timeout: float
    :returns: the body.
    :rtype: bytes
    :raises ProtocolError: when the URL, or the one it redirects to, is not HTTPS or the body is too large.
    """
    if not url.startswith(HTTPS_PREFIX):
        err_msg = f'bootstrap lists are fetched over HTTPS only, not {url}'
        raise ProtocolError(err_msg)

    # urlopen follows a redirect to plain HTTP too, so the address the body comes from is checked before it is read.
    # One byte more than the limit is enough to tell an oversized body without reading all of it
    with urllib.request.urlopen(url, timeout=timeout) as response:
        if not (final_url := response.geturl()).startswith(HTTPS_PREFIX):
            err_msg = f'{url} redirected to {final_url}, which is not HTTPS'
            raise ProtocolError(err_msg)
        data = bytes(response.read(limit + 1))

    if len(data) > limit:
        err_msg = f'{url} is larger than {limit} bytes'
        raise ProtocolError(err_msg)
    return data
