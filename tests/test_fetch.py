"""Unit tests of the bootstrap download: only an HTTPS body of bounded size is accepted."""

import http.client
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from ed2k_client.errors import ProtocolError
from ed2k_client.fetch import fetch_https

if TYPE_CHECKING:
    from unittest.mock import MagicMock

URLOPEN = 'ed2k_client.fetch.urllib.request.urlopen'
SERVER_MET_URL = 'https://lists.example.org/server.met'
PLAIN_URL = 'http://lists.example.org/server.met'
LIMIT = 1024
TIMEOUT = 1.0
BROKEN_STATUS = 'garbage'
PARTIAL_BODY = b'\xe0\x01'
BROKEN_RESPONSE = 'broken HTTP response'


class TestFetchHttps:
    """Tests of :func:`fetch_https`."""

    @patch(URLOPEN, autospec=True)
    def test_redirect_to_plain_http_is_refused(self, urlopen: MagicMock) -> None:
        """A list whose HTTPS address redirects to plain HTTP is refused before its body is read.

        A list fetched in the clear can be swapped on the way for one that points at hostile servers, so following the
        redirect would undo the reason the address had to be HTTPS.

        :param urlopen: the mocked ``urllib.request.urlopen``, whose response reports the redirected address.
        :type urlopen: MagicMock
        """
        response = urlopen.return_value.__enter__.return_value
        response.geturl.return_value = PLAIN_URL

        with pytest.raises(ProtocolError, match='not HTTPS'):
            fetch_https(SERVER_MET_URL, limit=LIMIT, timeout=TIMEOUT)
        response.read.assert_not_called()

    @patch(URLOPEN, autospec=True)
    def test_broken_status_line_is_a_protocol_error(self, urlopen: MagicMock) -> None:
        """A response whose status line is not HTTP fails as a protocol error.

        urllib wraps only an ``OSError`` in ``URLError`` and lets ``http.client.HTTPException`` through, which is no
        ``OSError``. Every caller falls back on ``OSError`` and ``ProtocolError`` alone, so without the translation a
        broken proxy would stop the client from starting instead of leaving it on its cached lists.

        :param urlopen: the mocked ``urllib.request.urlopen``, which fails as on a garbage status line.
        :type urlopen: MagicMock
        """
        urlopen.side_effect = http.client.BadStatusLine(BROKEN_STATUS)

        with pytest.raises(ProtocolError, match=BROKEN_RESPONSE):
            fetch_https(SERVER_MET_URL, limit=LIMIT, timeout=TIMEOUT)

    @patch(URLOPEN, autospec=True)
    def test_body_cut_short_is_a_protocol_error(self, urlopen: MagicMock) -> None:
        """A chunked body that ends before its last chunk fails as a protocol error.

        :param urlopen: the mocked ``urllib.request.urlopen``, whose response body breaks off.
        :type urlopen: MagicMock
        """
        response = urlopen.return_value.__enter__.return_value
        response.geturl.return_value = SERVER_MET_URL
        response.read.side_effect = http.client.IncompleteRead(PARTIAL_BODY)

        with pytest.raises(ProtocolError, match=BROKEN_RESPONSE):
            fetch_https(SERVER_MET_URL, limit=LIMIT, timeout=TIMEOUT)
