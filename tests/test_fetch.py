"""Unit tests of the bootstrap download: only an HTTPS body of bounded size is accepted."""

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
