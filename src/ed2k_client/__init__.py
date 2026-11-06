"""Python client for the eDonkey2000 (eD2k) and Kad networks: connect, search, download and share."""

from ed2k_client.client import Client, ClientConfig, ClientStatus
from ed2k_client.download import ContentPolicy, DownloadProgress, DownloadResult, DownloadSettings
from ed2k_client.errors import (
    ConnectionFailedError,
    DownloadError,
    Ed2kError,
    HashMismatchError,
    NotConnectedError,
    ProtocolError,
    SecurityError,
    StateInUseError,
)
from ed2k_client.hashing import Ed2kHash, FileHashes, hash_file
from ed2k_client.links import FileLink, ServerLink
from ed2k_client.search import FileType, SearchQuery, SearchResult
from ed2k_client.security import DocumentKind, Inspection, inspect_document
from ed2k_client.servermet import ServerEntry, ServerList
from ed2k_client.sources import Source

__all__ = [
    'Client',
    'ClientConfig',
    'ClientStatus',
    'ConnectionFailedError',
    'ContentPolicy',
    'DocumentKind',
    'DownloadError',
    'DownloadProgress',
    'DownloadResult',
    'DownloadSettings',
    'Ed2kError',
    'Ed2kHash',
    'FileHashes',
    'FileLink',
    'FileType',
    'HashMismatchError',
    'Inspection',
    'NotConnectedError',
    'ProtocolError',
    'SearchQuery',
    'SearchResult',
    'SecurityError',
    'ServerEntry',
    'ServerLink',
    'ServerList',
    'Source',
    'StateInUseError',
    'hash_file',
    'inspect_document',
]
