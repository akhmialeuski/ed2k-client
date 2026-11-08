"""Pytest configuration shared by every test of the suite."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Cache the case of the invocation directory while the real ``posixpath`` is still in place.

    Workaround for pyfakefs 6.3.2 on Python 3.14, https://github.com/pytest-dev/pyfakefs/issues/1359. While ``fs`` is
    active, pyfakefs swaps the ``posixpath`` that ``pathlib`` compares a path's parser against, so a real path first
    hashed then caches its normalised string in lower case for good. pytest first compares the invocation directory
    while it reports a failed test under ``fs``, and the summary of the run then fails in ``relative_to``. Hashing the
    directory here caches its true case before any test runs. Delete this hook with its test in ``test_conftest.py``
    once a pyfakefs release carries https://github.com/pytest-dev/pyfakefs/pull/1360, which keeps that ``posixpath``.

    :param config: the configuration of the run.
    :type config: pytest.Config
    """
    hash(config.invocation_params.dir)
