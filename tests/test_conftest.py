"""Tests of the suite's own pytest configuration."""

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pyfakefs.fake_filesystem import FakeFilesystem


class TestPytestConfigure:
    """Tests of the ``pytest_configure`` hook of ``tests/conftest.py``."""

    def test_invocation_dir_keeps_its_case_inside_a_fake_file_system(
        self, fs: FakeFilesystem, pytestconfig: pytest.Config
    ) -> None:
        """The directory pytest was started in keeps its case when a test first compares it under pyfakefs.

        pytest compares that directory while it reports a failed test, before the fake file system is torn down. A
        case cached in lower case there makes the summary of the run fail with ``ValueError`` from ``relative_to``.

        :param fs: the fake file system, active while the directory is compared.
        :type fs: FakeFilesystem
        :param pytestconfig: the configuration that holds the invocation directory.
        :type pytestconfig: pytest.Config
        """
        del fs
        directory = pytestconfig.invocation_params.dir
        if str(directory) == str(directory).lower():
            pytest.skip('the invocation directory has no upper-case letter to lose')

        assert directory._str_normcase == str(directory)
