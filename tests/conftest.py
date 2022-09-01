import os
import sqlite3
import tempfile
from logging import getLogger, DEBUG
from pathlib import Path
from unittest import mock

import pytest

import configuration
import database


@pytest.fixture(scope='session', autouse=True)
def set_logger_level():
    getLogger('CVEfixes').setLevel(DEBUG)


@pytest.fixture(scope='function', autouse=True)
def mocked_data_path():
    with tempfile.TemporaryDirectory(prefix='CVEfixes') as tmp_dir:
        data_path = str((Path(tmp_dir) / "Data"))
        os.mkdir(data_path)
        with mock.patch.object(configuration, "DATA_PATH", data_path):
            yield data_path


@pytest.fixture(scope='function', autouse=True)
def conn() -> sqlite3.Connection:
    """ Creates a temporary sqlite3 database """

    with sqlite3.Connection(":memory:") as mem_conn:
        with mock.patch.object(database, "conn", mem_conn) as mocked_conn:
            yield mocked_conn


@pytest.fixture(scope='function')
def tmp_dir() -> str:
    """ Create a temporary directory for testing purposes """
    with tempfile.TemporaryDirectory(prefix="CVEfixes_test") as tmpdir:
        yield tmpdir
