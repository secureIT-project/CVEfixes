import os
import sqlite3
from pathlib import Path
from typing import BinaryIO
from unittest import mock

import pytest
import pytest_mock
import requests_mock

import constants
import cve_importer
import extract_cwe_record

TEST_DATA = "./tests/data"


@pytest.fixture(scope='function')
def mock_zipped_cve_json_url(monkeypatch: pytest.MonkeyPatch, requests_mock: requests_mock.Mocker,
                             tmp_dir: str) -> BinaryIO:
    path_to_zip: Path = Path(tmp_dir) / 'nvdcve-1.1-2002.json.zip'
    json: str = 'nvdcve-1.1-2002.json'

    with monkeypatch.context() as m:
        m.chdir(TEST_DATA)
        if os.system(f'zip {path_to_zip} {json}') != 0:
            raise OSError(f'Could not compress the json file on path {json}.')

    try:
        with open(path_to_zip, 'rb') as zipped_json_file:
            requests_mock.register_uri(
                url='https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.zip',
                method='GET',
                headers={
                    "content-type": "application/x-zip-compressed",
                },
                content=zipped_json_file.read(),
                status_code=200)

            yield
    except IOError as err:
        raise IOError(err)


@pytest.fixture(scope='function')
def mock_zipped_cwe_json_url(monkeypatch: pytest.MonkeyPatch, tmp_dir: str):
    path_to_zip: Path = Path(tmp_dir) / 'cwec_v0.0.xml.zip'
    json: str = 'cwec_v0.0.xml'

    with monkeypatch.context() as m:
        m.chdir(TEST_DATA)
        if os.system(f'zip {path_to_zip} {json}') != 0:
            raise OSError(f'Could not compress the json file on path {json}.')

    try:
        with open(path_to_zip, 'rb') as zipped_json_file:
            with mock.patch.object(extract_cwe_record, "urlopen", return_value=zipped_json_file):
                yield
    except IOError as err:
        raise IOError(err)


# This function relies on that import_cves() function is working as expected
@pytest.fixture(scope='function')
def cve_populated_conn(conn: sqlite3.Connection,
                       mock_zipped_cve_json_url,
                       mock_zipped_cwe_json_url,
                       mocker: pytest_mock.MockerFixture,
                       requests_mock: requests_mock.Mocker) -> sqlite3.Connection:
    """ Connection to a database with a populated cve table """

    mocker.patch.object(cve_importer, "currentYear", constants.INIT_YEAR)
    mocker.patch.object(cve_importer, "INIT_YEAR", constants.INIT_YEAR)

    cve_importer.import_cves()

    mocker.resetall(return_value=True, side_effect=True)
    requests_mock.stop()

    yield conn
