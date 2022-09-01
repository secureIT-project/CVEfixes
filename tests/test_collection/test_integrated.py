import sqlite3
from typing import BinaryIO

import pandas as pd
import pytest
import pytest_mock

import collect_projects
import constants
import cve_importer


@pytest.mark.integrated
def test_import_cves(conn: sqlite3.Connection,
                     mock_zipped_cve_json_url,
                     mock_zipped_cwe_json_url,
                     mocker: pytest_mock.MockerFixture):
    mocker.patch.object(cve_importer, "currentYear", constants.INIT_YEAR)
    mocker.patch.object(cve_importer, "INIT_YEAR", constants.INIT_YEAR)

    cve_importer.import_cves()
    imported_cves = pd.read_sql("SELECT * FROM 'cve'", con=conn)

    assert len(imported_cves) == 4


SHOULD_BE_IN_FIXES = [
    {'cve_id': 'CVE-1999-0199', 'hash': '2864e767053317538feafa815046fff89e5a16be',
     'repo_url': 'https://github.com/bminor/glibc'},
    {'cve_id': 'CVE-1999-0731', 'hash': '04906bd5de2f220bf100b605dad37b4a1d9a91a6',
     'repo_url': 'https://github.com/KDE/kde1-kdebase'},
    {'cve_id': 'CVE-2002-2443', 'hash': 'cf1a0c411b2668c57c41e9c4efd15ba17b6b322c',
     'repo_url': 'https://github.com/krb5/krb5'},
]


@pytest.mark.integrated
def test_populate_fixes_table(cve_populated_conn: sqlite3.Connection,
                              mocker: pytest_mock.MockerFixture):
    mocker.patch.object(collect_projects, "find_unavailable_urls").return_value = []

    collect_projects.populate_fixes_table()

    df_fixes: pd.DataFrame = pd.read_sql("SELECT * FROM 'fixes'", cve_populated_conn)

    assert df_fixes.equals(pd.DataFrame(SHOULD_BE_IN_FIXES))
