import sqlite3

import pandas as pd
import pytest

import collect_commits

SHOULD_BE_IN_FIXES = [
    {'cve_id': 'CVE-1999-0199', 'hash': '2864e767053317538feafa815046fff89e5a16be',
     'repo_url': 'https://github.com/bminor/glibc'},
    {'cve_id': 'CVE-1999-0731', 'hash': '04906bd5de2f220bf100b605dad37b4a1d9a91a6',
     'repo_url': 'https://github.com/KDE/kde1-kdebase'},
    {'cve_id': 'CVE-2002-2443', 'hash': 'cf1a0c411b2668c57c41e9c4efd15ba17b6b322c',
     'repo_url': 'https://github.com/krb5/krb5'},
]


@pytest.fixture()
def populated_df_cve(cve_populated_conn: sqlite3.Connection) -> pd.DataFrame:
    df_cve_table = pd.read_sql("SELECT * FROM 'cve'", cve_populated_conn)

    return df_cve_table


class TestExtractProjectLinks:
    def test_added_columns(self, populated_df_cve: pd.DataFrame):
        df_fixes: pd.DataFrame = collect_commits.extract_project_links(populated_df_cve)

        # Test correct columns
        assert df_fixes.columns.tolist() == ['cve_id', 'hash', 'repo_url']

    def test_extract_project_links(self, populated_df_cve: pd.DataFrame):
        df_fixes: pd.DataFrame = collect_commits.extract_project_links(populated_df_cve)

        # Test that fixes dataframe contains the expected entries
        assert df_fixes.equals(pd.DataFrame(SHOULD_BE_IN_FIXES))

    def test_no_cves(self):
        df_fixes: pd.DataFrame = collect_commits.extract_project_links(pd.DataFrame())

        assert len(df_fixes) == 0