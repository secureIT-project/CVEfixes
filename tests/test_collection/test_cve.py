import json
import sqlite3
from typing import TextIO

import pandas as pd
import pytest

import constants
import cve_importer
from .conftest import TEST_DATA


@pytest.fixture(scope='function')
def cve_json_file() -> TextIO:
    try:
        with open(f'{TEST_DATA}/nvdcve-1.1-2002.json', 'r') as json_file:
            yield json_file
    except IOError as err:
        raise IOError(err)


def test_assign_cwes_to_cves(conn: sqlite3.Connection,
                             mock_zipped_cwe_json_url):
    cve_importer.assign_cwes_to_cves(
        pd.DataFrame([
            {'cve_id': 'CVE-1999-0199',
             'problemtype_json': [{
                 'description': [{
                     'lang': 'en',
                     'value': 'CWE-252'
                 }]
             }]
             }
        ])
    )

    cwe_classification: pd.DataFrame = pd.read_sql("SELECT * FROM 'cwe_classification'", con=conn)
    cwes: pd.DataFrame = pd.read_sql("SELECT * FROM 'cwe'", con=conn)

    # Test that 'cwe' table has been filled, with at least one of them
    assert len(cwes.loc[cwes['cwe_id'] == 'CWE-252']) == 1

    # Test that CVE and it's weakness ID have been added to cwe_classification
    assert cwe_classification.iloc[0].tolist() == ['CVE-1999-0199', 'CWE-252']


def test_preprocess_jsons(cve_json_file: TextIO):
    # The JSON file includes 5 CVEs, where 4 of them have GitHub references
    # and one of them has no references
    cve_data = json.load(cve_json_file)
    df = pd.DataFrame(cve_data)

    processed_df = cve_importer.preprocess_jsons(df)

    # Tests that CVEs without references have been filtered out
    assert len(processed_df) == 4

    # Tests that columns have been renamed, re-ordered, and that non-relevant have been filtered
    assert constants.ORDERED_CVE_COLUMNS == list(processed_df.columns)
