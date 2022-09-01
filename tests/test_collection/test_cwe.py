import os
import shutil
from logging import INFO
from pathlib import Path

import pandas as pd
import pytest

import extract_cwe_record
from .conftest import TEST_DATA


@pytest.fixture(scope='function', autouse=False)
def cwe_file_to_data_path(mocked_data_path):
    cwe_path = shutil.copy2(Path(TEST_DATA) / 'cwec_v0.0.xml', Path(mocked_data_path) / 'cwec_v0.0.xml')
    yield
    os.remove(cwe_path)


class TestExtractCWE:
    def test_columns_added(self, mock_zipped_cwe_json_url):
        expected_columns = ['cwe_id', 'cwe_name', 'description', 'extended_description', 'url', 'is_category']

        cwe_records: pd.DataFrame = extract_cwe_record.extract_cwe()

        # Test for whether the correct columns have been added
        assert list(cwe_records.columns) == expected_columns

    def test_default_entries_added(self, mock_zipped_cwe_json_url):
        cwe_records: pd.DataFrame = extract_cwe_record.extract_cwe()

        # Test for that the custom noinfo and Other CWEs have been added
        assert 1 == len(cwe_records.loc[cwe_records['cwe_id'] == 'NVD-CWE-noinfo'])
        assert 1 == len(cwe_records.loc[cwe_records['cwe_id'] == 'NVD-CWE-Other'])

    def test_cwe_json_entries_added(self, mock_zipped_cwe_json_url):

        cwe_records: pd.DataFrame = extract_cwe_record.extract_cwe()

        assert cwe_records[['cwe_id', 'cwe_name', 'url', 'is_category']].loc[
                   cwe_records['cwe_id'] == 'CWE-102'].values.tolist()[0] == [
                   'CWE-102',  # cwe_id
                   "Struts: Duplicate Validation Forms",  # cwe_name
                   'https://cwe.mitre.org/data/definitions/102.html',  # url
                   False  # is_category
               ]


class TestExtractFromExistingCWE:
    def test_logger(self, caplog: pytest.LogCaptureFixture, cwe_file_to_data_path: str):
        caplog.set_level(INFO, 'CVEfixes')
        extract_cwe_record.extract_cwe()

        assert INFO == caplog.records[-1].levelno
        assert 'Reusing the CWE XML file that' in caplog.records[-1].message

    def test_columns_added(self, mock_zipped_cwe_json_url):
        cwe_records: pd.DataFrame = extract_cwe_record.extract_cwe()

        # Test for whether the correct columns have been added
        assert list(cwe_records.columns) == ['cwe_id', 'cwe_name', 'description',
                                             'extended_description', 'url', 'is_category']

    def test_default_entries_added(self, mock_zipped_cwe_json_url):
        cwe_records: pd.DataFrame = extract_cwe_record.extract_cwe()

        # Test for that the custom noinfo and Other CWEs have been added
        assert len(cwe_records.loc[cwe_records['cwe_id'] == 'NVD-CWE-noinfo']) == 1
        assert len(cwe_records.loc[cwe_records['cwe_id'] == 'NVD-CWE-Other']) == 1

    def test_cwe_json_entries_added(self, mock_zipped_cwe_json_url):
        cwe_records: pd.DataFrame = extract_cwe_record.extract_cwe()

        assert cwe_records[['cwe_id', 'cwe_name', 'url', 'is_category']].loc[
                   cwe_records['cwe_id'] == 'CWE-102'].values.tolist()[0] == [
                   'CWE-102',  # cwe_id
                   "Struts: Duplicate Validation Forms",  # cwe_name
                   'https://cwe.mitre.org/data/definitions/102.html',  # url
                   False  # is_category
               ]


class TestCWEClass:
    def test_get_cwe_class(self):
        cve_info = [
            "[{'description': [{'lang': 'en', 'value': 'CWE-252'}]}]",
            "[{'description': [{'lang': 'en', 'value': 'NVD-CWE-Other'}]}]"
        ]

        cwe_classes = extract_cwe_record.get_cwe_class(cve_info)

        assert cwe_classes == [["CWE-252"], ["NVD-CWE-Other"]]

    def test_get_empty_cwe_class(self):
        cve_info = ["[{'description': ''}]"]

        cwe_classes = extract_cwe_record.get_cwe_class(cve_info)

        assert cwe_classes == [["unknown"]]
