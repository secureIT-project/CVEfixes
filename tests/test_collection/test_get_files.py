from logging import WARNING

import pandas as pd
import pytest
import pytest_mock

import collect_commits
from .mock_objects import MockCommit, MockModifiedFile

SAMPLE_PYTHON_CODE = """def test_guess_pl_no_code() -> str:
    assert guess_pl(" ") == 'unknown'
    assert guess_pl("") == 'unknown'

    # Just telling guesslang that it's actually PYTHON! :)
    return 'Python3.7'
"""


@pytest.fixture()
def mocked_commit() -> MockCommit:
    return MockCommit()


@pytest.fixture()
def mocked_modified_file() -> MockModifiedFile:
    return MockModifiedFile()


@pytest.fixture()
def mocked_commit_empty_modified_files(mocked_commit: MockCommit) -> MockCommit:
    mocked_commit.modified_files = []
    return mocked_commit


class TestGetFiles:
    def test_no_modified_files(self, mocked_commit_empty_modified_files: MockCommit):
        returned = collect_commits.get_files(mocked_commit_empty_modified_files)

        assert ([], []) == returned

    def test_exception(self, mocked_commit: MockCommit, caplog: pytest.LogCaptureFixture,
                       mocker: pytest_mock.MockerFixture):
        caplog.at_level(WARNING, 'CVEfixes')
        mocker.patch.object(collect_commits, 'get_methods', side_effect=Exception)

        collect_commits.get_files(mocked_commit)

        assert len(caplog.records) > 0
        assert caplog.records[-1].levelno == WARNING
        assert 'Problem while fetching the files:' in caplog.records[-1].message

    def test_get_files(self, mocked_commit: MockCommit, mocker: pytest_mock.MockerFixture):
        mocker.patch.object(collect_commits, 'get_methods', return_value=None)

        modified_file_info, _ = collect_commits.get_files(mocked_commit)

        assert mocked_commit.modified_files[0].file_row().items() <= modified_file_info[0].items()


class TestGetMethodCode:
    def test_get_method_code(self):
        assert "return 'Python3.7'" in collect_commits.get_method_code(SAMPLE_PYTHON_CODE, 6, 6)

    def test_none_code(self):
        assert collect_commits.get_method_code(None, 1, 1) is None

    def test_exception(self, caplog: pytest.LogCaptureFixture):
        caplog.at_level(WARNING, 'CVEfixes')

        collect_commits.get_method_code(5, 5, 5)

        assert len(caplog.records) > 0
        assert caplog.records[-1].levelno == WARNING
        assert "Problem while extracting method code" in caplog.records[-1].message


class TestChangedMethodsBoth:
    def test_methods_both(self, mocked_modified_file: MockModifiedFile):
        new, old = collect_commits.changed_methods_both(mocked_modified_file)

        assert new.pop() == mocked_modified_file.methods[0]
        assert old.pop() == mocked_modified_file.methods_before[0]


class TestGetMethods:
    def test_get_methods(self, mocker: pytest_mock.MockerFixture, mocked_modified_file: MockModifiedFile):
        mocker.patch.object(collect_commits, 'changed_methods_both',
                            return_value=([mocked_modified_file.methods[0]], [mocked_modified_file.methods_before[0]]))
        file_methods = collect_commits.get_methods(mocked_modified_file, None)

        df_file_methods = pd.DataFrame(file_methods)
        method_before = df_file_methods.loc[df_file_methods['before_change'] == 'True']
        method_after = df_file_methods.loc[df_file_methods['before_change'] == 'False']

        assert 'round' in str(method_before['code'])
        assert 'floor' not in str(method_before['code'])

        assert 'floor' in str(method_after['code'])
        assert 'round' not in str(method_after['code'])

    def test_no_changed_methods(self, mocked_modified_file: MockModifiedFile):
        mocked_modified_file.changed_methods = []

        returned_methods = collect_commits.get_methods(mocked_modified_file, None)

        assert returned_methods is None

    def test_exception(self, mocker: pytest_mock.MockerFixture, caplog: pytest.LogCaptureFixture,
                       mocked_modified_file: MockModifiedFile):
        caplog.at_level(WARNING, 'CVEfixes')
        mocker.patch.object(collect_commits, 'get_method_code', side_effect=Exception)

        collect_commits.get_methods(mocked_modified_file, None)

        assert 1 < len(caplog.records)
        assert WARNING == caplog.records[-1].levelno
        assert 'Problem while fetching the methods' in caplog.records[-1].message
