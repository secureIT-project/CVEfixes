from logging import WARNING

import pytest
import pytest_mock
import sqlite3
import pandas as pd

import collect_commits
import collect_projects
from .mock_objects import MockRepo, MockCommit, MockModifiedFile, MockMethod


@pytest.fixture(scope='function')
def mocked_repo(mocker: pytest_mock.MockerFixture) -> MockRepo:
    mock_repo = MockRepo()
    mocker.patch.object(collect_commits, 'Repository', return_value=mock_repo)

    return mock_repo


class TestExtractCommits:
    def test(self, mocker: pytest_mock.MockerFixture, mocked_repo: MockRepo):
        mocked_repo_commit = mocked_repo.traverse_commits()[0].commit_row()
        del mocked_repo_commit['modified_files']
        mocked_repo_commit_items = mocked_repo_commit.items()
        mocker.patch.object(collect_commits, 'get_files', return_value=([], []))

        df_commits, _, _ = collect_commits.extract_commits('https://bitbucket.com/test_owner/test_repo', ['some_hash'])
        returned_commit_items = df_commits.iloc[0].to_dict().items()

        assert returned_commit_items >= mocked_repo_commit_items

    def test_github(self, mocker: pytest_mock.MockerFixture, mocked_repo: MockRepo):
        repo_url = 'https://github.com/test_owner/test_repo'
        mocker.patch.object(collect_commits, 'get_files', return_value=([], []))

        df_commits, _, _ = collect_commits.extract_commits(repo_url, 'some_hash')
        returned_commit_items = df_commits.iloc[0].to_dict()

        assert returned_commit_items['repo_url'] == repo_url + '.git'

    def test_exception(self, caplog: pytest.LogCaptureFixture, mocked_repo: MockRepo, mocker: pytest_mock.MockerFixture):
        caplog.set_level(WARNING, 'CVEfixes')

        mocker.patch.object(collect_commits, 'get_files', side_effect=Exception)

        collect_commits.extract_commits('https://bitbucket.com/test_owner/test_repo', ['some_hash'])

        assert len(caplog.records) > 0
        assert caplog.records[-1].levelno == WARNING
        assert 'Problem while fetching the commits' in caplog.records[-1].message


class TestFetchAndStoreCommits:
    df_fixes = pd.DataFrame([{
            'cve_id': '1',
            'hash': 'test_commit_hash_abc123',
            'repo_url': 'https://github.com/test/test'
    }])

    def test_fetch_and_store_commits(self, conn: sqlite3.Connection, mocker: pytest_mock.MockerFixture):
        commit = pd.DataFrame([MockCommit().commit_row()])
        file = pd.DataFrame([MockModifiedFile().file_row()])
        method = pd.DataFrame([MockMethod().method_row(True), MockMethod().method_row(False)])

        mocker.patch.object(collect_projects, 'extract_commits', return_value=(commit, file, method))
        mocker.patch.object(collect_projects, 'save_repo_meta', side_effect=None)

        collect_projects.fetch_and_store_commits(self.df_fixes)

        commits = pd.read_sql("SELECT * FROM 'commits' WHERE hash = 'test_commit_hash_abc123'", conn)
        file_change = pd.read_sql("SELECT * FROM 'file_change' WHERE filename = 'test.py'", conn)
        method_change = pd.read_sql("SELECT * FROM 'method_change'", conn)

        assert len(commits) == 1
        assert len(file_change) == 1
        assert len(method_change) == 2

    def test_no_commits(self, conn: sqlite3.Connection, mocker: pytest_mock.MockerFixture,
                        caplog: pytest.LogCaptureFixture):
        caplog.set_level(WARNING, 'CVEfixes')
        mocker.patch.object(collect_projects, 'extract_commits', return_value=(None, None, None))

        collect_projects.fetch_and_store_commits(self.df_fixes)

        assert len(caplog.records) > 0
        assert caplog.records[0].levelno == WARNING
        assert 'Could not retrieve commit information from: ' in caplog.records[0].message

    def test_exception(self, conn: sqlite3.Connection, mocker: pytest_mock.MockerFixture,
                       caplog: pytest.LogCaptureFixture):
        caplog.set_level(WARNING, 'CVEfixes')
        mocker.patch.object(collect_projects, 'extract_commits', side_effect=Exception)

        collect_projects.fetch_and_store_commits(self.df_fixes)

        print(caplog.records)
        assert len(caplog.records) > 0
        assert caplog.records[0].levelno == WARNING
        assert 'Problem occurred while retrieving the project: ' in caplog.records[0].message
