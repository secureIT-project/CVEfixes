import sqlite3
from logging import DEBUG, WARNING
from unittest import mock

import pandas as pd
import pytest
import pytest_mock
from github.GithubException import BadCredentialsException

import collect_projects
from constants import REPO_COLUMNS
from .mock_objects import MockGetRepo, MockGetUser


@pytest.fixture(scope='function')
def repo_meta_mock():
    with mock.patch.object(collect_projects, "get_github_repo_meta") as mocked_get_github_meta_fn:
        yield mocked_get_github_meta_fn


class TestGetGithubMeta:
    def test_exception(self, caplog: pytest.LogCaptureFixture, mocker: pytest_mock.MockerFixture):
        caplog.set_level(WARNING, logger='CVEfixes')

        mocker.patch.object(collect_projects.github.Github, 'get_user', side_effect=Exception)
        collect_projects.get_github_repo_meta('https://github.com/owner/repository', 'None', None)

        assert caplog.records[-1].levelno == WARNING
        assert "issues while getting meta-data" in caplog.records[-1].message.lower()

    def test_bad_credentials_exception(self, caplog: pytest.LogCaptureFixture, mocker: pytest_mock.MockerFixture):
        caplog.set_level(DEBUG, logger='CVEfixes')

        mocker.patch.object(collect_projects.github.Github, 'get_user',
                            side_effect=BadCredentialsException(status=403, data='', headers={}))
        collect_projects.get_github_repo_meta('https://github.com/owner/repository', 'None', None)

        assert caplog.records[-1].levelno == WARNING
        assert "credential problem" in caplog.records[-1].message.lower()

    def test_get_github_meta(self, mocker: pytest_mock.MockerFixture):
        repo_url = 'https://www.github.com/test/test'
        expected_metadata = pd.DataFrame([MockGetRepo().renamed()], columns=REPO_COLUMNS)
        expected_metadata['repo_url'] = repo_url

        mocker.patch.object(collect_projects.github.Github, 'get_user', side_effect=MockGetUser)

        returned_metadata = collect_projects.get_github_repo_meta(repo_url, 'None', None)

        returned_metadata = pd.DataFrame([returned_metadata], columns=REPO_COLUMNS)

        assert returned_metadata.values.tolist() == expected_metadata.values.tolist()


class TestSaveGithubRepo:
    def test_repo_exists(self, conn: sqlite3.Connection, repo_meta_mock):
        fake_gh_url = 'https://github.com/test/test'
        repo_meta = MockGetRepo().renamed()
        repo_meta['repo_url'] = fake_gh_url
        repo_meta_mock.return_value = repo_meta

        collect_projects.save_repo_meta(fake_gh_url)
        collect_projects.save_repo_meta(fake_gh_url)

        stored_metadata = pd.read_sql(f"SELECT * from 'repository'", conn)

        assert 1 == len(stored_metadata)

    def test_repo_doesnt_exist(self, conn: sqlite3.Connection, repo_meta_mock: mock.Mock):
        fake_gh_url = 'https://github.com/test/test'
        expected_repo_meta = MockGetRepo().renamed()
        expected_repo_meta['repo_url'] = fake_gh_url

        repo_meta_mock.return_value = expected_repo_meta
        collect_projects.save_repo_meta(fake_gh_url)
        stored_metadata = pd.read_sql(f"SELECT * from 'repository'", conn).values.tolist()
        expected_repo_meta = pd.DataFrame([expected_repo_meta], columns=REPO_COLUMNS).values.tolist()

        assert expected_repo_meta == stored_metadata
