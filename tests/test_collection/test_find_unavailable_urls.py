from __future__ import annotations

from dataclasses import dataclass
from logging import DEBUG

import pytest
import pytest_mock
import requests_mock

import collect_projects

# ----------------------------------------------------------------------------------------------------------------------


@dataclass
class FakeURL:
    url: str
    status_code: int
    available: bool

    def _is_gitlab(self) -> bool:
        if 'gitlab.com/' in self.url.lower():
            return True

        return False

    def mock(self, requests_mock: requests_mock.Mocker):
        headers: dict['str', 'str'] = {}
        if self._is_gitlab() and not self.available:
            headers['location'] = 'https://gitlab.com/users/sign_in'

        requests_mock.head(self.url, status_code=self.status_code, headers=headers)

    def __str__(self):
        return self.url


# ----------------------------------------------------------------------------------------------------------------------

FAKE_URL_COLLECTION = [
    FakeURL("https://github.com/test1", 200, True),
    FakeURL("https://gitlab.com/test2", 308, False),
    FakeURL("https://github.com/test3", 403, False),
    FakeURL("https://github.com/test4", 404, False),
    FakeURL("https://gitlab.com/test5", 200, True),
]

# ----------------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("urls", [FAKE_URL_COLLECTION])
def test_find_unavailable_urls(urls: list[FakeURL], requests_mock: requests_mock.Mocker):
    """ Tests the correct urls are returned """

    [url.mock(requests_mock) for url in urls]
    expected_unavailable_urls = [url.url for url in urls if not url.available]

    returned_unavailable_urls = collect_projects.find_unavailable_urls([str(url) for url in urls])

    assert expected_unavailable_urls == returned_unavailable_urls


@pytest.mark.parametrize("url", FAKE_URL_COLLECTION)
def test_logging(url: FakeURL, caplog: pytest.LogCaptureFixture, requests_mock: requests_mock.Mocker):
    """ Tests logging for find_unavailable_urls """

    available: bool = url.available
    caplog.set_level(DEBUG, logger='CVEfixes')
    url.mock(requests_mock)

    if available:
        expected_logger_message = f"{url.url} is available with code: {url.status_code}"
    else:
        expected_logger_message = f"{url.url} is not available with code: {url.status_code}"

    collect_projects.find_unavailable_urls([url.url])

    assert expected_logger_message in caplog.records[-1].message


@pytest.mark.parametrize("url", [FakeURL("https://github.com/test1", 429, True)])
def test_timeout_response(url: FakeURL, mocker: pytest_mock.MockerFixture, requests_mock: requests_mock.Mocker):
    """ Tests that sleep is called response is of type timeout """

    def change_mock_status_code_to_ok(*args):
        url.status_code = 200
        url.mock(requests_mock)

    url.mock(requests_mock)

    mocked_sleep = mocker.patch.object(collect_projects.time, 'sleep', side_effect=change_mock_status_code_to_ok)

    collect_projects.find_unavailable_urls([str(url)])

    assert mocked_sleep.call_count == 1
    assert mocked_sleep.mock_calls[0][1][0] == 10
