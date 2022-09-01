from __future__ import annotations

import datetime
import json
import pathlib
import tempfile
from unittest import mock

import pytest
from hypothesis import strategies as st, given

import utils
from collect_commits import guess_pl
from collect_projects import convert_runtime


@pytest.fixture(scope='session')
def tmp_output_dir():
    """ Mock output directory as a temporary directory """
    with tempfile.TemporaryDirectory(prefix="CVEfixes_test_output") as tmpdir:
        with mock.patch.object(utils, 'output_dir', tmpdir):
            yield tmpdir


SAMPLE_PYTHON_CODE = """
from typing import Union


def test_guess_pl_no_code() -> str:
    assert guess_pl(" ") == 'unknown'
    assert guess_pl("") == 'unknown'

    # Just telling guesslang that it's actually PYTHON! :)
    return 'Python3.7'
"""


@pytest.mark.parametrize(('code', 'answer'),
                         [
                             (SAMPLE_PYTHON_CODE, 'Python'),
                             (None, 'unknown'),
                             (" ", 'unknown'),
                             ("", 'unknown'),
                         ])
def test_guess_pl(code, answer) -> None:
    assert guess_pl(code) == answer


def test_make_timestamp(tmp_dir: str) -> None:
    correct_answer = datetime.date.today()
    json_file_dates: list[dict[str, str]] = [
        {'CVE_data_timestamp': str(correct_answer)},
        {'CVE_data_timestamp': str(datetime.date.today() - datetime.timedelta(seconds=1))},      # prev. second
        {'CVE_data_timestamp': str(datetime.date.today() - datetime.timedelta(minutes=60))},     # prev. hour
        {'CVE_data_timestamp': str(datetime.date.today() - datetime.timedelta(days=1))},         # yesterday
        {'CVE_data_timestamp': str(datetime.date.today() - datetime.timedelta(weeks=5))},        # prev. month
        {'CVE_data_timestamp': str(datetime.date.today() - datetime.timedelta(weeks=52))},       # prev. year
    ]

    # Create and store paths for tmp JSON files
    json_files: list[str] = []
    for _ in json_file_dates:
        json_files.append(tempfile.mkstemp(suffix=".json", dir=tmp_dir)[1])

    # Write CVE_data_timestamp to all JSON files
    for i, date in enumerate(json_file_dates):
        with open(json_files[i], 'w') as f:
            json.dump(json_file_dates[i], f)

    assert utils.make_timestamp(pathlib.Path(tmp_dir)) == str(correct_answer)


@given(st.integers(min_value=0), st.integers(min_value=0), st.integers(max_value=59, min_value=0),
       st.integers(max_value=59, min_value=0))
def test_convert_runtime(start_time: int, hours: int, minutes: int, seconds: int):
    end_time = start_time + seconds + minutes * 60 + hours * 60 * 60

    assert (hours, minutes, seconds) == convert_runtime(start_time, end_time)
